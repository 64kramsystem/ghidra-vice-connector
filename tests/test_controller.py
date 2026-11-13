import threading
import time
from unittest.mock import MagicMock

import pytest

from vice.controller import ViceController, ViceStateError, ViceTraceSyncError
from vice.protocol import (
    Checkpoint,
    RawEvent,
    RESP_RESUMED,
    RESP_STOPPED,
    ViceConnectionError,
    ViceInfo,
    ViceTimeoutError,
    ViceValidationError,
)


def raw(sequence, kind, *, checkpoints=(), pc=0x1000):
    return RawEvent(
        sequence,
        kind,
        RESP_STOPPED if kind == "stopped" else RESP_RESUMED,
        pc,
        b"",
        time.monotonic(),
        tuple(checkpoints),
    )


class FakeClient:
    def __init__(self):
        self.event_callback = None
        self.terminal_callback = None
        self.connected = False
        self.calls = []
        self.next_events = []

    def set_event_callback(self, callback):
        self.event_callback = callback

    def set_terminal_callback(self, callback):
        self.terminal_callback = callback

    def connect(self, discover_registers=True):
        self.connected = True

    def vice_info(self):
        return ViceInfo((3, 11, 0, 0), None)

    def banks_available(self, timeout_ms=10_000):
        return []

    def disconnect(self):
        if self.connected:
            self.connected = False
            self.terminal_callback(ViceConnectionError("closed"))

    def abort(self, error):
        self.connected = False
        self.terminal_callback(error)

    def emit(self, event):
        self.event_callback(event)

    def fail(self, message="lost"):
        self.connected = False
        self.terminal_callback(ViceConnectionError(message))

    def _ack(self, name, timeout_ms):
        self.calls.append((name, timeout_ms))
        for event in self.next_events:
            self.emit(event)
        self.next_events = []
        return len(self.calls)

    def acknowledge_step(self, count, step_over, timeout_ms):
        return self._ack(("step", count, step_over), timeout_ms)

    def acknowledge_finish(self, timeout_ms):
        return self._ack("finish", timeout_ms)

    def acknowledge_resume(self, timeout_ms):
        return self._ack("resume", timeout_ms)

    def acknowledge_interrupt(self, timeout_ms):
        return self._ack("interrupt", timeout_ms)

    def registers_get(self, memspace, timeout_ms):
        self.calls.append(("registers_get", memspace, timeout_ms))
        return {"PC": 0x1234}


def connected_controller(*, sync=None):
    client = FakeClient()
    controller = ViceController(client, sync_event=sync)
    controller.connect(discover_registers=False)
    controller.start_event_coordinator(assume_stopped=True)
    return client, controller


def test_step_preserves_raw_order_and_increments_stop_count():
    synchronized = []
    client, controller = connected_controller(
        sync=lambda event, _remaining: synchronized.append(event.kind)
    )
    client.next_events = [raw(1, "resumed"), raw(2, "stopped", pc=0x2345)]

    result = controller.step(timeout_ms=1_000)

    assert synchronized == ["resumed", "stopped"]
    assert result.event.kind == "stopped"
    assert controller.status()["stop_count"] == 1
    assert controller.status()["pc"] == 0x2345
    controller.close()


def test_pending_event_is_drained_before_precondition():
    client, controller = connected_controller()
    with controller.operation_lock:
        client.emit(raw(1, "resumed"))
        with pytest.raises(ViceStateError):
            controller.get_registers()
    assert client.calls == []
    controller.close()


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ((8, 0, True), "row"),
        ((0, 8, True), "column"),
        ((0, 0, 1), "pressed"),
    ],
)
def test_keyboard_matrix_validates_before_stopped_check(arguments, message):
    client, controller = connected_controller()
    with controller._condition:
        controller._execution_state = "running"
    before = controller.command_sequence

    with pytest.raises(ViceValidationError, match=message):
        controller.set_keyboard_matrix(*arguments)

    assert controller.command_sequence == before
    assert client.calls == []
    controller.close()


def test_wait_for_stop_is_passive_and_returns_latest_stop():
    client, controller = connected_controller()
    result = {}

    def waiter():
        result["event"] = controller.wait_for_stop(0, 1_000)

    with controller.operation_lock:
        thread = threading.Thread(target=waiter)
        thread.start()
        client.emit(raw(1, "stopped", pc=0x4567))
        controller._publish(controller._pop_raw(None, require=True))
        thread.join(0.5)
    assert result["event"].pc == 0x4567
    controller.close()


def test_interrupt_accepts_a_checkpoint_stop():
    client, controller = connected_controller()
    with controller._condition:
        controller._execution_state = "running"
    checkpoint = Checkpoint(7, 0x1000, 0x1000, currently_hit=True)
    client.next_events = [
        raw(1, "stopped", checkpoints=(checkpoint,), pc=0x1000)
    ]

    result = controller.interrupt(timeout_ms=100)

    assert result.event.checkpoints == (checkpoint,)
    assert controller.execution_state == "stopped"
    controller.close()


def test_trace_sync_failure_does_not_hide_stopped_state():
    def fail_sync(_event, _remaining):
        raise RuntimeError("trace unavailable")

    client, controller = connected_controller(sync=fail_sync)
    with controller._condition:
        controller._execution_state = "running"
    client.next_events = [raw(1, "stopped", pc=0x2000)]

    with pytest.raises(ViceTraceSyncError):
        controller.interrupt(timeout_ms=100)

    assert controller.status()["execution_state"] == "stopped"
    assert controller.status()["stop_count"] == 1
    assert controller.status()["pc"] == 0x2000
    controller.close()


def test_connection_loss_wakes_waiter():
    client, controller = connected_controller()
    result = {}

    def waiter():
        try:
            controller.wait_for_stop(0, 10_000)
        except BaseException as error:
            result["error"] = error

    thread = threading.Thread(target=waiter)
    thread.start()
    time.sleep(0.01)
    client.fail()
    thread.join(0.5)
    assert isinstance(result["error"], ViceConnectionError)


def test_result_sync_runs_under_operation_lock():
    observed = []
    client = FakeClient()
    controller = ViceController(
        client,
        sync_result=lambda kind, result, _remaining: observed.append(
            (kind, result, controller.operation_lock._is_owned())
        ),
    )
    controller.connect(discover_registers=False)
    controller.start_event_coordinator(assume_stopped=True)

    controller.get_registers()

    assert observed == [("registers", {"PC": 0x1234}, True)]
    controller.close()


def test_high_level_operations_do_not_overlap():
    client, controller = connected_controller()
    active = 0
    maximum = 0
    guard = threading.Lock()

    def registers_get(memspace, timeout_ms):
        nonlocal active, maximum
        with guard:
            active += 1
            maximum = max(maximum, active)
        time.sleep(0.02)
        with guard:
            active -= 1
        return {"PC": 0x1234}

    client.registers_get = registers_get
    threads = [threading.Thread(target=controller.get_registers) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(1)

    assert maximum == 1
    controller.close()


def test_capability_discovery_failure_closes_client():
    client = FakeClient()
    client.vice_info = MagicMock(side_effect=ViceValidationError("bad VICE info"))
    controller = ViceController(client)

    with pytest.raises(ViceValidationError, match="bad VICE info"):
        controller.connect(discover_registers=False)

    assert client.connected is False
    assert controller.connection_state == "disconnected"


def test_rejected_ack_restores_pre_action_execution_state():
    client, controller = connected_controller()
    client.acknowledge_step = MagicMock(
        side_effect=ViceValidationError("bad count")
    )

    with pytest.raises(ViceValidationError, match="bad count"):
        controller.step(timeout_ms=1_000)

    assert controller.execution_state == "stopped"
    controller.close()


def test_composite_checkpoint_calls_share_one_timeout_budget():
    client, controller = connected_controller()
    budgets = []

    def checkpoint_set(*_args, timeout_ms, **_kwargs):
        budgets.append(timeout_ms)
        time.sleep(0.02)
        return Checkpoint(1, 0x1000, 0x1000)

    def checkpoint_list(*, timeout_ms):
        budgets.append(timeout_ms)
        return [Checkpoint(1, 0x1000, 0x1000)]

    client.checkpoint_set = checkpoint_set
    client.checkpoint_list = checkpoint_list

    controller.set_checkpoint(0x1000, 0x1000, timeout_ms=500)

    assert len(budgets) == 2
    assert 1 <= budgets[1] < budgets[0] <= 500
    controller.close()


def test_checkpoint_refresh_failure_reports_applied_mutation():
    client, controller = connected_controller()
    client.checkpoint_set = MagicMock(
        return_value=Checkpoint(1, 0x1000, 0x1000)
    )
    client.checkpoint_list = MagicMock(
        side_effect=ViceTimeoutError("list timed out")
    )

    with pytest.raises(ViceTraceSyncError) as caught:
        controller.set_checkpoint(0x1000, 0x1000, timeout_ms=500)

    assert caught.value.action_applied is True
    assert caught.value.trace_sync_failed is True
    assert isinstance(caught.value.__cause__, ViceTimeoutError)
    controller.close()


def test_raw_sequence_regression_aborts_client():
    client, controller = connected_controller()
    with controller.operation_lock:
        client.emit(raw(2, "stopped"))
        controller._drain_pending()

    client.emit(raw(1, "stopped"))

    assert controller.connection_state == "disconnected"
    assert controller.execution_state == "unknown"


def test_pre_send_budget_exhaustion_has_no_mutation_risk():
    with pytest.raises(ViceTimeoutError) as caught:
        ViceController._remaining_ms(time.monotonic() - 1)

    assert caught.value.outcome_unknown is True
    assert caught.value.state_may_have_changed is False


def test_trace_partial_start_retains_known_checkpoints_for_stop(tmp_path):
    client, controller = connected_controller()
    client.resource_get = MagicMock(side_effect=[0, '/tmp/old.log'])
    cp = MagicMock(number=12)
    client.checkpoint_set = MagicMock(side_effect=[cp, ViceTimeoutError('timeout')])
    client.checkpoint_list = MagicMock(return_value=[cp])
    client.checkpoint_delete = MagicMock()
    client.resource_set_string = MagicMock()
    client.resource_set_int = MagicMock()
    try:
        with pytest.raises(ViceTimeoutError) as caught:
            controller.start_trace([(1, 2), (3, 4)], 7, str(tmp_path / 'trace.log'))
        trace_id = caught.value.trace_id
        assert caught.value.checkpoint_ids == [12]
        with pytest.raises(ViceValidationError) as partial:
            controller.stop_trace(trace_id)
        assert partial.value.checkpoint_ids == []
        client.checkpoint_delete.assert_called_once_with(12, timeout_ms=pytest.approx(client.checkpoint_delete.call_args.kwargs['timeout_ms']))
        assert controller._native_trace['unknown_checkpoint']
    finally:
        controller.close()


def test_trace_stop_retries_only_remaining_owned_checkpoints(tmp_path):
    client, controller = connected_controller()
    client.resource_get = MagicMock(side_effect=[0, '/tmp/old.log'])
    cp1, cp2 = MagicMock(number=12), MagicMock(number=13)
    client.checkpoint_set = MagicMock(side_effect=[cp1, cp2])
    client.checkpoint_list = MagicMock(side_effect=[[cp1, cp2], [cp2]])
    client.checkpoint_delete = MagicMock(side_effect=[None, ViceValidationError('rejected'), None])
    client.resource_set_string = MagicMock()
    client.resource_set_int = MagicMock()
    try:
        _, trace = controller.start_trace([(1, 2), (3, 4)], 7, str(tmp_path / 'trace.log'))
        with pytest.raises(ViceValidationError) as caught:
            controller.stop_trace(trace['trace_id'])
        assert caught.value.checkpoint_ids == [13]
        controller.stop_trace(trace['trace_id'])
        assert [call.args[0] for call in client.checkpoint_delete.call_args_list] == [12, 13, 13]
        assert client.resource_set_string.call_args.args == ('MonitorLogFileName', '/tmp/old.log')
    finally:
        controller.close()


def test_trace_stop_does_not_delete_reused_checkpoint_id(tmp_path):
    client, controller = connected_controller()
    original = MagicMock(number=12, start=1, end=2, stop_on_hit=False, enabled=True,
                         cpu_op=7, temporary=False, memspace=0)
    replacement = MagicMock(number=12, start=3, end=4, stop_on_hit=True, enabled=True,
                            cpu_op=4, temporary=False, memspace=0)
    client.resource_get = MagicMock(side_effect=[0, '/tmp/old.log'])
    client.resource_set_string = MagicMock()
    client.resource_set_int = MagicMock()
    client.checkpoint_set = MagicMock(return_value=original)
    client.checkpoint_list = MagicMock(return_value=[replacement])
    client.checkpoint_delete = MagicMock()
    try:
        _, trace = controller.start_trace([(1, 2)], 7, str(tmp_path / 'trace.log'))
        controller.stop_trace(trace['trace_id'])
        client.checkpoint_delete.assert_not_called()
    finally:
        controller.close()


def test_public_delete_timeout_keeps_unresolved_owned_checkpoint(tmp_path):
    client, controller = connected_controller()
    cp = MagicMock(number=12)
    client.resource_get = MagicMock(side_effect=[0, '/tmp/old.log'])
    client.resource_set_string = MagicMock()
    client.resource_set_int = MagicMock()
    client.checkpoint_set = MagicMock(return_value=cp)
    client.checkpoint_delete = MagicMock(side_effect=ViceTimeoutError('unknown'))
    client.checkpoint_list = MagicMock(return_value=[cp])
    try:
        _, trace = controller.start_trace([(1, 2)], 7, str(tmp_path / 'trace.log'))
        with pytest.raises(ViceTimeoutError):
            controller.delete_checkpoint(12)
        assert controller._native_trace['checkpoint_ids'] == [12]
        with pytest.raises(ViceValidationError) as caught:
            controller.stop_trace(trace['trace_id'])
        assert caught.value.unknown_delete is True
        assert caught.value.checkpoint_ids == [12]
        assert client.checkpoint_delete.call_count == 1
    finally:
        controller.close()


def test_trace_preserves_primary_error_if_resume_fails():
    client, controller = connected_controller()
    controller._execution_state = 'running'
    def interrupt(**kwargs):
        controller._execution_state = 'stopped'
        return MagicMock(event=None)
    controller.interrupt = interrupt
    controller.resume = MagicMock(side_effect=ViceTimeoutError('resume failed'))
    try:
        with pytest.raises(ViceValidationError, match='primary') as caught:
            controller._trace_call(1000, lambda remaining: (_ for _ in ()).throw(ViceValidationError('primary')))
        assert caught.value.resume_error['message'] == 'resume failed'
    finally:
        controller.close()


def test_trace_unsent_checkpoint_timeout_is_not_unknown(tmp_path):
    client, controller = connected_controller()
    client.resource_get = MagicMock(side_effect=[0, '/tmp/old.log'])
    client.checkpoint_set = MagicMock()
    controller._remaining_ms = MagicMock(side_effect=[100, 100, ViceTimeoutError('budget')])
    try:
        with pytest.raises(ViceTimeoutError) as caught:
            controller.start_trace([(1, 2)], 7, str(tmp_path / 'trace.log'))
        assert caught.value.unknown_checkpoint is False
        assert caught.value.logger_enabled is False
        assert caught.value.log_filename == '/tmp/old.log'
        client.checkpoint_set.assert_not_called()
    finally:
        controller.close()


def test_stop_deletes_owned_checkpoint_after_it_is_disabled(tmp_path):
    client, controller = connected_controller()
    cp = MagicMock(number=12, start=1, end=2, stop_on_hit=False, enabled=True,
                   cpu_op=7, temporary=False, memspace=0)
    client.resource_get = MagicMock(side_effect=[0, '/tmp/old.log'])
    client.resource_set_string = MagicMock()
    client.resource_set_int = MagicMock()
    client.checkpoint_set = MagicMock(return_value=cp)
    client.checkpoint_list = MagicMock(return_value=[cp])
    client.checkpoint_delete = MagicMock()
    try:
        _, trace = controller.start_trace([(1, 2)], 7, str(tmp_path / 'trace.log'))
        cp.enabled = False
        controller.stop_trace(trace['trace_id'])
        assert client.checkpoint_delete.call_args.args == (12,)
    finally:
        controller.close()


def test_stop_reconciles_lost_delete_ack_when_checkpoint_is_gone(tmp_path):
    client, controller = connected_controller()
    cp = MagicMock(number=12, start=1, end=2, stop_on_hit=False, enabled=True,
                   cpu_op=7, temporary=False, memspace=0)
    client.resource_get = MagicMock(side_effect=[0, '/tmp/old.log'])
    client.resource_set_string = MagicMock()
    client.resource_set_int = MagicMock()
    client.checkpoint_set = MagicMock(return_value=cp)
    client.checkpoint_list = MagicMock(side_effect=[[cp], []])
    client.checkpoint_delete = MagicMock(side_effect=ViceTimeoutError('ack lost'))
    try:
        _, trace = controller.start_trace([(1, 2)], 7, str(tmp_path / 'trace.log'))
        with pytest.raises(ViceTimeoutError) as caught:
            controller.stop_trace(trace['trace_id'])
        assert caught.value.checkpoint_ids == [12]
        assert caught.value.unknown_delete is True
        _, result = controller.stop_trace(trace['trace_id'])
        assert result['checkpoint_ids'] == []
        assert client.checkpoint_delete.call_count == 1
        assert controller._native_trace is None
    finally:
        controller.close()


def test_frame_cleanup_runs_when_intermediate_trace_sync_fails():
    def sync(event, _remaining):
        if event.kind == "checkpoint_hit":
            raise RuntimeError("sync failed")

    client, controller = connected_controller(sync=sync)
    client.registers_get = lambda *args, **kwargs: {"PC": 0x1000, "LIN": 1}
    client.checkpoint_set = lambda *args, **kwargs: Checkpoint(42, 0, 65535)
    client.checkpoint_condition = lambda *args, **kwargs: None
    client.checkpoint_toggle = lambda *args, **kwargs: None
    deleted = []
    client.checkpoint_delete = lambda number, **kwargs: deleted.append(number)
    client.checkpoint_list = lambda **kwargs: []
    hit = raw(2, "checkpoint_hit", checkpoints=(Checkpoint(7, 1, 1, stop_on_hit=False),))
    client.next_events = [raw(1, "resumed"), hit, raw(3, "stopped")]
    with pytest.raises(ViceTraceSyncError):
        controller.advance_frames(1)
    assert deleted == [42]
    assert controller.execution_state == "stopped"
    assert controller.status()["stop_count"] == 1
    controller.close()


def test_frame_cleanup_failure_preserves_primary_error():
    client, controller = connected_controller()
    client.registers_get = lambda *args, **kwargs: {"PC": 0x1000, "LIN": 1}
    client.checkpoint_set = lambda *args, **kwargs: Checkpoint(42, 0, 65535)
    client.checkpoint_condition = MagicMock(side_effect=ViceConnectionError("primary"))
    client.checkpoint_delete = MagicMock(side_effect=ViceConnectionError("cleanup"))
    client.checkpoint_list = lambda **kwargs: []
    with pytest.raises(ViceConnectionError, match="primary") as caught:
        controller.advance_frames(1)
    assert caught.value.cleanup_complete is False
    assert controller.execution_state == "stopped"
    assert controller.get_registers()[1]["PC"] == 0x1000
    client.checkpoint_delete.assert_called_once()
    controller.close()


def test_frame_unknown_checkpoint_creation_reports_incomplete_cleanup():
    client, controller = connected_controller()
    client.registers_get = lambda *args, **kwargs: {"PC": 0x1000, "LIN": 1}
    client.checkpoint_set = MagicMock(side_effect=ViceTimeoutError("unknown checkpoint"))
    client.checkpoint_list = lambda **kwargs: []
    with pytest.raises(ViceTimeoutError, match="unknown checkpoint") as caught:
        controller.advance_frames(1)
    assert caught.value.cleanup_complete is False
    assert caught.value.unknown_checkpoint is True
    controller.close()


def test_frame_rejected_setup_restores_stopped_state():
    client, controller = connected_controller()
    client.registers_get = lambda *args, **kwargs: {"PC": 0x1000, "LIN": 1}
    client.checkpoint_set = lambda *args, **kwargs: Checkpoint(42, 0, 65535)
    client.checkpoint_condition = MagicMock(side_effect=ViceValidationError("rejected"))
    client.checkpoint_delete = MagicMock()
    client.checkpoint_list = lambda **kwargs: []
    with pytest.raises(ViceValidationError, match="rejected"):
        controller.advance_frames(1)
    assert controller.execution_state == "stopped"
    assert controller.get_registers()[1]["PC"] == 0x1000
    client.checkpoint_delete.assert_called_once()
    controller.close()


def test_frame_timeout_with_continuous_nonstopping_hits():
    client, controller = connected_controller()
    client.registers_get = lambda *args, **kwargs: {"PC": 0x1000, "LIN": 1}
    client.checkpoint_set = lambda *args, **kwargs: Checkpoint(42, 0, 65535)
    client.checkpoint_condition = lambda *args, **kwargs: None
    client.checkpoint_toggle = lambda *args, **kwargs: None
    client.checkpoint_delete = MagicMock()
    client.checkpoint_list = lambda **kwargs: []
    interrupted = []
    def interrupt(*, timeout_ms):
        interrupted.append(True)
        client.emit(raw(500, "stopped"))
        return 1
    client.acknowledge_interrupt = interrupt
    original_pop = controller._pop_raw
    def stream(deadline, *, require):
        if require and not interrupted:
            return raw(1, "checkpoint_hit", checkpoints=(Checkpoint(7, 1, 1, stop_on_hit=False),))
        return original_pop(deadline, require=require)
    controller._pop_raw = stream
    _, result = controller.advance_frames(2, timeout_ms=10)
    assert result["reason"] == "timeout"
    assert interrupted == [True]
    assert controller.execution_state == "stopped"
    assert controller.status()["stop_count"] == 1
    client.checkpoint_delete.assert_called_once()
    controller.close()


def test_already_target_reports_observed_pc_without_new_stop():
    client, controller = connected_controller()
    client.emit(raw(1, "stopped", pc=0x1234))
    with controller.operation_lock:
        controller._drain_pending()
    previous = controller._latest_stop
    client.registers_get = lambda *args, **kwargs: {"PC": 0, "LIN": 1}
    before = controller.status()["stop_count"]
    _, result = controller.run_until(0, 1)
    assert result["reason"] == "target"
    assert result["frames_completed"] == 0
    assert controller.status()["pc"] == 0
    assert controller.status()["stop_count"] == before
    assert controller._latest_stop == previous
    controller.close()


@pytest.mark.parametrize("intermediate_failure", [False, True])
def test_frame_final_sync_failure_preserves_known_stop_and_primary(intermediate_failure):
    def sync(event, _remaining):
        if event.kind == "stopped" or (intermediate_failure and event.kind == "checkpoint_hit"):
            raise RuntimeError("sync " + event.kind)

    client, controller = connected_controller(sync=sync)
    client.registers_get = lambda *args, **kwargs: {"PC": 0x1000, "LIN": 1}
    cp = Checkpoint(42, 0, 65535)
    client.checkpoint_set = lambda *args, **kwargs: cp
    client.checkpoint_condition = lambda *args, **kwargs: None
    client.checkpoint_toggle = lambda *args, **kwargs: None
    client.checkpoint_delete = lambda *args, **kwargs: None
    client.checkpoint_list = lambda **kwargs: []
    events = [raw(1, "resumed")]
    if intermediate_failure:
        events.append(raw(2, "checkpoint_hit", checkpoints=(Checkpoint(7, 1, 1, stop_on_hit=False),)))
    events.append(raw(3, "stopped", checkpoints=(cp,)))
    client.next_events = events
    with pytest.raises(ViceTraceSyncError, match="checkpoint_hit" if intermediate_failure else "stopped"):
        controller.advance_frames(1)
    assert controller.execution_state == "stopped"
    assert controller.status()["stop_count"] == 1
    assert controller.get_registers()[1]["PC"] == 0x1000
    controller.close()


def test_frame_expired_budget_before_creation_does_not_invent_unknown_checkpoint():
    client, controller = connected_controller()
    client.registers_get = lambda *args, **kwargs: {"PC": 0x1000, "LIN": 1}
    client.checkpoint_set = MagicMock()
    client.checkpoint_list = lambda **kwargs: []
    budgets = iter([100, ViceTimeoutError("expired"), 100])

    def remaining(_deadline):
        value = next(budgets)
        if isinstance(value, Exception):
            raise value
        return value

    controller._remaining_ms = remaining
    _, result = controller.advance_frames(1)
    assert result["reason"] == "timeout"
    assert result["frames_completed"] == 0
    assert controller.execution_state == "stopped"
    client.checkpoint_set.assert_not_called()
    controller.close()


def test_cpu_history_requires_stopped_and_serializes_without_trace_sync():
    client, controller = connected_controller()
    entered = threading.Event()
    release = threading.Event()
    def history(count, timeout_ms):
        entered.set()
        assert release.wait(2)
        return []
    client.cpu_history = MagicMock(side_effect=history)
    controller._sync_result = MagicMock()
    thread = threading.Thread(target=lambda: controller.cpu_history(3))
    thread.start()
    assert entered.wait(2)
    assert not controller.operation_lock.acquire(blocking=False)
    release.set()
    thread.join(2)
    assert not thread.is_alive()
    controller._sync_result.assert_not_called()
    controller._execution_state = "running"
    with pytest.raises(ViceStateError):
        controller.cpu_history(3)
    assert client.cpu_history.call_count == 1

def test_conditioned_checkpoint_is_configured_and_refreshed():
    client, controller = connected_controller()
    cp = Checkpoint(7, 0x1000, 0x1000)
    client.checkpoint_set = MagicMock(return_value=cp)
    client.checkpoint_condition = MagicMock()
    client.checkpoint_list = MagicMock(return_value=[cp])
    sequence, (result, _) = controller.set_checkpoint(0x1000, 0x1000, condition="A == $02")
    assert sequence > 0 and result == cp
    client.checkpoint_condition.assert_called_once()
    assert client.checkpoint_condition.call_args.args == (7, "A == $02")
    controller.close()


def test_rejected_condition_deletes_created_checkpoint():
    from vice.protocol import ViceCommandError
    client, controller = connected_controller()
    client.checkpoint_set = MagicMock(return_value=Checkpoint(7, 0x1000, 0x1000))
    client.checkpoint_condition = MagicMock(side_effect=ViceCommandError(1, command=0x22, request_id=2))
    client.checkpoint_delete = MagicMock()
    with pytest.raises(ViceCommandError):
        controller.set_checkpoint(0x1000, 0x1000, condition="invalid")
    assert client.checkpoint_delete.call_args.args == (7,)
    controller.close()


def test_resource_guard_and_autostart_events():
    client, controller = connected_controller()
    client.resource_set_string = MagicMock()
    for name in ("BinaryMonitorServer", "BinaryMonitorServerAddress", "MonitorServer", "MonitorServerAddress", "binarymonitorserver"):
        with pytest.raises(ViceValidationError):
            controller.set_resource(name, "1")
    controller._native_trace = {}
    with pytest.raises(ViceValidationError):
        controller.set_resource("MonitorLogEnabled", "0")
    controller._native_trace = None
    client.acknowledge_autostart = lambda *args, timeout_ms: client._ack("autostart", timeout_ms)
    client.next_events = [raw(1, "resumed"), raw(2, "stopped")]
    result = controller.autostart("/tmp/program.prg")
    assert result.event.kind == "resumed"
    controller._drain_pending(time.monotonic() + 1, through=controller._raw_watermark())
    assert controller.execution_state == "stopped"
    controller.close()


def test_rejected_autostart_publishes_actual_resume():
    from vice.protocol import ViceCommandError
    client, controller = connected_controller()
    def reject(*args, timeout_ms):
        client.emit(raw(1, "resumed"))
        raise ViceCommandError(0x8f, command=0xdd, request_id=8)
    client.acknowledge_autostart = reject
    with pytest.raises(ViceCommandError) as caught:
        controller.autostart("/tmp/missing.prg", timeout_ms=1000)
    assert caught.value.state_may_have_changed
    assert controller.execution_state == "running"
    controller.close()


def test_other_autostart_rejection_preserves_stopped_state():
    from vice.protocol import ViceCommandError
    client, controller = connected_controller()
    client.acknowledge_autostart = MagicMock(side_effect=ViceCommandError(1, command=0xdd, request_id=8))
    with pytest.raises(ViceCommandError):
        controller.autostart("/tmp/missing.prg", timeout_ms=1000)
    assert controller.execution_state == "stopped"
    controller.close()


def test_rejected_condition_cleanup_failure_reports_checkpoint():
    from vice.protocol import ViceCommandError
    client, controller = connected_controller()
    client.checkpoint_set = MagicMock(return_value=Checkpoint(7, 0x1000, 0x1000))
    client.checkpoint_condition = MagicMock(side_effect=ViceCommandError(0x8f, command=0x22, request_id=2))
    client.checkpoint_delete = MagicMock(side_effect=ViceValidationError("cleanup failed"))
    with pytest.raises(ViceCommandError) as caught:
        controller.set_checkpoint(0x1000, 0x1000, condition="invalid")
    assert caught.value.checkpoint_ids == [7]
    assert caught.value.state_may_have_changed is True
    assert caught.value.cleanup_error == "cleanup failed"
    controller.close()


def test_rejected_autostart_marks_only_new_events_as_applied():
    from vice.protocol import ViceCommandError
    client, controller = connected_controller()
    client.acknowledge_autostart = MagicMock(side_effect=ViceCommandError(0x8f, command=0xdd, request_id=8))
    controller._drain_pending = MagicMock()
    controller._raw_watermark = MagicMock(return_value=10)
    controller._pop_raw = MagicMock(side_effect=[raw(9, "stopped"), raw(11, "resumed")])
    controller._publish = MagicMock()
    with pytest.raises(ViceCommandError):
        controller.autostart("/tmp/missing.prg", timeout_ms=1000)
    assert [call.kwargs["action_applied"] for call in controller._publish.call_args_list] == [False, True]
    controller.close()
