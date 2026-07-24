import threading
import time
from unittest.mock import MagicMock

import pytest

from vice.controller import (
    ViceController,
    ViceEventHistoryLost,
    ViceInterruptSuperseded,
    ViceStateError,
    ViceTraceSyncError,
)
from vice.protocol import (
    Checkpoint,
    RawEvent,
    RESP_RESUMED,
    RESP_STOPPED,
    ViceConnectionError,
    ViceTimeoutError,
    ViceValidationError,
)


def raw(sequence, kind, *, checkpoint=None, pc=0x1000):
    return RawEvent(
        sequence,
        kind,
        RESP_STOPPED if kind == "stopped" else RESP_RESUMED,
        pc,
        checkpoint,
        b"",
        time.monotonic(),
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
        return "3.10.0"

    def banks_available(self, timeout_ms=10_000):
        return []

    def disconnect(self):
        if not self.connected:
            return
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


def connected_controller(*, sync=None, history=1024):
    client = FakeClient()
    controller = ViceController(
        client, sync_event=sync, event_history_limit=history
    )
    controller.connect(discover_registers=False)
    controller.start_event_coordinator(assume_stopped=True)
    return client, controller


class TestControllerOrdering:
    def test_step_publishes_resume_then_stop_in_raw_order(self):
        synchronized = []
        client, controller = connected_controller(
            sync=lambda event, _remaining: (
                synchronized.append(event.kind) or len(synchronized)
            )
        )
        client.next_events = [raw(1, "resumed"), raw(2, "stopped")]
        result = controller.step(timeout_ms=1_000)
        assert synchronized == ["resumed", "stopped"]
        assert [event.kind for event in controller.history] == [
            "resumed", "stopped"
        ]
        assert result.event.kind == "stopped"
        assert controller.execution_state == "stopped"
        controller.close()

    def test_pending_event_drains_before_stopped_precondition(self):
        client, controller = connected_controller()
        with controller.operation_lock:
            client.emit(raw(1, "resumed"))
            with pytest.raises(ViceStateError):
                controller.get_registers()
        assert client.calls == []
        controller.close()

    def test_wait_for_stop_does_not_take_operation_lock(self):
        client, controller = connected_controller()
        result = {}

        def waiter():
            result["event"] = controller.wait_for_stop(0, 1_000)

        with controller.operation_lock:
            thread = threading.Thread(target=waiter)
            thread.start()
            client.emit(raw(1, "stopped"))
            # Publish directly while deliberately retaining the operation lock;
            # the waiter must not need that lock after publication.
            event = controller._pop_raw(None, require=True)
            controller._publish(event)
            thread.join(0.5)
        assert not thread.is_alive()
        assert result["event"].sequence == 1
        controller.close()

    def test_coordinator_and_command_never_duplicate_event(self):
        client, controller = connected_controller()
        client.next_events = [raw(1, "resumed"), raw(2, "stopped")]
        controller.step(timeout_ms=1_000)
        time.sleep(0.02)
        assert [event.raw_sequence for event in controller.history] == [1, 2]
        controller.close()

    def test_result_sync_runs_under_operation_lock(self):
        client = FakeClient()
        observed = []
        controller = ViceController(client)
        controller._sync_result = lambda kind, result, _remaining: observed.append(
            (kind, result, controller.operation_lock._is_owned())
        )
        controller.connect(discover_registers=False)
        controller.start_event_coordinator(assume_stopped=True)
        controller.get_registers()
        assert observed == [("registers", {"PC": 0x1234}, True)]
        controller.close()

    def test_high_level_operations_do_not_overlap(self):
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
        threads = [
            threading.Thread(target=controller.get_registers)
            for _ in range(4)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(1)
        assert maximum == 1
        controller.close()


class TestControllerFailures:
    def test_capability_discovery_failure_closes_client(self):
        client = FakeClient()
        client.vice_info = MagicMock(
            side_effect=ViceValidationError("bad VICE info")
        )
        controller = ViceController(client)
        with pytest.raises(ViceValidationError, match="bad VICE info"):
            controller.connect(discover_registers=False)
        assert client.connected is False
        assert controller.connection_state == "disconnected"

    def test_rejected_ack_restores_pre_action_execution_state(self):
        client, controller = connected_controller()
        client.acknowledge_step = MagicMock(
            side_effect=ViceValidationError("bad count")
        )
        with pytest.raises(ViceValidationError, match="bad count"):
            controller.step(timeout_ms=1_000)
        assert controller.execution_state == "stopped"
        controller.close()

    def test_connection_loss_wakes_public_waiter(self):
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

    def test_checkpoint_stop_cannot_satisfy_interrupt(self):
        client, controller = connected_controller()
        with controller._condition:
            controller._execution_state = "running"
        checkpoint = Checkpoint(7, 0x1000, 0x1000, currently_hit=True)
        client.next_events = [raw(1, "stopped", checkpoint=checkpoint)]
        with pytest.raises(ViceInterruptSuperseded) as caught:
            controller.interrupt(timeout_ms=30)
        assert caught.value.checkpoint_event.checkpoint.number == 7
        assert controller.execution_state == "stopped"
        controller.close()

    def test_checkpoint_then_interrupt_stop_succeeds_in_order(self):
        client, controller = connected_controller()
        with controller._condition:
            controller._execution_state = "running"
        checkpoint = Checkpoint(7, 0x1000, 0x1000, currently_hit=True)
        client.next_events = [
            raw(1, "stopped", checkpoint=checkpoint),
            raw(2, "stopped", pc=0x2000),
        ]
        result = controller.interrupt(timeout_ms=100)
        assert result.event.raw_sequence == 2
        assert result.preceding_events[-1].checkpoint.number == 7
        assert [event.raw_sequence for event in controller.history] == [1, 2]
        controller.close()

    def test_history_loss_boundary(self):
        client, controller = connected_controller(history=2)
        with controller.operation_lock:
            for sequence in range(1, 4):
                client.emit(raw(sequence, "stopped"))
                controller._drain_pending()
        assert [event.sequence for event in controller.history] == [2, 3]
        assert controller.wait_for_stop(1, 100).sequence == 2
        with pytest.raises(ViceEventHistoryLost):
            controller.wait_for_stop(0, 100)
        controller.close()

    def test_sync_failure_does_not_publish_event(self):
        def fail_sync(_event, _remaining):
            raise RuntimeError("trace unavailable")

        client, controller = connected_controller(sync=fail_sync)
        client.next_events = [raw(1, "resumed"), raw(2, "stopped")]
        with pytest.raises(ViceTraceSyncError, match="trace unavailable") as caught:
            controller.step(timeout_ms=1_000)
        assert caught.value.action_applied is True
        assert controller.history == ()
        controller.close()

    def test_vice_failure_during_event_sync_is_trace_sync_failure(self):
        def fail_sync(_event, _remaining):
            raise ViceTimeoutError("refresh timed out")

        client, controller = connected_controller(sync=fail_sync)
        client.next_events = [raw(1, "resumed")]
        with pytest.raises(ViceTraceSyncError) as caught:
            controller.resume(timeout_ms=1_000)
        assert caught.value.action_applied is True
        assert caught.value.trace_sync_failed is True
        assert controller.history == ()
        controller.close()

    def test_vice_failure_during_result_sync_is_trace_sync_failure(self):
        client, controller = connected_controller()
        controller._sync_result = MagicMock(
            side_effect=ViceTimeoutError("trace refresh timed out")
        )
        with pytest.raises(ViceTraceSyncError) as caught:
            controller.get_registers(timeout_ms=1_000)
        assert caught.value.action_applied is True
        assert caught.value.trace_sync_failed is True
        controller.close()

    def test_composite_checkpoint_calls_share_one_timeout_budget(self):
        client, controller = connected_controller()
        budgets = []

        def checkpoint_set(*_args, timeout_ms, **_kwargs):
            budgets.append(timeout_ms)
            time.sleep(0.02)
            return Checkpoint(1, 0x1000, 0x1000)

        def checkpoint_list(*, timeout_ms):
            budgets.append(timeout_ms)
            return []

        client.checkpoint_set = checkpoint_set
        client.checkpoint_list = checkpoint_list
        controller.set_checkpoint(0x1000, 0x1000, timeout_ms=500)
        assert len(budgets) == 2
        assert 1 <= budgets[1] < budgets[0] <= 500
        controller.close()

    def test_checkpoint_refresh_failure_reports_applied_mutation(self):
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

    @pytest.mark.parametrize(
        ("method", "arguments", "client_method"),
        [
            ("delete_checkpoint", (1,), "checkpoint_delete"),
            ("toggle_checkpoint", (1, False), "checkpoint_toggle"),
        ],
    )
    def test_other_checkpoint_refresh_failures_report_applied_mutation(
        self, method, arguments, client_method
    ):
        client, controller = connected_controller()
        setattr(client, client_method, MagicMock(return_value=None))
        client.checkpoint_list = MagicMock(
            side_effect=ViceTimeoutError("list timed out")
        )
        with pytest.raises(ViceTraceSyncError) as caught:
            getattr(controller, method)(*arguments, timeout_ms=500)
        assert caught.value.action_applied is True
        assert caught.value.trace_sync_failed is True
        assert isinstance(caught.value.__cause__, ViceTimeoutError)
        controller.close()

    def test_budget_exhaustion_after_checkpoint_mutation_is_sync_failure(self):
        client, controller = connected_controller()

        def checkpoint_set(*_args, timeout_ms, **_kwargs):
            time.sleep(0.02)
            return Checkpoint(1, 0x1000, 0x1000)

        client.checkpoint_set = checkpoint_set
        client.checkpoint_list = MagicMock()
        with pytest.raises(ViceTraceSyncError) as caught:
            controller.set_checkpoint(0x1000, 0x1000, timeout_ms=10)
        assert caught.value.action_applied is True
        client.checkpoint_list.assert_not_called()
        controller.close()

    def test_raw_sequence_regression_aborts_client_and_coordinator(self):
        client, controller = connected_controller()
        with controller.operation_lock:
            client.emit(raw(2, "stopped"))
            controller._drain_pending()
        client.emit(raw(1, "stopped"))
        assert controller.connection_state == "disconnected"
        assert controller.execution_state == "unknown"
        assert controller._coordinator_stop is True

    def test_pre_send_budget_exhaustion_has_no_mutation_risk(self):
        with pytest.raises(ViceTimeoutError) as caught:
            ViceController._remaining_ms(time.monotonic() - 1)
        assert caught.value.outcome_unknown is True
        assert caught.value.state_may_have_changed is False

    def test_running_data_read_sends_no_protocol_frame(self):
        client, controller = connected_controller()
        with controller._condition:
            controller._execution_state = "running"
        with pytest.raises(ViceStateError):
            controller.get_registers()
        assert client.calls == []
        controller.close()

    def test_connection_loss_wakes_causal_event_waiter(self):
        client, controller = connected_controller()
        with controller._condition:
            controller._execution_state = "running"
        result = {}

        def run_interrupt():
            try:
                controller.interrupt(timeout_ms=10_000)
            except BaseException as error:
                result["error"] = error

        thread = threading.Thread(target=run_interrupt)
        thread.start()
        deadline = time.monotonic() + 1
        while not client.calls and time.monotonic() < deadline:
            time.sleep(0.005)
        client.fail()
        thread.join(0.5)
        assert isinstance(result["error"], ViceConnectionError)
