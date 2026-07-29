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
        return []

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
