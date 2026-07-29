import pytest

from vice.controller import (
    JOYPORT_DEVICE_IO_SIMULATION,
    ViceController,
    ViceEventHistoryLost,
    ViceSequenceMismatch,
    ViceTraceSyncError,
)
from vice.protocol import Bank, Checkpoint, ViceValidationError

from .test_controller import FakeClient, connected_controller, raw


class AutomationFakeClient(FakeClient):
    def __init__(self):
        super().__init__()
        self.reg_name_to_id = {"PC": 0, "A": 1}
        self.reg_name_to_bits = {"PC": 16, "A": 8}
        self.reg_id_to_name = {0: "PC", 1: "A"}
        self.resource_device = 1

    def registers_get(self, memspace, timeout_ms):
        self.calls.append(("registers_get", memspace, timeout_ms))
        return {"PC": 0xC000, "A": 0x42}

    def checkpoint_list(self, timeout_ms):
        self.calls.append(("checkpoint_list", timeout_ms))
        return [Checkpoint(7, 0xC000, 0xC000)]

    def memory_get(
        self, start, end, memspace, bank_id, side_effects, timeout_ms
    ):
        self.calls.append(
            (
                "memory_get",
                start,
                end,
                memspace,
                bank_id,
                side_effects,
                timeout_ms,
            )
        )
        return bytes((address & 0xFF for address in range(start, end + 1)))

    def keyboard_feed(self, data, timeout_ms):
        self.calls.append(("keyboard_feed", data, timeout_ms))

    def resource_get_int(self, name, timeout_ms):
        self.calls.append(("resource_get_int", name, timeout_ms))
        return self.resource_device

    def resource_set_int(self, name, value, timeout_ms):
        self.calls.append(("resource_set_int", name, value, timeout_ms))
        self.resource_device = value

    def joyport_set(self, port, value, timeout_ms):
        self.calls.append(("joyport_set", port, value, timeout_ms))

    def snapshot_save(
        self, filename, save_roms, save_disks, timeout_ms
    ):
        self.calls.append(
            (
                "snapshot_save",
                filename,
                save_roms,
                save_disks,
                timeout_ms,
            )
        )

    def snapshot_load(self, filename, timeout_ms):
        self.calls.append(("snapshot_load", filename, timeout_ms))
        return 0xC123


def automation_controller(*, sync_result=None):
    client = AutomationFakeClient()
    controller = ViceController(client, sync_result=sync_result)
    controller.connect(discover_registers=False)
    controller.start_event_coordinator(assume_stopped=True)
    controller.banks = (Bank(0, "default"),)
    client.calls.clear()
    return client, controller


def test_capture_state_is_one_stopped_operation_with_one_budget():
    client, controller = automation_controller()
    try:
        sequence, capture = controller.capture_state(
            expected_event_sequence=0,
            expected_command_sequence=0,
            ranges=[(0, 0, 0x1000, 0x1003), (0, 1, 0x2000, 0x2001)],
            register_names=["A"],
            include_checkpoints=True,
            timeout_ms=1000,
        )
        assert sequence == 1
        assert capture.connection_generation == controller.connection_generation
        assert capture.event_sequence == 0
        assert capture.raw_sequence == 0
        assert capture.banks == (Bank(0, "default"),)
        assert capture.registers == {"A": 0x42}
        assert [item.data for item in capture.ranges] == [
            b"\x00\x01\x02\x03",
            b"\x00\x01",
        ]
        assert [call[0] for call in client.calls] == [
            "registers_get",
            "checkpoint_list",
            "memory_get",
            "memory_get",
        ]
        assert all(
            call[5] is False
            for call in client.calls
            if call[0] == "memory_get"
        )
        assert all(call[-1] <= 1000 for call in client.calls)
    finally:
        controller.close()


@pytest.mark.parametrize(
    ("event_sequence", "command_sequence"),
    [(1, 0), (0, 1)],
)
def test_capture_sequence_mismatch_sends_no_monitor_io(
    event_sequence, command_sequence
):
    client, controller = automation_controller()
    try:
        with pytest.raises(ViceSequenceMismatch):
            controller.capture_state(
                expected_event_sequence=event_sequence,
                expected_command_sequence=command_sequence,
                ranges=[(0, 0, 0, 0)],
                register_names=[],
                include_checkpoints=False,
            )
        assert client.calls == []
    finally:
        controller.close()


def test_capture_validates_registers_and_total_size_before_monitor_io():
    client, controller = automation_controller()
    try:
        with pytest.raises(ViceValidationError, match="unknown register"):
            controller.capture_state(
                expected_event_sequence=0,
                expected_command_sequence=0,
                ranges=[],
                register_names=["NOPE"],
            )
        with pytest.raises(ViceValidationError, match="16384"):
            controller.capture_state(
                expected_event_sequence=0,
                expected_command_sequence=0,
                ranges=[(0, 0, 0, 0x4000)],
                register_names=[],
            )
        assert client.calls == []
    finally:
        controller.close()


def test_capture_refuses_unpublished_event_before_monitor_io():
    client, controller = automation_controller()
    try:
        with controller.operation_lock:
            client.emit(raw(1, "resumed"))
            with pytest.raises(ViceSequenceMismatch) as caught:
                controller.capture_state(
                    expected_event_sequence=0,
                    expected_command_sequence=0,
                    ranges=[],
                    register_names=[],
                )
        assert caught.value.pending_events is True
        assert client.calls == []
    finally:
        controller.close()


def test_list_events_is_bounded_and_detects_general_history_loss():
    client, controller = connected_controller(history=2)
    try:
        with controller.operation_lock:
            controller._publish(raw(1, "resumed"))
            controller._publish(raw(2, "stopped"))
            controller._publish(raw(3, "resumed"))
        with pytest.raises(ViceEventHistoryLost):
            controller.list_events(0, 10)
        events, current = controller.list_events(1, 1)
        assert [event.sequence for event in events] == [2]
        assert current == 3
        assert client.calls == []
    finally:
        controller.close()


def test_input_joyport_and_snapshots_are_serialized_stopped_operations():
    client, controller = automation_controller()
    try:
        assert controller.feed_keyboard(b"A")[0] == 1
        sequence, joy = controller.set_joyport(1, 0xEF)
        assert sequence == 2
        assert joy == {
            "port": 1,
            "value": 0xEF,
            "previous_device": 1,
            "device_changed": True,
        }
        assert controller.save_snapshot("/tmp/a.vsf")[0] == 3
        assert controller.load_snapshot("/tmp/a.vsf")[1] == 0xC123
        assert [call[0] for call in client.calls] == [
            "keyboard_feed",
            "resource_get_int",
            "resource_set_int",
            "joyport_set",
            "snapshot_save",
            "snapshot_load",
        ]
    finally:
        controller.close()


def test_joyport_keeps_already_selected_simulation_device():
    client, controller = automation_controller()
    client.resource_device = JOYPORT_DEVICE_IO_SIMULATION
    try:
        _sequence, result = controller.set_joyport(2, 0xFF)
        assert result["device_changed"] is False
        assert [call[0] for call in client.calls] == [
            "resource_get_int",
            "joyport_set",
        ]
    finally:
        controller.close()


def test_snapshot_result_sync_tracks_and_rejects_regressing_trace_snapshots():
    snapshots = iter((7, 6))
    client, controller = automation_controller(
        sync_result=lambda _kind, _result, _remaining: next(snapshots)
    )
    try:
        controller.load_snapshot("/tmp/a.vsf")
        assert controller._last_snapshot == 7
        with pytest.raises(
            ViceTraceSyncError,
            match="trace snapshot regressed from 7 to 6",
        ) as caught:
            controller.load_snapshot("/tmp/a.vsf")
        assert caught.value.code == "trace_sync_failed"
        assert caught.value.action_applied is True
        assert controller._last_snapshot == 7
        assert [call[0] for call in client.calls] == [
            "snapshot_load",
            "snapshot_load",
        ]
    finally:
        controller.close()
