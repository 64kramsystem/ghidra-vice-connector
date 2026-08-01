import json
from unittest.mock import MagicMock

import pytest

from vice import automation, commands, contracts, methods
from vice.controller import OperationResult, PublicEvent
from vice.protocol import ViceValidationError


def process():
    value = methods.C64()
    value.path = commands.C64_PATH
    return value


def payload(text):
    return json.loads(text)


@pytest.fixture
def controller():
    value = MagicMock()
    value.instance_id = "12345678-1234-1234-1234-123456789abc"
    value.command_sequence = 7
    value.vice_version = "3.10.0"
    value.status.return_value = {
        "connection_state": "connected",
        "execution_state": "stopped",
        "stop_count": 2,
        "pc": 0xC000,
    }
    value.client.reg_name_to_id = {"PC": 0, "A": 1}
    value.client.reg_name_to_bits = {"PC": 16, "A": 8}
    commands.STATE.controller = value
    yield value
    commands.STATE.controller = None


def test_capabilities_and_status_are_cached(controller):
    capabilities = payload(automation.capabilities(process()))
    status = payload(automation.status(process()))
    assert capabilities["ok"] is True
    assert capabilities["result"]["vice_version"] == "3.10.0"
    assert capabilities["result"]["limits"]["memory_chunk_bytes"] == 16_384
    assert capabilities["stop_count"] == 2
    assert status["ok"] is True
    controller.get_registers.assert_not_called()
    controller.client.command.assert_not_called()


def test_get_registers_preserves_requested_order(controller):
    controller.get_registers.return_value = (8, {"PC": 0xC000, "A": 0x42})
    result = payload(
        automation.get_registers(process(), ["A", "PC"], 0, 1000)
    )
    assert result["ok"] is True
    assert result["command_sequence"] == 8
    assert [item["name"] for item in result["result"]["registers"]] == [
        "A", "PC"
    ]


def test_set_registers_validates_all_before_io(controller):
    result = payload(
        automation.set_registers(process(), ["A"], [1, 2], 0, 1000)
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "vice_invalid_argument"
    controller.set_registers.assert_not_called()


def test_read_memory_is_bounded_and_reports_continuation(controller):
    controller.read_memory.return_value = (9, b"\x00\x01")
    result = payload(
        automation.read_memory(process(), 0, 0x1000, 0x100F, False, 2, 0, 1000)
    )
    assert result["result"]["bytes"] == "0001"
    assert result["result"]["complete"] is False
    assert result["result"]["next_address"] == 0x1002
    controller.read_memory.assert_called_once_with(
        0x1000,
        0x1001,
        memspace=0,
        bank_id=0,
        side_effects=False,
        timeout_ms=1000,
        sync_trace=False,
    )


def test_execution_envelope_contains_synchronized_event(controller):
    event = PublicEvent(3, "stopped", 0xC000, 0.0)
    controller.step.return_value = OperationResult(10, 4, event)
    result = payload(automation.step(process(), 1, 1000))
    assert result["ok"] is True
    assert result["command_sequence"] == 10
    assert result["result"]["event"]["pc_display"] == "$C000"


def test_expected_failure_becomes_stable_error_envelope(controller):
    controller.list_banks.side_effect = ViceValidationError("bad bank map")
    result = payload(automation.list_banks(process(), 1000))
    assert result["ok"] is False
    assert result["error"]["code"] == "vice_invalid_argument"
    assert result["error"]["command"] == "list_banks"


def test_unexpected_defect_propagates(controller):
    controller.list_banks.side_effect = AssertionError("bug")
    with pytest.raises(AssertionError, match="bug"):
        automation.list_banks(process(), 1000)


def test_status_reports_the_declared_connector_version(controller):
    """Runtime status remains the place the version is published."""
    status = payload(automation.status(process()))

    assert status["ok"] is True
    assert status["result"]["connector_version"] == contracts.CONNECTOR_VERSION


def test_input_and_snapshot_envelopes_forward_exact_arguments(controller):
    controller.feed_keyboard.return_value = (8, None)
    controller.set_joyport.return_value = (9, {"port": 2, "value": 0xEF})
    controller.set_keyboard_matrix.return_value = (
        10,
        {"row": 7, "column": 4, "pressed": True},
    )
    controller.save_snapshot.return_value = (11, None)
    controller.load_snapshot.return_value = (12, 0xC123)

    fed = payload(automation.feed_keyboard(process(), b"GO", 1000))
    joy = payload(automation.set_joyport(process(), 2, 0xEF, 1000))
    matrix = payload(
        automation.set_keyboard_matrix(process(), 7, 4, True, 1000)
    )
    saved = payload(
        automation.save_snapshot(process(), "start.vsf", True, False, 1000)
    )
    loaded = payload(automation.load_snapshot(process(), "start.vsf", 1000))

    assert fed["result"] == {"byte_count": 2}
    assert joy["result"] == {"port": 2, "value": 0xEF}
    assert matrix["result"] == {"row": 7, "column": 4, "pressed": True}
    assert saved["result"] == {"filename": "start.vsf"}
    assert loaded["result"]["pc"] == 0xC123
    controller.feed_keyboard.assert_called_once_with(b"GO", timeout_ms=1000)
    controller.set_joyport.assert_called_once_with(2, 0xEF, timeout_ms=1000)
    controller.set_keyboard_matrix.assert_called_once_with(
        7, 4, True, timeout_ms=1000
    )
    controller.save_snapshot.assert_called_once_with(
        "start.vsf", save_roms=True, save_disks=False, timeout_ms=1000
    )
    controller.load_snapshot.assert_called_once_with(
        "start.vsf", timeout_ms=1000
    )
