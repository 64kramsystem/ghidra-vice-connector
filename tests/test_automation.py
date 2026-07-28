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
        "event_sequence": 0,
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
    assert capabilities["result"]["surface_revision"] == 2
    assert "display.capture" in capabilities["result"]["capabilities"]
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
    event = PublicEvent(2, 3, "stopped", 0xC000, None, 5, 0.0)
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
