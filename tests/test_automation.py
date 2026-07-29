import json
import inspect
from typing import Annotated, get_args, get_origin
from unittest.mock import MagicMock

import pytest

from vice import automation, commands, contracts, methods
from ghidratrace.client import TraceObject
from vice.controller import (
    CapturedMemory,
    OperationResult,
    PublicEvent,
    StateCapture,
)
from vice.protocol import Bank, Checkpoint, ViceValidationError


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
    value.connection_generation = 2
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
    assert capabilities["result"]["surface_revision"] == 3
    assert "display.capture.chunked" in (
        capabilities["result"]["capabilities"]
    )
    assert "display.capture" not in capabilities["result"]["capabilities"]
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


def test_keyboard_joyport_and_snapshot_methods(controller):
    controller.feed_keyboard.return_value = (8, None)
    controller.set_joyport.return_value = (
        9,
        {
            "port": 2,
            "value": 0xEF,
            "previous_device": 1,
            "device_changed": True,
        },
    )
    controller.save_snapshot.return_value = (10, None)
    controller.load_snapshot.return_value = (11, 0xC123)

    keyboard = payload(automation.feed_keyboard(process(), b"GO", 1000))
    joyport = payload(automation.set_joyport(process(), 2, 0xEF, 1000))
    saved = payload(
        automation.save_snapshot(
            process(), "/tmp/a.vsf", False, True, 1000
        )
    )
    loaded = payload(
        automation.load_snapshot(process(), "/tmp/a.vsf", 1000)
    )

    assert keyboard["result"] == {"byte_count": 2}
    assert joyport["result"]["previous_device"] == 1
    assert saved["result"]["filename"] == "/tmp/a.vsf"
    assert loaded["result"] == {
        "filename": "/tmp/a.vsf",
        "pc": 0xC123,
        "pc_display": "$C123",
    }


def test_list_events_reports_continuation_without_monitor_io(controller):
    events = (
        PublicEvent(5, 6, "resumed", 0x1000, None, 3, 0.0),
        PublicEvent(6, 7, "stopped", 0x2000, None, 4, 0.0),
    )
    controller.list_events.return_value = (events, 8)

    result = payload(automation.list_events(process(), 4, 2))

    assert result["result"]["after_sequence"] == 4
    assert result["result"]["next_sequence"] == 6
    assert result["result"]["event_sequence"] == 8
    assert result["result"]["complete"] is False
    assert [event["sequence"] for event in result["result"]["events"]] == [5, 6]


def test_capture_state_returns_hashes_and_full_identity(controller):
    event = PublicEvent(4, 5, "stopped", 0xC000, None, 9, 0.0)
    capture = StateCapture(
        connection_generation=2,
        event_sequence=4,
        raw_sequence=5,
        event=event,
        banks=(Bank(0, "default"),),
        registers={"A": 0x42},
        checkpoints=(Checkpoint(7, 0xC000, 0xC000),),
        ranges=(CapturedMemory(0, 0, 0x1000, 0x1001, b"\x01\x02"),),
    )
    controller.capture_state.return_value = (8, capture)

    result = payload(
        automation.capture_state(
            process(),
            4,
            7,
            [0, 0, 0x1000, 0x1001],
            ["header"],
            ["A"],
            True,
            1000,
        )
    )

    state = result["result"]
    assert state["connection_generation"] == 2
    assert state["event_sequence"] == 4
    assert state["raw_sequence"] == 5
    assert state["ranges"][0]["name"] == "header"
    assert state["ranges"][0]["bytes"] == "0102"
    assert state["ranges"][0]["sha256"] == (
        "a12871fee210fb8619291eaea194581cbd2531e4b23759d225f6806923f63222"
    )
    assert state["raw_byte_count"] == 2


def _annotation_schema(annotation):
    if annotation is str:
        return "STRING"
    if annotation is int:
        return "LONG"
    if annotation is bool:
        return "BOOL"
    if annotation is bytes:
        return "BYTE_ARR"
    if (
        isinstance(annotation, type)
        and issubclass(annotation, TraceObject)
    ):
        return annotation.__name__
    if get_origin(annotation) is Annotated:
        array_type = get_args(annotation)[0]
        element_type = get_args(array_type)[0]
        return {
            str: "STRING_ARR",
            int: "LONG_ARR",
        }[element_type]
    raise AssertionError(f"unrecognized registry annotation {annotation!r}")


def test_contract_matches_registered_automation_method_signatures():
    declared = {
        specification["name"] for specification in contracts.METHODS
    }
    registered = {
        name
        for name in methods.REGISTRY.methods
        if name.startswith(contracts.METHOD_NAMESPACE)
    }
    assert registered == declared
    for specification in contracts.METHODS:
        callback = methods.REGISTRY.methods[specification["name"]]
        signature = inspect.signature(callback)
        actual = []
        for parameter in signature.parameters.values():
            actual.append(
                {
                    "name": parameter.name,
                    "type": _annotation_schema(parameter.annotation),
                    "required": parameter.default is inspect.Parameter.empty,
                    **(
                        {}
                        if parameter.default is inspect.Parameter.empty
                        else {"default": parameter.default}
                    ),
                }
            )
        assert actual == specification["parameters"]
        assert _annotation_schema(signature.return_annotation) == (
            specification["return_type"]
        )


def test_capture_state_validates_flat_ranges_and_names_before_controller_io(
    controller,
):
    result = payload(
        automation.capture_state(
            process(), 0, 7, [0, 0, 0], ["bad"], [], True, 1000
        )
    )
    assert result["error"]["code"] == "vice_invalid_argument"
    controller.capture_state.assert_not_called()
