import inspect
import json
from pathlib import Path
from typing import get_args, get_origin, Annotated
from unittest.mock import MagicMock

import pytest

from ghidratrace import sch

from vice import automation, commands, contracts, methods
from vice.contracts import METHODS, contract_json
from vice.controller import OperationResult, PublicEvent
from vice.protocol import ViceValidationError


ROOT = Path(__file__).resolve().parents[1]


def process():
    value = methods.C64()
    value.path = commands.C64_PATH
    return value


def payload(text):
    return json.loads(text)


def annotation_schema(annotation):
    if get_origin(annotation) is Annotated:
        _base, descriptor = get_args(annotation)
        schema = descriptor.schema
        for name in ("STRING_ARR", "LONG_ARR"):
            if schema is getattr(sch, name):
                return name
    return {
        methods.C64: "C64",
        int: "LONG",
        bool: "BOOL",
        str: "STRING",
        bytes: "BYTE_ARR",
    }[annotation]


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


def test_packaged_contract_is_generated_from_declaration():
    path = ROOT / "contracts" / "c64-vice-api-v1.json"
    assert path.read_text(encoding="utf-8") == contract_json()


def test_registered_method_surface_matches_contract():
    for contract_method in METHODS:
        callback = methods.REGISTRY.methods[contract_method["name"]]
        signature = inspect.signature(callback)
        actual = []
        for parameter in signature.parameters.values():
            item = {
                "name": parameter.name,
                "type": annotation_schema(parameter.annotation),
                "required": parameter.default is inspect.Parameter.empty,
            }
            if not item["required"]:
                item["default"] = parameter.default
            actual.append(item)
        assert actual == contract_method["parameters"], contract_method["name"]
        assert annotation_schema(signature.return_annotation) == "STRING"


def test_optional_defaults_are_serializable_by_ghidra_12_1():
    """Ghidra's Python writer omits schema while encoding parameter defaults."""
    scalar_defaults = (bool, int, str)
    for method in METHODS:
        for parameter in method["parameters"]:
            if not parameter["required"]:
                assert isinstance(parameter["default"], scalar_defaults), (
                    method["name"],
                    parameter["name"],
                    parameter["default"],
                )


def test_capabilities_and_status_are_cached(controller):
    capabilities = payload(automation.capabilities(process()))
    status = payload(automation.status(process()))
    assert capabilities["ok"] is True
    assert capabilities["result"]["vice_version"] == "3.10.0"
    assert capabilities["result"]["surface_revision"] == 2
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


def test_contract_declares_identity_without_the_release_version():
    """The contract names the connector; its release version is runtime metadata.

    Keeping the version here would force a coordinated commit in ghidra-mcp-c64
    on every release, enforced only by an opt-in test -- silent drift. Nothing
    compares it for compatibility, which is decided by api/machine/namespace/
    surface_revision/binary_monitor_api.
    """
    contract = contracts.build_contract()

    assert contract["connector"] == {"name": "ghidra-vice-connector"}
    assert "version" not in contract["connector"]


def test_status_reports_the_declared_connector_version(controller):
    """Runtime status remains the place the version is published."""
    status = payload(automation.status(process()))

    assert status["ok"] is True
    assert status["result"]["connector_version"] == contracts.CONNECTOR_VERSION
    assert status["result"]["connector_version"] == "0.99.0"
