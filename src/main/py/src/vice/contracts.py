"""Declarative C64 VICE TraceRMI automation contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

API = "c64.vice/1"
API_MAJOR = 1
API_MINOR = 0
SURFACE_REVISION = 2
METHOD_NAMESPACE = "c64_vice_v1_"
CONNECTOR_NAME = "ghidra-vice-connector"
CONNECTOR_VERSION = "0.99.0"

CAPABILITIES = (
    "status",
    "registers.read",
    "registers.write",
    "banks.list",
    "memory.read.bank",
    "memory.write.bank",
    "checkpoints.list",
    "checkpoints.create",
    "checkpoints.delete",
    "checkpoints.toggle",
    "execution.step",
    "execution.next",
    "execution.finish",
    "execution.resume",
    "execution.interrupt",
    "execution.wait_for_stop",
    "machine.reset",
    "display.capture",
    "trace.sync",
)


def required(name: str, schema: str) -> Dict[str, Any]:
    return {"name": name, "type": schema, "required": True}


def optional(name: str, schema: str, default: Any) -> Dict[str, Any]:
    return {
        "name": name,
        "type": schema,
        "required": False,
        "default": default,
    }


PROCESS = required("process", "C64")
TIMEOUT = optional("timeout_ms", "LONG", 10_000)
MEMSPACE = optional("memspace", "LONG", 0)


def method(name: str, *parameters: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": METHOD_NAMESPACE + name,
        "parameters": [PROCESS, *parameters],
        "return_type": "STRING",
    }


METHODS: List[Dict[str, Any]] = [
    method("capabilities"),
    method("status"),
    method(
        "get_registers",
        required("names", "STRING_ARR"),
        MEMSPACE,
        TIMEOUT,
    ),
    method(
        "set_registers",
        required("names", "STRING_ARR"),
        required("values", "LONG_ARR"),
        MEMSPACE,
        TIMEOUT,
    ),
    method("list_banks", TIMEOUT),
    method(
        "read_memory",
        required("bank_id", "LONG"),
        required("start", "LONG"),
        required("end", "LONG"),
        optional("side_effects", "BOOL", False),
        optional("max_bytes", "LONG", 4096),
        MEMSPACE,
        TIMEOUT,
    ),
    method(
        "write_memory",
        required("bank_id", "LONG"),
        required("start", "LONG"),
        required("data", "BYTE_ARR"),
        optional("side_effects", "BOOL", False),
        MEMSPACE,
        TIMEOUT,
    ),
    method("list_checkpoints", TIMEOUT),
    method(
        "set_checkpoint",
        required("start", "LONG"),
        required("end", "LONG"),
        optional("stop_on_hit", "BOOL", True),
        optional("enabled", "BOOL", True),
        optional("operations", "LONG", 4),
        optional("temporary", "BOOL", False),
        MEMSPACE,
        TIMEOUT,
    ),
    method(
        "delete_checkpoint",
        required("number", "LONG"),
        TIMEOUT,
    ),
    method(
        "toggle_checkpoint",
        required("number", "LONG"),
        required("enabled", "BOOL"),
        TIMEOUT,
    ),
    method("step", optional("count", "LONG", 1), TIMEOUT),
    method("next", optional("count", "LONG", 1), TIMEOUT),
    method("finish", TIMEOUT),
    method("resume", TIMEOUT),
    method("interrupt", TIMEOUT),
    method(
        "wait_for_stop",
        required("after_sequence", "LONG"),
        required("timeout_ms", "LONG"),
    ),
    method("reset", optional("kind", "STRING", "soft"), TIMEOUT),
    method(
        "capture_display",
        optional("use_vic", "BOOL", True),
        TIMEOUT,
    ),
]


def build_contract() -> Dict[str, Any]:
    return {
        "protocol": "c64.vice",
        "api": {"major": API_MAJOR, "minor": API_MINOR},
        "surface_revision": SURFACE_REVISION,
        "method_namespace": METHOD_NAMESPACE,
        # Only the connector's identity belongs in the contract. Its release
        # version is runtime metadata -- returned by status, and embedded in the
        # packaged extension -- so keeping it here would force a coordinated
        # commit in ghidra-mcp-c64 on every release, enforced only by an opt-in
        # test, which is silent drift waiting to happen.
        "connector": {
            "name": CONNECTOR_NAME,
        },
        "machine": "c64",
        "capabilities": list(CAPABILITIES),
        "limits": {
            "response_body_bytes": 16_777_216,
            "event_history": 1024,
            "banks": 4096,
            "checkpoints": 4096,
            "memory_read_bytes": 65_536,
            "memory_write_bytes": 65_536,
        },
        "methods": METHODS,
    }


def contract_json() -> str:
    return json.dumps(
        build_contract(), indent=2, sort_keys=True, separators=(",", ": ")
    ) + "\n"


def write_contract(path: Path) -> None:
    path.write_text(contract_json(), encoding="utf-8")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    write_contract(parser.parse_args().path)
