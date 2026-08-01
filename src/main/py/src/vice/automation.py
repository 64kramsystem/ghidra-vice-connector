"""Versioned TraceRMI automation methods for the C64 VICE connector."""

import base64
import json
from typing import Annotated, List

from ghidratrace import sch
from ghidratrace.client import ParamDesc

from . import commands
from .contracts import (
    API,
    API_MAJOR,
    CONNECTOR_NAME,
    CONNECTOR_VERSION,
    LIMITS,
    METHOD_NAMESPACE,
)
from .controller import (
    OperationResult,
    PublicEvent,
    ViceController,
    ViceTraceSyncError,
)
from .protocol import (
    Bank,
    Checkpoint,
    Register,
    ViceFailure,
    VicePartialWriteError,
    ViceTimeoutError,
    ViceValidationError,
)
from .registry import REGISTRY
from .schema_types import C64

StringArray = Annotated[List[str], ParamDesc(schema=sch.STRING_ARR)]
LongArray = Annotated[List[int], ParamDesc(schema=sch.LONG_ARR)]
MEMORY_CHUNK_BYTES = LIMITS["memory_chunk_bytes"]
DISPLAY_CHUNK_BYTES = LIMITS["display_capture_chunk_bytes"]


def _validate_process(process: C64) -> None:
    if getattr(process, "path", None) != commands.C64_PATH:
        raise ViceValidationError("process must be the canonical C64 object")


def _address(value: int) -> str:
    return f"${value:04X}"


def _checkpoint(item: Checkpoint) -> dict:
    return {
        "number": item.number,
        "start": item.start,
        "start_display": _address(item.start),
        "end": item.end,
        "end_display": _address(item.end),
        "stop_on_hit": item.stop_on_hit,
        "enabled": item.enabled,
        "operations": {
            "load": bool(item.cpu_op & 0x01),
            "store": bool(item.cpu_op & 0x02),
            "execute": bool(item.cpu_op & 0x04),
        },
        "temporary": item.temporary,
        "currently_hit": item.currently_hit,
        "hit_count": item.hit_count,
        "ignore_count": item.ignore_count,
        "has_condition": item.has_condition,
        "memspace": item.memspace,
    }


def _event(item: PublicEvent) -> dict:
    return {
        "kind": item.kind,
        "pc": item.pc,
        "pc_display": _address(item.pc) if item.pc is not None else None,
        "checkpoints": [_checkpoint(entry) for entry in item.checkpoints],
    }


def _operation(item: OperationResult) -> dict:
    return {
        "request_id": item.request_id,
        "event": _event(item.event) if item.event is not None else None,
    }


def _register_records(
    controller: ViceController, values: dict, names: List[str]
) -> list:
    metadata = {
        name: (
            controller.client.reg_name_to_id[name],
            controller.client.reg_name_to_bits[name],
        )
        for name in controller.client.reg_name_to_id
    }
    selected = names or list(metadata)
    if len(set(selected)) != len(selected):
        raise ViceValidationError("register names must not contain duplicates")
    unknown = [name for name in selected if name not in metadata]
    if unknown:
        raise ViceValidationError(
            "unknown register names: " + ", ".join(unknown)
        )
    records = []
    for name in selected:
        register_id, bits = metadata[name]
        value = values[name]
        width = max(2, (bits + 3) // 4)
        records.append(
            {
                "name": name,
                "id": register_id,
                "bits": bits,
                "value": value,
                "display": f"${value:0{width}X}",
            }
        )
    return records


def _envelope(
    controller: ViceController,
    *,
    ok: bool,
    command_sequence: int | None = None,
    result: object = None,
    error: dict | None = None,
) -> str:
    status = controller.status()
    payload = {
        "api": API,
        "ok": ok,
        "command_sequence": (
            controller.command_sequence
            if command_sequence is None else command_sequence
        ),
        "instance_id": controller.instance_id,
        "connection_state": status["connection_state"],
        "execution_state": status["execution_state"],
        "stop_count": status["stop_count"],
        "pc": status["pc"],
    }
    payload["result" if ok else "error"] = result if ok else error
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _failure(controller: ViceController, command: str, error: ViceFailure) -> str:
    details = {
        "code": error.code,
        "message": str(error),
        "command": command,
        "request_id": error.request_id,
        "outcome_unknown": error.outcome_unknown,
    }
    for name in (
        "state_may_have_changed",
        "partial",
        "completed_bytes",
        "memory_may_be_modified",
        "action_applied",
        "trace_sync_failed",
    ):
        if hasattr(error, name):
            details[name] = getattr(error, name)
    if isinstance(error, VicePartialWriteError):
        details["completed_ranges"] = [
            {"start": start, "end": end}
            for start, end in error.completed_ranges
        ]
        details["failed_range"] = {
            "start": error.failed_range[0],
            "end": error.failed_range[1],
        }
    if isinstance(error, ViceTraceSyncError):
        details["vice_action_applied"] = error.action_applied
    return _envelope(controller, ok=False, error=details)


def _call(process: C64, command: str, callback) -> str:
    controller = commands.STATE.require_controller()
    try:
        _validate_process(process)
        sequence, result = callback(controller)
        return _envelope(
            controller, ok=True, command_sequence=sequence, result=result
        )
    except ViceFailure as error:
        return _failure(controller, command, error)


@REGISTRY.method(name="c64_vice_v1_capabilities", display="C64 VICE capabilities")
def capabilities(process: C64) -> str:
    controller = commands.STATE.require_controller()
    try:
        _validate_process(process)
        result = {
            "protocol": "c64.vice",
            "api_major": API_MAJOR,
            "connector_name": CONNECTOR_NAME,
            "connector_version": CONNECTOR_VERSION,
            "instance_id": controller.instance_id,
            "machine": "c64",
            "vice_version": controller.vice_version,
            "binary_monitor_api": 2,
            "method_namespace": METHOD_NAMESPACE,
            "limits": LIMITS,
        }
        return _envelope(controller, ok=True, result=result)
    except ViceFailure as error:
        return _failure(controller, "capabilities", error)


@REGISTRY.method(name="c64_vice_v1_status", display="C64 VICE status")
def status(process: C64) -> str:
    controller = commands.STATE.require_controller()
    try:
        _validate_process(process)
        result = controller.status()
        result.update(
            {
                "connector_version": CONNECTOR_VERSION,
                "vice_version": controller.vice_version,
                "binary_monitor_api": 2,
            }
        )
        return _envelope(controller, ok=True, result=result)
    except ViceFailure as error:
        return _failure(controller, "status", error)


@REGISTRY.method(name="c64_vice_v1_get_registers")
def get_registers(
    process: C64,
    names: StringArray,
    memspace: int = 0,
    timeout_ms: int = 10_000,
) -> str:
    def invoke(controller):
        sequence, values = controller.get_registers(
            memspace, timeout_ms=timeout_ms
        )
        return sequence, {
            "memspace": memspace,
            "registers": _register_records(controller, values, names),
        }

    return _call(process, "get_registers", invoke)


@REGISTRY.method(name="c64_vice_v1_set_registers")
def set_registers(
    process: C64,
    names: StringArray,
    values: LongArray,
    memspace: int = 0,
    timeout_ms: int = 10_000,
) -> str:
    def invoke(controller):
        if not names or len(names) != len(values):
            raise ViceValidationError(
                "names and values must be non-empty and have equal lengths"
            )
        if len(set(names)) != len(names):
            raise ViceValidationError("register names must not contain duplicates")
        sequence, observed = controller.set_registers(
            dict(zip(names, values)), memspace, timeout_ms=timeout_ms
        )
        return sequence, {
            "memspace": memspace,
            "registers": _register_records(controller, observed, names),
        }

    return _call(process, "set_registers", invoke)


@REGISTRY.method(name="c64_vice_v1_list_banks")
def list_banks(process: C64, timeout_ms: int = 10_000) -> str:
    def invoke(controller):
        sequence, banks = controller.list_banks(timeout_ms=timeout_ms)
        return sequence, {
            "banks": [{"id": bank.id, "name": bank.name} for bank in banks]
        }

    return _call(process, "list_banks", invoke)


@REGISTRY.method(name="c64_vice_v1_read_memory")
def read_memory(
    process: C64,
    bank_id: int,
    start: int,
    end: int,
    side_effects: bool = False,
    max_bytes: int = 4096,
    memspace: int = 0,
    timeout_ms: int = 10_000,
) -> str:
    def invoke(controller):
        if not 1 <= max_bytes <= MEMORY_CHUNK_BYTES:
            raise ViceValidationError(
                f"max_bytes must be in 1..{MEMORY_CHUNK_BYTES}"
            )
        if not 0 <= start <= end <= 0xFFFF:
            raise ViceValidationError(
                "start/end must form a non-wrapping 16-bit range"
            )
        actual_end = min(end, start + max_bytes - 1)
        sequence, data = controller.read_memory(
            start,
            actual_end,
            memspace=memspace,
            bank_id=bank_id,
            side_effects=side_effects,
            timeout_ms=timeout_ms,
            sync_trace=False,
        )
        complete = actual_end == end
        return sequence, {
            "bank_id": bank_id,
            "memspace": memspace,
            "start": start,
            "start_display": _address(start),
            "end": actual_end,
            "end_display": _address(actual_end),
            "bytes": data.hex(),
            "byte_count": len(data),
            "complete": complete,
            "next_address": None if complete else actual_end + 1,
        }

    return _call(process, "read_memory", invoke)


@REGISTRY.method(name="c64_vice_v1_write_memory")
def write_memory(
    process: C64,
    bank_id: int,
    start: int,
    data: bytes,
    side_effects: bool = False,
    memspace: int = 0,
    timeout_ms: int = 10_000,
) -> str:
    def invoke(controller):
        if not data:
            raise ViceValidationError("data must not be empty")
        if len(data) > MEMORY_CHUNK_BYTES:
            raise ViceValidationError(
                f"data must contain at most {MEMORY_CHUNK_BYTES} bytes"
            )
        sequence, ranges = controller.write_memory(
            start,
            data,
            memspace=memspace,
            bank_id=bank_id,
            side_effects=side_effects,
            timeout_ms=timeout_ms,
            sync_trace=(memspace == 0 and bank_id == 0),
        )
        return sequence, {
            "bank_id": bank_id,
            "memspace": memspace,
            "start": start,
            "start_display": _address(start),
            "end": start + len(data) - 1,
            "end_display": _address(start + len(data) - 1),
            "byte_count": len(data),
            "completed_ranges": [
                {"start": begin, "end": finish}
                for begin, finish in ranges
            ],
        }

    return _call(process, "write_memory", invoke)


@REGISTRY.method(name="c64_vice_v1_list_checkpoints")
def list_checkpoints(process: C64, timeout_ms: int = 10_000) -> str:
    def invoke(controller):
        sequence, checkpoints = controller.list_checkpoints(
            timeout_ms=timeout_ms
        )
        return sequence, {
            "checkpoints": [_checkpoint(item) for item in checkpoints]
        }

    return _call(process, "list_checkpoints", invoke)


@REGISTRY.method(name="c64_vice_v1_set_checkpoint")
def set_checkpoint(
    process: C64,
    start: int,
    end: int,
    stop_on_hit: bool = True,
    enabled: bool = True,
    operations: int = 4,
    temporary: bool = False,
    memspace: int = 0,
    timeout_ms: int = 10_000,
) -> str:
    def invoke(controller):
        sequence, result = controller.set_checkpoint(
            start,
            end,
            stop_on_hit=stop_on_hit,
            enabled=enabled,
            cpu_op=operations,
            temporary=temporary,
            memspace=memspace,
            timeout_ms=timeout_ms,
        )
        checkpoint, _all = result
        return sequence, {"checkpoint": _checkpoint(checkpoint)}

    return _call(process, "set_checkpoint", invoke)


@REGISTRY.method(name="c64_vice_v1_delete_checkpoint")
def delete_checkpoint(
    process: C64, number: int, timeout_ms: int = 10_000
) -> str:
    return _call(
        process,
        "delete_checkpoint",
        lambda controller: (
            lambda pair: (pair[0], {"number": number, "deleted": True})
        )(controller.delete_checkpoint(number, timeout_ms=timeout_ms)),
    )


@REGISTRY.method(name="c64_vice_v1_toggle_checkpoint")
def toggle_checkpoint(
    process: C64, number: int, enabled: bool, timeout_ms: int = 10_000
) -> str:
    return _call(
        process,
        "toggle_checkpoint",
        lambda controller: (
            lambda pair: (
                pair[0],
                {"number": number, "enabled": enabled},
            )
        )(controller.toggle_checkpoint(number, enabled, timeout_ms=timeout_ms)),
    )


def _execution_call(process: C64, command: str, callback) -> str:
    return _call(
        process,
        command,
        lambda controller: (
            lambda operation: (
                operation.command_sequence,
                _operation(operation),
            )
        )(callback(controller)),
    )


@REGISTRY.method(name="c64_vice_v1_step")
def step(process: C64, count: int = 1, timeout_ms: int = 10_000) -> str:
    return _execution_call(
        process,
        "step",
        lambda controller: controller.step(count, timeout_ms=timeout_ms),
    )


@REGISTRY.method(name="c64_vice_v1_next")
def next_instruction(
    process: C64, count: int = 1, timeout_ms: int = 10_000
) -> str:
    return _execution_call(
        process,
        "next",
        lambda controller: controller.next(count, timeout_ms=timeout_ms),
    )


@REGISTRY.method(name="c64_vice_v1_finish")
def finish(process: C64, timeout_ms: int = 10_000) -> str:
    return _execution_call(
        process,
        "finish",
        lambda controller: controller.finish(timeout_ms=timeout_ms),
    )


@REGISTRY.method(name="c64_vice_v1_resume")
def resume(process: C64, timeout_ms: int = 10_000) -> str:
    return _execution_call(
        process,
        "resume",
        lambda controller: controller.resume(timeout_ms=timeout_ms),
    )


@REGISTRY.method(name="c64_vice_v1_interrupt")
def interrupt(process: C64, timeout_ms: int = 10_000) -> str:
    return _execution_call(
        process,
        "interrupt",
        lambda controller: controller.interrupt(timeout_ms=timeout_ms),
    )


@REGISTRY.method(name="c64_vice_v1_wait_for_stop")
def wait_for_stop(
    process: C64, after_stop_count: int, timeout_ms: int
) -> str:
    def invoke(controller):
        event = controller.wait_for_stop(after_stop_count, timeout_ms)
        return controller.command_sequence, {"event": _event(event)}

    return _call(process, "wait_for_stop", invoke)


@REGISTRY.method(name="c64_vice_v1_feed_keyboard")
def feed_keyboard(
    process: C64, data: bytes, timeout_ms: int = 10_000
) -> str:
    def invoke(controller):
        sequence, _ = controller.feed_keyboard(data, timeout_ms=timeout_ms)
        return sequence, {"byte_count": len(data)}

    return _call(process, "feed_keyboard", invoke)


@REGISTRY.method(name="c64_vice_v1_set_joyport")
def set_joyport(
    process: C64, port: int, value: int, timeout_ms: int = 10_000
) -> str:
    return _call(
        process,
        "set_joyport",
        lambda controller: controller.set_joyport(
            port, value, timeout_ms=timeout_ms
        ),
    )


@REGISTRY.method(name="c64_vice_v1_set_keyboard_matrix")
def set_keyboard_matrix(
    process: C64,
    row: int,
    column: int,
    pressed: bool,
    timeout_ms: int = 10_000,
) -> str:
    return _call(
        process,
        "set_keyboard_matrix",
        lambda controller: controller.set_keyboard_matrix(
            row, column, pressed, timeout_ms=timeout_ms
        ),
    )


@REGISTRY.method(name="c64_vice_v1_save_snapshot")
def save_snapshot(
    process: C64,
    filename: str,
    save_roms: bool = False,
    save_disks: bool = True,
    timeout_ms: int = 10_000,
) -> str:
    def invoke(controller):
        sequence, _ = controller.save_snapshot(
            filename,
            save_roms=save_roms,
            save_disks=save_disks,
            timeout_ms=timeout_ms,
        )
        return sequence, {"filename": filename}

    return _call(process, "save_snapshot", invoke)


@REGISTRY.method(name="c64_vice_v1_load_snapshot")
def load_snapshot(
    process: C64, filename: str, timeout_ms: int = 10_000
) -> str:
    def invoke(controller):
        sequence, pc = controller.load_snapshot(
            filename, timeout_ms=timeout_ms
        )
        return sequence, {
            "filename": filename,
            "pc": pc,
            "pc_display": _address(pc),
        }

    return _call(process, "load_snapshot", invoke)


@REGISTRY.method(name="c64_vice_v1_capture_display")
def capture_display(
    process: C64, use_vic: bool = True, timeout_ms: int = 10_000
) -> str:
    def invoke(controller):
        if not isinstance(use_vic, bool):
            raise ViceValidationError("use_vic must be a boolean")
        sequence, capture = controller.capture_display(
            use_vic=use_vic, timeout_ms=timeout_ms
        )
        frame = capture.frame
        return sequence, {
            "capture_id": capture.capture_id,
            "width": frame.width,
            "height": frame.height,
            "inner": {
                "x_offset": frame.x_offset,
                "y_offset": frame.y_offset,
                "width": frame.inner_width,
                "height": frame.inner_height,
            },
            "bits_per_pixel": frame.bits_per_pixel,
            "buffer_length": len(frame.buffer),
            "palette": [
                {"r": entry.r, "g": entry.g, "b": entry.b}
                for entry in capture.palette
            ],
            "vice_version": controller.vice_version,
            "vice_revision": controller.vice_revision,
        }

    return _call(process, "capture_display", invoke)


@REGISTRY.method(name="c64_vice_v1_read_display_capture")
def read_display_capture(
    process: C64,
    capture_id: str,
    offset: int,
    max_bytes: int = DISPLAY_CHUNK_BYTES,
) -> str:
    def invoke(controller):
        sequence, chunk, complete = controller.read_display_capture(
            capture_id, offset, max_bytes
        )
        return sequence, {
            "capture_id": capture_id,
            "offset": offset,
            "byte_count": len(chunk),
            "buffer_base64": base64.b64encode(chunk).decode("ascii"),
            "complete": complete,
            "next_offset": None if complete else offset + len(chunk),
        }

    return _call(process, "read_display_capture", invoke)


@REGISTRY.method(name="c64_vice_v1_discard_display_capture")
def discard_display_capture(process: C64, capture_id: str) -> str:
    def invoke(controller):
        sequence, _ = controller.discard_display_capture(capture_id)
        return sequence, {"capture_id": capture_id, "discarded": True}

    return _call(process, "discard_display_capture", invoke)


@REGISTRY.method(name="c64_vice_v1_reset")
def reset(
    process: C64, kind: str = "soft", timeout_ms: int = 10_000
) -> str:
    reset_types = {"soft": 0, "hard": 1}

    def invoke(controller):
        if kind not in reset_types:
            raise ViceValidationError("kind must be soft or hard")
        sequence, _ = controller.reset(
            reset_types[kind], timeout_ms=timeout_ms
        )
        return sequence, {"kind": kind}

    return _call(process, "reset", invoke)
