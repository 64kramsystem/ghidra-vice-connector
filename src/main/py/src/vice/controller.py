"""Serialized high-level control for one VICE BMP client.

GUI actions, TraceRMI automation, and unsolicited events all converge here.
The socket reader never acquires the operation lock or updates a Ghidra trace.
"""

from __future__ import annotations

import collections
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Deque, Dict, List, Optional, Sequence, Tuple

from .contracts import LIMITS
from .protocol import (
    Bank,
    Checkpoint,
    CPU_OP_EXEC,
    DisplayFrame,
    MEMSPACE_MAIN,
    PaletteEntry,
    RawEvent,
    ViceBmpClient,
    ViceConnectionError,
    ViceFailure,
    ViceProtocolError,
    ViceTimeoutError,
    ViceValidationError,
)

# Unsolicited events published per operation_lock acquisition. Bounded so a
# continuous checkpoint-hit stream cannot starve commands.
UNSOLICITED_DRAIN_BATCH = 64
JOYPORT_DEVICE_IO_SIMULATION = 37
DISPLAY_CHUNK_BYTES = LIMITS["display_capture_chunk_bytes"]


class ViceStateError(ViceFailure):
    code = "vice_target_not_stopped"


class ViceTraceSyncError(ViceFailure):
    code = "trace_sync_failed"

    def __init__(
        self,
        message: str,
        *,
        event: RawEvent,
        action_applied: bool,
        cause: BaseException,
    ):
        self.event = event
        self.action_applied = action_applied
        self.trace_sync_failed = True
        super().__init__(message, outcome_unknown=False)
        self.__cause__ = cause


@dataclass(frozen=True)
class PublicEvent:
    raw_sequence: int
    kind: str
    pc: Optional[int]
    received_at: float
    checkpoints: Tuple[Checkpoint, ...] = ()


@dataclass(frozen=True)
class OperationResult:
    command_sequence: int
    request_id: Optional[int]
    event: Optional[PublicEvent]


@dataclass(frozen=True)
class DisplayCapture:
    capture_id: str
    frame: DisplayFrame
    palette: Tuple[PaletteEntry, ...]


RemainingMs = Callable[[], int]
SyncEvent = Callable[[RawEvent, RemainingMs], None]
SyncResult = Callable[[str, object, RemainingMs], None]


def _no_sync(_event: RawEvent, _remaining_ms: RemainingMs) -> None:
    pass


def _no_result_sync(
    _kind: str, _result: object, _remaining_ms: RemainingMs
) -> None:
    return None


class ViceController:
    """Own high-level state and ordering for exactly one client."""

    def __init__(
        self,
        client: ViceBmpClient,
        *,
        sync_event: Optional[SyncEvent] = None,
        sync_result: Optional[SyncResult] = None,
    ):
        self.client = client
        self.instance_id = str(uuid.uuid4())
        self.operation_lock = threading.RLock()
        self._condition = threading.Condition(threading.RLock())
        self._raw_events: Deque[RawEvent] = collections.deque()
        self._sync_event = sync_event or _no_sync
        self._sync_result = sync_result or _no_result_sync
        self._command_sequence = 0
        self._last_raw_sequence = 0
        self._stop_count = 0
        self._last_event: Optional[PublicEvent] = None
        self._latest_stop: Optional[PublicEvent] = None
        self._display_capture: Optional[DisplayCapture] = None
        self._connection_state = "disconnected"
        self._execution_state = "unknown"
        self._terminal_error: Optional[ViceConnectionError] = None
        self._coordinator_stop = False
        self._coordinator: Optional[threading.Thread] = None
        self._events_enabled = False
        self.vice_version: Optional[str] = None
        # None on a release build, which reports no revision at all.
        self.vice_revision: Optional[int] = None
        self.banks: Tuple[Bank, ...] = ()
        client.set_event_callback(self._on_raw_event)
        client.set_terminal_callback(self._on_terminal)

    @property
    def command_sequence(self) -> int:
        with self._condition:
            return self._command_sequence

    @property
    def stop_count(self) -> int:
        with self._condition:
            return self._stop_count

    @property
    def connection_state(self) -> str:
        with self._condition:
            return self._connection_state

    @property
    def execution_state(self) -> str:
        with self._condition:
            return self._execution_state

    @property
    def terminal_error(self) -> Optional[ViceConnectionError]:
        with self._condition:
            return self._terminal_error

    def connect(self, *, discover_registers: bool = True) -> None:
        with self._condition:
            self._terminal_error = None
            self._execution_state = "unknown"
        try:
            self.client.connect(discover_registers=discover_registers)
            info = self.client.vice_info()
            self.vice_version = info.version_string
            self.vice_revision = info.revision
            self.banks = tuple(self.client.banks_available())
        except BaseException:
            self.client.disconnect()
            raise
        with self._condition:
            self._connection_state = "connected"
            self._condition.notify_all()

    def start_event_coordinator(self, *, assume_stopped: bool = False) -> None:
        with self._condition:
            if assume_stopped and self._connection_state == "connected":
                self._execution_state = "stopped"
            self._events_enabled = True
            if self._coordinator is None or not self._coordinator.is_alive():
                self._coordinator_stop = False
                self._coordinator = threading.Thread(
                    target=self._coordinate_unsolicited,
                    name="vice-event-coordinator",
                    daemon=True,
                )
                self._coordinator.start()
            self._condition.notify_all()

    def close(self) -> None:
        with self._condition:
            self._coordinator_stop = True
            self._events_enabled = False
            self._display_capture = None
            self._condition.notify_all()
        self.client.disconnect()
        coordinator = self._coordinator
        if coordinator is not None and coordinator is not threading.current_thread():
            coordinator.join(2)

    def _on_raw_event(self, event: RawEvent) -> None:
        abort_error = None
        with self._condition:
            if event.raw_sequence <= self._last_raw_sequence:
                abort_error = ViceConnectionError(
                    "VICE raw event sequence did not increase"
                )
            else:
                self._last_raw_sequence = event.raw_sequence
                self._raw_events.append(event)
                self._condition.notify_all()
        if abort_error is not None:
            self.client.abort(abort_error)

    def _on_terminal(self, error: ViceConnectionError) -> None:
        with self._condition:
            self._terminal_error = error
            self._connection_state = "disconnected"
            self._execution_state = "unknown"
            self._coordinator_stop = True
            self._events_enabled = False
            self._raw_events.clear()
            self._display_capture = None
            self._condition.notify_all()

    def _raise_if_disconnected_locked(self) -> None:
        if self._terminal_error is not None:
            raise self._terminal_error
        if self._connection_state != "connected":
            raise ViceConnectionError("VICE monitor is not connected")

    def _require_stopped(self) -> None:
        with self._condition:
            self._raise_if_disconnected_locked()
            if self._execution_state != "stopped":
                raise ViceStateError(
                    f"VICE target is {self._execution_state}, not stopped"
                )

    def _require_running(self) -> None:
        with self._condition:
            self._raise_if_disconnected_locked()
            if self._execution_state != "running":
                raise ViceStateError(
                    f"VICE target is {self._execution_state}, not running"
                )

    def _next_command_sequence(self) -> int:
        with self._condition:
            self._command_sequence += 1
            return self._command_sequence

    def _raw_watermark(self) -> int:
        with self._condition:
            return self._last_raw_sequence

    def _pop_raw(
        self, deadline: Optional[float], *, require: bool
    ) -> Optional[RawEvent]:
        with self._condition:
            while not self._raw_events:
                self._raise_if_disconnected_locked()
                if not require:
                    return None
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise ViceTimeoutError(
                        "timed out waiting for a VICE execution event",
                        state_may_have_changed=True,
                    )
                self._condition.wait(remaining)
            return self._raw_events.popleft()

    def _publish(
        self,
        event: RawEvent,
        *,
        action_applied: bool = False,
        deadline: Optional[float] = None,
    ) -> PublicEvent:
        public = PublicEvent(
            event.raw_sequence,
            event.kind,
            event.pc,
            event.received_at,
            event.checkpoints,
        )
        with self._condition:
            self._execution_state = (
                "stopped" if event.kind == "stopped" else "running"
            )
            self._last_event = public
            if event.kind == "stopped":
                self._stop_count += 1
                self._latest_stop = public
            self._condition.notify_all()

        sync_deadline = (
            time.monotonic() + 10.0 if deadline is None else deadline
        )
        try:
            self._sync_event(event, lambda: self._remaining_ms(sync_deadline))
        except ViceTraceSyncError:
            raise
        except BaseException as exc:
            raise ViceTraceSyncError(
                f"trace synchronization failed for raw event "
                f"{event.raw_sequence}: {exc}",
                event=event,
                action_applied=action_applied,
                cause=exc,
            ) from exc
        return public

    def _drain_pending(
        self,
        deadline: Optional[float] = None,
        limit: Optional[int] = None,
        through: Optional[int] = None,
    ) -> List[PublicEvent]:
        """Publish queued raw events.

        `limit` bounds one batch so the unsolicited coordinator cannot hold
        operation_lock indefinitely. `through` bounds the drain to a finite
        watermark, which is what a command needs: without it, a continuous
        checkpoint-hit stream means the queue never empties and the command's
        pre-drain never returns, so its acknowledgement is never sent.
        """
        result = []
        while limit is None or len(result) < limit:
            if through is not None and not self._has_raw_at_or_before(through):
                break
            event = self._pop_raw(None, require=False)
            if event is None:
                break
            result.append(self._publish(event, deadline=deadline))
        return result

    def _has_raw_at_or_before(self, watermark: int) -> bool:
        with self._condition:
            return bool(self._raw_events) \
                and self._raw_events[0].raw_sequence <= watermark

    def _coordinate_unsolicited(self) -> None:
        while True:
            with self._condition:
                while (
                    not self._coordinator_stop
                    and (not self._events_enabled or not self._raw_events)
                ):
                    self._condition.wait()
                if self._coordinator_stop:
                    return
            try:
                # Bounded batches: a continuously firing non-stopping
                # checkpoint would otherwise keep the raw queue non-empty and
                # hold operation_lock indefinitely, starving interrupt and
                # every other command. Releasing between batches lets a waiting
                # command take the lock.
                with self.operation_lock:
                    self._drain_pending(limit=UNSOLICITED_DRAIN_BATCH)
            except ViceConnectionError:
                continue
            except BaseException:
                # State was recorded before trace synchronization. A failed
                # trace update must not make the controller disagree with VICE.
                continue

    @staticmethod
    def _remaining_ms(deadline: float) -> int:
        remaining = int((deadline - time.monotonic()) * 1000)
        if remaining < 1:
            raise ViceTimeoutError(
                "VICE operation exhausted its timeout budget",
                state_may_have_changed=False,
            )
        return min(remaining, 55_000)

    def _execution_operation(
        self,
        pattern: Sequence[str],
        acknowledge: Callable[[int], int],
        *,
        timeout_ms: int,
        precondition: str = "stopped",
    ) -> OperationResult:
        if not 1 <= timeout_ms <= 55_000:
            raise ViceValidationError("timeout_ms must be in 1..55000")
        deadline = time.monotonic() + timeout_ms / 1000.0
        with self.operation_lock:
            # These events predate this operation, so its action was not applied.
            # Bounded by the watermark taken on entry: a continuous hit stream
            # must not stop this command from being acknowledged.
            self._drain_pending(
                deadline, through=self._raw_watermark()
            )
            if precondition == "running":
                self._require_running()
            else:
                self._require_stopped()
            watermark = self._raw_watermark()
            sequence = self._next_command_sequence()
            remaining = self._remaining_ms(deadline)
            with self._condition:
                self._execution_state = "transitioning"
            try:
                request_id = acknowledge(remaining)
            except ViceFailure as exc:
                # A rejected or locally invalid command did not change VICE
                # execution. Timeouts and transport failures remain unknown.
                if not exc.outcome_unknown:
                    with self._condition:
                        if self._connection_state == "connected":
                            self._execution_state = precondition
                            self._condition.notify_all()
                raise
            matched = 0
            last: Optional[PublicEvent] = None
            while matched < len(pattern):
                raw = self._pop_raw(deadline, require=True)
                assert raw is not None
                if raw.raw_sequence <= watermark:
                    self._publish(raw, deadline=deadline)
                    continue
                published = self._publish(
                    raw, action_applied=True, deadline=deadline
                )
                if raw.kind == pattern[matched]:
                    last = published
                    matched += 1
            return OperationResult(sequence, request_id, last)

    def step(
        self, count: int = 1, *, step_over: bool = False,
        timeout_ms: int = 10_000
    ) -> OperationResult:
        return self._execution_operation(
            ("resumed", "stopped"),
            lambda remaining: self.client.acknowledge_step(
                count, step_over, timeout_ms=remaining
            ),
            timeout_ms=timeout_ms,
        )

    def next(self, count: int = 1, *, timeout_ms: int = 10_000) -> OperationResult:
        return self.step(count, step_over=True, timeout_ms=timeout_ms)

    def finish(self, *, timeout_ms: int = 10_000) -> OperationResult:
        return self._execution_operation(
            ("resumed", "stopped"),
            lambda remaining: self.client.acknowledge_finish(
                timeout_ms=remaining
            ),
            timeout_ms=timeout_ms,
        )

    def resume(self, *, timeout_ms: int = 10_000) -> OperationResult:
        return self._execution_operation(
            ("resumed",),
            lambda remaining: self.client.acknowledge_resume(
                timeout_ms=remaining
            ),
            timeout_ms=timeout_ms,
        )

    def interrupt(self, *, timeout_ms: int = 10_000) -> OperationResult:
        return self._execution_operation(
            ("stopped",),
            lambda remaining: self.client.acknowledge_interrupt(
                timeout_ms=remaining
            ),
            timeout_ms=timeout_ms,
            precondition="running",
        )

    def _stopped_call(
        self,
        callback,
        *,
        timeout_ms: int,
        sync_kind: Optional[str] = None,
    ):
        if not 1 <= timeout_ms <= 55_000:
            raise ViceValidationError("timeout_ms must be in 1..55000")
        deadline = time.monotonic() + timeout_ms / 1000.0
        remaining_ms = lambda: self._remaining_ms(deadline)
        with self.operation_lock:
            self._drain_pending(deadline, through=self._raw_watermark())
            self._require_stopped()
            sequence = self._next_command_sequence()
            result = callback(remaining_ms)
            if sync_kind is not None:
                try:
                    self._sync_result(sync_kind, result, remaining_ms)
                except ViceTraceSyncError:
                    raise
                except BaseException as exc:
                    raise ViceTraceSyncError(
                        f"trace synchronization failed for {sync_kind}: {exc}",
                        event=RawEvent(
                            self._last_raw_sequence,
                            sync_kind,
                            0,
                            None,
                            b"",
                            time.monotonic(),
                        ),
                        action_applied=True,
                        cause=exc,
                    ) from exc
            return sequence, result

    def _post_action_sync_error(
        self, sync_kind: str, cause: BaseException
    ) -> ViceTraceSyncError:
        raw_sequence = self._raw_watermark()
        return ViceTraceSyncError(
            f"trace synchronization failed for {sync_kind}: {cause}",
            event=RawEvent(
                raw_sequence,
                sync_kind,
                0,
                None,
                b"",
                time.monotonic(),
            ),
            action_applied=True,
            cause=cause,
        )

    def get_registers(
        self, memspace: int = MEMSPACE_MAIN, *, timeout_ms: int = 10_000
    ) -> Tuple[int, Dict[str, int]]:
        return self._stopped_call(
            lambda remaining: self.client.registers_get(
                memspace, timeout_ms=remaining()
            ),
            timeout_ms=timeout_ms,
            sync_kind="registers",
        )

    def set_registers(
        self,
        values: Dict[str, int],
        memspace: int = MEMSPACE_MAIN,
        *,
        timeout_ms: int = 10_000,
    ) -> Tuple[int, Dict[str, int]]:
        return self._stopped_call(
            lambda remaining: self.client.registers_set(
                values, memspace, timeout_ms=remaining()
            ),
            timeout_ms=timeout_ms,
            sync_kind="registers",
        )

    def list_banks(
        self, *, timeout_ms: int = 10_000
    ) -> Tuple[int, List[Bank]]:
        def list_and_cache(remaining):
            result = self.client.banks_available(timeout_ms=remaining())
            self.banks = tuple(result)
            return result

        return self._stopped_call(
            list_and_cache, timeout_ms=timeout_ms, sync_kind="banks"
        )

    def read_memory(
        self,
        start: int,
        end: int,
        *,
        memspace: int = MEMSPACE_MAIN,
        bank_id: int = 0,
        side_effects: bool = False,
        timeout_ms: int = 10_000,
        sync_trace: bool = False,
    ) -> Tuple[int, bytes]:
        return self._stopped_call(
            lambda remaining: self.client.memory_get(
                start,
                end,
                memspace,
                bank_id,
                side_effects,
                timeout_ms=remaining(),
            ),
            timeout_ms=timeout_ms,
            sync_kind=(
                f"memory:{start}:{memspace}:{bank_id}"
                if sync_trace else None
            ),
        )

    def write_memory(
        self,
        start: int,
        data: bytes,
        *,
        memspace: int = MEMSPACE_MAIN,
        bank_id: int = 0,
        side_effects: bool = False,
        timeout_ms: int = 10_000,
        sync_trace: bool = True,
    ) -> Tuple[int, List[Tuple[int, int]]]:
        return self._stopped_call(
            lambda remaining: self.client.memory_set(
                start,
                data,
                memspace,
                bank_id,
                side_effects,
                timeout_ms=remaining(),
            ),
            timeout_ms=timeout_ms,
            sync_kind=(
                f"memory:{start}:{memspace}:{bank_id}"
                if sync_trace else None
            ),
        )

    def capture_display(
        self, *, use_vic: bool = True, timeout_ms: int = 10_000
    ) -> Tuple[int, DisplayCapture]:
        """Capture one frame together with the palette that renders it.

        Requires a stopped target, through `_stopped_call`, and refuses
        `running` or `unknown` before any frame is sent. That is not caution
        about reading pixels: sending *any* binary-monitor command traps VICE
        into the monitor, which emits registers and `STOPPED`. A capture
        advertised as read-only would therefore stop the emulator, hold the
        operation lock while the coordinator queued that `STOPPED`, and return
        claiming the execution state was unchanged -- exactly the divergence
        this controller exists to prevent. A caller wanting a frame mid-run
        does `interrupt` / `capture_display` / `resume`, where the mutations and
        their events stay visible.

        Both requests are non-mutating and share one timeout budget. The
        pairing is not atomic against an external palette change; the window is
        minimized, not eliminated.
        """
        def capture(remaining):
            frame = self.client.display_get(use_vic, timeout_ms=remaining())
            palette = self.client.palette_get(use_vic, timeout_ms=remaining())
            if frame.buffer:
                highest = max(frame.buffer)
                if highest >= len(palette):
                    raise ViceProtocolError(
                        f"display capture: pixel index {highest} is outside "
                        f"the {len(palette)}-entry palette, so the frame is "
                        f"not renderable"
                    )
            result = DisplayCapture(
                str(uuid.uuid4()), frame, tuple(palette)
            )
            self._display_capture = result
            return result

        return self._stopped_call(capture, timeout_ms=timeout_ms)

    def read_display_capture(
        self, capture_id: str, offset: int, max_bytes: int
    ) -> Tuple[int, bytes, bool]:
        if not isinstance(capture_id, str) or not capture_id:
            raise ViceValidationError("capture_id must not be blank")
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or offset < 0
        ):
            raise ViceValidationError("offset must be non-negative")
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or not 1 <= max_bytes <= DISPLAY_CHUNK_BYTES
        ):
            raise ViceValidationError(
                f"max_bytes must be in 1..{DISPLAY_CHUNK_BYTES}"
            )
        with self.operation_lock:
            with self._condition:
                self._raise_if_disconnected_locked()
            capture = self._display_capture
            if capture is None or capture.capture_id != capture_id:
                raise ViceValidationError("display capture is not available")
            data = capture.frame.buffer
            if offset > len(data):
                raise ViceValidationError("offset exceeds capture length")
            chunk = data[offset:offset + max_bytes]
            return (
                self._next_command_sequence(),
                chunk,
                offset + len(chunk) == len(data),
            )

    def discard_display_capture(self, capture_id: str) -> Tuple[int, None]:
        with self.operation_lock:
            with self._condition:
                self._raise_if_disconnected_locked()
            capture = self._display_capture
            if capture is None or capture.capture_id != capture_id:
                raise ViceValidationError("display capture is not available")
            self._display_capture = None
            return self._next_command_sequence(), None

    def feed_keyboard(
        self, data: bytes, *, timeout_ms: int = 10_000
    ) -> Tuple[int, None]:
        return self._stopped_call(
            lambda remaining: self.client.keyboard_feed(
                data, timeout_ms=remaining()
            ),
            timeout_ms=timeout_ms,
        )

    def set_joyport(
        self, port: int, value: int, *, timeout_ms: int = 10_000
    ) -> Tuple[int, Dict[str, int]]:
        if isinstance(port, bool) or port not in (1, 2):
            raise ViceValidationError("port must be 1 or 2")
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 0xFF
        ):
            raise ViceValidationError("value must be in 0..255")

        def configure(remaining):
            # VICE persists this resource if the user saves emulator settings.
            self.client.resource_set_int(
                f"JoyPort{port}Device",
                JOYPORT_DEVICE_IO_SIMULATION,
                timeout_ms=remaining(),
            )
            self.client.joyport_set(port, value, timeout_ms=remaining())
            return {
                "port": port,
                "value": value,
            }

        return self._stopped_call(configure, timeout_ms=timeout_ms)

    def set_keyboard_matrix(
        self,
        row: int,
        column: int,
        pressed: bool,
        *,
        timeout_ms: int = 10_000,
    ) -> Tuple[int, Dict[str, object]]:
        if (
            isinstance(row, bool)
            or not isinstance(row, int)
            or not 0 <= row <= 7
        ):
            raise ViceValidationError("row must be in 0..7")
        if (
            isinstance(column, bool)
            or not isinstance(column, int)
            or not 0 <= column <= 7
        ):
            raise ViceValidationError("column must be in 0..7")
        if not isinstance(pressed, bool):
            raise ViceValidationError("pressed must be boolean")

        def configure(remaining):
            self.client.keyboard_matrix_set(
                row, column, pressed, timeout_ms=remaining()
            )
            return {"row": row, "column": column, "pressed": pressed}

        return self._stopped_call(configure, timeout_ms=timeout_ms)

    def save_snapshot(
        self,
        filename: str,
        *,
        save_roms: bool = False,
        save_disks: bool = True,
        timeout_ms: int = 10_000,
    ) -> Tuple[int, None]:
        return self._stopped_call(
            lambda remaining: self.client.snapshot_save(
                filename,
                save_roms=save_roms,
                save_disks=save_disks,
                timeout_ms=remaining(),
            ),
            timeout_ms=timeout_ms,
        )

    def load_snapshot(
        self, filename: str, *, timeout_ms: int = 10_000
    ) -> Tuple[int, int]:
        return self._stopped_call(
            lambda remaining: self.client.snapshot_load(
                filename, timeout_ms=remaining()
            ),
            timeout_ms=timeout_ms,
            sync_kind="snapshot_load",
        )

    def list_checkpoints(
        self, *, timeout_ms: int = 10_000
    ) -> Tuple[int, List[Checkpoint]]:
        return self._stopped_call(
            lambda remaining: self.client.checkpoint_list(
                timeout_ms=remaining()
            ),
            timeout_ms=timeout_ms,
            sync_kind="checkpoints",
        )

    def set_checkpoint(
        self,
        start: int,
        end: int,
        *,
        stop_on_hit: bool = True,
        enabled: bool = True,
        cpu_op: int = CPU_OP_EXEC,
        temporary: bool = False,
        memspace: int = MEMSPACE_MAIN,
        timeout_ms: int = 10_000,
    ) -> Tuple[int, Tuple[Checkpoint, List[Checkpoint]]]:
        def create_and_list(remaining):
            checkpoint = self.client.checkpoint_set(
                start,
                end,
                stop_on_hit,
                enabled,
                cpu_op,
                temporary,
                memspace,
                timeout_ms=remaining(),
            )
            try:
                checkpoints = self.client.checkpoint_list(
                    timeout_ms=remaining()
                )
            except BaseException as exc:
                raise self._post_action_sync_error(
                    "checkpoint_change", exc
                ) from exc
            return checkpoint, checkpoints

        return self._stopped_call(
            create_and_list,
            timeout_ms=timeout_ms,
            sync_kind="checkpoint_change",
        )

    def delete_checkpoint(
        self, number: int, *, timeout_ms: int = 10_000
    ) -> Tuple[int, List[Checkpoint]]:
        def delete_and_list(remaining):
            self.client.checkpoint_delete(
                number, timeout_ms=remaining()
            )
            try:
                return self.client.checkpoint_list(timeout_ms=remaining())
            except BaseException as exc:
                raise self._post_action_sync_error(
                    "checkpoints", exc
                ) from exc

        return self._stopped_call(
            delete_and_list,
            timeout_ms=timeout_ms,
            sync_kind="checkpoints",
        )

    def toggle_checkpoint(
        self, number: int, enabled: bool, *, timeout_ms: int = 10_000
    ) -> Tuple[int, List[Checkpoint]]:
        def toggle_and_list(remaining):
            self.client.checkpoint_toggle(
                number, enabled, timeout_ms=remaining()
            )
            try:
                return self.client.checkpoint_list(timeout_ms=remaining())
            except BaseException as exc:
                raise self._post_action_sync_error(
                    "checkpoints", exc
                ) from exc

        return self._stopped_call(
            toggle_and_list,
            timeout_ms=timeout_ms,
            sync_kind="checkpoints",
        )

    def reset(
        self, reset_type: int, *, timeout_ms: int = 10_000
    ) -> Tuple[int, None]:
        return self._stopped_call(
            lambda remaining: self.client.reset(
                reset_type, timeout_ms=remaining()
            ),
            timeout_ms=timeout_ms,
            sync_kind="reset",
        )

    def status(self) -> Dict[str, object]:
        with self._condition:
            event = self._last_event
            return {
                "instance_id": self.instance_id,
                "connection_state": self._connection_state,
                "execution_state": self._execution_state,
                "command_sequence": self._command_sequence,
                "stop_count": self._stop_count,
                "pc": event.pc if event else None,
                "terminal_error": (
                    str(self._terminal_error)
                    if self._terminal_error is not None else None
                ),
            }

    def wait_for_stop(
        self, after_stop_count: int, timeout_ms: int
    ) -> PublicEvent:
        if (
            isinstance(after_stop_count, bool)
            or not isinstance(after_stop_count, int)
            or after_stop_count < 0
        ):
            raise ViceValidationError("after_stop_count must be non-negative")
        if not 1 <= timeout_ms <= 55_000:
            raise ViceValidationError("timeout_ms must be in 1..55000")
        deadline = time.monotonic() + timeout_ms / 1000.0
        with self._condition:
            while True:
                self._raise_if_disconnected_locked()
                if (
                    self._stop_count > after_stop_count
                    and self._latest_stop is not None
                ):
                    return self._latest_stop
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ViceTimeoutError(
                        f"no stop after count {after_stop_count} "
                        f"within {timeout_ms} ms"
                    )
                self._condition.wait(remaining)
