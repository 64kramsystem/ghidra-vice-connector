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

from .protocol import (
    Bank,
    Checkpoint,
    CPU_OP_EXEC,
    MEMSPACE_MAIN,
    RawEvent,
    Register,
    ViceBmpClient,
    ViceConnectionError,
    ViceFailure,
    ViceTimeoutError,
    ViceValidationError,
)

EVENT_HISTORY_LIMIT = 1024


class ViceStateError(ViceFailure):
    code = "vice_target_not_stopped"


class ViceEventHistoryLost(ViceFailure):
    code = "event_history_lost"

    def __init__(self, oldest_retained: int):
        self.oldest_retained = oldest_retained
        super().__init__(
            f"requested VICE event history is older than retained sequence "
            f"{oldest_retained}"
        )


class ViceInterruptSuperseded(ViceFailure):
    code = "vice_interrupt_superseded"

    def __init__(
        self,
        checkpoint_event: "PublicEvent",
        *,
        action_applied: bool,
    ):
        self.checkpoint_event = checkpoint_event
        self.action_applied = action_applied
        super().__init__(
            "interrupt was superseded by a checkpoint stop",
            outcome_unknown=False,
        )


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
    sequence: int
    raw_sequence: int
    kind: str
    pc: Optional[int]
    checkpoint: Optional[Checkpoint]
    snapshot: Optional[int]
    received_at: float


@dataclass(frozen=True)
class OperationResult:
    command_sequence: int
    request_id: Optional[int]
    event: Optional[PublicEvent]
    preceding_events: Tuple[PublicEvent, ...] = ()


SyncEvent = Callable[[RawEvent], Optional[int]]


def _no_sync(_event: RawEvent) -> Optional[int]:
    return None


class ViceController:
    """Own high-level state and ordering for exactly one client."""

    def __init__(
        self,
        client: ViceBmpClient,
        *,
        sync_event: Optional[SyncEvent] = None,
        event_history_limit: int = EVENT_HISTORY_LIMIT,
    ):
        if event_history_limit < 1:
            raise ValueError("event_history_limit must be positive")
        self.client = client
        self.instance_id = str(uuid.uuid4())
        self.operation_lock = threading.RLock()
        self._condition = threading.Condition(threading.RLock())
        self._raw_events: Deque[RawEvent] = collections.deque()
        self._history: Deque[PublicEvent] = collections.deque(
            maxlen=event_history_limit
        )
        self._sync_event = sync_event or _no_sync
        self._public_sequence = 0
        self._command_sequence = 0
        self._last_raw_sequence = 0
        self._connection_generation = 0
        self._connection_state = "disconnected"
        self._execution_state = "unknown"
        self._terminal_error: Optional[ViceConnectionError] = None
        self._last_snapshot: Optional[int] = None
        self._sync_failures: Deque[Tuple[int, str]] = collections.deque(maxlen=128)
        self._coordinator_stop = False
        self._coordinator: Optional[threading.Thread] = None
        self._events_enabled = False
        client.set_event_callback(self._on_raw_event)
        client.set_terminal_callback(self._on_terminal)

    @property
    def command_sequence(self) -> int:
        with self._condition:
            return self._command_sequence

    @property
    def connection_generation(self) -> int:
        with self._condition:
            return self._connection_generation

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

    @property
    def history(self) -> Tuple[PublicEvent, ...]:
        with self._condition:
            return tuple(self._history)

    def connect(self, *, discover_registers: bool = True) -> None:
        with self._condition:
            self._connection_generation += 1
            self._terminal_error = None
            self._connection_state = "disconnected"
            self._execution_state = "unknown"
        self.client.connect(discover_registers=discover_registers)
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
            self._connection_generation += 1
            self._coordinator_stop = True
            self._events_enabled = False
            self._raw_events.clear()
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
        self, event: RawEvent, *, action_applied: bool = False
    ) -> PublicEvent:
        try:
            snapshot = self._sync_event(event)
        except ViceFailure:
            raise
        except BaseException as exc:
            raise ViceTraceSyncError(
                f"trace synchronization failed for raw event "
                f"{event.raw_sequence}: {exc}",
                event=event,
                action_applied=action_applied,
                cause=exc,
            ) from exc
        with self._condition:
            if (
                snapshot is not None
                and self._last_snapshot is not None
                and snapshot < self._last_snapshot
            ):
                raise ViceTraceSyncError(
                    f"trace snapshot regressed from {self._last_snapshot} "
                    f"to {snapshot}",
                    event=event,
                    action_applied=action_applied,
                    cause=ValueError("trace snapshot regression"),
                )
            if snapshot is not None:
                self._last_snapshot = snapshot
            self._public_sequence += 1
            public = PublicEvent(
                self._public_sequence,
                event.raw_sequence,
                event.kind,
                event.pc,
                event.checkpoint,
                snapshot,
                event.received_at,
            )
            self._history.append(public)
            self._execution_state = (
                "stopped" if event.kind == "stopped" else "running"
            )
            self._condition.notify_all()
            return public

    def _drain_pending(self) -> List[PublicEvent]:
        result = []
        while True:
            event = self._pop_raw(None, require=False)
            if event is None:
                return result
            result.append(self._publish(event))

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
                with self.operation_lock:
                    self._drain_pending()
            except ViceConnectionError:
                continue
            except BaseException:
                # A failed unsolicited sync is resolved but not published. Keeping
                # the coordinator alive permits later events to make progress.
                with self._condition:
                    self._sync_failures.append(
                        (self._last_raw_sequence, "unsolicited trace sync failed")
                    )
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
        interrupt: bool = False,
    ) -> OperationResult:
        if not 1 <= timeout_ms <= 55_000:
            raise ViceValidationError("timeout_ms must be in 1..55000")
        deadline = time.monotonic() + timeout_ms / 1000.0
        with self.operation_lock:
            # These events predate this operation, so its action was not applied.
            preceding = self._drain_pending()
            if precondition == "running":
                self._require_running()
            else:
                self._require_stopped()
            watermark = self._raw_watermark()
            sequence = self._next_command_sequence()
            with self._condition:
                self._execution_state = "transitioning"
            request_id = acknowledge(self._remaining_ms(deadline))
            matched = 0
            checkpoint_stop: Optional[PublicEvent] = None
            last: Optional[PublicEvent] = None
            try:
                while matched < len(pattern):
                    raw = self._pop_raw(deadline, require=True)
                    assert raw is not None
                    if raw.raw_sequence <= watermark:
                        # Below-watermark events predate the acknowledged action.
                        preceding.append(self._publish(raw))
                        continue
                    expected = pattern[matched]
                    if raw.kind == expected and not (
                        interrupt and raw.kind == "stopped"
                        and raw.checkpoint is not None
                    ):
                        last = self._publish(raw, action_applied=True)
                        matched += 1
                    else:
                        published = self._publish(raw, action_applied=True)
                        preceding.append(published)
                        if (
                            interrupt
                            and raw.kind == "stopped"
                            and raw.checkpoint is not None
                        ):
                            checkpoint_stop = published
                return OperationResult(
                    sequence, request_id, last, tuple(preceding)
                )
            except ViceTimeoutError:
                if interrupt and checkpoint_stop is not None:
                    raise ViceInterruptSuperseded(
                        checkpoint_stop, action_applied=True
                    )
                raise

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
            interrupt=True,
        )

    def _stopped_call(self, callback):
        with self.operation_lock:
            self._drain_pending()
            self._require_stopped()
            sequence = self._next_command_sequence()
            return sequence, callback()

    def get_registers(
        self, memspace: int = MEMSPACE_MAIN, *, timeout_ms: int = 10_000
    ) -> Tuple[int, Dict[str, int]]:
        return self._stopped_call(
            lambda: self.client.registers_get(
                memspace, timeout_ms=timeout_ms
            )
        )

    def set_registers(
        self,
        values: Dict[str, int],
        memspace: int = MEMSPACE_MAIN,
        *,
        timeout_ms: int = 10_000,
    ) -> Tuple[int, Dict[str, int]]:
        return self._stopped_call(
            lambda: self.client.registers_set(
                values, memspace, timeout_ms=timeout_ms
            )
        )

    def list_banks(
        self, *, timeout_ms: int = 10_000
    ) -> Tuple[int, List[Bank]]:
        return self._stopped_call(
            lambda: self.client.banks_available(timeout_ms=timeout_ms)
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
    ) -> Tuple[int, bytes]:
        return self._stopped_call(
            lambda: self.client.memory_get(
                start,
                end,
                memspace,
                bank_id,
                side_effects,
                timeout_ms=timeout_ms,
            )
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
    ) -> Tuple[int, List[Tuple[int, int]]]:
        return self._stopped_call(
            lambda: self.client.memory_set(
                start,
                data,
                memspace,
                bank_id,
                side_effects,
                timeout_ms=timeout_ms,
            )
        )

    def list_checkpoints(
        self, *, timeout_ms: int = 10_000
    ) -> Tuple[int, List[Checkpoint]]:
        return self._stopped_call(
            lambda: self.client.checkpoint_list(timeout_ms=timeout_ms)
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
    ) -> Tuple[int, Checkpoint]:
        return self._stopped_call(
            lambda: self.client.checkpoint_set(
                start,
                end,
                stop_on_hit,
                enabled,
                cpu_op,
                temporary,
                memspace,
                timeout_ms=timeout_ms,
            )
        )

    def delete_checkpoint(
        self, number: int, *, timeout_ms: int = 10_000
    ) -> Tuple[int, None]:
        return self._stopped_call(
            lambda: self.client.checkpoint_delete(
                number, timeout_ms=timeout_ms
            )
        )

    def toggle_checkpoint(
        self, number: int, enabled: bool, *, timeout_ms: int = 10_000
    ) -> Tuple[int, None]:
        return self._stopped_call(
            lambda: self.client.checkpoint_toggle(
                number, enabled, timeout_ms=timeout_ms
            )
        )

    def reset(
        self, reset_type: int, *, timeout_ms: int = 10_000
    ) -> Tuple[int, None]:
        return self._stopped_call(
            lambda: self.client.reset(reset_type, timeout_ms=timeout_ms)
        )

    def status(self) -> Dict[str, object]:
        with self._condition:
            event = self._history[-1] if self._history else None
            return {
                "instance_id": self.instance_id,
                "connection_state": self._connection_state,
                "execution_state": self._execution_state,
                "connection_generation": self._connection_generation,
                "command_sequence": self._command_sequence,
                "event_sequence": self._public_sequence,
                "raw_sequence": self._last_raw_sequence,
                "pc": event.pc if event else None,
                "terminal_error": (
                    str(self._terminal_error)
                    if self._terminal_error is not None else None
                ),
            }

    def wait_for_stop(
        self, after_sequence: int, timeout_ms: int
    ) -> PublicEvent:
        if (
            isinstance(after_sequence, bool)
            or not isinstance(after_sequence, int)
            or after_sequence < 0
        ):
            raise ViceValidationError("after_sequence must be non-negative")
        if not 1 <= timeout_ms <= 55_000:
            raise ViceValidationError("timeout_ms must be in 1..55000")
        deadline = time.monotonic() + timeout_ms / 1000.0
        with self._condition:
            generation = self._connection_generation
            while True:
                self._raise_if_disconnected_locked()
                if generation != self._connection_generation:
                    raise self._terminal_error or ViceConnectionError(
                        "VICE connection changed while waiting"
                    )
                if self._history:
                    oldest = self._history[0].sequence
                    if after_sequence < oldest - 1:
                        raise ViceEventHistoryLost(oldest)
                    for event in self._history:
                        if (
                            event.sequence > after_sequence
                            and event.kind == "stopped"
                        ):
                            return event
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ViceTimeoutError(
                        f"no stopped event after sequence {after_sequence} "
                        f"within {timeout_ms} ms"
                    )
                self._condition.wait(remaining)
