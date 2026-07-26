"""Checkpoint-hit event aggregation, history correctness, and liveness.

Covers the two independent ways a single pending-checkpoint slot broke:
a non-stopping checkpoint firing repeatedly, and two overlapping *stopping*
checkpoints. VICE emits one checkpoint-info event per matching enabled
checkpoint before it consults ``cp->stop`` (``mon_breakpoint.c``), so a single
stop legitimately carries several checkpoint-info events.
"""

import struct
import threading
import time

import pytest

from vice.controller import (
    EVENT_HISTORY_LIMIT,
    ViceController,
    ViceEventHistoryLost,
)
from vice.protocol import (
    CPU_OP_EXEC,
    RESP_CHECKPOINT_INFO,
    RESP_RESUMED,
    RESP_STOPPED,
    Checkpoint,
    RawEvent,
    ViceProtocolError,
)


def checkpoint_body(number=1, start=0xC000, end=0xC000, *, stop_on_hit=True):
    return struct.pack(
        "<IBHHBBBBIIBB",
        number, 0, start, end, int(stop_on_hit), 1, CPU_OP_EXEC, 0, 0, 0, 0, 0,
    )


class FakeFrame:
    """Minimal stand-in for a decoded unsolicited frame."""

    def __init__(self, response_type, body=b""):
        self.response_type = response_type
        self.body = body
        self.error = 0
        self.request_id = 0xFFFFFFFF


@pytest.fixture
def bmp_client():
    """A client wired only for event dispatch; no socket is involved."""
    from vice.protocol import ViceBmpClient

    client = ViceBmpClient("127.0.0.1", 65000)
    events = []
    client.set_event_callback(events.append)
    return client, events


@pytest.fixture
def controller():
    from test_controller import connected_controller

    _client, instance = connected_controller()
    yield instance
    # Close so no coordinator daemon outlives the test.
    instance.close()


def drive(client, *frames):
    """Feed unsolicited frames through the client's event dispatch."""
    for frame in frames:
        client._receive_event(frame)


# ---------------------------------------------------------------------------
# protocol: event aggregation
# ---------------------------------------------------------------------------


def test_repeated_non_stopping_hits_emit_distinct_events(bmp_client):
    client, events = bmp_client
    drive(
        client,
        FakeFrame(RESP_CHECKPOINT_INFO, checkpoint_body(3, stop_on_hit=False)),
        FakeFrame(RESP_CHECKPOINT_INFO, checkpoint_body(3, stop_on_hit=False)),
    )

    assert [event.kind for event in events] == ["checkpoint_hit", "checkpoint_hit"]
    assert events[0].raw_sequence < events[1].raw_sequence
    assert all(event.pc is None for event in events)
    assert [event.checkpoint.number for event in events] == [3, 3]


def test_non_stopping_hits_do_not_synthesize_a_stop(bmp_client):
    client, events = bmp_client
    drive(
        client,
        FakeFrame(RESP_CHECKPOINT_INFO, checkpoint_body(3, stop_on_hit=False)),
        FakeFrame(RESP_CHECKPOINT_INFO, checkpoint_body(3, stop_on_hit=False)),
    )
    assert not any(event.kind == "stopped" for event in events)


def test_two_overlapping_stopping_checkpoints_yield_one_stop(bmp_client):
    client, events = bmp_client
    drive(
        client,
        FakeFrame(RESP_CHECKPOINT_INFO, checkpoint_body(1, 0xC000, 0xC0FF)),
        FakeFrame(RESP_CHECKPOINT_INFO, checkpoint_body(2, 0xC080, 0xC080)),
        FakeFrame(RESP_STOPPED, struct.pack("<H", 0xC080)),
    )

    assert [event.kind for event in events] == ["stopped"]
    stop = events[0]
    assert [item.number for item in stop.checkpoints] == [1, 2]
    # Singular field stays populated so consumers detecting "a checkpoint
    # caused this stop" keep working with more than one match.
    assert stop.checkpoint.number == 1


def test_mixed_stopping_and_non_stopping_at_one_address(bmp_client):
    client, events = bmp_client
    drive(
        client,
        FakeFrame(RESP_CHECKPOINT_INFO, checkpoint_body(4, stop_on_hit=False)),
        FakeFrame(RESP_CHECKPOINT_INFO, checkpoint_body(5)),
        FakeFrame(RESP_STOPPED, struct.pack("<H", 0xC000)),
    )

    assert [event.kind for event in events] == ["checkpoint_hit", "stopped"]
    assert events[0].checkpoint.number == 4
    assert [item.number for item in events[1].checkpoints] == [5]


def test_single_stopping_checkpoint_keeps_singular_field(bmp_client):
    client, events = bmp_client
    drive(
        client,
        FakeFrame(RESP_CHECKPOINT_INFO, checkpoint_body(9)),
        FakeFrame(RESP_STOPPED, b""),
    )
    assert events[0].checkpoint.number == 9
    assert [item.number for item in events[0].checkpoints] == [9]


def test_stopping_checkpoint_without_a_stop_still_errors(bmp_client):
    client, _ = bmp_client
    with pytest.raises(ViceProtocolError, match="not followed by a stopped"):
        drive(
            client,
            FakeFrame(RESP_CHECKPOINT_INFO, checkpoint_body(1)),
            FakeFrame(RESP_RESUMED, b""),
        )


# ---------------------------------------------------------------------------
# controller: history correctness and liveness
# ---------------------------------------------------------------------------


def hit_event(raw_sequence):
    return RawEvent(
        raw_sequence,
        "checkpoint_hit",
        RESP_CHECKPOINT_INFO,
        None,
        Checkpoint(number=1, start=0xC000, end=0xC000, stop_on_hit=False),
        b"",
        time.monotonic(),
    )


def stop_event(raw_sequence):
    return RawEvent(
        raw_sequence, "stopped", RESP_STOPPED, 0xC000, None, b"",
        time.monotonic(),
    )


def test_hit_flood_does_not_report_history_loss(controller):
    """More than 1024 hits then a stop: still waitable, no history loss."""
    after = 0
    for index in range(EVENT_HISTORY_LIMIT + 1):
        controller._publish(hit_event(index + 1))
    controller._publish(stop_event(EVENT_HISTORY_LIMIT + 2))

    event = controller.wait_for_stop(after, 1_000)
    assert event.kind == "stopped"


def test_evicted_stopped_event_still_reports_history_loss(controller):
    """The guard must stay: a genuinely lost stop is still an error."""
    controller._publish(stop_event(1))
    after = controller.history[-1].sequence
    controller._publish(stop_event(2))
    for index in range(EVENT_HISTORY_LIMIT + 4):
        controller._publish(hit_event(index + 3))

    with pytest.raises(ViceEventHistoryLost):
        controller.wait_for_stop(after, 1_000)


def test_checkpoint_hit_leaves_execution_state_running(controller):
    controller._publish(stop_event(1))
    assert controller.execution_state == "stopped"
    controller._publish(hit_event(2))
    assert controller.execution_state == "running"


def bare_controller(sync=None):
    """A connected controller with NO event coordinator running.

    The coordinator would concurrently drain the queue, which is what made the
    earlier versions of the two tests below vacuous: the backlog was empty by
    the time the command ran, so `through` was never exercised and an `all()`
    over an empty drained list passed trivially. Suppressing it makes the queue
    contents deterministic.
    """
    from test_controller import FakeClient

    client = FakeClient()
    instance = ViceController(client, sync_event=sync)
    instance.connect(discover_registers=False)
    with instance._condition:
        instance._events_enabled = True
        # Hits imply the target is running, which interrupt() requires.
        instance._execution_state = "running"
    return client, instance


def test_command_predrain_terminates_at_its_watermark():
    """The command-side pre-drain must be finite while hits keep arriving.

    Discriminating regression test: with an unbounded drain the call never
    returns, so the worker is still alive at join and the assert fails rather
    than the suite hanging. With the coordinator suppressed the drained set is
    exact, so this cannot pass vacuously.
    """
    _client, instance = bare_controller()
    for sequence in range(1, 6):
        instance._on_raw_event(hit_event(sequence))
    watermark = instance._raw_watermark()
    assert watermark == 5

    stop = threading.Event()

    def flood():
        sequence = 6
        while not stop.is_set():
            instance._on_raw_event(hit_event(sequence))
            sequence += 1

    drained = []
    outcome = {}

    def drain():
        with instance.operation_lock:
            drained.extend(instance._drain_pending(through=watermark))
        outcome["completed"] = True

    producer = threading.Thread(target=flood, daemon=True)
    worker = threading.Thread(target=drain, daemon=True)
    producer.start()
    worker.start()
    try:
        worker.join(timeout=5.0)
        assert outcome.get("completed") is True, \
            "pre-drain did not complete under a continuous hit stream"
        assert [event.raw_sequence for event in drained] == [1, 2, 3, 4, 5], \
            [event.raw_sequence for event in drained]
    finally:
        stop.set()
        producer.join(timeout=2.0)
        instance.close()


def test_interrupt_is_acknowledged_while_hits_arrive_continuously():
    """A real command must reach acknowledgement under continuous arrivals.

    Arrivals stay continuous until the acknowledgement callback fires, and only
    then become finite -- so an unbounded command-side drain never reaches the
    acknowledgement at all. Verified A/B: ignoring `through` leaves the worker
    blocked and `interrupt` absent from client.calls.
    """
    from test_controller import FakeClient

    stop = threading.Event()
    counter = {"next": 0}
    allocator = threading.Lock()

    def next_sequence():
        with allocator:
            counter["next"] += 1
            return counter["next"]

    state = {}

    class AckStopsProduction(FakeClient):
        def acknowledge_interrupt(self, timeout_ms):
            # Atomically end production, then emit the next in-sequence stop so
            # no raw-sequence regression can abort the connection.
            stop.set()
            producer = state.get("producer")
            if producer is not None:
                producer.join(timeout=2.0)
            self.calls.append(("interrupt", timeout_ms))
            self.emit(stop_event(next_sequence()))
            return len(self.calls)

    def slow_sync(_event, _remaining):
        time.sleep(0.0005)
        return None

    client = AckStopsProduction()
    instance = ViceController(client, sync_event=slow_sync)
    instance.connect(discover_registers=False)
    with instance._condition:
        instance._events_enabled = True
        instance._execution_state = "running"

    def flood():
        while not stop.is_set():
            instance._on_raw_event(hit_event(next_sequence()))
            time.sleep(0.0002)

    producer = threading.Thread(target=flood, daemon=True)
    state["producer"] = producer

    outcome = {}

    def run_interrupt():
        outcome["result"] = instance.interrupt(timeout_ms=20_000)

    worker = threading.Thread(target=run_interrupt, daemon=True)
    producer.start()
    try:
        # Build a real backlog before the command starts.
        time.sleep(0.2)
        assert instance._raw_watermark() > 0
        worker.start()
        worker.join(timeout=25.0)

        assert "result" in outcome, "interrupt never returned"
        assert outcome["result"].event is not None
        assert outcome["result"].event.kind == "stopped"
        assert any(call[0] == "interrupt" for call in client.calls), client.calls
        # A masked abort would surface here rather than passing silently.
        assert instance.connection_state == "connected"
        assert instance.get_registers(timeout_ms=1_000) is not None
    finally:
        stop.set()
        producer.join(timeout=2.0)
        instance.close()


# ---------------------------------------------------------------------------
# production synchronization path
# ---------------------------------------------------------------------------


def test_checkpoint_hit_syncs_through_production_path_as_no_op():
    """sync_event must accept checkpoint_hit without issuing a monitor command.

    A controller fake would pass regardless; this drives the real function.
    """
    from vice import commands

    assert commands.sync_event(hit_event(1), lambda: 1_000) is None
