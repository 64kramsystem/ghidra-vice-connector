"""Wire-level integration tests for the strict BMP client."""

import struct
import threading
from unittest.mock import MagicMock

import pytest

from bmp_helpers import (
    DEFAULT_REGISTERS,
    MockViceServer,
    build_registers_get_body,
)
from vice import protocol
from vice.protocol import (
    CMD_BANKS_AVAILABLE,
    CMD_CHECKPOINT_DELETE,
    CMD_CHECKPOINT_LIST,
    CMD_CHECKPOINT_SET,
    CMD_CHECKPOINT_TOGGLE,
    CMD_MEMORY_GET,
    CMD_MEMORY_SET,
    CMD_REGISTERS_GET,
    CMD_REGISTERS_SET,
    CPU_OP_EXEC,
    CPU_OP_LOAD,
    CPU_OP_STORE,
    Frame,
    RESP_BANKS_AVAILABLE,
    RESP_CHECKPOINT_DELETE,
    RESP_CHECKPOINT_INFO,
    RESP_CHECKPOINT_LIST,
    RESP_CHECKPOINT_TOGGLE,
    RESP_MEMORY_GET,
    RESP_MEMORY_SET,
    RESP_REGISTERS_GET,
    ViceBmpClient,
    ViceConnectionError,
    ViceProtocolError,
    ViceTimeoutError,
    ViceValidationError,
)


def memory_response(data):
    return RESP_MEMORY_GET, struct.pack("<H", len(data)) + data


def checkpoint_body(
    number=1, start=0xC000, end=0xC000, operations=CPU_OP_EXEC
):
    return struct.pack(
        "<IBHHBBBBIIBB",
        number, 0, start, end, 1, 1, operations, 0, 0, 0, 0, 0,
    )


def test_connect_discovers_register_metadata(connected_client):
    client, _ = connected_client
    assert len(client.reg_name_to_id) == len(DEFAULT_REGISTERS)
    assert client.reg_name_to_id["PC"] == 0
    assert client.reg_name_to_bits["PC"] == 16


def test_connect_failure_is_structured():
    client = ViceBmpClient("127.0.0.1", 19999)
    with pytest.raises(ViceConnectionError):
        client.connect()


def test_register_get_and_set_roundtrip_frames(connected_client):
    client, server = connected_client
    values = {
        "PC": 0xC000, "A": 0x41, "X": 0, "Y": 0,
        "SP": 0xFD, "FLAGS": 0x30,
    }
    server.handle(
        CMD_REGISTERS_GET,
        lambda _: (RESP_REGISTERS_GET, build_registers_get_body(values)),
    )
    assert client.registers_get()["PC"] == 0xC000

    observed = {}

    def set_handler(body):
        observed["memspace"], count = struct.unpack_from("<BH", body)
        observed["count"] = count
        observed["id"] = body[4]
        observed["value"] = struct.unpack_from("<H", body, 5)[0]
        return RESP_REGISTERS_GET, build_registers_get_body({"A": 0x42})

    server.handle(CMD_REGISTERS_SET, set_handler)
    assert client.registers_set({"A": 0x42}) == {"A": 0x42}
    assert observed == {"memspace": 0, "count": 1, "id": 1, "value": 0x42}


@pytest.mark.parametrize(
    ("values", "match"),
    [({"NOPE": 1}, "unknown register"), ({"A": 256}, "0..255")],
)
def test_register_set_validates_before_io(connected_client, values, match):
    client, _ = connected_client
    with pytest.raises(ViceValidationError, match=match):
        client.registers_set(values)


def test_memory_get_frame_and_bank(connected_client):
    client, server = connected_client
    seen = {}

    def handler(body):
        side_effects, start, end, memspace, bank = struct.unpack(
            "<BHHBH", body
        )
        seen.update(
            side_effects=side_effects, start=start, end=end,
            memspace=memspace, bank=bank,
        )
        return memory_response(bytes(end - start + 1))

    server.handle(CMD_MEMORY_GET, handler)
    assert len(client.memory_get(0x400, 0x4FF, bank_id=3)) == 256
    assert seen == {
        "side_effects": 0, "start": 0x400, "end": 0x4FF,
        "memspace": 0, "bank": 3,
    }


def test_full_64k_read_chunks_without_wrapping(connected_client):
    client, server = connected_client
    ranges = []

    def handler(body):
        _side_effects, start, end, _memspace, _bank = struct.unpack(
            "<BHHBH", body
        )
        ranges.append((start, end))
        return memory_response(bytes(end - start + 1))

    server.handle(CMD_MEMORY_GET, handler)
    result = client.memory_get(0, 0xFFFF)
    assert len(result) == 0x10000
    assert ranges == [(0, 0xFFFE), (0xFFFF, 0xFFFF)]


def test_full_64k_read_shares_one_deadline(monkeypatch):
    ticks = iter((100.0, 100.1, 100.4))
    monkeypatch.setattr(protocol.time, "monotonic", lambda: next(ticks))
    client = ViceBmpClient()
    first = b"\x00" * 0xFFFF
    second = b"\x00"
    client.command = MagicMock(
        side_effect=[
            Frame(
                RESP_MEMORY_GET,
                0,
                1,
                struct.pack("<H", len(first)) + first,
            ),
            Frame(
                RESP_MEMORY_GET,
                0,
                2,
                struct.pack("<H", len(second)) + second,
            ),
        ]
    )

    assert len(client.memory_get(0, 0xFFFF, timeout_ms=1_000)) == 0x10000
    budgets = [
        call.kwargs["timeout_ms"]
        for call in client.command.call_args_list
    ]
    assert len(budgets) == 2
    assert 0 < budgets[1] < budgets[0] <= 1_000


def test_memory_get_rejects_wrong_length(connected_client):
    client, server = connected_client
    server.handle(CMD_MEMORY_GET, lambda _: memory_response(b"\x00"))
    with pytest.raises(ViceProtocolError, match="expected 2"):
        client.memory_get(0, 1)


def test_memory_get_with_side_effects_marks_timeout_as_mutating():
    client = ViceBmpClient()
    client.command = MagicMock(side_effect=ViceTimeoutError("fixture"))
    with pytest.raises(ViceTimeoutError):
        client.memory_get(0, 0, side_effects=True)
    assert client.command.call_args.kwargs["mutating"] is True


@pytest.mark.parametrize("timeout_ms", [-1, 0, 55_001])
def test_memory_get_validates_shared_timeout_before_io(timeout_ms):
    client = ViceBmpClient()
    client.command = MagicMock()
    with pytest.raises(ViceValidationError, match="1..55000"):
        client.memory_get(0, 0xFFFF, timeout_ms=timeout_ms)
    client.command.assert_not_called()


def test_snapshot_save_timeout_reports_unknown_external_outcome():
    client = ViceBmpClient()
    client.command = MagicMock(side_effect=ViceTimeoutError("fixture"))
    with pytest.raises(ViceTimeoutError):
        client.snapshot_save("/tmp/state.vsf")
    assert client.command.call_args.kwargs["mutating"] is True


def test_memory_set_frame(connected_client):
    client, server = connected_client
    seen = {}

    def handler(body):
        seen["header"] = struct.unpack("<BHHBH", body[:8])
        seen["data"] = body[8:]
        return RESP_MEMORY_SET, b""

    server.handle(CMD_MEMORY_SET, handler)
    assert client.memory_set(0xC000, b"\xA9\x42\x60") == [
        (0xC000, 0xC002)
    ]
    assert seen["header"] == (0, 0xC000, 0xC002, 0, 0)
    assert seen["data"] == b"\xA9\x42\x60"


def test_full_64k_write_shares_one_deadline(monkeypatch):
    ticks = iter((100.0, 100.1, 100.4))
    monkeypatch.setattr(protocol.time, "monotonic", lambda: next(ticks))
    client = ViceBmpClient()
    client.command = MagicMock()

    assert client.memory_set(
        0, b"\x00" * 0x10000, timeout_ms=1_000
    ) == [(0, 0xFFFE), (0xFFFF, 0xFFFF)]
    budgets = [
        call.kwargs["timeout_ms"]
        for call in client.command.call_args_list
    ]
    assert len(budgets) == 2
    assert 0 < budgets[1] < budgets[0] <= 1_000


@pytest.mark.parametrize(
    ("start", "data"),
    [(0xFFFF, b"\x00\x01"), (-1, b"\x00"), (0, b"")],
)
def test_memory_set_rejects_invalid_ranges(connected_client, start, data):
    client, _ = connected_client
    if data:
        with pytest.raises(ViceValidationError):
            client.memory_set(start, data)
    else:
        assert client.memory_set(start, data) == []


def test_checkpoint_create_frame_and_result(connected_client):
    client, server = connected_client
    seen = {}

    def handler(body):
        seen["request"] = struct.unpack("<HHBBBBB", body)
        return RESP_CHECKPOINT_INFO, checkpoint_body(
            7, 0xD400, 0xD41C, CPU_OP_LOAD | CPU_OP_STORE
        )

    server.handle(CMD_CHECKPOINT_SET, handler)
    checkpoint = client.checkpoint_set(
        0xD400, 0xD41C, cpu_op=CPU_OP_LOAD | CPU_OP_STORE
    )
    assert checkpoint.number == 7
    assert checkpoint.memspace == 0
    assert seen["request"] == (
        0xD400, 0xD41C, 1, 1, CPU_OP_LOAD | CPU_OP_STORE, 0, 0
    )


def test_checkpoint_delete_and_toggle_frames(connected_client):
    client, server = connected_client
    seen = []
    server.handle(
        CMD_CHECKPOINT_DELETE,
        lambda body: seen.append(("delete", struct.unpack("<I", body)[0]))
        or (RESP_CHECKPOINT_DELETE, b""),
    )
    server.handle(
        CMD_CHECKPOINT_TOGGLE,
        lambda body: seen.append(("toggle", *struct.unpack("<IB", body)))
        or (RESP_CHECKPOINT_TOGGLE, b""),
    )
    client.checkpoint_delete(5)
    client.checkpoint_toggle(5, False)
    assert seen == [("delete", 5), ("toggle", 5, 0)]


def test_checkpoint_list_validates_terminal_count(connected_client):
    client, server = connected_client
    frames = [
        (RESP_CHECKPOINT_INFO, checkpoint_body(1)),
        (RESP_CHECKPOINT_INFO, checkpoint_body(2, 0xD000, 0xD000)),
        (RESP_CHECKPOINT_LIST, struct.pack("<I", 2)),
    ]
    server.handle(CMD_CHECKPOINT_LIST, lambda _: frames)
    assert [item.number for item in client.checkpoint_list()] == [1, 2]

    frames[-1] = (RESP_CHECKPOINT_LIST, struct.pack("<I", 3))
    with pytest.raises(ViceProtocolError, match="does not match"):
        client.checkpoint_list()


def test_banks_preserve_order_and_reused_ids(connected_client):
    client, server = connected_client
    items = []
    for bank_id, name in [(0, "default"), (0, "cpu"), (1, "ram")]:
        raw = name.encode()
        items.append(struct.pack("<BHB", 3 + len(raw), bank_id, len(raw)) + raw)
    body = struct.pack("<H", len(items)) + b"".join(items)
    server.handle(CMD_BANKS_AVAILABLE, lambda _: (RESP_BANKS_AVAILABLE, body))
    assert [(item.id, item.name) for item in client.banks_available()] == [
        (0, "default"), (0, "cpu"), (1, "ram")
    ]


def test_banks_reject_duplicate_name_with_different_id(connected_client):
    client, server = connected_client
    items = []
    for bank_id in (0, 1):
        raw = b"ram"
        items.append(struct.pack("<BHB", 3 + len(raw), bank_id, len(raw)) + raw)
    server.handle(
        CMD_BANKS_AVAILABLE,
        lambda _: (
            RESP_BANKS_AVAILABLE,
            struct.pack("<H", len(items)) + b"".join(items),
        ),
    )
    with pytest.raises(ViceProtocolError, match="duplicate"):
        client.banks_available()


@pytest.mark.parametrize(
    "invoke",
    [
        lambda client: client.memory_get(0, 0, side_effects=1),
        lambda client: client.memory_set(0, b"\x00", side_effects="yes"),
        lambda client: client.checkpoint_set(0, 0, enabled=1),
        lambda client: client.checkpoint_toggle(1, 0),
        lambda client: client.acknowledge_step(1, 0, timeout_ms=100),
    ],
)
def test_boolean_fields_are_not_truthiness_coerced(connected_client, invoke):
    client, _ = connected_client
    with pytest.raises(ViceValidationError, match="boolean"):
        invoke(client)


def test_unsolicited_events_are_ordered_without_coalescing(connected_client):
    client, server = connected_client
    events = []
    done = threading.Event()

    def callback(event):
        events.append(event)
        if len(events) == 2:
            done.set()

    client.set_event_callback(callback)
    server.send_event(0x63, struct.pack("<H", 0xC000))
    server.send_event(0x62, struct.pack("<H", 0xC003))
    assert done.wait(1)
    assert [event.kind for event in events] == ["resumed", "stopped"]
    assert [event.raw_sequence for event in events] == [1, 2]


def test_parallel_ping_correlation(connected_client):
    client, _ = connected_client
    results = []
    threads = [
        threading.Thread(target=lambda: results.append(client.ping()))
        for _ in range(10)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2)
    assert results == [True] * 10
