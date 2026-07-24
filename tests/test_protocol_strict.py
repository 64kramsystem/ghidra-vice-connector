import struct
import time
from unittest.mock import MagicMock

import pytest

from vice.protocol import (
    API_VERSION,
    CMD_ADVANCE_INSTRUCTIONS,
    CMD_BANKS_AVAILABLE,
    CMD_PING,
    CMD_REGISTERS_AVAILABLE,
    EVENT_REQUEST_ID,
    MAX_RESPONSE_BODY,
    RESP_ADVANCE_INSTRUCTIONS,
    RESP_BANKS_AVAILABLE,
    RESP_HDR_FMT,
    RESP_PING,
    STX,
    Cursor,
    ViceBmpClient,
    ViceCommandError,
    ViceConnectionError,
    VicePartialWriteError,
    ViceProtocolError,
    ViceTimeoutError,
    Frame,
    parse_checkpoint_info,
)

from .bmp_helpers import MockViceServer, build_registers_available_body


def wait_until(predicate, timeout=1):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError("condition did not become true")


class TestCursor:
    def test_rejects_truncation_with_context(self):
        cursor = Cursor(b"\x01", "fixture")
        with pytest.raises(ViceProtocolError, match="fixture"):
            cursor.u16()

    def test_rejects_trailing_bytes(self):
        cursor = Cursor(b"\x01\x02", "fixture")
        cursor.u8()
        with pytest.raises(ViceProtocolError, match="trailing"):
            cursor.finish()


class TestStrictParsers:
    def test_checkpoint_accepts_v2_memspace(self):
        body = struct.pack(
            "<IBHHBBBBIIBB",
            7, 1, 0x1000, 0x1001, 1, 1, 4, 0, 2, 3, 0, 0,
        )
        checkpoint = parse_checkpoint_info(body)
        assert checkpoint.number == 7
        assert checkpoint.memspace == 0

    def test_checkpoint_rejects_non_boolean_flag(self):
        body = struct.pack(
            "<IBHHBBBBIIBB",
            7, 2, 0x1000, 0x1001, 1, 1, 4, 0, 2, 3, 0, 0,
        )
        with pytest.raises(ViceProtocolError, match="currently_hit"):
            parse_checkpoint_info(body)

    def test_register_metadata_rejects_trailing_bytes(self):
        server = MockViceServer()
        valid = build_registers_available_body()
        server.handle(
            CMD_REGISTERS_AVAILABLE,
            lambda _: (CMD_REGISTERS_AVAILABLE, valid + b"\x00"),
        )
        server.start()
        client = ViceBmpClient("127.0.0.1", server.port)
        try:
            with pytest.raises(ViceProtocolError, match="trailing"):
                client.connect()
        finally:
            client.disconnect()
            server.stop()

    def test_bank_parser_rejects_duplicate_pair(self):
        server = MockViceServer()
        item = struct.pack("<BHB", 4, 0, 1) + b"x"
        server.handle(
            CMD_BANKS_AVAILABLE,
            lambda _: (CMD_BANKS_AVAILABLE, struct.pack("<H", 2) + item + item),
        )
        server.start()
        client = ViceBmpClient("127.0.0.1", server.port)
        try:
            client.connect()
            with pytest.raises(ViceProtocolError, match="duplicate"):
                client.banks_available()
        finally:
            client.disconnect()
            server.stop()


class TestTransport:
    def test_request_id_wrap_skips_live_id(self):
        client = ViceBmpClient()
        client._running = True
        client._sock = MagicMock()
        client._next_id = EVENT_REQUEST_ID - 1
        first, _ = client._alloc_pending(
            CMD_PING, (RESP_PING,), RESP_PING, 1
        )
        assert first == EVENT_REQUEST_ID - 1
        client._alloc_pending(CMD_PING, (RESP_PING,), RESP_PING, 1)
        second, _ = client._alloc_pending(
            CMD_PING, (RESP_PING,), RESP_PING, 1
        )
        assert second == 2

    def test_direct_execution_ack_is_retained(self):
        server = MockViceServer()
        server.handle(
            CMD_ADVANCE_INSTRUCTIONS,
            lambda _: (RESP_ADVANCE_INSTRUCTIONS, b""),
        )
        server.start()
        client = ViceBmpClient("127.0.0.1", server.port)
        try:
            client.connect()
            request_id = client.acknowledge_step(
                1, False, timeout_ms=1_000
            )
            assert request_id > 0
            assert client.connected
        finally:
            client.disconnect()
            server.stop()

    def test_unknown_request_id_is_terminal(self):
        server = MockViceServer()
        server.start()
        client = ViceBmpClient("127.0.0.1", server.port)
        try:
            client.connect()
            header = struct.pack(
                RESP_HDR_FMT, STX, API_VERSION, 0, RESP_PING, 0, 0x12345678
            )
            server.send_raw(header)
            wait_until(lambda: not client.connected)
            assert isinstance(client.terminal_error, ViceConnectionError)
            assert "unknown VICE request ID" in str(client.terminal_error)
        finally:
            client.disconnect()
            server.stop()

    def test_wrong_response_type_is_rejected_by_reader(self):
        server = MockViceServer()
        server.handle(CMD_PING, lambda _: (RESP_BANKS_AVAILABLE, b"\x00\x00"))
        server.start()
        client = ViceBmpClient("127.0.0.1", server.port)
        try:
            client.connect()
            with pytest.raises(ViceConnectionError, match="connection"):
                client.ping()
            assert not client.connected
            assert "unexpected type" in str(client.terminal_error)
        finally:
            client.disconnect()
            server.stop()

    def test_error_type_zero_is_correlated_by_request_id(self):
        server = MockViceServer()
        server.handle(CMD_PING, lambda _: (0x00, b"", 0x8F))
        server.start()
        client = ViceBmpClient("127.0.0.1", server.port)
        try:
            client.connect()
            with pytest.raises(ViceCommandError) as caught:
                client.ping()
            assert caught.value.error == 0x8F
            assert caught.value.command == CMD_PING
            assert client.connected
        finally:
            client.disconnect()
            server.stop()

    def test_reader_enforces_response_frame_cap_before_queue_growth(self):
        client = ViceBmpClient()
        client._running = True
        client._sock = MagicMock()
        request_id, request = client._alloc_pending(
            CMD_PING, (RESP_PING,), RESP_PING, 1
        )
        client._receive_response(Frame(RESP_PING, 0, request_id, b""))
        with pytest.raises(ViceProtocolError, match="completed"):
            client._receive_response(Frame(RESP_PING, 0, request_id, b""))
        assert request.response_queue.qsize() == 1

    def test_oversized_body_is_rejected_before_read(self):
        server = MockViceServer()
        server.start()
        client = ViceBmpClient("127.0.0.1", server.port)
        try:
            client.connect()
            header = struct.pack(
                RESP_HDR_FMT,
                STX,
                API_VERSION,
                MAX_RESPONSE_BODY + 1,
                RESP_PING,
                0,
                EVENT_REQUEST_ID,
            )
            server.send_raw(header)
            wait_until(lambda: not client.connected)
            assert "exceeds" in str(client.terminal_error)
        finally:
            client.disconnect()
            server.stop()

    def test_disconnect_fans_out_to_all_pending_waiters(self):
        client = ViceBmpClient()
        client._running = True
        client._sock = MagicMock()
        _, first = client._alloc_pending(
            CMD_PING, (RESP_PING,), RESP_PING, 1
        )
        _, second = client._alloc_pending(
            CMD_PING, (RESP_PING,), RESP_PING, 1
        )
        client._terminate(ViceConnectionError("fixture disconnect"))
        assert (
            first.response_queue.get_nowait().error is client.terminal_error
        )
        assert (
            second.response_queue.get_nowait().error is client.terminal_error
        )

    def test_timeout_keeps_connection_and_drains_late_response(self):
        def slow_ping(_payload):
            time.sleep(0.04)
            return RESP_PING, b""

        server = MockViceServer()
        server.handle(CMD_PING, slow_ping)
        server.start()
        client = ViceBmpClient("127.0.0.1", server.port)
        try:
            client.connect()
            with pytest.raises(ViceTimeoutError) as caught:
                client.ping(timeout_ms=5)
            assert caught.value.outcome_unknown is True
            assert caught.value.state_may_have_changed is False
            assert client.connected
            time.sleep(0.06)
            assert client.ping(timeout_ms=200)
            assert client.connected
            assert client._abandoned == {}
        finally:
            client.disconnect()
            server.stop()

    def test_partial_multichunk_write_reports_completed_range(self):
        client = ViceBmpClient()
        cause = ViceTimeoutError(
            "late",
            command=0x02,
            request_id=17,
            state_may_have_changed=True,
        )
        client.command = MagicMock(
            side_effect=[
                MagicMock(request_id=1),
                cause,
            ]
        )
        with pytest.raises(VicePartialWriteError) as caught:
            client.memory_set(0, bytes(0x10000))
        assert caught.value.partial is True
        assert caught.value.completed_bytes == 0xFFFF
        assert caught.value.completed_ranges == ((0, 0xFFFE),)
        assert caught.value.failed_range == (0xFFFF, 0xFFFF)
        assert caught.value.command == 0x02
        assert caught.value.request_id == 17
        assert caught.value.outcome_unknown is True

    def test_abandoned_request_limit_fails_closed(self):
        def slow_ping(_payload):
            time.sleep(0.1)
            return RESP_PING, b""

        server = MockViceServer()
        server.handle(CMD_PING, slow_ping)
        server.start()
        client = ViceBmpClient(
            "127.0.0.1", server.port, max_abandoned_requests=1
        )
        try:
            client.connect()
            with pytest.raises(ViceTimeoutError):
                client.ping(timeout_ms=5)
            with pytest.raises(ViceConnectionError, match="preserve correlation"):
                client.ping(timeout_ms=5)
            assert not client.connected
        finally:
            client.disconnect()
            server.stop()
