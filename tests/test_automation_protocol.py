import socket
import struct
import threading

import pytest

import vice.protocol as protocol
from vice.protocol import (
    API_VERSION,
    CMD_DISPLAY_GET,
    CMD_JOYPORT_SET,
    CMD_KEYBOARD_FEED,
    CMD_RESOURCE_GET,
    CMD_RESOURCE_SET,
    CMD_SNAPSHOT_DUMP,
    CMD_SNAPSHOT_UNDUMP,
    REQ_HDR_FMT,
    REQ_HDR_SIZE,
    RESP_DISPLAY_GET,
    RESP_HDR_FMT,
    RESP_JOYPORT_SET,
    RESP_KEYBOARD_FEED,
    RESP_RESOURCE_GET,
    RESP_RESOURCE_SET,
    RESP_SNAPSHOT_DUMP,
    RESP_SNAPSHOT_UNDUMP,
    STX,
    ViceBmpClient,
    ViceInfo,
    ViceTimeoutError,
    ViceValidationError,
)

from .bmp_helpers import MockViceServer


@pytest.fixture
def protocol_client():
    server = MockViceServer()
    requests = {}

    def record(command, response, body=b""):
        def handler(payload):
            requests.setdefault(command, []).append(payload)
            return response, body

        server.handle(command, handler)

    record(CMD_KEYBOARD_FEED, RESP_KEYBOARD_FEED)
    record(CMD_RESOURCE_GET, RESP_RESOURCE_GET, b"\x01\x04\x25\x00\x00\x00")
    record(CMD_RESOURCE_SET, RESP_RESOURCE_SET)
    record(CMD_JOYPORT_SET, RESP_JOYPORT_SET)
    record(CMD_SNAPSHOT_DUMP, RESP_SNAPSHOT_DUMP)
    record(CMD_SNAPSHOT_UNDUMP, RESP_SNAPSHOT_UNDUMP, b"\x34\x12")
    server.start()
    client = ViceBmpClient("127.0.0.1", server.port)
    client.connect(discover_registers=False)
    try:
        yield client, requests
    finally:
        client.disconnect()
        server.stop()


def test_input_resource_joyport_and_snapshot_wire_formats(protocol_client):
    client, requests = protocol_client

    client.keyboard_feed(b"\x41\xff")
    assert client.resource_get_int("JoyPort1Device") == 37
    client.resource_set_int("JoyPort1Device", 37)
    client.joyport_set(1, 0xEF)
    client.joyport_set(2, 0xF7)
    client.snapshot_save("/tmp/state.vsf", save_roms=False, save_disks=True)
    assert client.snapshot_load("/tmp/state.vsf") == 0x1234

    assert requests[CMD_KEYBOARD_FEED] == [b"\x02\x41\xff"]
    assert requests[CMD_RESOURCE_GET] == [b"\x0eJoyPort1Device"]
    assert requests[CMD_RESOURCE_SET] == [
        b"\x01\x0eJoyPort1Device\x04\x25\x00\x00\x00"
    ]
    assert requests[CMD_JOYPORT_SET] == [
        struct.pack("<HH", 0, 0xEF),
        struct.pack("<HH", 1, 0xF7),
    ]
    encoded = b"/tmp/state.vsf"
    assert requests[CMD_SNAPSHOT_DUMP] == [
        bytes((0, 1, len(encoded))) + encoded
    ]
    assert requests[CMD_SNAPSHOT_UNDUMP] == [bytes((len(encoded),)) + encoded]


@pytest.mark.parametrize("data", [b"", b"\x00", b"A\x00B", b"A" * 256])
def test_keyboard_feed_rejects_empty_nul_and_oversized_data(data):
    client = ViceBmpClient()
    with pytest.raises(ViceValidationError):
        client.keyboard_feed(data)


def test_stalled_response_body_terminates_poisoned_connection(
    monkeypatch,
):
    monkeypatch.setattr(
        protocol, "RESPONSE_BODY_IDLE_TIMEOUT_SECONDS", 0.5
    )
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    server_done = threading.Event()
    caller_timed_out = threading.Event()

    def serve():
        conn = None
        try:
            conn, _ = listener.accept()
            header = _recv_exact(conn, REQ_HDR_SIZE)
            _stx, _api, body_len, request_id, command = struct.unpack(
                REQ_HDR_FMT, header
            )
            _recv_exact(conn, body_len)
            assert command == CMD_DISPLAY_GET
            declared_length = 100
            response = struct.pack(
                RESP_HDR_FMT,
                STX,
                API_VERSION,
                declared_length,
                RESP_DISPLAY_GET,
                0,
                request_id,
            )
            conn.sendall(response + b"\x01")
            assert caller_timed_out.wait(1)
            conn.settimeout(1)
            while conn.recv(1):
                pass
        except (OSError, AssertionError):
            pass
        finally:
            if conn is not None:
                conn.close()
            listener.close()
            server_done.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client = ViceBmpClient("127.0.0.1", port)
    client.connect(discover_registers=False)
    client._vice_info = ViceInfo((3, 11, 0, 0), None)
    try:
        with pytest.raises(ViceTimeoutError):
            client.display_get(timeout_ms=20)
        caller_timed_out.set()
        client.join(1)
        assert not client.connected
        assert client.terminal_error is not None
        assert "body stalled" in str(client.terminal_error)
    finally:
        client.disconnect()
        server_done.wait(1)


def test_slow_complete_body_after_request_timeout_keeps_connection(
    monkeypatch,
):
    monkeypatch.setattr(
        protocol, "RESPONSE_BODY_IDLE_TIMEOUT_SECONDS", 1.0
    )
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    server_done = threading.Event()
    release_body = threading.Event()
    body_sent = threading.Event()

    def request(conn):
        header = _recv_exact(conn, REQ_HDR_SIZE)
        _stx, _api, body_len, request_id, command = struct.unpack(
            REQ_HDR_FMT, header
        )
        _recv_exact(conn, body_len)
        return request_id, command

    def serve():
        conn = None
        try:
            conn, _ = listener.accept()
            request_id, command = request(conn)
            assert command == CMD_DISPLAY_GET
            header = struct.pack(
                RESP_HDR_FMT,
                STX,
                API_VERSION,
                1,
                RESP_DISPLAY_GET,
                0,
                request_id,
            )
            conn.sendall(header)
            assert release_body.wait(1)
            conn.sendall(b"\x00")
            body_sent.set()
            request_id, command = request(conn)
            assert command == protocol.CMD_PING
            conn.sendall(struct.pack(
                RESP_HDR_FMT,
                STX,
                API_VERSION,
                0,
                protocol.RESP_PING,
                0,
                request_id,
            ))
        except (OSError, AssertionError):
            pass
        finally:
            if conn is not None:
                conn.close()
            listener.close()
            server_done.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client = ViceBmpClient("127.0.0.1", port)
    client.connect(discover_registers=False)
    client._vice_info = ViceInfo((3, 11, 0, 0), None)
    try:
        with pytest.raises(ViceTimeoutError):
            client.display_get(timeout_ms=20)
        release_body.set()
        assert body_sent.wait(1)
        assert client.connected
        assert client.ping(timeout_ms=200)
    finally:
        client.disconnect()
        server_done.wait(1)


def _recv_exact(sock, count):
    result = bytearray()
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise OSError("disconnected")
        result.extend(chunk)
    return bytes(result)
