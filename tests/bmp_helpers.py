"""
Shared test helpers for BMP protocol tests.
Imported by conftest.py and test modules directly.
"""

import socket
import struct
import threading
import time
from typing import Callable, Dict, Optional

from vice.util import (
    STX, API_VERSION,
    REQ_HDR_FMT, REQ_HDR_SIZE,
    RESP_HDR_FMT,
    EVENT_REQUEST_ID,
    CMD_REGISTERS_AVAILABLE, CMD_PING,
    RESP_REGISTERS_AVAILABLE, RESP_PING,
)

DEFAULT_REGISTERS = [
    # (reg_id, name, bit_size)
    (0, 'PC', 16),
    (1, 'A', 8),
    (2, 'X', 8),
    (3, 'Y', 8),
    (4, 'SP', 8),
    (5, 'FLAGS', 8),
]


def build_registers_available_body(registers=None) -> bytes:
    """Build a REGISTERS_AVAILABLE response body from [(id, name, bit_size), ...] list.

    Wire format per item:
      item_size(1) reg_id(1) bit_size(1) name_len(1) name(N)
    where item_size = 3 + len(name)  (everything after the item_size byte).
    """
    regs = registers or DEFAULT_REGISTERS
    body = struct.pack('<H', len(regs))
    for rid, name, bit_size in regs:
        nb = name.encode('ascii')
        item_size = 3 + len(nb)   # reg_id(1) + bit_size(1) + name_len(1) + name
        body += struct.pack('<BBBB', item_size, rid, bit_size, len(nb)) + nb
    return body


def build_registers_get_body(reg_values: Dict[str, int],
                              registers=None) -> bytes:
    """Build a REGISTERS_GET response body. reg_values: {name: value}"""
    regs = {name: rid for rid, name, *_ in (registers or DEFAULT_REGISTERS)}
    items = []
    for name, val in reg_values.items():
        rid = regs[name]
        items.append(struct.pack('<BBH', 3, rid, val & 0xFFFF))
    body = struct.pack('<H', len(items))
    for item in items:
        body += item
    return body


class MockViceServer:
    """
    Minimal TCP server that speaks VICE Binary Monitor Protocol v2.

    Handler signature:
        handler(payload: bytes) -> (resp_type: int, resp_body: bytes)

    If no handler is registered for a command, the server responds with
    error code 0x8F (general failure).
    """

    def __init__(self, registers=None):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(('127.0.0.1', 0))
        self.port: int = self._sock.getsockname()[1]
        self._handlers: Dict[int, Callable] = {}
        self._conn: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._registers = registers or DEFAULT_REGISTERS
        self._install_defaults()

    def _install_defaults(self):
        reg_body = build_registers_available_body(self._registers)
        self.handle(CMD_REGISTERS_AVAILABLE,
                    lambda _: (RESP_REGISTERS_AVAILABLE, reg_body))
        self.handle(CMD_PING, lambda _: (RESP_PING, b''))

    def handle(self, cmd: int, handler: Callable):
        self._handlers[cmd] = handler

    def start(self):
        self._running = True
        self._sock.listen(1)
        self._thread = threading.Thread(
            target=self._serve, name='mock-vice', daemon=True
        )
        self._thread.start()
        time.sleep(0.01)

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass
        if self._conn:
            try:
                self._conn.close()
            except OSError:
                pass

    def send_event(self, resp_type: int, body: bytes = b''):
        """Inject an unsolicited event into the connected client."""
        if self._conn:
            hdr = struct.pack(
                RESP_HDR_FMT, STX, API_VERSION, len(body),
                resp_type, 0x00, EVENT_REQUEST_ID,
            )
            self._conn.sendall(hdr + body)

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("client disconnected")
            buf.extend(chunk)
        return bytes(buf)

    def _serve(self):
        try:
            self._conn, _ = self._sock.accept()
        except OSError:
            return
        while self._running:
            try:
                raw = self._recv_exact(self._conn, REQ_HDR_SIZE)
            except (OSError, ConnectionError):
                break
            try:
                stx, api_ver, body_len, req_id, cmd = struct.unpack(REQ_HDR_FMT, raw)
                body = self._recv_exact(self._conn, body_len) if body_len else b''

                handler = self._handlers.get(cmd)
                if handler:
                    result = handler(body)
                    # Handler may return:
                    #   (resp_type, body)          — single frame
                    #   [(resp_type, body), ...]   — multiple frames
                    if isinstance(result, list):
                        frames = result
                    else:
                        frames = [result]
                    error = 0x00
                else:
                    frames = [(cmd, b'')]
                    error = 0x8F

                for resp_type, resp_body in frames:
                    resp_hdr = struct.pack(
                        RESP_HDR_FMT, STX, API_VERSION, len(resp_body),
                        resp_type, error, req_id,
                    )
                    self._conn.sendall(resp_hdr + resp_body)
            except (OSError, ConnectionError):
                break
