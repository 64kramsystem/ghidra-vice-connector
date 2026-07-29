"""Strict VICE Binary Monitor Protocol v2 client.

The client owns exactly one socket reader. Direct responses are correlated by
request ID; unsolicited frames are converted to immutable raw events and
handed to a non-blocking callback. Protocol corruption is terminal because a
byte stream cannot be safely re-synchronized.
"""

from __future__ import annotations

import logging
import math
import queue
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

log = logging.getLogger("vice-agent")

STX = 0x02
API_VERSION = 0x02
REQ_HDR_FMT = "<BBIIB"
REQ_HDR_SIZE = struct.calcsize(REQ_HDR_FMT)
RESP_HDR_FMT = "<BBIBBI"
RESP_HDR_SIZE = struct.calcsize(RESP_HDR_FMT)
EVENT_REQUEST_ID = 0xFFFFFFFF
MAX_RESPONSE_BODY = 16 * 1024 * 1024
MAX_LIST_ITEMS = 4096
MAX_MEMORY_FRAME = 0xFFFF
MAX_ABANDONED_REQUESTS = 4096
# Once a response header declares a body, the reader must receive every byte
# before it can recover framing.
RESPONSE_BODY_IDLE_TIMEOUT_SECONDS = 5.0

CMD_MEMORY_GET = 0x01
CMD_MEMORY_SET = 0x02
CMD_CHECKPOINT_GET = 0x11
CMD_CHECKPOINT_SET = 0x12
CMD_CHECKPOINT_DELETE = 0x13
CMD_CHECKPOINT_LIST = 0x14
CMD_CHECKPOINT_TOGGLE = 0x15
CMD_REGISTERS_GET = 0x31
CMD_REGISTERS_SET = 0x32
CMD_SNAPSHOT_DUMP = 0x41
CMD_SNAPSHOT_UNDUMP = 0x42
CMD_RESOURCE_SET = 0x52
CMD_ADVANCE_INSTRUCTIONS = 0x71
CMD_KEYBOARD_FEED = 0x72
CMD_EXECUTE_UNTIL_RETURN = 0x73
CMD_PING = 0x81
CMD_BANKS_AVAILABLE = 0x82
CMD_REGISTERS_AVAILABLE = 0x83
CMD_DISPLAY_GET = 0x84
CMD_VICE_INFO = 0x85
CMD_PALETTE_GET = 0x91
CMD_JOYPORT_SET = 0xA2
CMD_EXIT = 0xAA
CMD_QUIT = 0xBB
CMD_RESET = 0xCC

RESP_MEMORY_GET = 0x01
RESP_MEMORY_SET = 0x02
RESP_CHECKPOINT_INFO = 0x11
RESP_CHECKPOINT_DELETE = 0x13
RESP_CHECKPOINT_LIST = 0x14
RESP_CHECKPOINT_TOGGLE = 0x15
RESP_REGISTERS_GET = 0x31
RESP_SNAPSHOT_DUMP = 0x41
RESP_SNAPSHOT_UNDUMP = 0x42
RESP_RESOURCE_SET = 0x52
RESP_STOPPED = 0x62
RESP_RESUMED = 0x63
RESP_ADVANCE_INSTRUCTIONS = 0x71
RESP_KEYBOARD_FEED = 0x72
RESP_EXECUTE_UNTIL_RETURN = 0x73
RESP_PING = 0x81
RESP_BANKS_AVAILABLE = 0x82
RESP_REGISTERS_AVAILABLE = 0x83
RESP_DISPLAY_GET = 0x84
RESP_VICE_INFO = 0x85
RESP_PALETTE_GET = 0x91
RESP_JOYPORT_SET = 0xA2
RESP_EXIT = 0xAA
RESP_RESET = 0xCC

# `display get` format selector: 0x00 is the only one VICE implements, one
# palette index per byte.
DISPLAY_FORMAT_INDEXED8 = 0x00
# DW(2) DH(2) XO(2) YO(2) IW(2) IH(2) BP(1). Anything past this inside the
# declared metadata length is a later addition and is skipped.
DISPLAY_METADATA_SIZE = 13
DISPLAY_BITS_PER_PIXEL = 8
MAX_PALETTE_ITEMS = 256
PALETTE_ITEM_SIZE = 3

# VICE computed the 0x84 response length as `4 + info + buffer` while writing
# `FL + info + BL + buffer`, four bytes more, so it wrote past its own
# allocation *before* replying. Upstream fixed that in r46020; the fix postdates
# the 3.10 release, so 3.11 is the first release family carrying it. A client
# cannot make an affected build safe after the fact -- the overrun has already
# happened -- so the command must never be sent to one.
DISPLAY_GET_MIN_REVISION = 46020
DISPLAY_GET_MIN_RELEASE = (3, 11)

MEMSPACE_MAIN = 0
MEMSPACE_DRIVE8 = 1
MEMSPACE_DRIVE9 = 2
MEMSPACE_DRIVE10 = 3
MEMSPACE_DRIVE11 = 4

CPU_OP_LOAD = 0x01
CPU_OP_STORE = 0x02
CPU_OP_EXEC = 0x04


class ViceFailure(Exception):
    """Base class for failures that automation can translate predictably."""

    code = "vice_error"

    def __init__(
        self,
        message: str,
        *,
        command: Optional[int] = None,
        request_id: Optional[int] = None,
        outcome_unknown: bool = False,
    ):
        super().__init__(message)
        self.command = command
        self.request_id = request_id
        self.outcome_unknown = outcome_unknown


class ViceConnectionError(ViceFailure):
    code = "vice_connection_lost"


class ViceProtocolError(ViceFailure):
    code = "vice_protocol_error"


class ViceCommandError(ViceFailure):
    code = "vice_command_failed"

    def __init__(self, error: int, *, command: int, request_id: int):
        self.error = error
        super().__init__(
            f"VICE returned error 0x{error:02x} for command "
            f"0x{command:02x} (request {request_id})",
            command=command,
            request_id=request_id,
        )


class ViceTimeoutError(ViceFailure):
    code = "vice_timeout"

    def __init__(self, message: str, *, state_may_have_changed: bool = False, **kwargs):
        super().__init__(message, outcome_unknown=True, **kwargs)
        self.state_may_have_changed = state_may_have_changed


class ViceValidationError(ViceFailure):
    code = "vice_invalid_argument"


class ViceUnsupportedBuildError(ViceFailure):
    """The connected VICE build cannot be asked for this command.

    Distinct from :class:`ViceValidationError`, which would read as a caller
    mistake, and from :class:`ViceProtocolError`, which means VICE answered
    something malformed. Here VICE answered perfectly well; the build it
    described is one we refuse to send the command to.
    """

    code = "vice_unsupported_build"


class VicePartialWriteError(ViceFailure):
    code = "vice_partial_write"

    def __init__(
        self,
        message: str,
        *,
        completed_ranges: Sequence[Tuple[int, int]],
        failed_range: Tuple[int, int],
        cause: BaseException,
    ):
        self.completed_ranges = tuple(completed_ranges)
        self.completed_bytes = sum(end - start + 1 for start, end in completed_ranges)
        self.failed_range = failed_range
        self.partial = bool(completed_ranges)
        self.memory_may_be_modified = bool(completed_ranges)
        super().__init__(
            message,
            command=getattr(cause, "command", None),
            request_id=getattr(cause, "request_id", None),
            outcome_unknown=getattr(cause, "outcome_unknown", True),
        )
        self.__cause__ = cause


# Old public name retained because it describes a protocol command error well.
ViceError = ViceCommandError


@dataclass(frozen=True)
class Frame:
    response_type: int
    error: int
    request_id: int
    body: bytes


@dataclass(frozen=True)
class Checkpoint:
    number: int
    start: int
    end: int
    enabled: bool = True
    cpu_op: int = CPU_OP_EXEC
    stop_on_hit: bool = True
    currently_hit: bool = False
    temporary: bool = False
    hit_count: int = 0
    ignore_count: int = 0
    has_condition: bool = False
    memspace: int = MEMSPACE_MAIN


@dataclass(frozen=True)
class Bank:
    id: int
    name: str


@dataclass(frozen=True)
class Register:
    id: int
    name: str
    bits: int
    value: Optional[int] = None


@dataclass(frozen=True)
class ViceInfo:
    """What VICE reports about itself.

    `version` is every component VICE sent, not a truncated three-part string:
    the build guard needs the release family, and the result surface publishes
    the whole dotted version. `revision` is the Subversion revision, or `None`
    for a release build -- which reports no revision at all, sending `SV` as
    zero. `None` and `0` therefore mean the same thing on the wire and must not
    be conflated with "revision 0".
    """

    version: Tuple[int, ...]
    revision: Optional[int] = None

    @property
    def version_string(self) -> str:
        return ".".join(str(component) for component in self.version)


@dataclass(frozen=True)
class DisplayFrame:
    """One captured frame: an indexed buffer plus the geometry describing it.

    `buffer` is row-major, one byte per pixel, each byte an index into the
    palette returned by `palette get`. `width`/`height` describe the whole debug
    buffer; the inner rectangle is the visible screen inside it.
    """

    width: int
    height: int
    x_offset: int
    y_offset: int
    inner_width: int
    inner_height: int
    bits_per_pixel: int
    buffer: bytes


@dataclass(frozen=True)
class PaletteEntry:
    r: int
    g: int
    b: int


@dataclass(frozen=True)
class RawEvent:
    raw_sequence: int
    kind: str
    response_type: int
    pc: Optional[int]
    body: bytes
    received_at: float
    checkpoints: Tuple[Checkpoint, ...] = ()


@dataclass(frozen=True)
class _Terminal:
    error: ViceConnectionError


@dataclass
class _AbandonedRequest:
    command: int
    expected: frozenset[int]
    terminal_response: int
    max_frames: int
    frames_seen: int = 0


@dataclass
class _PendingRequest:
    command: int
    expected: frozenset[int]
    terminal_response: int
    max_frames: int
    response_queue: queue.Queue = field(init=False)
    frames_seen: int = 0
    terminal_seen: bool = False

    def __post_init__(self) -> None:
        # Reserve one slot for a terminal connection error even when every
        # permitted response frame is already buffered.
        self.response_queue = queue.Queue(maxsize=self.max_frames + 1)


class Cursor:
    """Bounds-checked little-endian body parser."""

    def __init__(self, body: bytes, context: str):
        self.body = body
        self.offset = 0
        self.context = context

    @property
    def remaining(self) -> int:
        return len(self.body) - self.offset

    def take(self, size: int) -> bytes:
        if size < 0 or self.remaining < size:
            raise ViceProtocolError(
                f"{self.context}: need {size} bytes at offset {self.offset}, "
                f"only {self.remaining} remain"
            )
        start = self.offset
        self.offset += size
        return self.body[start:self.offset]

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def finish(self) -> None:
        if self.remaining:
            raise ViceProtocolError(
                f"{self.context}: {self.remaining} unexpected trailing bytes"
            )


def _require_bool_byte(value: int, field: str) -> bool:
    if value not in (0, 1):
        raise ViceProtocolError(f"{field}: expected 0 or 1, got {value}")
    return bool(value)


def parse_checkpoint_info(body: bytes) -> Checkpoint:
    cur = Cursor(body, "checkpoint info")
    result = Checkpoint(
        number=cur.u32(),
        currently_hit=_require_bool_byte(cur.u8(), "checkpoint currently_hit"),
        start=cur.u16(),
        end=cur.u16(),
        stop_on_hit=_require_bool_byte(cur.u8(), "checkpoint stop_on_hit"),
        enabled=_require_bool_byte(cur.u8(), "checkpoint enabled"),
        cpu_op=cur.u8(),
        temporary=_require_bool_byte(cur.u8(), "checkpoint temporary"),
        hit_count=cur.u32(),
        ignore_count=cur.u32(),
        has_condition=_require_bool_byte(cur.u8(), "checkpoint has_condition"),
        memspace=cur.u8() if cur.remaining else MEMSPACE_MAIN,
    )
    cur.finish()
    if result.start > result.end:
        raise ViceProtocolError(
            f"checkpoint {result.number}: reversed range "
            f"0x{result.start:04x}-0x{result.end:04x}"
        )
    if result.cpu_op & ~(CPU_OP_LOAD | CPU_OP_STORE | CPU_OP_EXEC):
        raise ViceProtocolError(
            f"checkpoint {result.number}: invalid operation mask "
            f"0x{result.cpu_op:02x}"
        )
    return result


# Existing tests and callers used this private spelling.
_parse_checkpoint_info = parse_checkpoint_info


def parse_vice_info(body: bytes) -> ViceInfo:
    """Parse a VICE_INFO body: VL, version bytes, SL, revision bytes.

    Both fields are length-prefixed and variable width. The revision is little
    endian, and zero means "this build has no revision", which every release
    build reports.
    """
    cur = Cursor(body, "VICE info")
    version = tuple(cur.take(cur.u8()))
    revision_bytes = cur.take(cur.u8())
    cur.finish()
    if len(version) < 3:
        raise ViceProtocolError("VICE version contains fewer than 3 components")
    revision = int.from_bytes(revision_bytes, "little") if revision_bytes else 0
    return ViceInfo(version, revision or None)


def build_display_get_body(use_vic: bool = True) -> bytes:
    """VC (use VIC-II; 0 selects the VDC, ignored except on a C128) then FM."""
    return struct.pack("<BB", int(bool(use_vic)), DISPLAY_FORMAT_INDEXED8)


def build_palette_get_body(use_vic: bool = True) -> bytes:
    """VC alone; `palette get` takes no format selector."""
    return struct.pack("<B", int(bool(use_vic)))


def parse_display_get(body: bytes) -> DisplayFrame:
    """Parse a DISPLAY_GET body into a validated frame.

    Wire order is `FL`, `FL` bytes of `DW`..`BP` metadata, `BL`, then `BL`
    buffer bytes. `FL` counts the metadata only -- it excludes both itself and
    `BL` -- so it locates `BL`, not `BD`. Requiring `FL == 13` would throw away
    the forward compatibility that reading `FL` buys, so a longer metadata block
    is accepted and its unknown tail skipped.
    """
    cur = Cursor(body, "display get")
    info_length = cur.u32()
    if info_length < DISPLAY_METADATA_SIZE:
        raise ViceProtocolError(
            f"display get: metadata length {info_length} is shorter than the "
            f"{DISPLAY_METADATA_SIZE}-byte DW..BP prefix"
        )
    info = Cursor(cur.take(info_length), "display get metadata")
    width = info.u16()
    height = info.u16()
    x_offset = info.u16()
    y_offset = info.u16()
    inner_width = info.u16()
    inner_height = info.u16()
    bits_per_pixel = info.u8()
    # Any remaining declared metadata is a later addition: skipped, not read.

    if bits_per_pixel != DISPLAY_BITS_PER_PIXEL:
        raise ViceProtocolError(
            f"display get: bits per pixel {bits_per_pixel} is unsupported; "
            f"the indexed format is {DISPLAY_BITS_PER_PIXEL} and the pixel "
            f"arithmetic assumes one byte per pixel"
        )
    for name, value in (
        ("debug width", width),
        ("debug height", height),
        ("inner width", inner_width),
        ("inner height", inner_height),
    ):
        if value <= 0:
            raise ViceProtocolError(
                f"display get: {name} {value} must be positive"
            )
    if x_offset + inner_width > width:
        raise ViceProtocolError(
            f"display get: inner screen x offset {x_offset} plus inner width "
            f"{inner_width} exceeds debug width {width}"
        )
    if y_offset + inner_height > height:
        raise ViceProtocolError(
            f"display get: inner screen y offset {y_offset} plus inner height "
            f"{inner_height} exceeds debug height {height}"
        )

    buffer_length = cur.u32()
    expected = width * height
    if buffer_length != expected:
        raise ViceProtocolError(
            f"display get: buffer length {buffer_length} does not equal "
            f"{width} x {height} = {expected} bytes at "
            f"{DISPLAY_BITS_PER_PIXEL} bits per pixel"
        )
    if cur.remaining < buffer_length:
        raise ViceProtocolError(
            f"display get: declared buffer length {buffer_length} but only "
            f"{cur.remaining} bytes were delivered"
        )
    buffer = cur.take(buffer_length)
    cur.finish()
    return DisplayFrame(
        width,
        height,
        x_offset,
        y_offset,
        inner_width,
        inner_height,
        bits_per_pixel,
        buffer,
    )


def parse_palette_get(body: bytes) -> List[PaletteEntry]:
    """Parse a PALETTE_GET body: PC, then PC items of IS, RR, GG, BB.

    `IS` excludes itself. Items longer than three bytes are accepted and their
    declared remainder skipped, the same forward-compatible policy `FL` gets.
    """
    cur = Cursor(body, "palette get")
    count = cur.u16()
    if not 1 <= count <= MAX_PALETTE_ITEMS:
        raise ViceProtocolError(
            f"palette get: item count {count} is outside 1..{MAX_PALETTE_ITEMS}"
        )
    entries: List[PaletteEntry] = []
    for index in range(count):
        item_size = cur.u8()
        if item_size < PALETTE_ITEM_SIZE:
            raise ViceProtocolError(
                f"palette get: item {index} declares size {item_size}, "
                f"smaller than the {PALETTE_ITEM_SIZE}-byte RGB record"
            )
        item = Cursor(cur.take(item_size), f"palette get item {index}")
        entries.append(PaletteEntry(item.u8(), item.u8(), item.u8()))
        # The declared remainder is a later addition: skipped, not read.
    cur.finish()
    return entries


def _validate_u16(value: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF:
        raise ViceValidationError(f"{field} must be an integer in 0..65535")
    return value


def _validate_id(value: int, field: str, maximum: int = 0xFFFF) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ViceValidationError(f"{field} must be an integer in 0..{maximum}")
    return value


def _validate_bool(value: bool, field: str) -> bool:
    if not isinstance(value, bool):
        raise ViceValidationError(f"{field} must be a boolean")
    return value


def _operation_deadline(timeout_ms: int) -> float:
    if (
        isinstance(timeout_ms, bool)
        or not isinstance(timeout_ms, int)
        or not 1 <= timeout_ms <= 55_000
    ):
        raise ViceValidationError("timeout_ms must be in 1..55000")
    return time.monotonic() + timeout_ms / 1000.0


def _remaining_timeout_ms(
    deadline: float, *, state_may_have_changed: bool = False
) -> int:
    remaining = math.ceil((deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        raise ViceTimeoutError(
            "VICE memory operation exhausted its timeout",
            state_may_have_changed=state_may_have_changed,
        )
    return remaining


def _length_prefixed_text(value: str, field: str) -> bytes:
    if not isinstance(value, str):
        raise ViceValidationError(f"{field} must be a string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ViceValidationError(f"{field} is not valid UTF-8") from exc
    if not 1 <= len(encoded) <= 0xFF:
        raise ViceValidationError(
            f"{field} must encode to between 1 and 255 bytes"
        )
    if b"\x00" in encoded:
        raise ViceValidationError(f"{field} must not contain NUL")
    return bytes((len(encoded),)) + encoded


class ViceBmpClient:
    """One-connection, one-reader, request-correlating BMP client."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6502,
        *,
        max_response_body: int = MAX_RESPONSE_BODY,
        max_abandoned_requests: int = MAX_ABANDONED_REQUESTS,
    ):
        if max_response_body < 0:
            raise ValueError("max_response_body must be non-negative")
        if max_abandoned_requests < 1:
            raise ValueError("max_abandoned_requests must be positive")
        self.host = host
        self.port = port
        self.max_response_body = max_response_body
        self.max_abandoned_requests = max_abandoned_requests
        self._sock: Optional[socket.socket] = None
        self._send_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._pending: Dict[int, _PendingRequest] = {}
        self._abandoned: Dict[int, _AbandonedRequest] = {}
        self._next_id = 1
        self._running = False
        self._terminal_error: Optional[ViceConnectionError] = None
        self._recv_thread: Optional[threading.Thread] = None
        self._event_callback: Optional[Callable[[RawEvent], None]] = None
        self._terminal_callback: Optional[Callable[[ViceConnectionError], None]] = None
        self._raw_sequence = 0
        self._pending_checkpoints: List[Checkpoint] = []
        # Build information for the 0x84 guard. Absent until VICE_INFO has been
        # read on *this* connection, and absent means refuse.
        self._vice_info: Optional[ViceInfo] = None
        self.reg_name_to_id: Dict[str, int] = {}
        self.reg_id_to_name: Dict[int, str] = {}
        self.reg_name_to_bits: Dict[str, int] = {}

    @property
    def connected(self) -> bool:
        with self._state_lock:
            return self._running and self._terminal_error is None

    @property
    def terminal_error(self) -> Optional[ViceConnectionError]:
        with self._state_lock:
            return self._terminal_error

    @property
    def vice_build_info(self) -> Optional[ViceInfo]:
        """The build record for this connection, or `None` if none was read."""
        with self._state_lock:
            return self._vice_info

    def set_event_callback(self, callback: Callable[[RawEvent], None]) -> None:
        with self._state_lock:
            self._event_callback = callback

    def set_terminal_callback(
        self, callback: Callable[[ViceConnectionError], None]
    ) -> None:
        with self._state_lock:
            self._terminal_callback = callback

    def connect(self, *, discover_registers: bool = True) -> None:
        try:
            with self._state_lock:
                if self._running:
                    raise ViceValidationError("VICE client is already connected")
                self._terminal_error = None
                self._pending_checkpoints = []
                # A record from an earlier session says nothing about the
                # emulator we are about to talk to.
                self._vice_info = None
                self._sock = socket.create_connection(
                    (self.host, self.port), timeout=10
                )
                self._sock.settimeout(None)
                self._running = True
                self._recv_thread = threading.Thread(
                    target=self._recv_loop, name="vice-bmp-recv", daemon=True
                )
                self._recv_thread.start()
        except ViceFailure:
            raise
        except OSError as exc:
            error = ViceConnectionError(
                f"could not connect to VICE at {self.host}:{self.port}: {exc}"
            )
            self._terminate(error)
            raise error from exc
        if discover_registers:
            try:
                self._discover_registers()
            except BaseException:
                self.disconnect()
                raise

    def disconnect(self) -> None:
        self._terminate(ViceConnectionError("VICE monitor connection closed"))

    def abort(self, error: ViceConnectionError) -> None:
        """Fail the connection because a controller/client invariant was broken."""
        self._terminate(error)

    def join(self, timeout: Optional[float] = None) -> None:
        thread = self._recv_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)

    def _terminate(self, error: ViceConnectionError) -> None:
        callback = None
        sock = None
        pending: List[_PendingRequest] = []
        with self._state_lock:
            if self._terminal_error is not None:
                return
            self._terminal_error = error
            self._running = False
            self._vice_info = None
            sock, self._sock = self._sock, None
            pending = list(self._pending.values())
            self._pending.clear()
            self._abandoned.clear()
            callback = self._terminal_callback
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        terminal = _Terminal(error)
        for request in pending:
            request.response_queue.put_nowait(terminal)
        if callback is not None:
            try:
                callback(error)
            except BaseException:
                log.exception("VICE terminal callback failed")

    def _alloc_pending(
        self,
        command: int,
        expected: Sequence[int],
        terminal_response: int,
        max_frames: int,
    ) -> Tuple[int, _PendingRequest]:
        if max_frames < 1:
            raise ValueError("max_frames must be positive")
        with self._state_lock:
            if not self._running or self._sock is None:
                raise self._terminal_error or ViceConnectionError(
                    "VICE monitor is not connected"
                )
            if len(self._abandoned) >= self.max_abandoned_requests:
                error = ViceConnectionError(
                    f"VICE has {len(self._abandoned)} timed-out requests "
                    "without terminal responses; closing to preserve correlation"
                )
                self._terminate(error)
                raise error
            for _ in range(EVENT_REQUEST_ID - 1):
                request_id = self._next_id
                self._next_id += 1
                if self._next_id >= EVENT_REQUEST_ID:
                    self._next_id = 1
                if (
                    request_id not in self._pending
                    and request_id not in self._abandoned
                ):
                    request = _PendingRequest(
                        command,
                        frozenset(expected),
                        terminal_response,
                        max_frames,
                    )
                    self._pending[request_id] = request
                    return request_id, request
        raise ViceProtocolError("all VICE request IDs are in use")

    def _send_raw(self, command: int, payload: bytes, request_id: int) -> None:
        header = struct.pack(
            REQ_HDR_FMT, STX, API_VERSION, len(payload), request_id, command
        )
        with self._send_lock:
            with self._state_lock:
                sock = self._sock
                error = self._terminal_error
            if sock is None:
                raise error or ViceConnectionError("VICE monitor is not connected")
            try:
                sock.sendall(header + payload)
            except OSError as exc:
                terminal = ViceConnectionError(
                    f"VICE send failed: {exc}",
                    command=command,
                    request_id=request_id,
                    outcome_unknown=True,
                )
                self._terminate(terminal)
                raise terminal from exc

    def _recv_exact(
        self, size: int, *, body_idle_timeout: Optional[float] = None
    ) -> bytes:
        data = bytearray()
        while len(data) < size:
            with self._state_lock:
                sock = self._sock
            if sock is None:
                raise ViceConnectionError("VICE monitor connection closed")
            if body_idle_timeout is not None:
                readable, _, _ = select.select(
                    [sock], [], [], body_idle_timeout
                )
                if not readable:
                    raise ViceConnectionError(
                        "VICE response body stalled after its header"
                    )
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise ViceConnectionError("VICE monitor disconnected")
            data.extend(chunk)
        return bytes(data)

    def _recv_loop(self) -> None:
        try:
            while True:
                header = self._recv_exact(RESP_HDR_SIZE)
                marker, api, body_length, response_type, error, request_id = (
                    struct.unpack(RESP_HDR_FMT, header)
                )
                if marker != STX:
                    raise ViceProtocolError(
                        f"invalid VICE response marker 0x{marker:02x}"
                    )
                if api != API_VERSION:
                    raise ViceProtocolError(
                        f"unsupported VICE response API 0x{api:02x}"
                    )
                if body_length > self.max_response_body:
                    raise ViceProtocolError(
                        f"VICE response body {body_length} exceeds "
                        f"{self.max_response_body}"
                    )
                body = (
                    self._recv_exact(
                        body_length,
                        body_idle_timeout=RESPONSE_BODY_IDLE_TIMEOUT_SECONDS,
                    )
                    if body_length
                    else b""
                )
                frame = Frame(response_type, error, request_id, body)
                if request_id == EVENT_REQUEST_ID:
                    self._receive_event(frame)
                else:
                    self._receive_response(frame)
        except BaseException as exc:
            if isinstance(exc, ViceConnectionError):
                terminal = exc
            else:
                terminal = ViceConnectionError(
                    f"VICE protocol connection failed: {exc}"
                )
                terminal.__cause__ = exc
            self._terminate(terminal)

    def _receive_response(self, frame: Frame) -> None:
        with self._state_lock:
            request = self._pending.get(frame.request_id)
            abandoned = self._abandoned.get(frame.request_id)
            if abandoned is not None:
                self._discard_abandoned_frame_locked(frame, abandoned)
                return
            if request is not None:
                if request.terminal_seen:
                    raise ViceProtocolError(
                        f"response for completed VICE request ID "
                        f"{frame.request_id}"
                    )
                # VICE emits response type 0x00 for some command failures.
                # The matching request ID still correlates that frame; only
                # successful responses must have the declared response type.
                if not frame.error and frame.response_type not in request.expected:
                    raise ViceProtocolError(
                        f"response for command 0x{request.command:02x} "
                        f"request {frame.request_id} has unexpected type "
                        f"0x{frame.response_type:02x}"
                    )
                request.frames_seen += 1
                if request.frames_seen > request.max_frames:
                    raise ViceProtocolError(
                        f"response for request {frame.request_id} exceeded "
                        f"{request.max_frames} frames"
                    )
                request.terminal_seen = bool(
                    frame.error
                    or frame.response_type == request.terminal_response
                )
                request.response_queue.put_nowait(frame)
                return
            raise ViceProtocolError(
                f"response for unknown VICE request ID {frame.request_id}"
            )

    def _discard_abandoned_frame_locked(
        self, frame: Frame, abandoned: _AbandonedRequest
    ) -> None:
        if not frame.error and frame.response_type not in abandoned.expected:
            raise ViceProtocolError(
                f"late response for command 0x{abandoned.command:02x} "
                f"request {frame.request_id} has unexpected type "
                f"0x{frame.response_type:02x}"
            )
        abandoned.frames_seen += 1
        if abandoned.frames_seen > abandoned.max_frames:
            raise ViceProtocolError(
                f"late response for request {frame.request_id} exceeded "
                f"{abandoned.max_frames} frames"
            )
        if frame.error or frame.response_type == abandoned.terminal_response:
            self._abandoned.pop(frame.request_id, None)

    def _receive_event(self, frame: Frame) -> None:
        if frame.error:
            raise ViceProtocolError(
                f"unsolicited VICE event 0x{frame.response_type:02x} "
                f"has error 0x{frame.error:02x}"
            )
        if frame.response_type == RESP_CHECKPOINT_INFO:
            checkpoint = parse_checkpoint_info(frame.body)
            # VICE emits one checkpoint-info event per matching enabled
            # checkpoint before it consults cp->stop (mon_breakpoint.c), so a
            # single stop can carry several. A non-stopping checkpoint gets no
            # following stop at all, so it is published immediately instead.
            if checkpoint.stop_on_hit:
                self._pending_checkpoints.append(checkpoint)
            else:
                self._emit_event(
                    "checkpoint_hit",
                    frame.response_type,
                    None,
                    (checkpoint,),
                    frame.body,
                )
            return
        if frame.response_type not in (RESP_STOPPED, RESP_RESUMED):
            log.debug(
                "ignoring unsolicited VICE response 0x%02x (%d bytes)",
                frame.response_type,
                len(frame.body),
            )
            return
        if len(frame.body) not in (0, 2):
            raise ViceProtocolError(
                f"execution event 0x{frame.response_type:02x} has "
                f"invalid {len(frame.body)}-byte body"
            )
        pc = struct.unpack("<H", frame.body)[0] if frame.body else None
        checkpoints: Tuple[Checkpoint, ...] = ()
        if frame.response_type == RESP_STOPPED:
            checkpoints = tuple(self._pending_checkpoints)
            self._pending_checkpoints = []
        elif self._pending_checkpoints:
            raise ViceProtocolError(
                "checkpoint-info event was not followed by a stopped event"
            )
        self._emit_event(
            "stopped" if frame.response_type == RESP_STOPPED else "resumed",
            frame.response_type,
            pc,
            checkpoints,
            frame.body,
        )

    def _emit_event(
        self,
        kind: str,
        response_type: int,
        pc: Optional[int],
        checkpoints: Tuple[Checkpoint, ...],
        body: bytes,
    ) -> None:
        with self._state_lock:
            self._raw_sequence += 1
            event = RawEvent(
                self._raw_sequence,
                kind,
                response_type,
                pc,
                body,
                time.monotonic(),
                checkpoints,
            )
            callback = self._event_callback
        if callback is not None:
            callback(event)

    def _command_frames(
        self,
        command: int,
        payload: bytes = b"",
        *,
        expected: Sequence[int],
        terminal_response: int,
        timeout_ms: int = 10_000,
        max_frames: int = MAX_LIST_ITEMS + 1,
        mutating: bool = False,
    ) -> Tuple[int, List[Frame]]:
        if not 1 <= timeout_ms <= 55_000:
            raise ViceValidationError("timeout_ms must be in 1..55000")
        request_id, request = self._alloc_pending(
            command, expected, terminal_response, max_frames
        )
        response_queue = request.response_queue
        timed_out = False
        try:
            self._send_raw(command, payload, request_id)
            deadline = time.monotonic() + timeout_ms / 1000.0
            frames: List[Frame] = []
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise queue.Empty
                item = response_queue.get(timeout=remaining)
                if isinstance(item, _Terminal):
                    raise item.error
                frame: Frame = item
                if frame.error:
                    raise ViceCommandError(
                        frame.error, command=command, request_id=request_id
                    )
                if frame.response_type not in expected:
                    raise ViceProtocolError(
                        f"command 0x{command:02x} request {request_id} expected "
                        f"{[hex(value) for value in expected]}, got "
                        f"0x{frame.response_type:02x}",
                        command=command,
                        request_id=request_id,
                    )
                frames.append(frame)
                if len(frames) > max_frames:
                    raise ViceProtocolError(
                        f"command 0x{command:02x} exceeded {max_frames} frames",
                        command=command,
                        request_id=request_id,
                    )
                if frame.response_type == terminal_response:
                    return request_id, frames
        except queue.Empty as exc:
            timed_out = True
            with self._state_lock:
                if self._terminal_error is not None:
                    timed_out = False
                    raise self._terminal_error
                self._pending.pop(request_id, None)
                if not request.terminal_seen:
                    self._abandoned[request_id] = _AbandonedRequest(
                        command,
                        frozenset(expected),
                        terminal_response,
                        max_frames,
                        frames_seen=request.frames_seen,
                    )
            timeout = ViceTimeoutError(
                f"VICE command 0x{command:02x} timed out after {timeout_ms} ms",
                command=command,
                request_id=request_id,
                state_may_have_changed=mutating,
            )
            raise timeout from exc
        except ViceProtocolError as exc:
            self._terminate(
                ViceConnectionError(
                    f"VICE protocol corruption: {exc}",
                    command=command,
                    request_id=request_id,
                    outcome_unknown=mutating,
                )
            )
            raise
        finally:
            if not timed_out:
                with self._state_lock:
                    self._pending.pop(request_id, None)

    def command(
        self,
        command: int,
        payload: bytes = b"",
        *,
        expected: int,
        timeout_ms: int = 10_000,
        mutating: bool = False,
    ) -> Frame:
        _, frames = self._command_frames(
            command,
            payload,
            expected=(expected,),
            terminal_response=expected,
            timeout_ms=timeout_ms,
            max_frames=1,
            mutating=mutating,
        )
        return frames[0]

    def _discover_registers(self, memspace: int = MEMSPACE_MAIN) -> None:
        registers = self.registers_available(memspace)
        self.reg_name_to_id = {item.name: item.id for item in registers}
        self.reg_id_to_name = {item.id: item.name for item in registers}
        self.reg_name_to_bits = {item.name: item.bits for item in registers}

    def registers_available(
        self, memspace: int = MEMSPACE_MAIN, *, timeout_ms: int = 10_000
    ) -> List[Register]:
        _validate_id(memspace, "memspace", 0xFF)
        frame = self.command(
            CMD_REGISTERS_AVAILABLE,
            struct.pack("<B", memspace),
            expected=RESP_REGISTERS_AVAILABLE,
            timeout_ms=timeout_ms,
        )
        cur = Cursor(frame.body, "registers available")
        count = cur.u16()
        if count > MAX_LIST_ITEMS:
            raise ViceProtocolError(f"register count {count} exceeds {MAX_LIST_ITEMS}")
        result: List[Register] = []
        ids = set()
        names = set()
        for index in range(count):
            item_size = cur.u8()
            item = Cursor(cur.take(item_size), f"register metadata item {index}")
            if item_size < 3:
                raise ViceProtocolError(
                    f"register metadata item {index}: size {item_size} is too small"
                )
            register_id = item.u8()
            bits = item.u8()
            name_length = item.u8()
            name_bytes = item.take(name_length)
            item.finish()
            if not 1 <= bits <= 16:
                raise ViceProtocolError(
                    f"register metadata item {index}: bit width {bits} is invalid"
                )
            try:
                name = name_bytes.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ViceProtocolError(
                    f"register metadata item {index}: name is not ASCII"
                ) from exc
            if not name or register_id in ids or name in names:
                raise ViceProtocolError(
                    f"duplicate or empty register metadata at item {index}"
                )
            ids.add(register_id)
            names.add(name)
            result.append(Register(register_id, name, bits))
        cur.finish()
        return result

    def registers_get(
        self, memspace: int = MEMSPACE_MAIN, *, timeout_ms: int = 10_000
    ) -> Dict[str, int]:
        _validate_id(memspace, "memspace", 0xFF)
        frame = self.command(
            CMD_REGISTERS_GET,
            struct.pack("<B", memspace),
            expected=RESP_REGISTERS_GET,
            timeout_ms=timeout_ms,
        )
        return self._parse_register_values(frame.body)

    def _parse_register_values(self, body: bytes) -> Dict[str, int]:
        cur = Cursor(body, "register values")
        count = cur.u16()
        if count > MAX_LIST_ITEMS:
            raise ViceProtocolError(f"register count {count} exceeds {MAX_LIST_ITEMS}")
        result: Dict[str, int] = {}
        seen = set()
        for index in range(count):
            item_size = cur.u8()
            item = Cursor(cur.take(item_size), f"register value item {index}")
            register_id = item.u8()
            if item.remaining not in (1, 2):
                raise ViceProtocolError(
                    f"register value item {index}: unsupported "
                    f"{item.remaining}-byte value"
                )
            value = item.u8() if item.remaining == 1 else item.u16()
            item.finish()
            if register_id in seen:
                raise ViceProtocolError(f"duplicate register ID {register_id}")
            seen.add(register_id)
            name = self.reg_id_to_name.get(register_id)
            if name is None:
                raise ViceProtocolError(f"unknown register ID {register_id}")
            bits = self.reg_name_to_bits[name]
            if value >= 1 << bits:
                raise ViceProtocolError(
                    f"register {name} value {value} exceeds {bits} bits"
                )
            result[name] = value
        cur.finish()
        return result

    def registers_set(
        self,
        values: Dict[str, int],
        memspace: int = MEMSPACE_MAIN,
        *,
        timeout_ms: int = 10_000,
    ) -> Dict[str, int]:
        if not values:
            raise ViceValidationError("at least one register value is required")
        _validate_id(memspace, "memspace", 0xFF)
        entries = []
        for name, value in values.items():
            if name not in self.reg_name_to_id:
                raise ViceValidationError(f"unknown register {name!r}")
            bits = self.reg_name_to_bits[name]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << bits:
                raise ViceValidationError(
                    f"register {name} must be an integer in 0..{(1 << bits) - 1}"
                )
            entries.append(
                struct.pack("<BBH", 3, self.reg_name_to_id[name], value)
            )
        frame = self.command(
            CMD_REGISTERS_SET,
            struct.pack("<BH", memspace, len(entries)) + b"".join(entries),
            expected=RESP_REGISTERS_GET,
            timeout_ms=timeout_ms,
            mutating=True,
        )
        # VICE returns the observed register values in the SET response.
        return self._parse_register_values(frame.body)

    def memory_get(
        self,
        start: int,
        end: int,
        memspace: int = MEMSPACE_MAIN,
        bank_id: int = 0,
        side_effects: bool = False,
        *,
        timeout_ms: int = 10_000,
    ) -> bytes:
        start = _validate_u16(start, "start")
        end = _validate_u16(end, "end")
        if start > end:
            raise ViceValidationError("memory range must not wrap")
        _validate_id(memspace, "memspace", 0xFF)
        _validate_id(bank_id, "bank_id")
        _validate_bool(side_effects, "side_effects")
        deadline = _operation_deadline(timeout_ms)
        result = bytearray()
        cursor = start
        while cursor <= end:
            chunk_end = min(end, cursor + MAX_MEMORY_FRAME - 1)
            payload = struct.pack(
                "<BHHBH",
                int(bool(side_effects)),
                cursor,
                chunk_end,
                memspace,
                bank_id,
            )
            frame = self.command(
                CMD_MEMORY_GET,
                payload,
                expected=RESP_MEMORY_GET,
                timeout_ms=_remaining_timeout_ms(
                    deadline, state_may_have_changed=bool(side_effects)
                ),
                mutating=bool(side_effects),
            )
            body = Cursor(frame.body, "memory get")
            length = body.u16()
            data = body.take(length)
            body.finish()
            expected_length = chunk_end - cursor + 1
            if length != expected_length:
                raise ViceProtocolError(
                    f"memory get returned {length} bytes, expected {expected_length}"
                )
            result.extend(data)
            cursor = chunk_end + 1
        return bytes(result)

    def memory_set(
        self,
        start: int,
        data: bytes,
        memspace: int = MEMSPACE_MAIN,
        bank_id: int = 0,
        side_effects: bool = False,
        *,
        timeout_ms: int = 10_000,
    ) -> List[Tuple[int, int]]:
        start = _validate_u16(start, "start")
        if not isinstance(data, bytes):
            raise ViceValidationError("data must be bytes")
        if len(data) > 0x10000 or start + len(data) > 0x10000:
            raise ViceValidationError("memory write must fit without wrapping")
        _validate_id(memspace, "memspace", 0xFF)
        _validate_id(bank_id, "bank_id")
        _validate_bool(side_effects, "side_effects")
        deadline = _operation_deadline(timeout_ms)
        completed = []
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + MAX_MEMORY_FRAME]
            chunk_start = start + offset
            chunk_end = chunk_start + len(chunk) - 1
            payload = struct.pack(
                "<BHHBH",
                int(bool(side_effects)),
                chunk_start,
                chunk_end,
                memspace,
                bank_id,
            ) + chunk
            try:
                self.command(
                    CMD_MEMORY_SET,
                    payload,
                    expected=RESP_MEMORY_SET,
                    timeout_ms=_remaining_timeout_ms(
                        deadline, state_may_have_changed=True
                    ),
                    mutating=True,
                )
            except ViceFailure as exc:
                if not completed:
                    raise
                raise VicePartialWriteError(
                    f"VICE memory write failed after {sum(end - begin + 1 for begin, end in completed)} bytes",
                    completed_ranges=completed,
                    failed_range=(chunk_start, chunk_end),
                    cause=exc,
                ) from exc
            completed.append((chunk_start, chunk_end))
            offset += len(chunk)
        return completed

    def checkpoint_set(
        self,
        start: int,
        end: int,
        stop_on_hit: bool = True,
        enabled: bool = True,
        cpu_op: int = CPU_OP_EXEC,
        temporary: bool = False,
        memspace: int = MEMSPACE_MAIN,
        *,
        timeout_ms: int = 10_000,
    ) -> Checkpoint:
        start = _validate_u16(start, "start")
        end = _validate_u16(end, "end")
        if start > end:
            raise ViceValidationError("checkpoint range must not wrap")
        if not cpu_op or cpu_op & ~(CPU_OP_LOAD | CPU_OP_STORE | CPU_OP_EXEC):
            raise ViceValidationError("cpu_op must contain only load/store/execute")
        _validate_id(memspace, "memspace", 0xFF)
        _validate_bool(stop_on_hit, "stop_on_hit")
        _validate_bool(enabled, "enabled")
        _validate_bool(temporary, "temporary")
        payload = struct.pack(
            "<HHBBBBB",
            start,
            end,
            int(bool(stop_on_hit)),
            int(bool(enabled)),
            cpu_op,
            int(bool(temporary)),
            memspace,
        )
        frame = self.command(
            CMD_CHECKPOINT_SET,
            payload,
            expected=RESP_CHECKPOINT_INFO,
            timeout_ms=timeout_ms,
            mutating=True,
        )
        return parse_checkpoint_info(frame.body)

    def checkpoint_delete(
        self, number: int, *, timeout_ms: int = 10_000
    ) -> None:
        _validate_id(number, "checkpoint number", 0xFFFFFFFF)
        self.command(
            CMD_CHECKPOINT_DELETE,
            struct.pack("<I", number),
            expected=RESP_CHECKPOINT_DELETE,
            timeout_ms=timeout_ms,
            mutating=True,
        )

    def checkpoint_toggle(
        self, number: int, enabled: bool, *, timeout_ms: int = 10_000
    ) -> None:
        _validate_id(number, "checkpoint number", 0xFFFFFFFF)
        _validate_bool(enabled, "enabled")
        self.command(
            CMD_CHECKPOINT_TOGGLE,
            struct.pack("<IB", number, int(bool(enabled))),
            expected=RESP_CHECKPOINT_TOGGLE,
            timeout_ms=timeout_ms,
            mutating=True,
        )

    def checkpoint_list(
        self, *, timeout_ms: int = 10_000
    ) -> List[Checkpoint]:
        _, frames = self._command_frames(
            CMD_CHECKPOINT_LIST,
            expected=(RESP_CHECKPOINT_INFO, RESP_CHECKPOINT_LIST),
            terminal_response=RESP_CHECKPOINT_LIST,
            timeout_ms=timeout_ms,
            max_frames=MAX_LIST_ITEMS + 1,
        )
        terminal = Cursor(frames[-1].body, "checkpoint list terminal")
        expected_count = terminal.u32()
        terminal.finish()
        checkpoints = [
            parse_checkpoint_info(frame.body)
            for frame in frames[:-1]
        ]
        if len(checkpoints) != expected_count:
            raise ViceProtocolError(
                f"checkpoint list terminal count {expected_count} does not "
                f"match {len(checkpoints)} records"
            )
        numbers = [item.number for item in checkpoints]
        if len(set(numbers)) != len(numbers):
            raise ViceProtocolError("checkpoint list contains duplicate numbers")
        return checkpoints

    def banks_available(self, *, timeout_ms: int = 10_000) -> List[Bank]:
        frame = self.command(
            CMD_BANKS_AVAILABLE,
            expected=RESP_BANKS_AVAILABLE,
            timeout_ms=timeout_ms,
        )
        cur = Cursor(frame.body, "banks available")
        count = cur.u16()
        if count > MAX_LIST_ITEMS:
            raise ViceProtocolError(f"bank count {count} exceeds {MAX_LIST_ITEMS}")
        result = []
        pairs = set()
        names = set()
        for index in range(count):
            item_size = cur.u8()
            item = Cursor(cur.take(item_size), f"bank item {index}")
            bank_id = item.u16()
            name_length = item.u8()
            name_bytes = item.take(name_length)
            item.finish()
            try:
                name = name_bytes.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ViceProtocolError(
                    f"bank item {index}: name is not ASCII"
                ) from exc
            pair = (bank_id, name)
            if not name or pair in pairs or name in names:
                raise ViceProtocolError(f"duplicate or empty bank item {index}")
            pairs.add(pair)
            names.add(name)
            result.append(Bank(bank_id, name))
        cur.finish()
        return result

    def vice_info(self, *, timeout_ms: int = 10_000) -> ViceInfo:
        """Read and cache what VICE reports about itself.

        The full version components and the revision are both returned: the
        0x84 build guard is decided from them, and a truncated
        "major.minor.build" string cannot express either the release family or
        the revision it needs.
        """
        frame = self.command(
            CMD_VICE_INFO, expected=RESP_VICE_INFO, timeout_ms=timeout_ms
        )
        info = parse_vice_info(frame.body)
        with self._state_lock:
            self._vice_info = info
        return info

    def _require_display_get_support(self) -> ViceInfo:
        """Refuse `display get` unless this build is known to carry r46020.

        Ordered so the revision wins wherever it exists: a build that reports
        one is judged by it, and only a release build -- which reports none --
        falls through to its version. Unknown build information refuses; the
        guard must not fall open, because the damage from guessing wrong is an
        out-of-bounds write inside the emulator.
        """
        info = self.vice_build_info
        if info is None:
            raise ViceUnsupportedBuildError(
                "VICE build information is unknown on this connection, so "
                "display capture is refused: builds before r46020 overrun "
                "their own allocation while answering the command"
            )
        requirement = (
            f"a build at r{DISPLAY_GET_MIN_REVISION} or later, or release "
            f"{DISPLAY_GET_MIN_RELEASE[0]}.{DISPLAY_GET_MIN_RELEASE[1]} or later"
        )
        detected = (
            f"VICE version {info.version_string or '(none)'} revision "
            f"{'none' if info.revision is None else 'r%d' % info.revision}"
        )
        if info.revision is not None:
            if info.revision < DISPLAY_GET_MIN_REVISION:
                raise ViceUnsupportedBuildError(
                    f"{detected} predates the display-capture fix; "
                    f"display capture requires {requirement}"
                )
            return info
        # A release build. Compare exactly two components: in Python
        # `(3, 10, 0, 0) > (3, 10)` is True, which would admit the vulnerable
        # 3.10 release itself.
        if len(info.version) < 2:
            raise ViceUnsupportedBuildError(
                f"{detected} does not identify a release family; "
                f"display capture requires {requirement}"
            )
        if (info.version[0], info.version[1]) < DISPLAY_GET_MIN_RELEASE:
            raise ViceUnsupportedBuildError(
                f"{detected} predates the display-capture fix; "
                f"display capture requires {requirement}"
            )
        return info

    def display_get(
        self, use_vic: bool = True, *, timeout_ms: int = 10_000
    ) -> DisplayFrame:
        """Fetch one indexed frame buffer and its geometry.

        The build guard runs here, immediately before the command can be sent,
        rather than only in the caller: an affected VICE performs the
        out-of-bounds write before it replies, so there is no recovery at this
        end and no second door into the command.
        """
        _validate_bool(use_vic, "use_vic")
        self._require_display_get_support()
        frame = self.command(
            CMD_DISPLAY_GET,
            build_display_get_body(use_vic),
            expected=RESP_DISPLAY_GET,
            timeout_ms=timeout_ms,
        )
        return parse_display_get(frame.body)

    def palette_get(
        self, use_vic: bool = True, *, timeout_ms: int = 10_000
    ) -> List[PaletteEntry]:
        """Fetch the palette the frame buffer's indices refer to."""
        _validate_bool(use_vic, "use_vic")
        frame = self.command(
            CMD_PALETTE_GET,
            build_palette_get_body(use_vic),
            expected=RESP_PALETTE_GET,
            timeout_ms=timeout_ms,
        )
        return parse_palette_get(frame.body)

    def ping(self, *, timeout_ms: int = 10_000) -> bool:
        self.command(CMD_PING, expected=RESP_PING, timeout_ms=timeout_ms)
        return True

    def keyboard_feed(
        self, data: bytes, *, timeout_ms: int = 10_000
    ) -> None:
        if not isinstance(data, bytes) or not 1 <= len(data) <= 0xFF:
            raise ViceValidationError(
                "keyboard data must contain between 1 and 255 bytes"
            )
        if b"\x00" in data:
            raise ViceValidationError("keyboard data must not contain NUL")
        self.command(
            CMD_KEYBOARD_FEED,
            bytes((len(data),)) + data,
            expected=RESP_KEYBOARD_FEED,
            timeout_ms=timeout_ms,
            mutating=True,
        )

    def joyport_set(
        self, port: int, value: int, *, timeout_ms: int = 10_000
    ) -> None:
        if isinstance(port, bool) or port not in (1, 2):
            raise ViceValidationError("joyport must be 1 or 2")
        _validate_id(value, "joyport value", 0xFF)
        self.command(
            CMD_JOYPORT_SET,
            # Printed C64 ports are 1/2; VICE's binary-monitor enum is 0/1.
            struct.pack("<HH", port - 1, value),
            expected=RESP_JOYPORT_SET,
            timeout_ms=timeout_ms,
            mutating=True,
        )

    def resource_set_int(
        self, name: str, value: int, *, timeout_ms: int = 10_000
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not -(1 << 31) <= value < (1 << 31)
        ):
            raise ViceValidationError(
                "resource value must be a signed 32-bit integer"
            )
        payload = (
            b"\x01"
            + _length_prefixed_text(name, "resource name")
            + b"\x04"
            + value.to_bytes(4, "little", signed=True)
        )
        self.command(
            CMD_RESOURCE_SET,
            payload,
            expected=RESP_RESOURCE_SET,
            timeout_ms=timeout_ms,
            mutating=True,
        )

    def snapshot_save(
        self,
        filename: str,
        *,
        save_roms: bool = False,
        save_disks: bool = True,
        timeout_ms: int = 10_000,
    ) -> None:
        _validate_bool(save_roms, "save_roms")
        _validate_bool(save_disks, "save_disks")
        self.command(
            CMD_SNAPSHOT_DUMP,
            bytes((int(save_roms), int(save_disks)))
            + _length_prefixed_text(filename, "snapshot filename"),
            expected=RESP_SNAPSHOT_DUMP,
            timeout_ms=timeout_ms,
            mutating=True,
        )

    def snapshot_load(
        self, filename: str, *, timeout_ms: int = 10_000
    ) -> int:
        frame = self.command(
            CMD_SNAPSHOT_UNDUMP,
            _length_prefixed_text(filename, "snapshot filename"),
            expected=RESP_SNAPSHOT_UNDUMP,
            timeout_ms=timeout_ms,
            mutating=True,
        )
        cur = Cursor(frame.body, "snapshot load")
        pc = cur.u16()
        cur.finish()
        return pc

    def acknowledge_step(
        self, count: int, step_over: bool, *, timeout_ms: int
    ) -> int:
        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 0xFFFF:
            raise ViceValidationError("count must be in 1..65535")
        _validate_bool(step_over, "step_over")
        frame = self.command(
            CMD_ADVANCE_INSTRUCTIONS,
            struct.pack("<BH", int(bool(step_over)), count),
            expected=RESP_ADVANCE_INSTRUCTIONS,
            timeout_ms=timeout_ms,
            mutating=True,
        )
        return frame.request_id

    def acknowledge_finish(self, *, timeout_ms: int) -> int:
        frame = self.command(
            CMD_EXECUTE_UNTIL_RETURN,
            expected=RESP_EXECUTE_UNTIL_RETURN,
            timeout_ms=timeout_ms,
            mutating=True,
        )
        return frame.request_id

    def acknowledge_resume(self, *, timeout_ms: int) -> int:
        frame = self.command(
            CMD_EXIT,
            expected=RESP_EXIT,
            timeout_ms=timeout_ms,
            mutating=True,
        )
        return frame.request_id

    def acknowledge_interrupt(self, *, timeout_ms: int) -> int:
        frame = self.command(
            CMD_PING,
            expected=RESP_PING,
            timeout_ms=timeout_ms,
            mutating=True,
        )
        return frame.request_id

    def reset(self, reset_type: int = 0, *, timeout_ms: int = 10_000) -> None:
        if reset_type not in (0, 1, 8, 9):
            raise ViceValidationError("reset type must be 0, 1, 8, or 9")
        self.command(
            CMD_RESET,
            struct.pack("<B", reset_type),
            expected=RESP_RESET,
            timeout_ms=timeout_ms,
            mutating=True,
        )
