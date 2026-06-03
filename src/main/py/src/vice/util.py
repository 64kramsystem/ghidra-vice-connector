"""
VICE Binary Monitor Protocol (BMP) TCP client.

Packet format (API v2):
  Request:  STX(1) API_VER(1) body_len(4 LE) request_id(4 LE) cmd(1) payload(N)
  Response: STX(1) API_VER(1) body_len(4 LE) resp_type(1) error(1) request_id(4 LE) payload(N)

Reference: https://vice-emu.sourceforge.io/vice_13.html
"""

import logging
import queue
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

log = logging.getLogger('vice-agent')

# ── Protocol constants ─────────────────────────────────────────────────────────

STX = 0x02
API_VERSION = 0x02

# Request header: B B I I B  (1+1+4+4+1 = 11 bytes)
REQ_HDR_FMT = '<BBIIB'
REQ_HDR_SIZE = struct.calcsize(REQ_HDR_FMT)  # 11

# Response header: B B I B B I  (1+1+4+1+1+4 = 12 bytes)
RESP_HDR_FMT = '<BBIBBI'
RESP_HDR_SIZE = struct.calcsize(RESP_HDR_FMT)  # 12

EVENT_REQUEST_ID = 0xFFFFFFFF

# ── Command IDs ────────────────────────────────────────────────────────────────

CMD_MEMORY_GET           = 0x01
CMD_MEMORY_SET           = 0x02
CMD_CHECKPOINT_GET       = 0x11
CMD_CHECKPOINT_SET       = 0x12
CMD_CHECKPOINT_DELETE    = 0x13
CMD_CHECKPOINT_LIST      = 0x14
CMD_CHECKPOINT_TOGGLE    = 0x15
CMD_REGISTERS_GET        = 0x31
CMD_REGISTERS_SET        = 0x32
CMD_ADVANCE_INSTRUCTIONS = 0x71
CMD_EXECUTE_UNTIL_RETURN = 0x73
CMD_PING                 = 0x81
CMD_BANKS_AVAILABLE      = 0x82
CMD_REGISTERS_AVAILABLE  = 0x83
CMD_VICE_INFO            = 0x85
CMD_EXIT                 = 0xAA
CMD_QUIT                 = 0xBB
CMD_RESET                = 0xCC

# ── Response / event types ─────────────────────────────────────────────────────

RESP_MEMORY_GET           = 0x01
RESP_MEMORY_SET           = 0x02
RESP_CHECKPOINT_INFO      = 0x11
RESP_CHECKPOINT_DELETE    = 0x13
RESP_CHECKPOINT_LIST      = 0x14
RESP_CHECKPOINT_TOGGLE    = 0x15
RESP_REGISTERS_GET        = 0x31  # response to both REGISTERS_GET and REGISTERS_SET
RESP_BANKS_AVAILABLE      = 0x82
RESP_REGISTERS_AVAILABLE  = 0x83
RESP_VICE_INFO            = 0x85
RESP_PING                 = 0x81
RESP_RESET                = 0xCC
RESP_STOPPED              = 0x62  # event: CPU stopped (breakpoint / step complete)
RESP_RESUMED              = 0x63  # event: CPU resumed

# ── Memory spaces ──────────────────────────────────────────────────────────────

MEMSPACE_MAIN    = 0x00
MEMSPACE_DRIVE8  = 0x01
MEMSPACE_DRIVE9  = 0x02
MEMSPACE_DRIVE10 = 0x03
MEMSPACE_DRIVE11 = 0x04

# ── Checkpoint CPU operation flags ────────────────────────────────────────────

CPU_OP_LOAD  = 0x01  # memory read
CPU_OP_STORE = 0x02  # memory write
CPU_OP_EXEC  = 0x04  # instruction fetch / execution

# ── Checkpoint INFO item format ────────────────────────────────────────────────
# number(4) hit(1) start(2) end(2) stop(1) enabled(1) cpu_op(1) temp(1)
# hit_count(4) ignore_count(4) has_condition(1) — total 22 bytes

_CHECKPOINT_INFO_FMT  = '<IBHHBBBBIIb'
_CHECKPOINT_INFO_SIZE = struct.calcsize(_CHECKPOINT_INFO_FMT)  # 22


class ViceError(Exception):
    """VICE returned a non-zero error code for a command."""

    def __init__(self, code: int, cmd: Optional[int] = None, request_id: Optional[int] = None):
        self.code = code
        self.cmd = cmd
        self.request_id = request_id
        detail = f" (command 0x{cmd:02X}, request {request_id})" if cmd is not None else ""
        super().__init__(f"VICE BMP error 0x{code:02X}{detail}")


class ViceProtocolError(Exception):
    """The response type does not match what the command expects."""

    def __init__(self, cmd: int, request_id: int, expected, actual: int):
        self.cmd = cmd
        self.request_id = request_id
        self.expected = expected
        self.actual = actual
        if isinstance(expected, int):
            exp = f"0x{expected:02X}"
        else:
            exp = '{' + ', '.join(f"0x{e:02X}" for e in sorted(expected)) + '}'
        super().__init__(
            f"command 0x{cmd:02X} (request {request_id}) expected response type "
            f"{exp}, got 0x{actual:02X}")


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


@dataclass(frozen=True)
class Bank:
    id: int
    name: str


def _parse_checkpoint_info(body: bytes, offset: int = 0) -> Checkpoint:
    """Parse one CHECKPOINT_INFO item from a response body."""
    (number, hit, start, end, stop, enabled, cpu_op, temp,
     hit_count, ignore_count, has_condition) = struct.unpack_from(
        _CHECKPOINT_INFO_FMT, body, offset
    )
    return Checkpoint(
        number=number,
        start=start,
        end=end,
        enabled=bool(enabled),
        cpu_op=cpu_op,
        stop_on_hit=bool(stop),
        currently_hit=bool(hit),
        temporary=bool(temp),
        hit_count=hit_count,
        ignore_count=ignore_count,
        has_condition=bool(has_condition),
    )


class ViceBmpClient:
    """
    Thread-safe async client for the VICE Binary Monitor Protocol.

    Usage:
        client = ViceBmpClient('localhost', 6502)
        client.connect()
        client.on_event(RESP_STOPPED, my_stop_handler)
        regs = client.registers_get()
        client.disconnect()

    Event handlers are called from the receive thread:
        handler(resp_type: int, error: int, body: bytes) -> None
    """

    def __init__(self, host: str = 'localhost', port: int = 6502):
        self.host = host
        self.port = port
        self._sock: Optional[socket.socket] = None
        self._send_lock    = threading.Lock()
        self._pending_lock = threading.Lock()
        self._event_lock   = threading.Lock()
        self._next_id = 1
        # Pending queues: request_id → Queue.
        # The receive loop puts ALL responses with a matching ID into the queue
        # but does NOT remove the entry.  The command method removes it when done.
        self._pending: Dict[int, queue.Queue] = {}
        self._event_handlers: Dict[int, Callable] = {}
        self._running = False
        self._recv_thread: Optional[threading.Thread] = None
        # Worker thread for event handlers — keeps recv loop free to read responses
        self._event_thread: Optional[threading.Thread] = None
        self._event_queue: queue.Queue = queue.Queue()

        # Populated by _discover_registers() after connect
        self.reg_name_to_id: Dict[str, int] = {}
        self.reg_id_to_name: Dict[int, str] = {}

    # ── Connection ─────────────────────────────────────────────────────────────

    def connect(self):
        log.info(f"ViceBmpClient.connect(): connecting to {self.host}:{self.port}")
        self._sock = socket.create_connection((self.host, self.port), timeout=10)
        self._sock.settimeout(None)
        self._running = True
        self._recv_thread = threading.Thread(
            target=self._recv_loop, name="vice-bmp-recv", daemon=True
        )
        self._recv_thread.start()
        self._event_thread = threading.Thread(
            target=self._event_worker, name="vice-bmp-events", daemon=True
        )
        self._event_thread.start()
        log.debug("ViceBmpClient.connect(): recv + event threads started, discovering registers")
        self._discover_registers()
        log.info(f"ViceBmpClient.connect(): connected, {len(self.reg_name_to_id)} registers discovered: {list(self.reg_name_to_id.keys())}")

    def disconnect(self):
        log.info("ViceBmpClient.disconnect()")
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None

    def on_event(self, resp_type: int, handler: Callable):
        """Register a callback for unsolicited VICE events (stop/resume/etc.)."""
        log.debug(f"ViceBmpClient.on_event(): registering handler for 0x{resp_type:02X}: {handler}")
        with self._event_lock:
            self._event_handlers[resp_type] = handler

    # ── Low-level send / receive ───────────────────────────────────────────────

    def _alloc_id(self) -> int:
        with self._pending_lock:
            rid = self._next_id
            self._next_id += 1
            if self._next_id >= EVENT_REQUEST_ID:
                self._next_id = 1
            return rid

    def _send_raw(self, cmd: int, payload: bytes, rid: int):
        log.debug(f"_send_raw: cmd=0x{cmd:02X} rid={rid} payload_len={len(payload)} payload={payload.hex()}")
        header = struct.pack(REQ_HDR_FMT, STX, API_VERSION, len(payload), rid, cmd)
        with self._send_lock:
            self._sock.sendall(header + payload)

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("VICE disconnected")
            buf.extend(chunk)
        return bytes(buf)

    def _recv_loop(self):
        log.debug("_recv_loop: started")
        while self._running:
            try:
                raw = self._recv_exact(RESP_HDR_SIZE)
                stx, api_ver, body_len, resp_type, error, req_id = struct.unpack(
                    RESP_HDR_FMT, raw
                )
                # Validate before trusting body_len: after a framing error there is no
                # reliable resync marker, so the stream is dead.
                if stx != STX or api_ver != API_VERSION:
                    raise ConnectionError(
                        f"corrupt response header (STX=0x{stx:02X}, API=0x{api_ver:02X}): "
                        f"stream desynced")
                body = self._recv_exact(body_len) if body_len else b''

                if req_id == EVENT_REQUEST_ID:
                    log.info(f"recv EVENT: type=0x{resp_type:02X} error={error} body_len={body_len} body={body[:32].hex()}")
                    with self._event_lock:
                        handler = self._event_handlers.get(resp_type)
                        registered = list(self._event_handlers.keys())
                    if handler:
                        log.debug(f"recv EVENT: queuing to worker for handler {handler.__name__}")
                        self._event_queue.put((handler, resp_type, error, body))
                    else:
                        log.warning(f"recv EVENT: NO handler for event type 0x{resp_type:02X} (registered: {[f'0x{k:02X}' for k in registered]})")
                else:
                    with self._pending_lock:
                        q = self._pending.get(req_id)
                        pending_ids = list(self._pending.keys())
                    if q is not None:
                        log.debug(f"recv RESPONSE: type=0x{resp_type:02X} rid={req_id} error={error} body_len={body_len} -> pending queue")
                        q.put_nowait((resp_type, error, body))
                    elif error != 0x00:
                        # Fire-and-forget ack (step/resume/interrupt) carrying an error —
                        # the command was rejected and nobody is waiting for the reply.
                        log.error(f"recv ORPHAN with VICE error: type=0x{resp_type:02X} rid={req_id} error=0x{error:02X}")
                    else:
                        log.debug(f"recv ORPHAN: type=0x{resp_type:02X} rid={req_id} (pending_ids={pending_ids})")
            except Exception:
                if self._running:
                    log.error("_recv_loop: exception", exc_info=True)
                    self._running = False
                break
        log.debug("_recv_loop: exited")

    def _event_worker(self):
        """Process event handlers on a dedicated thread.

        This keeps the recv loop free to read socket data and deliver
        responses to pending _command() calls, avoiding deadlocks when
        event handlers themselves call _command().

        Events are dispatched in batches: the first event blocks, anything
        already queued is drained behind it. Within a batch, a RESUMED with a
        later STOPPED is dropped — VICE emits that pair for every step, and the
        transient RUNNING transition triggers expensive Ghidra refreshes.
        STOPPED events are never dropped: each one is a trace-history record.
        """
        log.debug("_event_worker: started")
        while self._running:
            try:
                batch = [self._event_queue.get(timeout=1.0)]
            except queue.Empty:
                continue
            try:
                while True:
                    batch.append(self._event_queue.get_nowait())
            except queue.Empty:
                pass
            stop_idxs = [i for i, (_, rt, _e, _b) in enumerate(batch) if rt == RESP_STOPPED]
            last_stop = stop_idxs[-1] if stop_idxs else -1
            for i, (handler, resp_type, error, body) in enumerate(batch):
                if resp_type == RESP_RESUMED and i < last_stop:
                    log.debug("_event_worker: coalesced RESUMED (STOPPED later in batch)")
                    continue
                log.debug(f"_event_worker: dispatching {handler.__name__} for event 0x{resp_type:02X}")
                try:
                    handler(resp_type, error, body)
                except Exception:
                    log.error(f"_event_worker: handler {handler.__name__} for 0x{resp_type:02X} raised", exc_info=True)
        log.debug("_event_worker: exited")

    def _command(
        self, cmd: int, payload: bytes = b'', timeout: float = 5.0,
        expect: Optional[int] = None,
    ) -> Tuple[int, bytes]:
        """Send a command and block until its (single) response arrives.

        A non-zero VICE error raises ViceError (checked first: on error frames the
        response type is less meaningful). A response type other than `expect`
        raises ViceProtocolError.
        """
        rid = self._alloc_id()
        log.debug(f"_command: cmd=0x{cmd:02X} rid={rid} timeout={timeout}")
        q: queue.Queue = queue.Queue()
        with self._pending_lock:
            self._pending[rid] = q
        try:
            self._send_raw(cmd, payload, rid)
            resp_type, error, body = q.get(timeout=timeout)
            if error != 0x00:
                log.error(f"_command: cmd=0x{cmd:02X} rid={rid} VICE error=0x{error:02X}")
                raise ViceError(error, cmd=cmd, request_id=rid)
            if expect is not None and resp_type != expect:
                log.error(f"_command: cmd=0x{cmd:02X} rid={rid} unexpected resp type 0x{resp_type:02X} (expected 0x{expect:02X})")
                raise ViceProtocolError(cmd, rid, expect, resp_type)
            log.debug(f"_command: cmd=0x{cmd:02X} rid={rid} -> resp=0x{resp_type:02X} body_len={len(body)}")
            return resp_type, body
        except queue.Empty:
            log.error(f"_command: cmd=0x{cmd:02X} rid={rid} TIMED OUT after {timeout}s")
            raise TimeoutError(f"command 0x{cmd:02X} timed out after {timeout}s")
        finally:
            with self._pending_lock:
                self._pending.pop(rid, None)

    def _command_multi(
        self,
        cmd: int,
        payload: bytes = b'',
        terminal_resp_type: int = 0,
        timeout: float = 5.0,
        expect: Optional[frozenset] = None,
    ) -> List[Tuple[int, bytes]]:
        """
        Send a command and collect ALL response frames until one with
        resp_type == terminal_resp_type arrives.
        Returns list of (resp_type, body) for all frames including the terminal.
        Frames with a response type outside `expect` raise ViceProtocolError.
        """
        rid = self._alloc_id()
        q: queue.Queue = queue.Queue(maxsize=1000)
        with self._pending_lock:
            self._pending[rid] = q
        try:
            self._send_raw(cmd, payload, rid)
            responses = []
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"command 0x{cmd:02X} timed out collecting multi-frame response")
                resp_type, error, body = q.get(timeout=remaining)
                if error != 0x00:
                    raise ViceError(error, cmd=cmd, request_id=rid)
                if expect is not None and resp_type not in expect:
                    raise ViceProtocolError(cmd, rid, expect, resp_type)
                responses.append((resp_type, body))
                if resp_type == terminal_resp_type:
                    break
            return responses
        finally:
            with self._pending_lock:
                self._pending.pop(rid, None)

    # ── Register discovery ────────────────────────────────────────────────────

    def _discover_registers(self):
        """
        Query REGISTERS_AVAILABLE to build name ↔ id maps.

        Response layout:
          count (2 LE)
          per item: item_size (1)  reg_id (1)  name_len (1)  name (name_len bytes)
          item_size = 2 + name_len
        """
        _, body = self._command(CMD_REGISTERS_AVAILABLE, struct.pack('<B', MEMSPACE_MAIN),
                                expect=RESP_REGISTERS_AVAILABLE)
        count = struct.unpack_from('<H', body, 0)[0]
        offset = 2
        for _ in range(count):
            item_size = body[offset]
            reg_id    = body[offset + 1]
            # offset+2 is register size in bits (e.g. 0x08, 0x10) — skip it
            name_len  = body[offset + 3]
            name      = body[offset + 4: offset + 4 + name_len].decode('ascii')
            self.reg_name_to_id[name] = reg_id
            self.reg_id_to_name[reg_id] = name
            offset += 1 + item_size     # step past item_size byte + item body

    # ── High-level commands ───────────────────────────────────────────────────

    def ping(self) -> bool:
        log.debug("ping()")
        try:
            self._command(CMD_PING, expect=RESP_PING)
            log.debug("ping(): success")
            return True
        except Exception as e:
            log.warning(f"ping(): failed: {e}")
            return False

    def interrupt(self):
        """Send a fire-and-forget ping to force VICE into monitor mode.

        When VICE is running, receiving any command causes it to pause.
        The RESP_STOPPED event handler will update state.
        """
        log.info("interrupt(): sending fire-and-forget ping")
        self._send_no_reply(CMD_PING)

    def registers_set(self, values: Dict[str, int], memspace: int = MEMSPACE_MAIN):
        """
        Write registers by name.

        Payload: memspace(1) count(2 LE) [item_size(1) reg_id(1) value(2 LE)]*
        item_size is always 3 (reg_id + value = 1 + 2 bytes).
        """
        for name in values:
            if name not in self.reg_name_to_id:
                raise KeyError(f"Unknown register: {name!r}")
        payload = struct.pack('<BH', memspace, len(values))
        for name, val in values.items():
            rid = self.reg_name_to_id[name]
            payload += struct.pack('<BBH', 3, rid, val & 0xFFFF)
        # VICE answers REGISTERS_SET with a register-info response (0x31).
        self._command(CMD_REGISTERS_SET, payload, expect=RESP_REGISTERS_GET)

    def memory_get(
        self,
        start: int,
        end: int,
        memspace: int = MEMSPACE_MAIN,
        bank_id: int = 0,
        side_effects: bool = False,
    ) -> bytes:
        """
        Read [start, end] inclusive from VICE memory.

        Request payload:  side_effects(1) start(2 LE) end(2 LE) memspace(1) bank_id(2 LE)
        Response body:    mem_len(2 LE) data(mem_len bytes)
        """
        payload = struct.pack(
            '<BHHBH',
            1 if side_effects else 0,
            start & 0xFFFF,
            end & 0xFFFF,
            memspace,
            bank_id,
        )
        _, body = self._command(CMD_MEMORY_GET, payload, expect=RESP_MEMORY_GET)
        # Strip the 2-byte length prefix that VICE prepends to the memory data
        mem_len = struct.unpack_from('<H', body, 0)[0]
        return body[2:2 + mem_len]

    def memory_set(
        self,
        start: int,
        data: bytes,
        memspace: int = MEMSPACE_MAIN,
        bank_id: int = 0,
        side_effects: bool = False,
    ):
        """
        Write bytes to VICE memory starting at start.

        Payload: side_effects(1) start(2 LE) end(2 LE) memspace(1) bank_id(2 LE) data(N)
        """
        if not data:
            return
        if start + len(data) - 1 > 0xFFFF:
            raise ValueError(
                f"memory_set would exceed 0xFFFF: "
                f"start=0x{start:04X}, len={len(data)}"
            )
        end = start + len(data) - 1
        payload = struct.pack(
            '<BHHBH',
            1 if side_effects else 0,
            start & 0xFFFF,
            end,
            memspace,
            bank_id,
        ) + data
        self._command(CMD_MEMORY_SET, payload, expect=RESP_MEMORY_SET)

    def registers_get(self, memspace: int = MEMSPACE_MAIN) -> Dict[str, int]:
        """
        Returns {reg_name: value} for all CPU registers.

        Response layout:
          count (2 LE)
          per item: item_size (1)  reg_id (1)  value (2 LE)
        """
        log.debug(f"registers_get(memspace={memspace})")
        _, body = self._command(CMD_REGISTERS_GET, struct.pack('<B', memspace),
                                expect=RESP_REGISTERS_GET)
        count = struct.unpack_from('<H', body, 0)[0]
        offset = 2
        result = {}
        for _ in range(count):
            item_size = body[offset]
            reg_id    = body[offset + 1]
            value     = struct.unpack_from('<H', body, offset + 2)[0]
            name = self.reg_id_to_name.get(reg_id, f"r{reg_id}")
            result[name] = value
            offset += 1 + item_size
        log.debug(f"registers_get(): {result}")
        return result

    def checkpoint_set(
        self,
        start: int,
        end: int,
        stop_on_hit: bool = True,
        enabled: bool = True,
        cpu_op: int = CPU_OP_EXEC,
        temporary: bool = False,
        memspace: int = MEMSPACE_MAIN,
    ) -> int:
        """
        Create a VICE checkpoint (breakpoint / watchpoint).
        Returns the checkpoint number assigned by VICE.

        Payload: start(2 LE) end(2 LE) stop(1) enabled(1) cpu_op(1) temporary(1)
        Response (RESP_CHECKPOINT_INFO): checkpoint data starting with number(4 LE)
        """
        log.info(f"checkpoint_set(start=0x{start:04X}, end=0x{end:04X}, stop={stop_on_hit}, enabled={enabled}, cpu_op=0x{cpu_op:02X}, temp={temporary})")
        payload = struct.pack(
            '<HHBBBB',
            start & 0xFFFF,
            end & 0xFFFF,
            1 if stop_on_hit else 0,
            1 if enabled else 0,
            cpu_op,
            1 if temporary else 0,
        )
        _, body = self._command(CMD_CHECKPOINT_SET, payload, expect=RESP_CHECKPOINT_INFO)
        cp = _parse_checkpoint_info(body)
        log.info(f"checkpoint_set(): VICE assigned number={cp.number}")
        return cp.number

    def checkpoint_delete(self, number: int):
        log.info(f"checkpoint_delete({number})")
        self._command(CMD_CHECKPOINT_DELETE, struct.pack('<I', number),
                      expect=RESP_CHECKPOINT_DELETE)

    def checkpoint_toggle(self, number: int, enabled: bool):
        log.info(f"checkpoint_toggle({number}, enabled={enabled})")
        self._command(CMD_CHECKPOINT_TOGGLE, struct.pack('<IB', number, 1 if enabled else 0),
                      expect=RESP_CHECKPOINT_TOGGLE)

    def checkpoint_list(self) -> List[Checkpoint]:
        """
        Returns the current checkpoints.

        VICE sends one RESP_CHECKPOINT_INFO (0x11) frame per checkpoint,
        followed by a terminal RESP_CHECKPOINT_LIST (0x14) frame.
        We collect all frames until the terminal one arrives.
        """
        log.debug("checkpoint_list()")
        frames = self._command_multi(
            CMD_CHECKPOINT_LIST,
            terminal_resp_type=RESP_CHECKPOINT_LIST,
            expect=frozenset({RESP_CHECKPOINT_INFO, RESP_CHECKPOINT_LIST}),
        )
        checkpoints = []
        for resp_type, body in frames:
            if resp_type == RESP_CHECKPOINT_INFO:
                cp = _parse_checkpoint_info(body)
                log.debug(f"checkpoint_list(): cp #{cp.number} 0x{cp.start:04X}-0x{cp.end:04X} op=0x{cp.cpu_op:02X} en={cp.enabled}")
                checkpoints.append(cp)
        log.info(f"checkpoint_list(): {len(checkpoints)} checkpoints")
        return checkpoints

    def _send_no_reply(self, cmd: int, payload: bytes = b''):
        """Send a command without waiting for a response.

        Used for commands like step/step-out where VICE signals completion
        via RESP_STOPPED event rather than a direct reply.
        """
        rid = self._alloc_id()
        log.debug(f"_send_no_reply: cmd=0x{cmd:02X} rid={rid} (fire-and-forget)")
        self._send_raw(cmd, payload, rid)
        # No pending queue — the ack is orphaned (the recv loop logs it if it carries an error).

    def step(self, count: int = 1, step_over: bool = False):
        """
        Advance by count instructions.

        Payload: step_over(1) count(2 LE)

        Fire-and-forget: VICE sends RESP_STOPPED event when done.
        The direct ACK response is orphaned (no pending queue).
        """
        log.info(f"step(count={count}, step_over={step_over})")
        self._send_no_reply(
            CMD_ADVANCE_INSTRUCTIONS,
            struct.pack('<BH', 1 if step_over else 0, count),
        )
        log.info("step(): command sent (fire-and-forget)")

    def step_until_return(self):
        """Continue execution until the next RTS/RTI.

        Fire-and-forget: VICE sends RESP_STOPPED event when done.
        """
        log.info("step_until_return()")
        self._send_no_reply(CMD_EXECUTE_UNTIL_RETURN)
        log.info("step_until_return(): command sent (fire-and-forget)")

    def resume(self):
        """
        Resume execution.
        CMD_EXIT (0xAA) exits the monitor and lets VICE run freely
        until the next breakpoint or interrupt.

        VICE signals state changes via RESP_RESUMED/RESP_STOPPED events.
        """
        log.info("resume()")
        self._send_no_reply(CMD_EXIT)
        log.debug("resume(): command sent")

    def reset(self, reset_type: int = 0):
        """
        Reset the machine.
        reset_type: 0=soft, 1=hard, 8=drive8, 9=drive9
        """
        self._command(CMD_RESET, struct.pack('<B', reset_type), expect=RESP_RESET)

    def vice_info(self) -> str:
        """
        Return the VICE version as 'major.minor.patch'.

        Body: verlen(1) version(verlen bytes: major minor patch rc) svnlen(1) svn(svnlen)
        """
        _, body = self._command(CMD_VICE_INFO, expect=RESP_VICE_INFO)
        verlen = body[0]
        version = body[1:1 + verlen]
        return '.'.join(str(b) for b in version[:3])

    def banks_available(self) -> List[Bank]:
        """
        Returns the available memory banks.

        Response: count(2 LE) [item_size(1) bank_id(2 LE) name_len(1) name(N)]*
        """
        _, body = self._command(CMD_BANKS_AVAILABLE, expect=RESP_BANKS_AVAILABLE)
        count = struct.unpack_from('<H', body, 0)[0]
        offset = 2
        banks = []
        for _ in range(count):
            item_size = body[offset]
            bank_id   = struct.unpack_from('<H', body, offset + 1)[0]
            name_len  = body[offset + 3]
            name      = body[offset + 4: offset + 4 + name_len].decode('ascii')
            banks.append(Bank(id=bank_id, name=name))
            offset += 1 + item_size
        return banks
