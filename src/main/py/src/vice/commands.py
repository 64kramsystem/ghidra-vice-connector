"""
Trace population commands.

Each put_*() function reads state from VICE and writes it into the Ghidra trace.
Called on stop events, on refresh requests, and at initial connection.
"""

import inspect
import logging
import os
import socket
import struct
import threading
from contextlib import contextmanager
from typing import Optional

from ghidratrace import sch
from ghidratrace.client import (
    Address,
    AddressRange,
    Client,
    RegVal,
)

from . import arch
from .util import (
    CPU_OP_EXEC,
    CPU_OP_LOAD,
    CPU_OP_STORE,
    ViceBmpClient,
)
from .controller import ViceController

log = logging.getLogger('vice-agent')


def _default_remaining_ms():
    return 10_000

# ── Trace path patterns ───────────────────────────────────────────────────────

C64_PATH    = 'C64'
THREADS_PATH = 'C64.Threads'
THREAD_PATH  = 'C64.Threads[0]'
STACK_PATH   = 'C64.Threads[0].Stack'
FRAME_PATH   = 'C64.Threads[0].Stack[0]'
REGS_PATH    = 'C64.Threads[0].Stack[0].Registers'
REG_PATH     = 'C64.Threads[0].Stack[0].Registers[{name}]'
MEM_PATH     = 'C64.Memory'
MEM_REGION_PATH = 'C64.Memory[{key}]'
BPS_PATH     = 'C64.Breakpoints'
BP_PATH      = 'C64.Breakpoints[{n}]'
ENV_PATH     = 'C64.Environment'
BANKS_PATH   = 'C64.Environment.Banks'
BANK_PATH    = 'C64.Environment.Banks[{name}]'

# ── Shared agent state ────────────────────────────────────────────────────────
# Follows the GDB/Frida agent pattern: require_*() enforces preconditions,
# reset_*() cleans up on disconnect.


class State:
    def __init__(self):
        self.reset_client()

    def reset_client(self):
        self.client: Optional[Client] = None
        self.reset_trace()
        self.reset_vice()

    def reset_trace(self):
        self.trace = None
        self.snap: int = 0

    def reset_vice(self):
        self.controller: Optional[ViceController] = None

    @property
    def vice(self):
        """The one controller-owned client (kept as a diagnostic convenience)."""
        return self.controller.client if self.controller is not None else None

    @vice.setter
    def vice(self, client):
        if client is None:
            self.controller = None
        else:
            self.controller = ViceController(
                client, sync_event=sync_event, sync_result=sync_result
            )

    def require_client(self) -> Client:
        if self.client is None:
            raise RuntimeError("Not connected to Ghidra")
        return self.client

    def require_trace(self):
        if self.trace is None:
            raise RuntimeError("Trace not started")
        return self.trace

    def require_controller(self) -> ViceController:
        if self.controller is None:
            raise RuntimeError("Not connected to VICE")
        return self.controller

    def require_vice(self) -> ViceBmpClient:
        return self.require_controller().client


STATE = State()

# Serialize ALL trace operations (transactions, batches, activate).
# Multiple threads (method executor, event worker, Ghidra refresh callbacks)
# compete for the trace lock, causing "Unable to lock due to active transaction"
# errors and snap mismatches.
TRACE_LOCK = threading.RLock()


# ── Helpers ───────────────────────────────────────────────────────────────────

@contextmanager
def open_tracked_tx(description: str):
    with TRACE_LOCK:
        with STATE.require_trace().open_tx(description) as tx:
            yield tx


def require_vice():
    STATE.require_vice()


def require_trace():
    STATE.require_trace()


# ── Connection / trace lifecycle ──────────────────────────────────────────────

def connect_vice(host: str, port: int):
    client = ViceBmpClient(host, port)
    controller = ViceController(
        client,
        sync_event=sync_event,
        sync_result=sync_result,
    )
    STATE.controller = controller
    controller.connect()


def start_trace(host: str, port: int, registry):
    """Connect to Ghidra's TraceRmi server and create the trace."""
    c = socket.socket()
    c.connect((host, port))
    STATE.client = Client(c, 'vice-c64', registry)
    STATE.trace = STATE.client.create_trace('VICE C64', arch.LANGUAGE_ID,
                                            arch.COMPILER_SPEC, extra=None)


def populate_initial_state():
    """Populate schema objects and initial register/memory snapshot."""
    log.debug("populate_initial_state() called")
    controller = STATE.require_controller()
    vice = controller.client
    trace = STATE.require_trace()

    # Global order: controller operation lock, then trace lock.
    with controller.operation_lock:
        regs = vice.registers_get()
        pc = regs.get('PC', regs.get('pc', 0))
        checkpoints = vice.checkpoint_list()
        start = max(arch.RAM_START, pc - 0x100)
        end = min(start + 0x400 - 1, arch.RAM_END)
        data = vice.memory_get(start, end)

        log.debug(f"populate_initial_state(): PC=0x{pc:04X}, regs={regs}")

        with TRACE_LOCK:
            _populate_initial_trace(
                trace,
                controller,
                regs,
                checkpoints,
                start,
                end,
                data,
                pc,
            )
    controller.start_event_coordinator(assume_stopped=True)
    log.debug("populate_initial_state(): complete")


def _end_batch_checked(client, where):
    """End a batch and surface any operation that failed inside it.

    ghidratrace's Batch._get_result catches BaseException and *returns* the exception object
    instead of raising, so end_batch() hands back a list that may contain exceptions. All three
    call sites here discarded it, which meant a failed queued operation -- an endTx among them --
    left no trace in this process and made the next trace operation fail without exposing the
    original cause.

    Note end_batch() returns None when the batch is nested and the refcount has not reached zero;
    only the outermost end_batch waits on the futures.
    """
    results = client.end_batch()
    if not results:
        return
    failures = [r for r in results if isinstance(r, BaseException)]
    if failures:
        raise RuntimeError(
            f"{where}: {len(failures)} of {len(results)} batched trace operations failed; "
            f"first: {failures[0]!r}"
        )


def _populate_initial_trace(
    trace, controller, regs, checkpoints, start, end, data, pc
):
    """Commit already-observed startup state without BMP I/O under TRACE_LOCK."""
    log.debug("populate_initial_state(): starting batch")
    STATE.require_client().start_batch()
    try:
        with trace.open_tx('Stopped') as tx:
            trace.snapshot('Initial snapshot')
            log.debug("populate_initial_state(): skeleton")
            _create_object_skeleton()
            log.debug("populate_initial_state(): environment")
            put_environment(controller.banks)
            log.debug("populate_initial_state(): memory regions")
            put_memory_regions()
            log.debug("populate_initial_state(): registers")
            put_registers(regs)
            log.debug("populate_initial_state(): breakpoints")
            put_breakpoints_from(checkpoints)
            log.debug(
                f"populate_initial_state(): memory "
                f"0x{start:04X}-0x{end:04X} ({end-start+1} bytes)"
            )
            trace.put_bytes(Address('RAM', start), data)
            log.debug("populate_initial_state(): put_event_thread")
            put_event_thread()
    finally:
        log.debug("populate_initial_state(): end_batch")
        _end_batch_checked(STATE.require_client(), "populate_initial_state")
    # Disassemble and activate AFTER batch — Ghidra needs committed data first
    snap = trace.snap()
    log.debug(f"populate_initial_state(): current snap={snap}")
    log.debug(
        f"populate_initial_state(): disassemble at "
        f"Address('RAM', 0x{pc:04X}) snap={snap}"
    )
    with trace.open_tx('Disassemble') as tx:
        n = trace.disassemble(Address('RAM', pc))
    log.debug(f"populate_initial_state(): disassemble returned {n}")

    log.debug(f"populate_initial_state(): activate {FRAME_PATH}")
    with trace.open_tx('Activate') as tx:
        trace.proxy_object_path(FRAME_PATH).activate()


def _create_object_skeleton():
    """Create the static object hierarchy (process, thread, frame, containers)."""
    t = STATE.trace

    schema_fn = os.path.join(os.path.dirname(inspect.getfile(_create_object_skeleton)),
                             'schema.xml')
    log.debug(f"_create_object_skeleton(): loading schema from {schema_fn}")
    log.debug(f"_create_object_skeleton(): __file__ = {__file__}")
    with open(schema_fn, 'r') as f:
        schema_xml = f.read()
    log.debug(f"_create_object_skeleton(): schema length = {len(schema_xml)}")
    root = t.create_root_object(schema_xml, 'Session')
    root.insert()

    c64 = t.create_object(C64_PATH)
    c64.set_value('_display', 'C64')
    c64.set_value('_state', 'STOPPED')
    c64.insert()

    threads = t.create_object(THREADS_PATH)
    threads.insert()

    thread = t.create_object(THREAD_PATH)
    thread.set_value('_display', '6510 CPU')
    thread.set_value('_state', 'STOPPED')
    thread.insert()

    stack = t.create_object(STACK_PATH)
    stack.insert()

    frame = t.create_object(FRAME_PATH)
    frame.set_value('_display', 'frame 0')
    frame.insert()

    regs = t.create_object(REGS_PATH)
    regs.insert()

    mem = t.create_object(MEM_PATH)
    mem.insert()

    bps = t.create_object(BPS_PATH)
    bps.insert()


# ── Register population ───────────────────────────────────────────────────────

def put_registers(values=None):
    """Read all VICE registers and write them into the trace."""
    vice = STATE.require_vice()
    regs = vice.registers_get() if values is None else values
    t = STATE.trace
    log.debug(f"put_registers(): raw regs from VICE = {regs}")

    # Registers that are 2 bytes in Ghidra's 6502 spec (use Ghidra names)
    _2byte = {'PC'}
    reg_vals = []
    for vice_name, value in regs.items():
        ghidra_name = arch.VICE_TO_GHIDRA_REG.get(vice_name, vice_name)
        path = REG_PATH.format(name=ghidra_name)
        obj = t.create_object(path)
        obj.set_value('_display', f'{ghidra_name} = 0x{value:04X}')
        obj.set_value('value', value)
        obj.insert()
        # Only include registers Ghidra knows about
        if vice_name not in arch.VICE_TO_GHIDRA_REG:
            continue
        # Build RegVal: PC is 2 bytes, others are 1 byte (big-endian)
        if ghidra_name in _2byte:
            reg_vals.append(RegVal(ghidra_name, struct.pack('>H', value & 0xFFFF)))
        else:
            reg_vals.append(RegVal(ghidra_name, bytes([value & 0xFF])))

    log.debug(f"put_registers(): reg_vals = {[(r.name, r.value.hex()) for r in reg_vals]}")

    # Write actual register values so Ghidra tracks PC for Listing navigation.
    # The space must be the full Registers path with a register overlay space.
    log.debug(f"put_registers(): create_overlay_space('register', '{REGS_PATH}')")
    t.create_overlay_space('register', REGS_PATH)
    log.debug(f"put_registers(): put_registers('{REGS_PATH}', ...)")
    t.put_registers(REGS_PATH, reg_vals)

    pc = regs.get('PC', regs.get('pc', 0))
    pc_addr = Address('RAM', pc)
    log.debug(f"put_registers(): setting frame PC to Address('RAM', 0x{pc:04X})")
    frame = t.create_object(FRAME_PATH)
    frame.set_value('_display', f'frame @ 0x{pc:04X}')
    frame.set_value('PC', pc_addr)
    frame.insert()

    thread = t.create_object(THREAD_PATH)
    thread.set_value('_display', f'6510 CPU  PC=0x{pc:04X}')
    thread.insert()
    log.debug("put_registers() complete")


# ── Environment population ────────────────────────────────────────────────────

def put_environment(banks_value=None):
    """Populate the Environment node: VICE version, connection, memory banks."""
    t = STATE.trace
    vice = STATE.require_vice()
    version = (
        STATE.require_controller().vice_version
        or vice.vice_info().version_string
    )

    env = t.create_object(ENV_PATH)
    env.set_value('_arch', '6502')
    env.set_value('_os', 'C64')
    env.set_value('_endian', 'little')
    env.set_value('_debugger', f'VICE {version}')
    env.set_value('_display', f'VICE {version} @ {vice.host}:{vice.port}')
    env.insert()

    banks = t.create_object(BANKS_PATH)
    banks.insert()
    # Banks are static per machine; memory reads always use bank 0 (the default bank),
    # so this is informational metadata. Keyed by name: VICE reuses ids (0 is both
    # 'default' and 'cpu').
    for bank in (
        vice.banks_available() if banks_value is None else banks_value
    ):
        obj = t.create_object(BANK_PATH.format(name=bank.name))
        obj.set_value('_display', f'{bank.name} (id {bank.id})')
        obj.set_value('id', bank.id)
        obj.insert()
    log.debug("put_environment() complete")


# ── Memory region population ──────────────────────────────────────────────────

def put_memory_regions():
    """Create static memory region objects."""
    t = STATE.trace
    for region in arch.MEMORY_REGIONS:
        path = MEM_REGION_PATH.format(key=region['key'])
        rng = AddressRange.extend(
            Address('RAM', region['start']),
            region['end'] - region['start'] + 1,
        )
        log.debug(f"put_memory_regions(): {path} _range={rng} "
                  f"_readable={region['readable']} _writable={region['writable']} "
                  f"_executable={region['executable']}")
        obj = t.create_object(path)
        obj.set_value('_display', region['display'])
        obj.set_value('_range', rng)
        obj.set_value('_readable',   region['readable'])
        obj.set_value('_writable',   region['writable'])
        obj.set_value('_executable', region['executable'])
        obj.insert()


def put_memory_bytes(start: int, length: int = 256):
    """
    Read a slice of VICE memory and write it into the trace memory map.
    Called on-demand (e.g. when Ghidra requests a memory refresh).
    """
    vice = STATE.require_vice()
    end = min(start + length - 1, arch.RAM_END)
    data = vice.memory_get(start, end)
    addr = Address('RAM', start)
    with open_tracked_tx(f'Memory 0x{start:04X}-0x{end:04X}'):
        STATE.trace.put_bytes(addr, data)


# ── Breakpoint population ─────────────────────────────────────────────────────

def _cpu_op_to_kinds(cpu_op: int) -> str:
    parts = []
    if cpu_op & CPU_OP_EXEC:
        parts.append('SW_EXECUTE')
    if cpu_op & CPU_OP_LOAD:
        parts.append('READ')
    if cpu_op & CPU_OP_STORE:
        parts.append('WRITE')
    return ','.join(parts) if parts else 'UNKNOWN'


def put_breakpoints():
    """Sync VICE checkpoints into the Ghidra trace breakpoint container."""
    STATE.require_vice()
    t = STATE.trace
    checkpoints = STATE.require_vice().checkpoint_list()
    log.debug(f"put_breakpoints(): {len(checkpoints)} checkpoints")
    put_breakpoints_from(checkpoints)


# ── Execution state helpers ───────────────────────────────────────────────────

def set_process_state_inner(state: str):
    """Update the _state attribute on C64 and Thread (no transaction)."""
    t = STATE.trace
    c64 = t.create_object(C64_PATH)
    c64.set_value('_state', state)
    c64.insert()
    thread = t.create_object(THREAD_PATH)
    thread.set_value('_state', state)
    thread.insert()


def set_process_state(state: str):
    """Update the _state attribute on C64 and Thread (e.g. 'RUNNING', 'STOPPED')."""
    with open_tracked_tx(f'State -> {state}'):
        set_process_state_inner(state)


def put_event_thread():
    """Set _event_thread on the root object so Ghidra knows which thread stopped."""
    t = STATE.trace
    tobj = t.proxy_object_path(THREAD_PATH)
    log.debug(f"put_event_thread(): thread obj = {tobj} (path={getattr(tobj, 'path', '?')})")
    root = t.proxy_object_path('')
    log.debug(f"put_event_thread(): root obj = {root} (path={getattr(root, 'path', '?')})")
    root.set_value('_event_thread', tobj)
    log.debug("put_event_thread() complete")


def on_stop(remaining_ms=_default_remaining_ms):
    """Called by hooks when VICE signals a stop event."""
    log.debug("on_stop() called")
    vice = STATE.require_vice()
    regs = vice.registers_get(timeout_ms=remaining_ms())
    pc = regs.get('PC', regs.get('pc', 0))
    checkpoints = vice.checkpoint_list(timeout_ms=remaining_ms())
    start = max(arch.RAM_START, pc - 0x100)
    end = min(start + 0x400 - 1, arch.RAM_END)
    data = vice.memory_get(start, end, timeout_ms=remaining_ms())
    log.debug(f"on_stop(): PC=0x{pc:04X}")

    # Hold TRACE_LOCK for the entire stop sequence to prevent interleaving
    # with method executor threads (step/resume) or Ghidra refresh callbacks.
    with TRACE_LOCK:
        client = STATE.require_client()
        trace = STATE.require_trace()
        log.debug("on_stop(): starting batch")
        client.start_batch()
        try:
            with trace.open_tx('Stopped') as tx:
                trace.snapshot('Stopped')
                set_process_state_inner('STOPPED')
                put_registers(regs)
                put_breakpoints_from(checkpoints)
                # Read memory around PC for listing context
                log.debug(f"on_stop(): memory 0x{start:04X}-0x{end:04X}")
                trace.put_bytes(Address('RAM', start), data)
                put_event_thread()
        finally:
            log.debug("on_stop(): end_batch")
            _end_batch_checked(client, "on_stop")
        # Disassemble and activate AFTER batch — Ghidra needs committed data first
        log.debug(f"on_stop(): disassemble at Address('RAM', 0x{pc:04X})")
        with trace.open_tx('Disassemble') as tx:
            n = trace.disassemble(Address('RAM', pc))
        log.debug(f"on_stop(): disassemble returned {n}")

        log.debug(f"on_stop(): activate {FRAME_PATH}")
        with trace.open_tx('Activate') as tx:
            trace.proxy_object_path(FRAME_PATH).activate()
    log.debug("on_stop(): complete")


def on_resume():
    """Called by hooks when VICE signals a resume event."""
    log.debug("on_resume() called")
    set_process_state('RUNNING')
    log.debug("on_resume() done")


def sync_event(event, remaining_ms):
    """Synchronize one ordered controller event into the trace."""
    if event.kind == "checkpoint_hit":
        # A non-stopping checkpoint hit leaves VICE running. Synchronizing here
        # would require a monitor command, and every monitor command stops the
        # emulator — so this is deliberately a no-op that takes no snapshot.
        return None
    if event.kind == "stopped":
        on_stop(remaining_ms)
    elif event.kind == "resumed":
        on_resume()
    else:
        raise ValueError(f"Unsupported controller event kind: {event.kind}")
    snap = STATE.require_trace().snap()
    return int(snap) if snap is not None else None


def sync_result(kind: str, result, remaining_ms):
    """Synchronize a completed non-execution operation while its lock is held."""
    client = STATE.require_client()
    trace = STATE.require_trace()
    prepared = result
    if kind == "reset":
        prepared = STATE.require_vice().registers_get(
            timeout_ms=remaining_ms()
        )
    elif kind == "snapshot_load":
        vice = STATE.require_vice()
        memory = vice.memory_get(
            arch.RAM_START,
            arch.RAM_END,
            timeout_ms=remaining_ms(),
        )
        prepared = (
            vice.registers_get(timeout_ms=remaining_ms()),
            vice.checkpoint_list(timeout_ms=remaining_ms()),
            memory,
        )
    elif kind.startswith("memory:") and not isinstance(result, bytes):
        _prefix, start_text, memspace_text, bank_text = kind.split(":")
        start = int(start_text)
        memspace = int(memspace_text)
        bank_id = int(bank_text)
        ranges = result
        if not ranges:
            prepared = b""
        else:
            prepared = STATE.require_vice().memory_get(
                start,
                ranges[-1][1],
                memspace,
                bank_id,
                timeout_ms=remaining_ms(),
            )

    with TRACE_LOCK:
        client.start_batch()
        try:
            with trace.open_tx(f"VICE {kind}"):
                if kind == "registers":
                    put_registers(prepared)
                elif kind == "reset":
                    put_registers(prepared)
                elif kind == "snapshot_load":
                    registers, checkpoints, memory = prepared
                    trace.snapshot("VICE snapshot loaded")
                    set_process_state_inner("STOPPED")
                    put_registers(registers)
                    put_breakpoints_from(checkpoints)
                    trace.put_bytes(Address("RAM", arch.RAM_START), memory)
                    put_event_thread()
                elif kind == "banks":
                    put_environment(prepared)
                elif kind == "checkpoints":
                    put_breakpoints_from(prepared)
                elif kind == "checkpoint_change":
                    _changed, checkpoints = prepared
                    put_breakpoints_from(checkpoints)
                elif kind.startswith("memory:"):
                    _prefix, start_text, memspace_text, bank_text = kind.split(":")
                    start = int(start_text)
                    if prepared:
                        trace.put_bytes(Address("RAM", start), prepared)
                else:
                    raise ValueError(f"Unsupported trace sync kind: {kind}")
        finally:
            _end_batch_checked(client, "sync_trace")
        if kind == "snapshot_load":
            registers, _checkpoints, _memory = prepared
            pc = registers.get("PC", registers.get("pc", 0))
            with trace.open_tx("Disassemble"):
                trace.disassemble(Address("RAM", pc))
            with trace.open_tx("Activate"):
                trace.proxy_object_path(FRAME_PATH).activate()
            snap = trace.snap()
            return int(snap) if snap is not None else None
    return None


def put_breakpoints_from(checkpoints):
    """Write already-observed checkpoint records without another BMP request."""
    t = STATE.require_trace()
    keys = [f"[{cp.number}]" for cp in checkpoints]
    bps = t.create_object(BPS_PATH)
    bps.retain_values(keys, kinds="elements")
    for cp in checkpoints:
        path = BP_PATH.format(n=cp.number)
        obj = t.create_object(path)
        kinds = _cpu_op_to_kinds(cp.cpu_op)
        obj.set_value(
            "_display",
            f"[{cp.number}] 0x{cp.start:04X} {kinds} "
            f"{'EN' if cp.enabled else 'DIS'}",
        )
        obj.set_value(
            "_range",
            AddressRange.extend(
                Address("RAM", cp.start), cp.end - cp.start + 1
            ),
        )
        obj.set_value("_enabled", cp.enabled)
        obj.set_value("_kinds", kinds)
        obj.insert()
