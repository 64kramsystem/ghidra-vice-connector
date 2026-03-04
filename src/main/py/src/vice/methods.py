"""
Remote methods — actions Ghidra can invoke from the debugger UI
(toolbar buttons, right-click menus, keyboard shortcuts).

Each method is decorated with @REGISTRY.method and maps to a Ghidra action.
The 'action' keyword controls which built-in Ghidra action the button binds to.
"""

import logging
from concurrent.futures import ThreadPoolExecutor

from ghidratrace.client import Address, AddressRange, MethodRegistry, TraceObject

from . import arch, commands
from .util import CPU_OP_EXEC, CPU_OP_LOAD, CPU_OP_STORE

log = logging.getLogger('vice-agent')

REGISTRY = MethodRegistry(ThreadPoolExecutor())


# ── Schema type stubs (match names in schema.xml) ────────────────────────────

class C64(TraceObject):
    pass

class C64Thread(TraceObject):
    pass

class C64Frame(TraceObject):
    pass

class RegisterContainer(TraceObject):
    pass

class MemoryRegion(TraceObject):
    pass

class BreakpointContainer(TraceObject):
    pass

class ViceBreakpoint(TraceObject):
    pass


# ── Execution control ─────────────────────────────────────────────────────────

@REGISTRY.method(action='resume', display='Resume')
def resume(thread: C64Thread):
    """Resume execution."""
    log.info("resume: called")
    commands.STATE.require_vice().resume()


@REGISTRY.method(action='interrupt', display='Interrupt')
def interrupt(thread: C64Thread):
    """Interrupt (pause) execution — sending any command causes VICE to stop."""
    log.info("interrupt: called")
    # Send fire-and-forget ping — forces VICE into monitor mode.
    # The RESP_STOPPED event handler will call on_stop() to update state.
    commands.STATE.require_vice().interrupt()


@REGISTRY.method(action='step_into', display='Step Into')
def step_into(thread: C64Thread):
    """Execute one instruction."""
    log.info("step_into: called")
    commands.STATE.require_vice().step(count=1, step_over=False)


@REGISTRY.method(action='step_over', display='Step Over')
def step_over(thread: C64Thread):
    """Execute one instruction, stepping over JSR."""
    log.info("step_over: called")
    commands.STATE.require_vice().step(count=1, step_over=True)


@REGISTRY.method(action='step_out', display='Step Out (Until RTS)')
def step_out(thread: C64Thread):
    """Continue until RTS/RTI."""
    log.info("step_out: called")
    commands.STATE.require_vice().step_until_return()


# ── Activation (focus) methods ───────────────────────────────────────────────
# Following the GDB/Frida agent pattern: Ghidra pushes focus via activate().

@REGISTRY.method(action='activate', display='Activate')
def activate_thread(thread: C64Thread):
    """Set the active thread (single-CPU — no-op, but required by Ghidra)."""
    pass


@REGISTRY.method(action='activate', display='Activate')
def activate_frame(frame: C64Frame):
    """Set the active stack frame (single-frame — no-op, but required by Ghidra)."""
    pass


# ── Refresh methods ───────────────────────────────────────────────────────────

@REGISTRY.method(action='refresh', display='Refresh Registers')
def refresh_registers(node: RegisterContainer):
    """Re-read all CPU registers from VICE."""
    commands.STATE.require_vice()
    with commands.TRACE_LOCK:
        commands.STATE.require_client().start_batch()
        try:
            with commands.STATE.require_trace().open_tx('Refresh registers'):
                commands.put_registers()
        finally:
            commands.STATE.require_client().end_batch()


@REGISTRY.method(action='refresh', display='Refresh Memory')
def refresh_memory(node: MemoryRegion):
    """Re-read the 64 KB address space from VICE."""
    commands.STATE.require_vice()
    CHUNK = 0x1000
    for start in range(arch.RAM_START, arch.RAM_END + 1, CHUNK):
        length = min(CHUNK, arch.RAM_END - start + 1)
        commands.put_memory_bytes(start, length)


@REGISTRY.method(action='refresh', display='Refresh Breakpoints')
def refresh_breakpoints(node: BreakpointContainer):
    """Re-sync VICE checkpoints."""
    commands.STATE.require_vice()
    with commands.open_tracked_tx('Refresh breakpoints'):
        commands.put_breakpoints()


# ── Breakpoint management ─────────────────────────────────────────────────────

@REGISTRY.method(action='break_sw_execute', display='Set Execute Breakpoint')
def set_breakpoint_execute(process: C64, address: Address):
    """Set an execution breakpoint at the given address."""
    vice = commands.STATE.require_vice()
    n = vice.checkpoint_set(address.offset, address.offset, cpu_op=CPU_OP_EXEC)
    with commands.open_tracked_tx(f'Add breakpoint {n}'):
        commands.put_breakpoints()


@REGISTRY.method(action='break_read', display='Set Read Watchpoint')
def set_watchpoint_read(process: C64, range: AddressRange):
    """Set a read watchpoint on an address range."""
    vice = commands.STATE.require_vice()
    n = vice.checkpoint_set(range.min.offset, range.max.offset, cpu_op=CPU_OP_LOAD)
    with commands.open_tracked_tx(f'Add watchpoint {n}'):
        commands.put_breakpoints()


@REGISTRY.method(action='break_write', display='Set Write Watchpoint')
def set_watchpoint_write(process: C64, range: AddressRange):
    """Set a write watchpoint on an address range."""
    vice = commands.STATE.require_vice()
    n = vice.checkpoint_set(range.min.offset, range.max.offset, cpu_op=CPU_OP_STORE)
    with commands.open_tracked_tx(f'Add watchpoint {n}'):
        commands.put_breakpoints()


@REGISTRY.method(action='delete', display='Delete Breakpoint')
def delete_breakpoint(breakpoint: ViceBreakpoint):
    """Delete a VICE checkpoint by its object path index."""
    vice = commands.STATE.require_vice()
    n = int(breakpoint.path.split('[')[-1].rstrip(']'))
    vice.checkpoint_delete(n)
    with commands.open_tracked_tx(f'Delete breakpoint {n}'):
        commands.put_breakpoints()


@REGISTRY.method(action='toggle', display='Toggle Breakpoint')
def toggle_breakpoint(breakpoint: ViceBreakpoint, enabled: bool):
    """Enable or disable a VICE checkpoint."""
    vice = commands.STATE.require_vice()
    n = int(breakpoint.path.split('[')[-1].rstrip(']'))
    vice.checkpoint_toggle(n, enabled)
    with commands.open_tracked_tx(f'Toggle breakpoint {n}'):
        commands.put_breakpoints()


# ── Memory read/write ─────────────────────────────────────────────────────────

@REGISTRY.method(action='read_mem', display='Read Memory')
def read_memory(process: C64, range: AddressRange):
    """Refresh a specific memory range from VICE."""
    commands.STATE.require_vice()
    start  = range.min.offset
    length = range.max.offset - start + 1
    commands.put_memory_bytes(start, length)


@REGISTRY.method(action='write_mem', display='Write Memory')
def write_memory(process: C64, address: Address, data: bytes):
    """Write bytes into VICE memory at the given address."""
    commands.STATE.require_vice().memory_set(address.offset, data)


# ── Register write ───────────────────────────────────────────────────────────

@REGISTRY.method(action='write_reg', display='Write Register')
def write_register(frame: C64Frame, name: str, value: int):
    """Write a single register value to VICE."""
    vice = commands.STATE.require_vice()
    # Map Ghidra register name back to VICE name
    ghidra_to_vice = {v: k for k, v in arch.VICE_TO_GHIDRA_REG.items()}
    vice_name = ghidra_to_vice.get(name, name)
    vice.registers_set({vice_name: value})
    # Refresh registers in the trace so Ghidra sees the update
    with commands.open_tracked_tx('Write register'):
        commands.put_registers()


# ── Machine control ───────────────────────────────────────────────────────────

@REGISTRY.method(display='Reset (Soft)')
def reset_soft(process: C64):
    """Trigger a soft reset of the C64."""
    commands.STATE.require_vice().reset(0)


@REGISTRY.method(display='Reset (Hard)')
def reset_hard(process: C64):
    """Trigger a hard reset of the C64."""
    commands.STATE.require_vice().reset(1)
