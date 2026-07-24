"""
Remote methods — actions Ghidra can invoke from the debugger UI
(toolbar buttons, right-click menus, keyboard shortcuts).

Each method is decorated with @REGISTRY.method and maps to a Ghidra action.
The 'action' keyword controls which built-in Ghidra action the button binds to.
"""

import logging
from typing import Annotated

from ghidratrace.client import Address, AddressRange, ParamDesc

from . import arch, commands
from .protocol import CPU_OP_EXEC, CPU_OP_LOAD, CPU_OP_STORE
from .registry import REGISTRY
from .schema_types import (
    BreakpointContainer,
    C64,
    C64Frame,
    C64Thread,
    MemoryRegion,
    RegisterContainer,
    ViceBreakpoint,
)

log = logging.getLogger('vice-agent')

# ── Execution control ─────────────────────────────────────────────────────────

@REGISTRY.method(action='resume', display='Resume')
def resume(thread: C64Thread):
    """Resume execution."""
    log.info("resume: called")
    commands.STATE.require_controller().resume()


@REGISTRY.method(action='interrupt', display='Interrupt')
def interrupt(thread: C64Thread):
    """Interrupt (pause) execution — sending any command causes VICE to stop."""
    log.info("interrupt: called")
    commands.STATE.require_controller().interrupt()


@REGISTRY.method(action='step_into', display='Step Into')
def step_into(thread: C64Thread):
    """Execute one instruction."""
    log.info("step_into: called")
    commands.STATE.require_controller().step(count=1, step_over=False)


@REGISTRY.method(action='step_over', display='Step Over')
def step_over(thread: C64Thread):
    """Execute one instruction, stepping over JSR."""
    log.info("step_over: called")
    commands.STATE.require_controller().next(count=1)


@REGISTRY.method(action='step_out', display='Step Out (Until RTS)')
def step_out(thread: C64Thread):
    """Continue until RTS/RTI."""
    log.info("step_out: called")
    commands.STATE.require_controller().finish()


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
    commands.STATE.require_controller().get_registers()


@REGISTRY.method(action='refresh', display='Refresh Memory')
def refresh_memory(node: MemoryRegion):
    """Re-read the 64 KB address space from VICE."""
    commands.STATE.require_controller().read_memory(
        arch.RAM_START, arch.RAM_END, sync_trace=True
    )


@REGISTRY.method(action='refresh', display='Refresh Breakpoints')
def refresh_breakpoints(node: BreakpointContainer):
    """Re-sync VICE checkpoints."""
    commands.STATE.require_controller().list_checkpoints()


# ── Breakpoint management ─────────────────────────────────────────────────────

@REGISTRY.method(action='break_sw_execute', display='Set Execute Breakpoint')
def set_breakpoint_execute(process: C64,
                           address: Annotated[Address, ParamDesc(display='Address')]):
    """Set an execution breakpoint at the given address."""
    commands.STATE.require_controller().set_checkpoint(
        address.offset, address.offset, cpu_op=CPU_OP_EXEC
    )


@REGISTRY.method(action='break_read', display='Set Read Watchpoint')
def set_watchpoint_read(process: C64,
                        range: Annotated[AddressRange, ParamDesc(display='Range')]):
    """Set a read watchpoint on an address range."""
    commands.STATE.require_controller().set_checkpoint(
        range.min.offset, range.max.offset, cpu_op=CPU_OP_LOAD
    )


@REGISTRY.method(action='break_write', display='Set Write Watchpoint')
def set_watchpoint_write(process: C64,
                         range: Annotated[AddressRange, ParamDesc(display='Range')]):
    """Set a write watchpoint on an address range."""
    commands.STATE.require_controller().set_checkpoint(
        range.min.offset, range.max.offset, cpu_op=CPU_OP_STORE
    )


@REGISTRY.method(action='delete', display='Delete Breakpoint')
def delete_breakpoint(breakpoint: ViceBreakpoint):
    """Delete a VICE checkpoint by its object path index."""
    n = int(breakpoint.path.split('[')[-1].rstrip(']'))
    commands.STATE.require_controller().delete_checkpoint(n)


@REGISTRY.method(action='toggle', display='Toggle Breakpoint')
def toggle_breakpoint(breakpoint: ViceBreakpoint,
                      enabled: Annotated[bool, ParamDesc(display='Enabled')]):
    """Enable or disable a VICE checkpoint."""
    n = int(breakpoint.path.split('[')[-1].rstrip(']'))
    commands.STATE.require_controller().toggle_checkpoint(n, enabled)


# ── Memory read/write ─────────────────────────────────────────────────────────

@REGISTRY.method(action='read_mem', display='Read Memory')
def read_memory(process: C64,
                range: Annotated[AddressRange, ParamDesc(display='Range')]):
    """Refresh a specific memory range from VICE."""
    start  = range.min.offset
    commands.STATE.require_controller().read_memory(
        start, range.max.offset, sync_trace=True
    )


@REGISTRY.method(action='write_mem', display='Write Memory')
def write_memory(process: C64,
                 address: Annotated[Address, ParamDesc(display='Address')],
                 data: Annotated[bytes, ParamDesc(display='Data')]):
    """Write bytes into VICE memory at the given address."""
    commands.STATE.require_controller().write_memory(address.offset, data)


# ── Register write ───────────────────────────────────────────────────────────

@REGISTRY.method(action='write_reg', display='Write Register')
def write_register(frame: C64Frame,
                   name: Annotated[str, ParamDesc(display='Register')],
                   value: Annotated[int, ParamDesc(display='Value')]):
    """Write a single register value to VICE."""
    controller = commands.STATE.require_controller()
    # Map Ghidra register name back to VICE name
    ghidra_to_vice = {v: k for k, v in arch.VICE_TO_GHIDRA_REG.items()}
    vice_name = ghidra_to_vice.get(name, name)
    controller.set_registers({vice_name: value})


# ── Machine control ───────────────────────────────────────────────────────────

@REGISTRY.method(display='Reset (Soft)')
def reset_soft(process: C64):
    """Trigger a soft reset of the C64."""
    commands.STATE.require_controller().reset(0)


@REGISTRY.method(display='Reset (Hard)')
def reset_hard(process: C64):
    """Trigger a hard reset of the C64."""
    commands.STATE.require_controller().reset(1)


# Register the versioned automation surface in the same single-worker registry.
from . import automation as _automation  # noqa: E402,F401
