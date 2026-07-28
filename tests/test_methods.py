from unittest.mock import MagicMock, call

import pytest

from vice import automation, commands, methods
from vice.protocol import CPU_OP_EXEC, CPU_OP_LOAD, CPU_OP_STORE


def address(offset):
    from ghidratrace.client import Address
    return Address("RAM", offset)


def address_range(start, end):
    from ghidratrace.client import Address, AddressRange
    return AddressRange(Address("RAM", start), end - start + 1)


@pytest.fixture
def controller():
    value = MagicMock()
    commands.STATE.controller = value
    yield value
    commands.STATE.controller = None


def test_gui_and_automation_methods_share_the_runtime_registry():
    assert methods.REGISTRY.methods["resume"] is methods.resume
    assert (
        methods.REGISTRY.methods["c64_vice_v1_capabilities"]
        is automation.capabilities
    )


def test_execution_controls_use_controller(controller):
    thread = methods.C64Thread()
    methods.resume(thread)
    methods.interrupt(thread)
    methods.step_into(thread)
    methods.step_over(thread)
    methods.step_out(thread)
    controller.resume.assert_called_once_with()
    controller.interrupt.assert_called_once_with()
    controller.step.assert_called_once_with(count=1, step_over=False)
    controller.next.assert_called_once_with(count=1)
    controller.finish.assert_called_once_with()


def test_refresh_registers_and_breakpoints_use_controller(controller):
    methods.refresh_registers(methods.RegisterContainer())
    methods.refresh_breakpoints(methods.BreakpointContainer())
    controller.get_registers.assert_called_once_with()
    controller.list_checkpoints.assert_called_once_with()


def test_refresh_memory_uses_controller_and_trace_sync(controller):
    methods.refresh_memory(methods.MemoryRegion())
    controller.read_memory.assert_called_once_with(
        0, 0xFFFF, sync_trace=True
    )


@pytest.mark.parametrize(
    ("method", "cpu_op"),
    [
        (methods.set_breakpoint_execute, CPU_OP_EXEC),
        (methods.set_watchpoint_read, CPU_OP_LOAD),
        (methods.set_watchpoint_write, CPU_OP_STORE),
    ],
)
def test_breakpoint_creation_uses_controller(controller, method, cpu_op):
    target = address(0xC000) if cpu_op == CPU_OP_EXEC else address_range(
        0xC000, 0xC010
    )
    method(methods.C64(), target)
    expected_end = 0xC000 if cpu_op == CPU_OP_EXEC else 0xC010
    controller.set_checkpoint.assert_called_once_with(
        0xC000, expected_end, cpu_op=cpu_op
    )


def test_delete_and_toggle_breakpoint_use_controller(controller):
    item = methods.ViceBreakpoint()
    item.path = "C64.Breakpoints[7]"
    methods.delete_breakpoint(item)
    methods.toggle_breakpoint(item, True)
    controller.delete_checkpoint.assert_called_once_with(7)
    controller.toggle_checkpoint.assert_called_once_with(7, True)


def test_memory_methods_use_controller(controller):
    methods.read_memory(methods.C64(), address_range(0x2000, 0x20FF))
    methods.write_memory(methods.C64(), address(0x3000), b"\x01\x02")
    controller.read_memory.assert_called_once_with(
        0x2000, 0x20FF, sync_trace=True
    )
    controller.write_memory.assert_called_once_with(0x3000, b"\x01\x02")


@pytest.mark.parametrize(
    ("name", "vice_name"),
    [("S", "SP"), ("P", "FL"), ("PC", "PC"), ("A", "A")],
)
def test_register_write_maps_names(controller, name, vice_name):
    methods.write_register(methods.C64Frame(), name, 0x42)
    controller.set_registers.assert_called_once_with({vice_name: 0x42})


def test_reset_methods_use_controller(controller):
    process = methods.C64()
    methods.reset_soft(process)
    methods.reset_hard(process)
    assert controller.reset.call_args_list == [call(0), call(1)]


def test_methods_require_controller():
    commands.STATE.controller = None
    with pytest.raises(RuntimeError, match="Not connected"):
        methods.resume(methods.C64Thread())
