"""
Tests for methods.py — the Ghidra-facing remote method API.

Validates that each method:
  - Dispatches to the correct VICE command
  - Passes correct parameters
  - Syncs trace state (breakpoints, registers) after mutations
  - Raises when VICE is not connected
"""

from unittest.mock import MagicMock, patch, call

import pytest

from vice import commands, methods, arch
from vice.util import CPU_OP_EXEC, CPU_OP_LOAD, CPU_OP_STORE


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_mock_vice(checkpoints=None):
    vice = MagicMock()
    vice.checkpoint_list.return_value = checkpoints or []
    vice.registers_get.return_value = {
        'PC': 0xC000, 'A': 0, 'X': 0, 'Y': 0, 'SP': 0xFF, 'FL': 0
    }
    return vice


def make_mock_trace():
    trace = MagicMock()
    trace.create_object.return_value = MagicMock()

    class FakeCtx:
        def __enter__(self): return self
        def __exit__(self, *a): pass

    trace.open_tx.return_value = FakeCtx()
    return trace


def make_address(offset):
    """Create a stub Address object."""
    from ghidratrace.client import Address
    return Address('RAM', offset)


def make_range(start, end):
    """Create a stub AddressRange object."""
    from ghidratrace.client import AddressRange, Address
    return AddressRange(Address('RAM', start), end - start + 1)


def make_breakpoint_obj(path):
    """Create a stub ViceBreakpoint with a path."""
    bp = methods.ViceBreakpoint()
    bp.path = path
    return bp


@pytest.fixture(autouse=True)
def reset_state():
    commands.STATE.vice = None
    commands.STATE.client = None
    commands.STATE.trace = None
    commands.STATE.snap = 0
    yield
    commands.STATE.vice = None
    commands.STATE.client = None
    commands.STATE.trace = None


# ── Registration ─────────────────────────────────────────────────────────────

class TestRegistry:
    def test_all_methods_registered(self):
        expected = {
            'resume', 'interrupt', 'step_into', 'step_over', 'step_out',
            'activate_thread', 'activate_frame',
            'refresh_registers', 'refresh_memory', 'refresh_breakpoints',
            'set_breakpoint_execute', 'set_watchpoint_read', 'set_watchpoint_write',
            'delete_breakpoint', 'toggle_breakpoint',
            'read_memory', 'write_memory', 'write_register',
            'reset_soft', 'reset_hard',
        }
        registered = set(methods.REGISTRY.methods.keys())
        assert expected.issubset(registered), (
            f"Missing methods: {expected - registered}"
        )


# ── Execution control ────────────────────────────────────────────────────────

class TestExecutionControl:
    def setup_method(self):
        commands.STATE.vice = make_mock_vice()
        commands.STATE.trace = make_mock_trace()
        commands.STATE.client = MagicMock()

    def test_resume_calls_vice_resume(self):
        methods.resume(methods.C64Thread())
        commands.STATE.vice.resume.assert_called_once()

    def test_interrupt_calls_vice_interrupt(self):
        methods.interrupt(methods.C64Thread())
        commands.STATE.vice.interrupt.assert_called_once()

    def test_step_into_calls_step_no_over(self):
        methods.step_into(methods.C64Thread())
        commands.STATE.vice.step.assert_called_once_with(count=1, step_over=False)

    def test_step_over_calls_step_with_over(self):
        methods.step_over(methods.C64Thread())
        commands.STATE.vice.step.assert_called_once_with(count=1, step_over=True)

    def test_step_out_calls_step_until_return(self):
        methods.step_out(methods.C64Thread())
        commands.STATE.vice.step_until_return.assert_called_once()

    def test_resume_raises_when_not_connected(self):
        commands.STATE.vice = None
        with pytest.raises(RuntimeError, match="Not connected to VICE"):
            methods.resume(methods.C64Thread())

    def test_interrupt_raises_when_not_connected(self):
        commands.STATE.vice = None
        with pytest.raises(RuntimeError):
            methods.interrupt(methods.C64Thread())

    def test_step_into_raises_when_not_connected(self):
        commands.STATE.vice = None
        with pytest.raises(RuntimeError):
            methods.step_into(methods.C64Thread())


# ── Activation ───────────────────────────────────────────────────────────────

class TestActivation:
    def test_activate_thread_is_noop(self):
        # Must not raise, must not need VICE connected
        methods.activate_thread(methods.C64Thread())

    def test_activate_frame_is_noop(self):
        methods.activate_frame(methods.C64Frame())


# ── Breakpoint management ────────────────────────────────────────────────────

class TestBreakpointManagement:
    def setup_method(self):
        commands.STATE.vice = make_mock_vice()
        commands.STATE.trace = make_mock_trace()
        commands.STATE.client = MagicMock()

    def test_set_breakpoint_execute_calls_checkpoint_set(self):
        commands.STATE.vice.checkpoint_set.return_value = 1
        methods.set_breakpoint_execute(methods.C64(), make_address(0xC000))
        commands.STATE.vice.checkpoint_set.assert_called_once_with(
            0xC000, 0xC000, cpu_op=CPU_OP_EXEC
        )

    def test_set_breakpoint_execute_syncs_breakpoints(self):
        commands.STATE.vice.checkpoint_set.return_value = 1
        with patch.object(commands, 'put_breakpoints') as mock_put:
            methods.set_breakpoint_execute(methods.C64(), make_address(0xC000))
            mock_put.assert_called_once()

    def test_set_watchpoint_read_passes_range(self):
        commands.STATE.vice.checkpoint_set.return_value = 2
        methods.set_watchpoint_read(methods.C64(), make_range(0xD400, 0xD41C))
        commands.STATE.vice.checkpoint_set.assert_called_once_with(
            0xD400, 0xD41C, cpu_op=CPU_OP_LOAD
        )

    def test_set_watchpoint_write_passes_range(self):
        commands.STATE.vice.checkpoint_set.return_value = 3
        methods.set_watchpoint_write(methods.C64(), make_range(0xD000, 0xD000))
        commands.STATE.vice.checkpoint_set.assert_called_once_with(
            0xD000, 0xD000, cpu_op=CPU_OP_STORE
        )

    def test_delete_breakpoint_parses_path_index(self):
        bp = make_breakpoint_obj('C64.Breakpoints[7]')
        methods.delete_breakpoint(bp)
        commands.STATE.vice.checkpoint_delete.assert_called_once_with(7)

    def test_delete_breakpoint_syncs_breakpoints(self):
        bp = make_breakpoint_obj('C64.Breakpoints[1]')
        with patch.object(commands, 'put_breakpoints') as mock_put:
            methods.delete_breakpoint(bp)
            mock_put.assert_called_once()

    def test_toggle_breakpoint_enable(self):
        bp = make_breakpoint_obj('C64.Breakpoints[3]')
        methods.toggle_breakpoint(bp, True)
        commands.STATE.vice.checkpoint_toggle.assert_called_once_with(3, True)

    def test_toggle_breakpoint_disable(self):
        bp = make_breakpoint_obj('C64.Breakpoints[3]')
        methods.toggle_breakpoint(bp, False)
        commands.STATE.vice.checkpoint_toggle.assert_called_once_with(3, False)

    def test_toggle_breakpoint_syncs(self):
        bp = make_breakpoint_obj('C64.Breakpoints[3]')
        with patch.object(commands, 'put_breakpoints') as mock_put:
            methods.toggle_breakpoint(bp, True)
            mock_put.assert_called_once()

    def test_delete_breakpoint_raises_when_not_connected(self):
        commands.STATE.vice = None
        bp = make_breakpoint_obj('C64.Breakpoints[1]')
        with pytest.raises(RuntimeError):
            methods.delete_breakpoint(bp)


class TestBreakpointPathParsing:
    """The path parsing logic is fragile — test edge cases."""
    def setup_method(self):
        commands.STATE.vice = make_mock_vice()
        commands.STATE.trace = make_mock_trace()
        commands.STATE.client = MagicMock()

    def test_single_digit_index(self):
        bp = make_breakpoint_obj('C64.Breakpoints[5]')
        methods.delete_breakpoint(bp)
        commands.STATE.vice.checkpoint_delete.assert_called_with(5)

    def test_multi_digit_index(self):
        bp = make_breakpoint_obj('C64.Breakpoints[42]')
        methods.delete_breakpoint(bp)
        commands.STATE.vice.checkpoint_delete.assert_called_with(42)

    def test_large_index(self):
        bp = make_breakpoint_obj('C64.Breakpoints[1000]')
        methods.delete_breakpoint(bp)
        commands.STATE.vice.checkpoint_delete.assert_called_with(1000)


# ── Memory read/write ────────────────────────────────────────────────────────

class TestMemoryMethods:
    def setup_method(self):
        commands.STATE.vice = make_mock_vice()
        commands.STATE.trace = make_mock_trace()
        commands.STATE.client = MagicMock()

    def test_read_memory_calls_put_memory_bytes(self):
        commands.STATE.vice.memory_get.return_value = b'\x00' * 16
        with patch.object(commands, 'put_memory_bytes') as mock_put:
            methods.read_memory(methods.C64(), make_range(0x1000, 0x100F))
            mock_put.assert_called_once_with(0x1000, 16)

    def test_write_memory_calls_vice_memory_set(self):
        data = b'\xA9\x42\x60'
        methods.write_memory(methods.C64(), make_address(0xC000), data)
        commands.STATE.vice.memory_set.assert_called_once_with(0xC000, data)

    def test_write_memory_raises_when_not_connected(self):
        commands.STATE.vice = None
        with pytest.raises(RuntimeError):
            methods.write_memory(methods.C64(), make_address(0xC000), b'\x00')


# ── Register write ───────────────────────────────────────────────────────────

class TestWriteRegister:
    def setup_method(self):
        commands.STATE.vice = make_mock_vice()
        commands.STATE.trace = make_mock_trace()
        commands.STATE.client = MagicMock()

    def test_write_register_maps_ghidra_S_to_vice_SP(self):
        methods.write_register(methods.C64Frame(), 'S', 0xFD)
        commands.STATE.vice.registers_set.assert_called_once_with({'SP': 0xFD})

    def test_write_register_maps_ghidra_P_to_vice_FL(self):
        methods.write_register(methods.C64Frame(), 'P', 0x30)
        commands.STATE.vice.registers_set.assert_called_once_with({'FL': 0x30})

    def test_write_register_PC_unchanged(self):
        methods.write_register(methods.C64Frame(), 'PC', 0xC000)
        commands.STATE.vice.registers_set.assert_called_once_with({'PC': 0xC000})

    def test_write_register_A_unchanged(self):
        methods.write_register(methods.C64Frame(), 'A', 0x42)
        commands.STATE.vice.registers_set.assert_called_once_with({'A': 0x42})

    def test_write_register_syncs_trace(self):
        with patch.object(commands, 'put_registers') as mock_put:
            methods.write_register(methods.C64Frame(), 'A', 0x42)
            mock_put.assert_called_once()

    def test_write_register_raises_when_not_connected(self):
        commands.STATE.vice = None
        with pytest.raises(RuntimeError):
            methods.write_register(methods.C64Frame(), 'A', 0)

    def test_write_register_unknown_name_passed_through(self):
        """Unknown Ghidra name should be passed as-is to VICE."""
        methods.write_register(methods.C64Frame(), 'LIN', 0x100)
        commands.STATE.vice.registers_set.assert_called_once_with({'LIN': 0x100})


# ── Machine control ──────────────────────────────────────────────────────────

class TestMachineControl:
    def setup_method(self):
        commands.STATE.vice = make_mock_vice()

    def test_reset_soft_sends_type_0(self):
        methods.reset_soft(methods.C64())
        commands.STATE.vice.reset.assert_called_once_with(0)

    def test_reset_hard_sends_type_1(self):
        methods.reset_hard(methods.C64())
        commands.STATE.vice.reset.assert_called_once_with(1)

    def test_reset_soft_raises_when_not_connected(self):
        commands.STATE.vice = None
        with pytest.raises(RuntimeError):
            methods.reset_soft(methods.C64())


# ── Refresh methods ──────────────────────────────────────────────────────────

class TestRefreshMethods:
    def setup_method(self):
        commands.STATE.vice = make_mock_vice()
        commands.STATE.trace = make_mock_trace()
        commands.STATE.client = MagicMock()

    def test_refresh_registers_calls_put_registers(self):
        with patch.object(commands, 'put_registers') as mock_put:
            methods.refresh_registers(methods.RegisterContainer())
            mock_put.assert_called_once()

    def test_refresh_breakpoints_calls_put_breakpoints(self):
        with patch.object(commands, 'put_breakpoints') as mock_put:
            methods.refresh_breakpoints(methods.BreakpointContainer())
            mock_put.assert_called_once()

    def test_refresh_registers_raises_when_not_connected(self):
        commands.STATE.vice = None
        with pytest.raises(RuntimeError):
            methods.refresh_registers(methods.RegisterContainer())

    def test_refresh_memory_calls_put_memory_bytes_multiple_times(self):
        """refresh_memory reads full 64KB in chunks."""
        commands.STATE.vice.memory_get.return_value = b'\x00' * 0x1000
        with patch.object(commands, 'put_memory_bytes') as mock_put:
            methods.refresh_memory(methods.MemoryRegion())
            # 64KB / 4KB = 16 calls
            assert mock_put.call_count == 16
