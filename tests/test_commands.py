"""
Tests for commands.py trace-population logic.

ViceBmpClient and the ghidratrace Client/Trace are both mocked so these
tests focus purely on the orchestration logic: correct method calls,
correct path strings, correct attribute values.
"""

import struct
from unittest.mock import MagicMock, call, patch, PropertyMock

import pytest

# ghidratrace stubs are installed by conftest.py before this import
from vice import commands, arch
from vice.util import CPU_OP_EXEC, CPU_OP_LOAD, CPU_OP_STORE


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_mock_vice(registers=None, checkpoints=None):
    """Return a MagicMock ViceBmpClient pre-loaded with fixture data."""
    vice = MagicMock()
    vice.registers_get.return_value = registers or {
        'PC': 0xC000, 'A': 0x41, 'X': 0x00, 'Y': 0xFF, 'SP': 0xFD, 'FLAGS': 0x30
    }
    vice.checkpoint_list.return_value = checkpoints or []
    return vice


def make_mock_trace():
    """Return a MagicMock trace with a working create_object that returns a stub."""
    trace = MagicMock()
    obj = MagicMock()
    trace.create_object.return_value = obj

    class FakeCtx:
        def __enter__(self): return self
        def __exit__(self, *a): pass

    trace.open_tx.return_value = FakeCtx()
    return trace


@pytest.fixture(autouse=True)
def reset_state():
    """Reset commands.STATE before each test."""
    commands.STATE.vice   = None
    commands.STATE.client = None
    commands.STATE.trace  = None
    commands.STATE.snap   = 0
    yield
    commands.STATE.vice   = None
    commands.STATE.client = None
    commands.STATE.trace  = None


# ── require_vice / require_trace ───────────────────────────────────────────────

class TestGuards:
    def test_require_vice_raises_when_not_connected(self):
        with pytest.raises(RuntimeError, match="Not connected"):
            commands.require_vice()

    def test_require_vice_passes_when_connected(self):
        commands.STATE.vice = MagicMock()
        commands.require_vice()  # must not raise

    def test_require_trace_raises_when_not_started(self):
        with pytest.raises(RuntimeError, match="Trace not started"):
            commands.require_trace()

    def test_require_trace_passes_when_started(self):
        commands.STATE.trace = MagicMock()
        commands.require_trace()  # must not raise


# ── put_registers ──────────────────────────────────────────────────────────────

class TestPutRegisters:
    def setup_method(self):
        commands.STATE.vice  = make_mock_vice()
        commands.STATE.trace = make_mock_trace()

    def test_calls_registers_get(self):
        commands.put_registers()
        commands.STATE.vice.registers_get.assert_called_once()

    def test_creates_register_objects(self):
        commands.put_registers()
        paths_created = [c.args[0] for c in commands.STATE.trace.create_object.call_args_list]
        # At minimum PC, A, X, Y, SP, FLAGS (mapped to Ghidra names) must appear
        assert any('Registers' in p for p in paths_created)

    def test_register_path_uses_ghidra_name(self):
        commands.put_registers()
        paths = [c.args[0] for c in commands.STATE.trace.create_object.call_args_list]
        # VICE 'PC' → Ghidra 'PC' (same); 'FLAGS' → 'P'; 'SP' → 'S'
        reg_paths = [p for p in paths if 'Registers[' in p]
        reg_names = {p.split('[')[-1].rstrip(']') for p in reg_paths}
        assert 'PC' in reg_names

    def test_frame_display_updated_with_pc(self):
        commands.STATE.vice.registers_get.return_value = {
            'PC': 0xC123, 'A': 0, 'X': 0, 'Y': 0, 'SP': 0xFF, 'FLAGS': 0
        }
        commands.put_registers()
        obj = commands.STATE.trace.create_object.return_value
        display_calls = [c for c in obj.set_value.call_args_list
                         if c.args[0] == '_display']
        display_values = [c.args[1] for c in display_calls]
        assert any('C123' in str(v).upper() for v in display_values)


# ── put_memory_regions ─────────────────────────────────────────────────────────

class TestPutMemoryRegions:
    def setup_method(self):
        commands.STATE.trace = make_mock_trace()

    def test_creates_memory_region_objects(self):
        commands.put_memory_regions()
        paths = [c.args[0] for c in commands.STATE.trace.create_object.call_args_list]
        assert any('Memory' in p for p in paths)

    def test_creates_ram_region(self):
        commands.put_memory_regions()
        paths = [c.args[0] for c in commands.STATE.trace.create_object.call_args_list]
        assert any('ram' in p for p in paths)

    def test_sets_readable_writable_executable(self):
        commands.put_memory_regions()
        obj = commands.STATE.trace.create_object.return_value
        attr_names = [c.args[0] for c in obj.set_value.call_args_list]
        assert '_readable'   in attr_names
        assert '_writable'   in attr_names
        assert '_executable' in attr_names


# ── put_breakpoints ────────────────────────────────────────────────────────────

class TestPutBreakpoints:
    def setup_method(self):
        commands.STATE.vice  = make_mock_vice()
        commands.STATE.trace = make_mock_trace()

    def test_no_breakpoints_no_bp_objects(self):
        commands.STATE.vice.checkpoint_list.return_value = []
        commands.put_breakpoints()
        paths = [c.args[0] for c in commands.STATE.trace.create_object.call_args_list]
        bp_paths = [p for p in paths if 'Breakpoints[' in p]
        assert bp_paths == []

    def test_single_breakpoint_creates_object(self):
        commands.STATE.vice.checkpoint_list.return_value = [{
            'number': 1, 'start': 0xC000, 'end': 0xC000,
            'enabled': True, 'cpu_op': CPU_OP_EXEC,
        }]
        commands.put_breakpoints()
        paths = [c.args[0] for c in commands.STATE.trace.create_object.call_args_list]
        assert any('Breakpoints[1]' in p for p in paths)

    def test_breakpoint_display_includes_address(self):
        commands.STATE.vice.checkpoint_list.return_value = [{
            'number': 1, 'start': 0xD020, 'end': 0xD020,
            'enabled': True, 'cpu_op': CPU_OP_STORE,
        }]
        commands.put_breakpoints()
        obj = commands.STATE.trace.create_object.return_value
        display_calls = [c for c in obj.set_value.call_args_list
                         if c.args[0] == '_display']
        display_values = [c.args[1] for c in display_calls]
        assert any('D020' in str(v).upper() for v in display_values)

    def test_multiple_breakpoints_all_created(self):
        commands.STATE.vice.checkpoint_list.return_value = [
            {'number': 1, 'start': 0xC000, 'end': 0xC000, 'enabled': True, 'cpu_op': CPU_OP_EXEC},
            {'number': 2, 'start': 0xD000, 'end': 0xD000, 'enabled': True, 'cpu_op': CPU_OP_LOAD},
            {'number': 3, 'start': 0xD400, 'end': 0xD41C, 'enabled': False, 'cpu_op': CPU_OP_STORE},
        ]
        commands.put_breakpoints()
        paths = [c.args[0] for c in commands.STATE.trace.create_object.call_args_list]
        bp_paths = [p for p in paths if 'Breakpoints[' in p]
        assert len(bp_paths) == 3


# ── _cpu_op_to_kinds ───────────────────────────────────────────────────────────

class TestCpuOpToKinds:
    def test_exec(self):
        result = commands._cpu_op_to_kinds(CPU_OP_EXEC)
        assert 'SW_EXECUTE' in result

    def test_load(self):
        result = commands._cpu_op_to_kinds(CPU_OP_LOAD)
        assert 'READ' in result

    def test_store(self):
        result = commands._cpu_op_to_kinds(CPU_OP_STORE)
        assert 'WRITE' in result

    def test_combined_load_store(self):
        result = commands._cpu_op_to_kinds(CPU_OP_LOAD | CPU_OP_STORE)
        assert 'READ'  in result
        assert 'WRITE' in result

    def test_unknown_op(self):
        result = commands._cpu_op_to_kinds(0x00)
        assert result == 'UNKNOWN'

    def test_all_three(self):
        result = commands._cpu_op_to_kinds(CPU_OP_EXEC | CPU_OP_LOAD | CPU_OP_STORE)
        assert 'SW_EXECUTE' in result
        assert 'READ'        in result
        assert 'WRITE'       in result


# ── on_stop / on_resume ────────────────────────────────────────────────────────

class TestStopResume:
    def setup_method(self):
        commands.STATE.vice   = make_mock_vice()
        commands.STATE.trace  = make_mock_trace()
        commands.STATE.client = MagicMock()

    def test_on_stop_calls_put_registers(self):
        with patch.object(commands, 'put_registers') as mock_put:
            commands.on_stop()
            mock_put.assert_called_once()

    def test_on_stop_sets_state_stopped(self):
        commands.on_stop()
        obj = commands.STATE.trace.create_object.return_value
        state_calls = [c for c in obj.set_value.call_args_list
                       if c.args[0] == '_state']
        states = [c.args[1] for c in state_calls]
        assert 'STOPPED' in states

    def test_on_stop_saves_trace(self):
        commands.on_stop()
        commands.STATE.trace.save.assert_called()

    def test_on_resume_sets_state_running(self):
        commands.on_resume()
        obj = commands.STATE.trace.create_object.return_value
        state_calls = [c for c in obj.set_value.call_args_list
                       if c.args[0] == '_state']
        states = [c.args[1] for c in state_calls]
        assert 'RUNNING' in states

    def test_on_resume_does_not_save_trace(self):
        """on_resume() only updates state — it does not save the trace.
        (RUNNING is transient; save happens on the next STOPPED event.)"""
        commands.on_resume()
        commands.STATE.trace.save.assert_not_called()

    def test_on_stop_does_not_set_running(self):
        commands.on_stop()
        obj = commands.STATE.trace.create_object.return_value
        state_calls = [c for c in obj.set_value.call_args_list
                       if c.args[0] == '_state']
        states = [c.args[1] for c in state_calls]
        assert 'RUNNING' not in states


# ── path constant consistency ──────────────────────────────────────────────────

class TestPathConstants:
    """
    Path strings in commands.py must be consistent with the schema hierarchy
    defined in schema_vice.xml.
    """

    def test_thread_path_is_child_of_c64(self):
        assert commands.THREAD_PATH.startswith(commands.C64_PATH + '.')

    def test_frame_path_is_child_of_thread(self):
        assert commands.FRAME_PATH.startswith(commands.THREAD_PATH + '.')

    def test_regs_path_is_child_of_frame(self):
        assert commands.REGS_PATH.startswith(commands.FRAME_PATH + '.')

    def test_mem_path_is_child_of_c64(self):
        assert commands.MEM_PATH.startswith(commands.C64_PATH + '.')

    def test_bps_path_is_child_of_c64(self):
        assert commands.BPS_PATH.startswith(commands.C64_PATH + '.')

    def test_reg_path_template_contains_name(self):
        assert '{name}' in commands.REG_PATH

    def test_bp_path_template_contains_n(self):
        assert '{n}' in commands.BP_PATH

    def test_reg_path_instantiation(self):
        p = commands.REG_PATH.format(name='PC')
        assert p.startswith(commands.REGS_PATH)
        assert p.endswith('[PC]')

    def test_bp_path_instantiation(self):
        p = commands.BP_PATH.format(n=3)
        assert p.startswith(commands.BPS_PATH)
        assert p.endswith('[3]')

    def test_mem_region_path_template_contains_key(self):
        assert '{key}' in commands.MEM_REGION_PATH

    def test_mem_region_path_instantiation(self):
        p = commands.MEM_REGION_PATH.format(key='ram')
        assert p.startswith(commands.MEM_PATH)
        assert p.endswith('[ram]')


# ── put_registers detailed checks ────────────────────────────────────────────

class TestPutRegistersDetailed:
    """Test that put_registers builds correct RegVal byte representations."""
    def setup_method(self):
        commands.STATE.vice  = make_mock_vice(registers={
            'PC': 0xC000, 'A': 0x41, 'X': 0x10, 'Y': 0xFF, 'SP': 0xFD, 'FL': 0x30
        })
        commands.STATE.trace = make_mock_trace()

    def test_pc_is_big_endian_2_bytes(self):
        """PC is 16-bit and packed as big-endian for Ghidra's register space."""
        commands.put_registers()
        # put_registers calls trace.put_registers(REGS_PATH, reg_vals)
        call_args = commands.STATE.trace.put_registers.call_args
        reg_vals = call_args.args[1]
        pc_val = next(r for r in reg_vals if r.name == 'PC')
        assert pc_val.value == struct.pack('>H', 0xC000)
        assert len(pc_val.value) == 2

    def test_8bit_regs_are_single_byte(self):
        """A, X, Y, S, P are 8-bit — packed as single bytes."""
        commands.put_registers()
        call_args = commands.STATE.trace.put_registers.call_args
        reg_vals = call_args.args[1]
        a_val = next(r for r in reg_vals if r.name == 'A')
        assert a_val.value == bytes([0x41])
        assert len(a_val.value) == 1

    def test_sp_mapped_to_ghidra_S(self):
        """VICE 'SP' maps to Ghidra '6502' register 'S'."""
        commands.put_registers()
        call_args = commands.STATE.trace.put_registers.call_args
        reg_vals = call_args.args[1]
        names = [r.name for r in reg_vals]
        assert 'S' in names
        assert 'SP' not in names

    def test_fl_mapped_to_ghidra_P(self):
        """VICE 'FL' maps to Ghidra 6502 register 'P'."""
        commands.put_registers()
        call_args = commands.STATE.trace.put_registers.call_args
        reg_vals = call_args.args[1]
        names = [r.name for r in reg_vals]
        assert 'P' in names
        assert 'FL' not in names

    def test_unknown_vice_reg_excluded_from_regvals(self):
        """Registers not in VICE_TO_GHIDRA_REG are shown as objects but
        excluded from the put_registers() RegVal list."""
        commands.STATE.vice.registers_get.return_value = {
            'PC': 0xC000, 'A': 0, 'X': 0, 'Y': 0, 'SP': 0, 'FL': 0,
            'LIN': 0,  # extra register not in the mapping
        }
        commands.put_registers()
        call_args = commands.STATE.trace.put_registers.call_args
        reg_vals = call_args.args[1]
        names = [r.name for r in reg_vals]
        assert 'LIN' not in names


# ── on_stop memory window edge cases ─────────────────────────────────────────

class TestOnStopMemoryWindow:
    """Verify on_stop reads a sensible memory window even when PC is near edges."""
    def setup_method(self):
        commands.STATE.vice   = make_mock_vice()
        commands.STATE.trace  = make_mock_trace()
        commands.STATE.client = MagicMock()

    def test_pc_near_zero(self):
        """PC=0x0010: memory window start should clamp to 0x0000."""
        commands.STATE.vice.registers_get.return_value = {
            'PC': 0x0010, 'A': 0, 'X': 0, 'Y': 0, 'SP': 0xFF, 'FL': 0
        }
        commands.STATE.vice.memory_get.return_value = b'\x00' * 0x400
        commands.on_stop()
        start_arg = commands.STATE.vice.memory_get.call_args.args[0]
        assert start_arg == 0x0000

    def test_pc_near_end(self):
        """PC=0xFFF0: memory window end should clamp to 0xFFFF."""
        commands.STATE.vice.registers_get.return_value = {
            'PC': 0xFFF0, 'A': 0, 'X': 0, 'Y': 0, 'SP': 0xFF, 'FL': 0
        }
        commands.STATE.vice.memory_get.return_value = b'\x00' * 0x400
        commands.on_stop()
        end_arg = commands.STATE.vice.memory_get.call_args.args[1]
        assert end_arg <= 0xFFFF

    def test_pc_at_zero(self):
        """PC=0x0000: should not produce negative start address."""
        commands.STATE.vice.registers_get.return_value = {
            'PC': 0x0000, 'A': 0, 'X': 0, 'Y': 0, 'SP': 0xFF, 'FL': 0
        }
        commands.STATE.vice.memory_get.return_value = b'\x00' * 0x400
        commands.on_stop()
        start_arg = commands.STATE.vice.memory_get.call_args.args[0]
        assert start_arg >= 0

    def test_pc_at_ffff(self):
        """PC=0xFFFF: should clamp end to 0xFFFF."""
        commands.STATE.vice.registers_get.return_value = {
            'PC': 0xFFFF, 'A': 0, 'X': 0, 'Y': 0, 'SP': 0xFF, 'FL': 0
        }
        commands.STATE.vice.memory_get.return_value = b'\x00' * 0x200
        commands.on_stop()
        end_arg = commands.STATE.vice.memory_get.call_args.args[1]
        assert end_arg == 0xFFFF


# ── breakpoint kinds coverage ─────────────────────────────────────────────────

class TestCpuOpToKindsExhaustive:
    """Ensure every valid cpu_op flag combination produces correct kind strings."""
    def test_all_seven_combinations(self):
        for cpu_op in range(1, 8):  # 1 through 7 (all non-zero combos of 3 bits)
            result = commands._cpu_op_to_kinds(cpu_op)
            if cpu_op & 0x04:
                assert 'SW_EXECUTE' in result
            else:
                assert 'SW_EXECUTE' not in result
            if cpu_op & 0x01:
                assert 'READ' in result
            else:
                assert 'READ' not in result
            if cpu_op & 0x02:
                assert 'WRITE' in result
            else:
                assert 'WRITE' not in result
