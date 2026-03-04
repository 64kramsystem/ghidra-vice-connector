"""
Tests for populate_initial_state and put_memory_bytes.

Verifies the full initialization sequence with mocked VICE/trace,
and the on-demand memory read path.
"""

from unittest.mock import MagicMock, patch, call

import pytest

from vice import commands, arch


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_mock_vice(pc=0xC000):
    vice = MagicMock()
    vice.registers_get.return_value = {
        'PC': pc, 'A': 0x41, 'X': 0x00, 'Y': 0xFF, 'SP': 0xFD, 'FL': 0x30
    }
    vice.checkpoint_list.return_value = []
    vice.memory_get.return_value = b'\xEA' * 0x400  # NOP fill
    return vice


def make_mock_trace():
    trace = MagicMock()
    obj = MagicMock()
    trace.create_object.return_value = obj
    trace.proxy_object_path.return_value = obj
    trace.snap.return_value = 0
    trace.disassemble.return_value = 3

    class FakeCtx:
        def __enter__(self): return self
        def __exit__(self, *a): pass

    trace.open_tx.return_value = FakeCtx()
    return trace


@pytest.fixture(autouse=True)
def reset_state():
    commands.STATE.vice   = None
    commands.STATE.client = None
    commands.STATE.trace  = None
    commands.STATE.snap   = 0
    yield
    commands.STATE.vice   = None
    commands.STATE.client = None
    commands.STATE.trace  = None


# ── populate_initial_state ───────────────────────────────────────────────────

class TestPopulateInitialState:
    def setup_method(self):
        commands.STATE.vice   = make_mock_vice()
        commands.STATE.trace  = make_mock_trace()
        commands.STATE.client = MagicMock()

    def test_reads_registers(self):
        commands.populate_initial_state()
        commands.STATE.vice.registers_get.assert_called()

    def test_creates_snapshot(self):
        commands.populate_initial_state()
        commands.STATE.trace.snapshot.assert_called_once_with('Initial snapshot')

    def test_calls_disassemble(self):
        commands.populate_initial_state()
        commands.STATE.trace.disassemble.assert_called_once()

    def test_disassemble_at_pc(self):
        commands.STATE.vice = make_mock_vice(pc=0xE000)
        commands.populate_initial_state()
        addr_arg = commands.STATE.trace.disassemble.call_args.args[0]
        assert addr_arg.space == 'RAM'
        assert addr_arg.offset == 0xE000

    def test_calls_activate(self):
        commands.populate_initial_state()
        # proxy_object_path should be called with FRAME_PATH for activate
        paths = [c.args[0] for c in commands.STATE.trace.proxy_object_path.call_args_list]
        assert commands.FRAME_PATH in paths

    def test_saves_trace(self):
        commands.populate_initial_state()
        commands.STATE.trace.save.assert_called()

    def test_starts_and_ends_batch(self):
        commands.populate_initial_state()
        commands.STATE.client.start_batch.assert_called_once()
        commands.STATE.client.end_batch.assert_called_once()

    def test_end_batch_called_even_on_error(self):
        """end_batch must be called even if the transaction body raises."""
        commands.STATE.trace.snapshot.side_effect = RuntimeError("boom")
        with pytest.raises(RuntimeError, match="boom"):
            commands.populate_initial_state()
        commands.STATE.client.end_batch.assert_called_once()

    def test_reads_memory_around_pc(self):
        commands.STATE.vice = make_mock_vice(pc=0x8000)
        commands.populate_initial_state()
        start_arg = commands.STATE.vice.memory_get.call_args.args[0]
        end_arg   = commands.STATE.vice.memory_get.call_args.args[1]
        assert start_arg <= 0x8000
        assert end_arg   >= 0x8000

    def test_creates_root_object(self):
        commands.populate_initial_state()
        commands.STATE.trace.create_root_object.assert_called_once()

    def test_raises_when_vice_not_connected(self):
        commands.STATE.vice = None
        with pytest.raises(RuntimeError, match="Not connected to VICE"):
            commands.populate_initial_state()

    def test_raises_when_trace_not_started(self):
        commands.STATE.trace = None
        with pytest.raises(RuntimeError, match="Trace not started"):
            commands.populate_initial_state()


# ── put_memory_bytes ─────────────────────────────────────────────────────────

class TestPutMemoryBytes:
    def setup_method(self):
        commands.STATE.vice  = make_mock_vice()
        commands.STATE.trace = make_mock_trace()

    def test_reads_from_vice(self):
        commands.put_memory_bytes(0x1000, 256)
        commands.STATE.vice.memory_get.assert_called_once_with(0x1000, 0x10FF)

    def test_writes_to_trace(self):
        commands.STATE.vice.memory_get.return_value = b'\xAB' * 16
        commands.put_memory_bytes(0x2000, 16)
        commands.STATE.trace.put_bytes.assert_called_once()
        addr_arg = commands.STATE.trace.put_bytes.call_args.args[0]
        assert addr_arg.offset == 0x2000

    def test_clamps_end_to_ram_end(self):
        """Reading past 0xFFFF should clamp to arch.RAM_END."""
        commands.put_memory_bytes(0xFF00, 0x200)
        end_arg = commands.STATE.vice.memory_get.call_args.args[1]
        assert end_arg == arch.RAM_END

    def test_default_length_is_256(self):
        commands.put_memory_bytes(0x3000)
        end_arg = commands.STATE.vice.memory_get.call_args.args[1]
        assert end_arg == 0x30FF

    def test_raises_when_vice_not_connected(self):
        commands.STATE.vice = None
        with pytest.raises(RuntimeError):
            commands.put_memory_bytes(0x1000)


# ── on_stop with breakpoint sync ─────────────────────────────────────────────

class TestOnStopBreakpointSync:
    """Verify on_stop() now syncs breakpoints (catches temp BP consumption)."""
    def setup_method(self):
        commands.STATE.vice   = make_mock_vice()
        commands.STATE.trace  = make_mock_trace()
        commands.STATE.client = MagicMock()

    def test_on_stop_calls_put_breakpoints(self):
        with patch.object(commands, 'put_breakpoints') as mock_put:
            commands.on_stop()
            mock_put.assert_called_once()

    def test_on_stop_calls_put_registers(self):
        with patch.object(commands, 'put_registers') as mock_put:
            commands.on_stop()
            mock_put.assert_called_once()
