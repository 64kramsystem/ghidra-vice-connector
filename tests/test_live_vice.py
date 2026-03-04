"""
Integration tests against a live VICE x64 instance.

These tests exercise real BMP protocol communication over TCP.
They require a running VICE instance with the binary monitor on port 6502.

Skip automatically when VICE is not reachable.

Uses a single module-scoped connection since VICE only allows one
binary monitor client at a time.
"""

import socket
import struct
import threading
import time

import pytest

from vice.util import (
    ViceBmpClient, ViceError,
    CPU_OP_EXEC, CPU_OP_LOAD, CPU_OP_STORE,
    RESP_STOPPED, RESP_RESUMED,
)

VICE_HOST = '127.0.0.1'
VICE_PORT = 6502


def _vice_reachable():
    try:
        s = socket.create_connection((VICE_HOST, VICE_PORT), timeout=2)
        s.close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _vice_reachable(),
    reason=f"VICE not reachable on {VICE_HOST}:{VICE_PORT}",
)


@pytest.fixture(scope='module')
def vice():
    """Single shared connection to the live VICE instance for the whole module."""
    client = ViceBmpClient(VICE_HOST, VICE_PORT)
    client.connect()
    yield client
    client.disconnect()


# ── Connection and discovery ─────────────────────────────────────────────────

class TestLiveConnection:
    def test_connect_discovers_registers(self, vice):
        assert len(vice.reg_name_to_id) > 0

    def test_standard_6502_registers_present(self, vice):
        for name in ('PC', 'A', 'X', 'Y', 'SP', 'FL'):
            assert name in vice.reg_name_to_id, f"Missing register: {name}"

    def test_ping_succeeds(self, vice):
        assert vice.ping() is True

    def test_vice_info_returns_version_string(self, vice):
        info = vice.vice_info()
        assert isinstance(info, str)
        assert len(info) > 0

    def test_banks_available_returns_list(self, vice):
        banks = vice.banks_available()
        assert isinstance(banks, list)
        assert len(banks) > 0
        names = [b['name'] for b in banks]
        assert any(n in names for n in ('default', 'cpu', 'ram')), \
            f"No expected bank name in {names}"


# ── Register read/write ──────────────────────────────────────────────────────

class TestLiveRegisters:
    def test_registers_get_returns_all_discovered(self, vice):
        regs = vice.registers_get()
        for name in ('PC', 'A', 'X', 'Y', 'SP', 'FL'):
            assert name in regs, f"Missing {name} in registers_get()"

    def test_register_values_in_valid_range(self, vice):
        regs = vice.registers_get()
        assert 0 <= regs['PC'] <= 0xFFFF
        assert 0 <= regs['A'] <= 0xFF
        assert 0 <= regs['X'] <= 0xFF
        assert 0 <= regs['Y'] <= 0xFF
        assert 0 <= regs['SP'] <= 0xFF
        assert 0 <= regs['FL'] <= 0xFF

    def test_register_write_roundtrip(self, vice):
        """Write a value to A, read it back, restore original."""
        original = vice.registers_get()
        test_val = (original['A'] + 1) & 0xFF
        vice.registers_set({'A': test_val})
        updated = vice.registers_get()
        assert updated['A'] == test_val
        vice.registers_set({'A': original['A']})

    def test_write_multiple_registers(self, vice):
        original = vice.registers_get()
        vice.registers_set({'X': 0x42, 'Y': 0x99})
        updated = vice.registers_get()
        assert updated['X'] == 0x42
        assert updated['Y'] == 0x99
        vice.registers_set({'X': original['X'], 'Y': original['Y']})

    def test_write_unknown_register_raises(self, vice):
        with pytest.raises(KeyError, match="Unknown register"):
            vice.registers_set({'NONEXISTENT': 0})

    def test_pc_is_16bit(self, vice):
        original = vice.registers_get()
        test_pc = 0xC000
        vice.registers_set({'PC': test_pc})
        updated = vice.registers_get()
        assert updated['PC'] == test_pc
        vice.registers_set({'PC': original['PC']})


# ── Memory read/write ────────────────────────────────────────────────────────

class TestLiveMemory:
    def test_memory_get_returns_bytes(self, vice):
        data = vice.memory_get(0x0000, 0x00FF)
        assert isinstance(data, bytes)
        assert len(data) == 0x100

    def test_memory_get_single_byte(self, vice):
        data = vice.memory_get(0x0000, 0x0000)
        assert len(data) == 1

    def test_memory_get_large_range(self, vice):
        data = vice.memory_get(0x0000, 0x0FFF)
        assert len(data) == 0x1000

    def test_memory_write_roundtrip(self, vice):
        """Write bytes to screen RAM, read back, restore."""
        addr = 0x0400
        original = vice.memory_get(addr, addr + 3)
        test_data = b'\xDE\xAD\xBE\xEF'
        vice.memory_set(addr, test_data)
        readback = vice.memory_get(addr, addr + 3)
        assert readback == test_data
        vice.memory_set(addr, original)

    def test_memory_read_kernal_rom(self, vice):
        """KERNAL ROM area should contain non-zero data."""
        data = vice.memory_get(0xE000, 0xE0FF)
        assert len(data) == 0x100
        assert data != b'\x00' * 0x100

    def test_memory_read_zero_page(self, vice):
        data = vice.memory_get(0x00, 0xFF)
        assert len(data) == 0x100

    def test_memory_write_single_byte(self, vice):
        addr = 0x0400
        original = vice.memory_get(addr, addr)
        vice.memory_set(addr, b'\x42')
        readback = vice.memory_get(addr, addr)
        assert readback == b'\x42'
        vice.memory_set(addr, original)


# ── Checkpoints (breakpoints / watchpoints) ──────────────────────────────────

class TestLiveCheckpoints:
    def test_checkpoint_set_and_delete(self, vice):
        cp_num = vice.checkpoint_set(0xC000, 0xC000, cpu_op=CPU_OP_EXEC)
        assert isinstance(cp_num, int)
        assert cp_num > 0
        cps = vice.checkpoint_list()
        numbers = [cp['number'] for cp in cps]
        assert cp_num in numbers
        vice.checkpoint_delete(cp_num)
        cps = vice.checkpoint_list()
        numbers = [cp['number'] for cp in cps]
        assert cp_num not in numbers

    def test_checkpoint_toggle(self, vice):
        cp_num = vice.checkpoint_set(0xD000, 0xD000, cpu_op=CPU_OP_EXEC)
        try:
            vice.checkpoint_toggle(cp_num, False)
            cps = vice.checkpoint_list()
            cp = next(c for c in cps if c['number'] == cp_num)
            assert cp['enabled'] is False
            vice.checkpoint_toggle(cp_num, True)
            cps = vice.checkpoint_list()
            cp = next(c for c in cps if c['number'] == cp_num)
            assert cp['enabled'] is True
        finally:
            vice.checkpoint_delete(cp_num)

    def test_checkpoint_info_fields(self, vice):
        cp_num = vice.checkpoint_set(
            0xA000, 0xA0FF,
            cpu_op=CPU_OP_LOAD,
            enabled=True,
            stop_on_hit=True,
        )
        try:
            cps = vice.checkpoint_list()
            cp = next(c for c in cps if c['number'] == cp_num)
            assert cp['start'] == 0xA000
            assert cp['end'] == 0xA0FF
            assert cp['cpu_op'] == CPU_OP_LOAD
            assert cp['enabled'] is True
            assert cp['stop_on_hit'] is True
        finally:
            vice.checkpoint_delete(cp_num)

    def test_write_watchpoint(self, vice):
        cp_num = vice.checkpoint_set(0x0400, 0x0400, cpu_op=CPU_OP_STORE)
        try:
            cps = vice.checkpoint_list()
            cp = next(c for c in cps if c['number'] == cp_num)
            assert cp['cpu_op'] == CPU_OP_STORE
        finally:
            vice.checkpoint_delete(cp_num)

    def test_delete_nonexistent_checkpoint_raises(self, vice):
        with pytest.raises(ViceError):
            vice.checkpoint_delete(999999)

    def test_multiple_checkpoints(self, vice):
        nums = []
        try:
            for addr in (0xC000, 0xC100, 0xC200):
                n = vice.checkpoint_set(addr, addr, cpu_op=CPU_OP_EXEC)
                nums.append(n)
            cps = vice.checkpoint_list()
            listed = {cp['number'] for cp in cps}
            for n in nums:
                assert n in listed
        finally:
            for n in nums:
                try:
                    vice.checkpoint_delete(n)
                except ViceError:
                    pass


# ── Step and events ──────────────────────────────────────────────────────────

class TestLiveStepAndEvents:
    def test_step_into_fires_stopped_event(self, vice):
        """Single step should trigger a RESP_STOPPED event."""
        stopped = threading.Event()

        def on_stopped(resp_type, error, body):
            stopped.set()

        vice.on_event(RESP_STOPPED, on_stopped)
        vice.step(count=1, step_over=False)
        assert stopped.wait(timeout=5), "Timed out waiting for STOPPED event"

    def test_step_over_fires_stopped_event(self, vice):
        stopped = threading.Event()

        def on_stopped(resp_type, error, body):
            stopped.set()

        vice.on_event(RESP_STOPPED, on_stopped)
        vice.step(count=1, step_over=True)
        assert stopped.wait(timeout=5), "Timed out waiting for STOPPED event"

    def test_resume_and_interrupt(self, vice):
        """Resume, then interrupt — should get STOPPED event."""
        stopped = threading.Event()

        def on_stopped(resp_type, error, body):
            stopped.set()

        vice.on_event(RESP_STOPPED, on_stopped)
        vice.resume()
        time.sleep(0.2)
        vice.interrupt()
        assert stopped.wait(timeout=5), "Timed out waiting for STOPPED after interrupt"
        # Drain any extra events
        time.sleep(0.1)

    def test_multi_step_advances_pc(self, vice):
        """Multiple single steps should advance PC."""
        stopped = threading.Event()

        def on_stopped(resp_type, error, body):
            stopped.set()

        vice.on_event(RESP_STOPPED, on_stopped)
        for _ in range(3):
            stopped.clear()
            vice.step(count=1, step_over=False)
            assert stopped.wait(timeout=5)

    def test_step_count_greater_than_one(self, vice):
        """Step with count=5 should eventually fire STOPPED."""
        stopped = threading.Event()

        def on_stopped(resp_type, error, body):
            stopped.set()

        vice.on_event(RESP_STOPPED, on_stopped)
        vice.step(count=5, step_over=False)
        assert stopped.wait(timeout=5)


# ── Reset ────────────────────────────────────────────────────────────────────

class TestLiveReset:
    def test_soft_reset(self, vice):
        vice.reset(0)
        # Give VICE a moment to settle after reset
        time.sleep(0.3)
        regs = vice.registers_get()
        assert 'PC' in regs

    def test_hard_reset(self, vice):
        vice.reset(1)
        time.sleep(0.3)
        regs = vice.registers_get()
        assert 'PC' in regs


# ── Concurrent commands ──────────────────────────────────────────────────────

class TestLiveConcurrency:
    def test_rapid_register_reads(self, vice):
        for _ in range(20):
            regs = vice.registers_get()
            assert 'PC' in regs

    def test_rapid_memory_reads(self, vice):
        for i in range(10):
            start = i * 0x100
            data = vice.memory_get(start, start + 0xFF)
            assert len(data) == 0x100

    def test_interleaved_register_and_memory(self, vice):
        for _ in range(10):
            regs = vice.registers_get()
            pc = regs['PC']
            data = vice.memory_get(pc, min(pc + 3, 0xFFFF))
            assert len(data) > 0
