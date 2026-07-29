"""
Integration tests against a live VICE x64 instance.

These tests exercise real BMP protocol communication over TCP.
They require a running VICE instance with the binary monitor on port 6502.

Skip automatically when VICE is not reachable.

Uses a single module-scoped connection since VICE only allows one
binary monitor client at a time.
"""

import os
import re
import socket
import time

import pytest

from vice.controller import ViceController, ViceStateError
from vice.protocol import (
    ViceBmpClient, ViceFailure, ViceUnsupportedBuildError, ViceValidationError,
    CPU_OP_EXEC, CPU_OP_LOAD, CPU_OP_STORE,
)

VICE_HOST = os.environ.get("VICE_HOST", "127.0.0.1")
VICE_PORT = int(os.environ.get("VICE_PORT", "6502"))


def _vice_reachable():
    try:
        s = socket.create_connection((VICE_HOST, VICE_PORT), timeout=2)
        s.close()
        return True
    except OSError:
        return False


_VICE_UP = _vice_reachable()

# CI boots an emulator and sets REQUIRE_LIVE_VICE so a VICE boot failure fails the suite
# instead of silently skipping it.
if os.environ.get('REQUIRE_LIVE_VICE') and not _VICE_UP:
    pytest.fail(f"REQUIRE_LIVE_VICE is set but VICE is not reachable on {VICE_HOST}:{VICE_PORT}",
                pytrace=False)

pytestmark = pytest.mark.skipif(
    not _VICE_UP,
    reason=f"VICE not reachable on {VICE_HOST}:{VICE_PORT}",
)


@pytest.fixture(scope='module')
def vice():
    """Single shared connection to the live VICE instance for the whole module."""
    client = ViceBmpClient(VICE_HOST, VICE_PORT)
    controller = ViceController(client)
    controller.connect()
    controller.start_event_coordinator(assume_stopped=True)

    class LiveVice:
        def __init__(self):
            self.controller = controller
            self.client = client

        def __getattr__(self, name):
            return getattr(client, name)

        def step(self, count=1, step_over=False):
            return controller.step(
                count, step_over=step_over, timeout_ms=5_000
            )

        def resume(self):
            return controller.resume(timeout_ms=5_000)

        def interrupt(self):
            return controller.interrupt(timeout_ms=5_000)

        def capture_display(self, use_vic=True):
            return controller.capture_display(
                use_vic=use_vic, timeout_ms=15_000
            )

    yield LiveVice()
    controller.close()


def require_display_capture(vice):
    """Skip unless this build carries the r46020 `display get` fix.

    Deliberately asks the production guard rather than re-deriving the rule:
    an affected VICE writes past its own allocation *before* replying, so a
    test that decided this for itself could drift into triggering exactly the
    bug the guard exists to prevent.
    """
    try:
        vice.client._require_display_get_support()
    except ViceUnsupportedBuildError as refusal:
        pytest.skip(str(refusal))


# ── Connection and discovery ─────────────────────────────────────────────────

class TestLiveConnection:
    def test_connect_discovers_registers(self, vice):
        assert len(vice.reg_name_to_id) > 0

    def test_standard_6502_registers_present(self, vice):
        for name in ('PC', 'A', 'X', 'Y', 'SP', 'FL'):
            assert name in vice.reg_name_to_id, f"Missing register: {name}"

    def test_ping_succeeds(self, vice):
        assert vice.ping() is True

    def test_vice_info_returns_version_components_and_revision(self, vice):
        info = vice.vice_info()
        assert len(info.version) >= 3
        assert re.fullmatch(r'(\d+\.){2,}\d+', info.version_string)
        # None on a release build, which reports no revision at all.
        assert info.revision is None or info.revision > 0

    def test_banks_available_returns_list(self, vice):
        banks = vice.banks_available()
        assert isinstance(banks, list)
        assert len(banks) > 0
        names = [b.name for b in banks]
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
        with pytest.raises(ViceValidationError, match="unknown register"):
            vice.registers_set({'NONEXISTENT': 0})

    def test_pc_is_16bit(self, vice):
        original = vice.registers_get()
        test_pc = 0xC000
        vice.registers_set({'PC': test_pc})
        updated = vice.registers_get()
        assert updated['PC'] == test_pc
        vice.registers_set({'PC': original['PC']})


# ── Deterministic automation primitives ─────────────────────────────────────

class TestLiveAutomationPrimitives:
    def test_keyboard_feed_reaches_the_kernal_queue(self, vice):
        data = b"QZXJ"
        vice.memory_set(0x0277, b"\x00" * 10)
        vice.memory_set(0x00C6, b"\x00")
        try:
            sequence, result = vice.controller.feed_keyboard(data)
            assert sequence > 0
            assert result is None
            assert vice.memory_get(0x00C6, 0x00C6) == bytes((len(data),))
            assert vice.memory_get(
                0x0277, 0x0277 + len(data) - 1
            ) == data
        finally:
            vice.memory_set(0x00C6, b"\x00")

    def test_joyport_two_controls_cia1_port_a_active_low(self, vice):
        io_bank = next(
            (
                bank for bank in vice.banks_available()
                if bank.name.lower() == "io"
            ),
            None,
        )
        assert io_bank is not None, "VICE did not publish its I/O bank"
        original_device = vice.resource_get_int("JoyPort2Device")
        try:
            vice.controller.set_joyport(2, 0xFF)
            released = vice.memory_get(
                0xDC00, 0xDC00, bank_id=io_bank.id
            )[0]
            vice.controller.set_joyport(2, 0xEF)
            pressed = vice.memory_get(
                0xDC00, 0xDC00, bank_id=io_bank.id
            )[0]
            assert released & 0x10
            assert not pressed & 0x10
        finally:
            vice.joyport_set(2, 0xFF)
            vice.resource_set_int("JoyPort2Device", original_device)

    def test_snapshot_roundtrip_restores_register_state(
        self, vice, tmp_path
    ):
        if VICE_HOST not in {"127.0.0.1", "localhost", "::1"}:
            pytest.skip("snapshot paths require VICE on the pytest host")
        filename = str(tmp_path / "automation-roundtrip.vsf")
        original = vice.registers_get()
        vice.controller.save_snapshot(
            filename, save_roms=False, save_disks=False
        )
        changed = (original["A"] + 1) & 0xFF
        vice.registers_set({"A": changed})
        assert vice.registers_get()["A"] == changed
        _sequence, pc = vice.controller.load_snapshot(filename)
        time.sleep(0.05)
        assert vice.controller.execution_state == "stopped"
        restored = vice.registers_get()
        assert pc == restored["PC"]
        assert restored["A"] == original["A"]


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
        cp_num = vice.checkpoint_set(
            0xC000, 0xC000, cpu_op=CPU_OP_EXEC
        ).number
        assert isinstance(cp_num, int)
        assert cp_num > 0
        cps = vice.checkpoint_list()
        numbers = [cp.number for cp in cps]
        assert cp_num in numbers
        vice.checkpoint_delete(cp_num)
        cps = vice.checkpoint_list()
        numbers = [cp.number for cp in cps]
        assert cp_num not in numbers

    def test_checkpoint_toggle(self, vice):
        cp_num = vice.checkpoint_set(
            0xD000, 0xD000, cpu_op=CPU_OP_EXEC
        ).number
        try:
            vice.checkpoint_toggle(cp_num, False)
            cps = vice.checkpoint_list()
            cp = next(c for c in cps if c.number == cp_num)
            assert cp.enabled is False
            vice.checkpoint_toggle(cp_num, True)
            cps = vice.checkpoint_list()
            cp = next(c for c in cps if c.number == cp_num)
            assert cp.enabled is True
        finally:
            vice.checkpoint_delete(cp_num)

    def test_checkpoint_info_fields(self, vice):
        cp_num = vice.checkpoint_set(
            0xA000, 0xA0FF,
            cpu_op=CPU_OP_LOAD,
            enabled=True,
            stop_on_hit=True,
        ).number
        try:
            cps = vice.checkpoint_list()
            cp = next(c for c in cps if c.number == cp_num)
            assert cp.start == 0xA000
            assert cp.end == 0xA0FF
            assert cp.cpu_op == CPU_OP_LOAD
            assert cp.enabled is True
            assert cp.stop_on_hit is True
        finally:
            vice.checkpoint_delete(cp_num)

    def test_write_watchpoint(self, vice):
        cp_num = vice.checkpoint_set(
            0x0400, 0x0400, cpu_op=CPU_OP_STORE
        ).number
        try:
            cps = vice.checkpoint_list()
            cp = next(c for c in cps if c.number == cp_num)
            assert cp.cpu_op == CPU_OP_STORE
        finally:
            vice.checkpoint_delete(cp_num)

    def test_delete_nonexistent_checkpoint_raises(self, vice):
        with pytest.raises(ViceFailure):
            vice.checkpoint_delete(999999)

    def test_multiple_checkpoints(self, vice):
        nums = []
        try:
            for addr in (0xC000, 0xC100, 0xC200):
                n = vice.checkpoint_set(
                    addr, addr, cpu_op=CPU_OP_EXEC
                ).number
                nums.append(n)
            cps = vice.checkpoint_list()
            listed = {cp.number for cp in cps}
            for n in nums:
                assert n in listed
        finally:
            for n in nums:
                try:
                    vice.checkpoint_delete(n)
                except ViceFailure:
                    pass


# ── Step and events ──────────────────────────────────────────────────────────

class TestLiveStepAndEvents:
    def test_step_into_fires_stopped_event(self, vice):
        result = vice.step(count=1, step_over=False)
        assert result.event.kind == "stopped"

    def test_step_over_fires_stopped_event(self, vice):
        result = vice.step(count=1, step_over=True)
        assert result.event.kind == "stopped"

    def test_resume_and_interrupt(self, vice):
        """Resume, then interrupt through the serialized controller."""
        vice.resume()
        time.sleep(0.2)
        result = vice.interrupt()
        assert result.event.kind == "stopped"

    def test_multi_step_advances_pc(self, vice):
        """Multiple single steps should advance PC."""
        for _ in range(3):
            assert vice.step(count=1, step_over=False).event.kind == "stopped"

    def test_step_count_greater_than_one(self, vice):
        """Step with count=5 should eventually fire STOPPED."""
        assert vice.step(count=5, step_over=False).event.kind == "stopped"


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


# ── Display capture ──────────────────────────────────────────────────────────
#
# These require a VICE at r46020 or later and skip on anything older: before
# that revision VICE overruns its own allocation while answering `display get`,
# so the command must never be sent to such a build. The skip is decided by the
# production guard, not by a rule copied into the test.

class TestLiveDisplayCapture:
    def test_capture_returns_a_renderable_c64_frame(self, vice):
        require_display_capture(vice)
        _sequence, capture = vice.capture_display()
        frame = capture.frame
        palette = capture.palette
        assert frame.bits_per_pixel == 8
        assert (frame.inner_width, frame.inner_height) == (320, 200)
        assert len(frame.buffer) == frame.width * frame.height
        assert frame.x_offset + frame.inner_width <= frame.width
        assert frame.y_offset + frame.inner_height <= frame.height
        assert max(frame.buffer) < len(palette)
        # A uniformly blank frame satisfies every structural check above while
        # proving nothing was actually rendered.
        assert len(set(frame.buffer)) >= 2

    def test_capture_while_running_is_refused_without_stopping(self, vice):
        require_display_capture(vice)
        vice.resume()
        try:
            with pytest.raises(ViceStateError) as caught:
                vice.capture_display()
            assert caught.value.code == "vice_target_not_stopped"
            # The refusal must not itself have stopped the emulator: it is a
            # precondition check, taken before any frame reaches the socket.
            assert vice.controller.execution_state == "running"
        finally:
            vice.interrupt()


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
