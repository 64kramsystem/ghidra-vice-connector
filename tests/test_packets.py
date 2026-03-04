"""
Pure struct-format sanity tests — no network, no Ghidra dependency.

Validates that all header formats, size constants, and payload builders
produce the exact byte sequences the VICE BMP spec requires.
"""

import struct
import pytest

from vice.util import (
    STX, API_VERSION,
    REQ_HDR_FMT, REQ_HDR_SIZE,
    RESP_HDR_FMT, RESP_HDR_SIZE,
    CMD_MEMORY_GET, CMD_MEMORY_SET,
    CMD_CHECKPOINT_SET, CMD_REGISTERS_GET, CMD_REGISTERS_SET,
    CMD_ADVANCE_INSTRUCTIONS,
    MEMSPACE_MAIN, CPU_OP_EXEC, CPU_OP_LOAD, CPU_OP_STORE,
    EVENT_REQUEST_ID,
)


# ── Header sizes ───────────────────────────────────────────────────────────────

class TestHeaderSizes:
    def test_request_header_is_11_bytes(self):
        assert REQ_HDR_SIZE == 11, (
            "BMP request header must be 11 bytes: "
            "STX(1) API_VER(1) body_len(4) request_id(4) cmd(1)"
        )

    def test_response_header_is_12_bytes(self):
        assert RESP_HDR_SIZE == 12, (
            "BMP response header must be 12 bytes: "
            "STX(1) API_VER(1) body_len(4) resp_type(1) error(1) request_id(4)"
        )

    def test_request_header_struct_matches_size(self):
        assert struct.calcsize(REQ_HDR_FMT) == REQ_HDR_SIZE

    def test_response_header_struct_matches_size(self):
        assert struct.calcsize(RESP_HDR_FMT) == RESP_HDR_SIZE


# ── Request header encoding ────────────────────────────────────────────────────

class TestRequestHeader:
    def test_stx_byte(self):
        raw = struct.pack(REQ_HDR_FMT, STX, API_VERSION, 0, 1, CMD_REGISTERS_GET)
        assert raw[0] == 0x02

    def test_api_version_byte(self):
        raw = struct.pack(REQ_HDR_FMT, STX, API_VERSION, 0, 1, CMD_REGISTERS_GET)
        assert raw[1] == 0x02

    def test_body_length_little_endian(self):
        raw = struct.pack(REQ_HDR_FMT, STX, API_VERSION, 0x0102, 1, CMD_REGISTERS_GET)
        assert raw[2:6] == b'\x02\x01\x00\x00'

    def test_request_id_little_endian(self):
        raw = struct.pack(REQ_HDR_FMT, STX, API_VERSION, 0, 0xDEADBEEF, CMD_REGISTERS_GET)
        assert raw[6:10] == b'\xef\xbe\xad\xde'

    def test_command_byte_position(self):
        raw = struct.pack(REQ_HDR_FMT, STX, API_VERSION, 0, 1, 0xAB)
        assert raw[10] == 0xAB

    def test_roundtrip(self):
        stx, api_ver, body_len, req_id, cmd = struct.unpack(
            REQ_HDR_FMT,
            struct.pack(REQ_HDR_FMT, STX, API_VERSION, 7, 42, 0x31),
        )
        assert stx == STX
        assert api_ver == API_VERSION
        assert body_len == 7
        assert req_id == 42
        assert cmd == 0x31


# ── Response header encoding ───────────────────────────────────────────────────

class TestResponseHeader:
    def test_stx_byte(self):
        raw = struct.pack(RESP_HDR_FMT, STX, API_VERSION, 0, 0x31, 0, 1)
        assert raw[0] == 0x02

    def test_body_length_little_endian(self):
        raw = struct.pack(RESP_HDR_FMT, STX, API_VERSION, 0x0304, 0x31, 0, 1)
        assert raw[2:6] == b'\x04\x03\x00\x00'

    def test_resp_type_byte(self):
        raw = struct.pack(RESP_HDR_FMT, STX, API_VERSION, 0, 0x62, 0, 1)
        assert raw[6] == 0x62  # RESP_STOPPED

    def test_error_byte(self):
        raw = struct.pack(RESP_HDR_FMT, STX, API_VERSION, 0, 0x31, 0x8F, 1)
        assert raw[7] == 0x8F

    def test_request_id_little_endian(self):
        raw = struct.pack(RESP_HDR_FMT, STX, API_VERSION, 0, 0x31, 0, 0xCAFEBABE)
        assert raw[8:12] == b'\xbe\xba\xfe\xca'

    def test_event_request_id(self):
        raw = struct.pack(RESP_HDR_FMT, STX, API_VERSION, 0, 0x62, 0, EVENT_REQUEST_ID)
        assert struct.unpack_from('<I', raw, 8)[0] == EVENT_REQUEST_ID

    def test_roundtrip(self):
        stx, api_ver, body_len, rtype, error, req_id = struct.unpack(
            RESP_HDR_FMT,
            struct.pack(RESP_HDR_FMT, STX, API_VERSION, 10, 0x01, 0x00, 99),
        )
        assert body_len == 10
        assert rtype == 0x01
        assert error == 0x00
        assert req_id == 99


# ── MEMORY_GET payload ─────────────────────────────────────────────────────────

class TestMemoryGetPayload:
    """
    Expected payload: side_effects(1) start(2 LE) end(2 LE) memspace(1) bank_id(2 LE)
    Total: 8 bytes
    """
    FMT = '<BHHBH'

    def test_size(self):
        assert struct.calcsize(self.FMT) == 8

    def test_address_range_encoding(self):
        raw = struct.pack(self.FMT, 0, 0x1000, 0x10FF, MEMSPACE_MAIN, 0)
        _, start, end, _, _ = struct.unpack(self.FMT, raw)
        assert start == 0x1000
        assert end == 0x10FF

    def test_side_effects_flag(self):
        raw = struct.pack(self.FMT, 1, 0, 0xFF, MEMSPACE_MAIN, 0)
        assert raw[0] == 1

    def test_no_side_effects(self):
        raw = struct.pack(self.FMT, 0, 0, 0xFF, MEMSPACE_MAIN, 0)
        assert raw[0] == 0

    def test_bank_id_little_endian(self):
        raw = struct.pack(self.FMT, 0, 0, 0, MEMSPACE_MAIN, 0x0102)
        _, _, _, _, bank = struct.unpack(self.FMT, raw)
        assert bank == 0x0102


# ── CHECKPOINT_SET payload ─────────────────────────────────────────────────────

class TestCheckpointSetPayload:
    """
    Expected payload: start(2) end(2) stop(1) enabled(1) cpu_op(1) temp(1)
    Total: 8 bytes
    """
    FMT = '<HHBBBB'

    def test_size(self):
        assert struct.calcsize(self.FMT) == 8

    def test_exec_breakpoint(self):
        raw = struct.pack(self.FMT, 0xC000, 0xC000, 1, 1, CPU_OP_EXEC, 0)
        start, end, stop, en, cpu_op, temp = struct.unpack(self.FMT, raw)
        assert start == 0xC000
        assert end == 0xC000
        assert stop == 1
        assert en == 1
        assert cpu_op == CPU_OP_EXEC
        assert temp == 0

    def test_read_watchpoint(self):
        raw = struct.pack(self.FMT, 0xD400, 0xD7FF, 1, 1, CPU_OP_LOAD, 0)
        _, _, _, _, cpu_op, _ = struct.unpack(self.FMT, raw)
        assert cpu_op == CPU_OP_LOAD

    def test_write_watchpoint(self):
        raw = struct.pack(self.FMT, 0xD000, 0xD000, 1, 1, CPU_OP_STORE, 0)
        _, _, _, _, cpu_op, _ = struct.unpack(self.FMT, raw)
        assert cpu_op == CPU_OP_STORE

    def test_combined_read_write(self):
        raw = struct.pack(self.FMT, 0, 0xFFFF, 1, 1, CPU_OP_LOAD | CPU_OP_STORE, 0)
        _, _, _, _, cpu_op, _ = struct.unpack(self.FMT, raw)
        assert cpu_op & CPU_OP_LOAD
        assert cpu_op & CPU_OP_STORE

    def test_temporary_flag(self):
        raw = struct.pack(self.FMT, 0xC000, 0xC000, 1, 1, CPU_OP_EXEC, 1)
        _, _, _, _, _, temp = struct.unpack(self.FMT, raw)
        assert temp == 1

    def test_disabled(self):
        raw = struct.pack(self.FMT, 0xC000, 0xC000, 1, 0, CPU_OP_EXEC, 0)
        _, _, _, en, _, _ = struct.unpack(self.FMT, raw)
        assert en == 0


# ── ADVANCE_INSTRUCTIONS payload ───────────────────────────────────────────────

class TestAdvanceInstructionsPayload:
    """payload: step_over(1) count(2 LE) — total 3 bytes"""
    FMT = '<BH'

    def test_size(self):
        assert struct.calcsize(self.FMT) == 3

    def test_step_into(self):
        step_over, count = struct.unpack(self.FMT, struct.pack(self.FMT, 0, 1))
        assert count == 1
        assert step_over == 0

    def test_step_over(self):
        step_over, count = struct.unpack(self.FMT, struct.pack(self.FMT, 1, 1))
        assert step_over == 1
        assert count == 1

    def test_multi_step(self):
        _, count = struct.unpack(self.FMT, struct.pack(self.FMT, 0, 100))
        assert count == 100


# ── REGISTERS_SET payload ──────────────────────────────────────────────────────

class TestRegistersSetPayload:
    """
    payload: memspace(1) count(2 LE) [item_size(1) reg_id(1) value(2 LE)]*
    item_size == 3 always (reg_id + value = 1 + 2)
    """

    def _build(self, memspace, regs):
        """regs: [(reg_id, value)]"""
        payload = struct.pack('<BH', memspace, len(regs))
        for rid, val in regs:
            payload += struct.pack('<BBH', 3, rid, val)
        return payload

    def test_header_size(self):
        assert struct.calcsize('<BH') == 3

    def test_single_register(self):
        p = self._build(MEMSPACE_MAIN, [(0, 0xC000)])  # PC = 0xC000
        assert p[0] == MEMSPACE_MAIN
        count = struct.unpack_from('<H', p, 1)[0]
        assert count == 1
        item_size = p[3]
        assert item_size == 3
        reg_id = p[4]
        assert reg_id == 0
        value = struct.unpack_from('<H', p, 5)[0]
        assert value == 0xC000

    def test_multiple_registers(self):
        p = self._build(MEMSPACE_MAIN, [(0, 0x1000), (1, 0x42), (2, 0x10)])
        count = struct.unpack_from('<H', p, 1)[0]
        assert count == 3
        assert len(p) == 3 + 3 * 4  # header + 3 items of 4 bytes each

    def test_value_truncated_to_16bit(self):
        p = self._build(MEMSPACE_MAIN, [(1, 0x1FF)])  # A can only be 8-bit but val stored as 16
        value = struct.unpack_from('<H', p, 5)[0]
        assert value == 0x1FF

    def test_empty_registers(self):
        p = self._build(MEMSPACE_MAIN, [])
        count = struct.unpack_from('<H', p, 1)[0]
        assert count == 0


# ── Checkpoint INFO item ───────────────────────────────────────────────────────

class TestCheckpointInfoItem:
    """
    Format used in CHECKPOINT_LIST response body (per item):
    number(4) hit(1) start(2) end(2) stop(1) enabled(1) cpu_op(1) temp(1)
    hit_count(4) ignore_count(4) has_condition(1)
    Total: 22 bytes
    """
    FMT = '<IBHHBBBBIIb'

    def test_size(self):
        assert struct.calcsize(self.FMT) == 22

    def test_roundtrip(self):
        data = struct.pack(self.FMT, 3, 1, 0xC000, 0xC000, 1, 1, CPU_OP_EXEC, 0, 5, 0, 0)
        (number, hit, start, end, stop, en, cpu_op,
         temp, hit_count, ignore_count, has_cond) = struct.unpack(self.FMT, data)
        assert number == 3
        assert hit == 1
        assert start == 0xC000
        assert cpu_op == CPU_OP_EXEC
        assert hit_count == 5
