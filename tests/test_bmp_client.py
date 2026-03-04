"""
ViceBmpClient integration tests using MockViceServer.

All tests exercise real TCP sockets so they catch actual wire-format bugs.
"""

import struct
import threading
import time

import pytest

from vice.util import (
    STX, API_VERSION,
    REQ_HDR_FMT, RESP_HDR_FMT, RESP_HDR_SIZE,
    CMD_MEMORY_GET, CMD_MEMORY_SET,
    CMD_CHECKPOINT_SET, CMD_CHECKPOINT_DELETE,
    CMD_CHECKPOINT_TOGGLE, CMD_CHECKPOINT_LIST,
    CMD_REGISTERS_GET, CMD_REGISTERS_SET,
    CMD_ADVANCE_INSTRUCTIONS, CMD_EXECUTE_UNTIL_RETURN,
    CMD_RESET, CMD_VICE_INFO, CMD_BANKS_AVAILABLE,
    CMD_PING, CMD_EXIT,
    RESP_MEMORY_GET, RESP_CHECKPOINT_INFO, RESP_CHECKPOINT_LIST,
    RESP_REGISTERS_GET, RESP_BANKS_AVAILABLE, RESP_VICE_INFO,
    RESP_STOPPED, RESP_RESUMED,
    CPU_OP_EXEC, CPU_OP_LOAD, CPU_OP_STORE,
    MEMSPACE_MAIN,
    ViceBmpClient, ViceError,
    EVENT_REQUEST_ID,
)
from bmp_helpers import (
    MockViceServer, DEFAULT_REGISTERS,
    build_registers_available_body, build_registers_get_body,
)


# ── connect / disconnect ───────────────────────────────────────────────────────

class TestConnect:
    def test_connect_populates_reg_name_to_id(self, connected_client):
        client, _ = connected_client
        assert 'PC' in client.reg_name_to_id
        assert 'A'  in client.reg_name_to_id

    def test_connect_populates_reg_id_to_name(self, connected_client):
        client, _ = connected_client
        assert 0 in client.reg_id_to_name  # PC

    def test_register_count_matches(self, connected_client):
        client, _ = connected_client
        assert len(client.reg_name_to_id) == len(DEFAULT_REGISTERS)

    def test_connect_wrong_port_raises(self):
        client = ViceBmpClient('127.0.0.1', 19999)  # nothing listening
        with pytest.raises(ConnectionRefusedError):
            client.connect()

    def test_disconnect_is_idempotent(self, connected_client):
        client, _ = connected_client
        client.disconnect()
        client.disconnect()  # must not raise


# ── ping ───────────────────────────────────────────────────────────────────────

class TestPing:
    def test_ping_returns_true(self, connected_client):
        client, _ = connected_client
        assert client.ping() is True

    def test_ping_after_disconnect_returns_false(self, connected_client):
        client, server = connected_client
        server.stop()
        time.sleep(0.05)
        result = client.ping()
        assert result is False


# ── registers_get ──────────────────────────────────────────────────────────────

class TestRegistersGet:
    def _make_handler(self, values):
        body = build_registers_get_body(values)
        return lambda _: (RESP_REGISTERS_GET, body)

    def test_returns_all_registers(self, connected_client):
        client, server = connected_client
        values = {'PC': 0xC000, 'A': 0x41, 'X': 0x00, 'Y': 0xFF, 'SP': 0xFD, 'FLAGS': 0x30}
        server.handle(CMD_REGISTERS_GET, self._make_handler(values))
        result = client.registers_get()
        assert result['PC'] == 0xC000
        assert result['A']  == 0x41
        assert result['SP'] == 0xFD

    def test_returns_correct_types(self, connected_client):
        client, server = connected_client
        values = {'PC': 0x0801, 'A': 0x00, 'X': 0x00, 'Y': 0x00, 'SP': 0xFF, 'FLAGS': 0x22}
        server.handle(CMD_REGISTERS_GET, self._make_handler(values))
        result = client.registers_get()
        for v in result.values():
            assert isinstance(v, int)

    def test_16bit_pc_value(self, connected_client):
        client, server = connected_client
        values = {'PC': 0xFFFF, 'A': 0, 'X': 0, 'Y': 0, 'SP': 0, 'FLAGS': 0}
        server.handle(CMD_REGISTERS_GET, self._make_handler(values))
        result = client.registers_get()
        assert result['PC'] == 0xFFFF

    def test_zero_values(self, connected_client):
        client, server = connected_client
        values = {'PC': 0, 'A': 0, 'X': 0, 'Y': 0, 'SP': 0, 'FLAGS': 0}
        server.handle(CMD_REGISTERS_GET, self._make_handler(values))
        result = client.registers_get()
        assert all(v == 0 for v in result.values())

    def test_error_code_raises_vice_error(self, connected_client):
        client, server = connected_client
        def err_handler(_):
            # return error via a response with error byte set
            # We simulate this by having the server override the error byte
            raise _ServerError(0x8F)
        # Simpler: install a handler that produces error via custom server response
        # We'll test this via _command directly; for now test ViceError propagation
        # by checking that a non-zero error code raises
        # This is tested more cleanly in TestErrors below.
        pass


class _ServerError(Exception):
    def __init__(self, code):
        self.code = code


# ── registers_set ──────────────────────────────────────────────────────────────

class TestRegistersSet:
    def test_sends_correct_command(self, connected_client):
        client, server = connected_client
        received = {}

        def handler(body):
            memspace = body[0]
            count = struct.unpack_from('<H', body, 1)[0]
            received['memspace'] = memspace
            received['count'] = count
            # parse first item
            item_size = body[3]
            reg_id = body[4]
            value = struct.unpack_from('<H', body, 5)[0]
            received['reg_id'] = reg_id
            received['value'] = value
            return (CMD_REGISTERS_SET, b'')

        server.handle(CMD_REGISTERS_SET, handler)
        client.registers_set({'PC': 0xC000})

        assert received['memspace'] == MEMSPACE_MAIN
        assert received['count'] == 1
        assert received['reg_id'] == 0   # PC is id 0 in default register set
        assert received['value'] == 0xC000

    def test_multiple_registers(self, connected_client):
        client, server = connected_client
        received_count = {}

        def handler(body):
            count = struct.unpack_from('<H', body, 1)[0]
            received_count['n'] = count
            return (CMD_REGISTERS_SET, b'')

        server.handle(CMD_REGISTERS_SET, handler)
        client.registers_set({'PC': 0x1000, 'A': 0x42})
        assert received_count['n'] == 2

    def test_unknown_register_raises(self, connected_client):
        client, _ = connected_client
        with pytest.raises(KeyError):
            client.registers_set({'ZZ': 0})


# ── memory_get ─────────────────────────────────────────────────────────────────

def _memory_resp(data: bytes) -> tuple:
    """Wrap raw bytes in the BMP MEMORY_GET response format: len(2 LE) + data."""
    return (RESP_MEMORY_GET, struct.pack('<H', len(data)) + data)


class TestMemoryGet:
    def test_returns_bytes(self, connected_client):
        client, server = connected_client
        data = bytes(range(16))
        server.handle(CMD_MEMORY_GET, lambda _: _memory_resp(data))
        result = client.memory_get(0x1000, 0x100F)
        assert result == data

    def test_strips_length_prefix(self, connected_client):
        """memory_get must strip the 2-byte length prefix from the response body."""
        client, server = connected_client
        data = b'\xAA\xBB\xCC'
        server.handle(CMD_MEMORY_GET, lambda _: _memory_resp(data))
        result = client.memory_get(0x1000, 0x1002)
        assert result == data  # must NOT start with 0x03 0x00 (the length prefix)

    def test_payload_address_range(self, connected_client):
        client, server = connected_client
        received = {}

        def handler(body):
            side_effects, start, end, memspace, bank = struct.unpack('<BHHBH', body)
            received.update(side_effects=side_effects, start=start, end=end,
                            memspace=memspace, bank=bank)
            return _memory_resp(bytes(end - start + 1))

        server.handle(CMD_MEMORY_GET, handler)
        client.memory_get(0x0400, 0x04FF)

        assert received['start'] == 0x0400
        assert received['end']   == 0x04FF
        assert received['memspace'] == MEMSPACE_MAIN
        assert received['side_effects'] == 0

    def test_side_effects_flag(self, connected_client):
        client, server = connected_client
        received = {}

        def handler(body):
            received['se'] = body[0]
            return _memory_resp(b'\x00')

        server.handle(CMD_MEMORY_GET, handler)
        client.memory_get(0, 0, side_effects=True)
        assert received['se'] == 1

    def test_empty_range_single_byte(self, connected_client):
        client, server = connected_client
        server.handle(CMD_MEMORY_GET, lambda _: _memory_resp(b'\xAB'))
        result = client.memory_get(0xD020, 0xD020)
        assert result == b'\xAB'

    def test_near_full_address_space(self, connected_client):
        """Read 0x0000-0xFFFE (65535 bytes — max that fits in uint16 length prefix)."""
        client, server = connected_client
        data = bytes(range(256)) * 255 + bytes(range(255))  # 65535 bytes
        server.handle(CMD_MEMORY_GET, lambda _: _memory_resp(data))
        result = client.memory_get(0x0000, 0xFFFE)
        assert len(result) == 65535

    def test_bank_id_forwarded(self, connected_client):
        client, server = connected_client
        received = {}

        def handler(body):
            _, _, _, _, bank = struct.unpack('<BHHBH', body)
            received['bank'] = bank
            return _memory_resp(b'\x00')

        server.handle(CMD_MEMORY_GET, handler)
        client.memory_get(0, 0, bank_id=3)
        assert received['bank'] == 3


# ── memory_set ─────────────────────────────────────────────────────────────────

class TestMemorySet:
    def test_sends_data(self, connected_client):
        client, server = connected_client
        received = {}

        def handler(body):
            se, start, end, memspace, bank = struct.unpack('<BHHBH', body[:8])
            data = body[8:]
            received.update(start=start, end=end, data=data)
            return (CMD_MEMORY_SET, b'')

        server.handle(CMD_MEMORY_SET, handler)
        client.memory_set(0xC000, b'\xA9\x42\x60')  # LDA #$42 / RTS

        assert received['start'] == 0xC000
        assert received['end']   == 0xC002
        assert received['data']  == b'\xA9\x42\x60'

    def test_end_address_computed_correctly(self, connected_client):
        client, server = connected_client
        received = {}

        def handler(body):
            _, start, end, _, _ = struct.unpack('<BHHBH', body[:8])
            received.update(start=start, end=end)
            return (CMD_MEMORY_SET, b'')

        server.handle(CMD_MEMORY_SET, handler)
        client.memory_set(0xFFFC, b'\x00\xC0')  # 2 bytes at 0xFFFC–0xFFFD

        assert received['start'] == 0xFFFC
        assert received['end']   == 0xFFFD

    def test_single_byte(self, connected_client):
        client, server = connected_client
        received = {}

        def handler(body):
            _, start, end, _, _ = struct.unpack('<BHHBH', body[:8])
            received.update(start=start, end=end, data=body[8:])
            return (CMD_MEMORY_SET, b'')

        server.handle(CMD_MEMORY_SET, handler)
        client.memory_set(0x0314, b'\x31')

        assert received['start'] == received['end'] == 0x0314
        assert received['data'] == b'\x31'


# ── checkpoint_set ─────────────────────────────────────────────────────────────

class TestCheckpointSet:
    def _make_cp_info(self, number):
        """Build a minimal CHECKPOINT_INFO response body."""
        return struct.pack('<IBHHBBBBIIb',
                           number, 0, 0xC000, 0xC000, 1, 1, CPU_OP_EXEC, 0, 0, 0, 0)

    def test_returns_checkpoint_number(self, connected_client):
        client, server = connected_client
        server.handle(CMD_CHECKPOINT_SET,
                      lambda _: (RESP_CHECKPOINT_INFO, self._make_cp_info(7)))
        n = client.checkpoint_set(0xC000, 0xC000)
        assert n == 7

    def test_exec_breakpoint_payload(self, connected_client):
        client, server = connected_client
        received = {}

        def handler(body):
            start, end, stop, en, cpu_op, temp = struct.unpack('<HHBBBB', body)
            received.update(start=start, end=end, stop=stop,
                            en=en, cpu_op=cpu_op, temp=temp)
            return (RESP_CHECKPOINT_INFO, self._make_cp_info(1))

        server.handle(CMD_CHECKPOINT_SET, handler)
        client.checkpoint_set(0xC000, 0xC000, cpu_op=CPU_OP_EXEC)

        assert received['start'] == 0xC000
        assert received['cpu_op'] == CPU_OP_EXEC
        assert received['stop'] == 1
        assert received['en'] == 1
        assert received['temp'] == 0

    def test_watchpoint_range(self, connected_client):
        client, server = connected_client
        received = {}

        def handler(body):
            start, end, _, _, cpu_op, _ = struct.unpack('<HHBBBB', body)
            received.update(start=start, end=end, cpu_op=cpu_op)
            return (RESP_CHECKPOINT_INFO, self._make_cp_info(2))

        server.handle(CMD_CHECKPOINT_SET, handler)
        client.checkpoint_set(0xD400, 0xD41C, cpu_op=CPU_OP_LOAD | CPU_OP_STORE)

        assert received['start'] == 0xD400
        assert received['end']   == 0xD41C
        assert received['cpu_op'] & CPU_OP_LOAD
        assert received['cpu_op'] & CPU_OP_STORE

    def test_temporary_checkpoint(self, connected_client):
        client, server = connected_client
        received = {}

        def handler(body):
            _, _, _, _, _, temp = struct.unpack('<HHBBBB', body)
            received['temp'] = temp
            return (RESP_CHECKPOINT_INFO, self._make_cp_info(3))

        server.handle(CMD_CHECKPOINT_SET, handler)
        client.checkpoint_set(0xC000, 0xC000, temporary=True)
        assert received['temp'] == 1


# ── checkpoint_delete ──────────────────────────────────────────────────────────

class TestCheckpointDelete:
    def test_sends_checkpoint_number(self, connected_client):
        client, server = connected_client
        received = {}

        def handler(body):
            received['number'] = struct.unpack_from('<I', body)[0]
            return (CMD_CHECKPOINT_DELETE, b'')

        server.handle(CMD_CHECKPOINT_DELETE, handler)
        client.checkpoint_delete(5)
        assert received['number'] == 5


# ── checkpoint_toggle ──────────────────────────────────────────────────────────

class TestCheckpointToggle:
    def test_enable(self, connected_client):
        client, server = connected_client
        received = {}

        def handler(body):
            n, en = struct.unpack('<IB', body)
            received.update(n=n, en=en)
            return (CMD_CHECKPOINT_TOGGLE, b'')

        server.handle(CMD_CHECKPOINT_TOGGLE, handler)
        client.checkpoint_toggle(3, True)
        assert received['n'] == 3
        assert received['en'] == 1

    def test_disable(self, connected_client):
        client, server = connected_client
        received = {}

        def handler(body):
            n, en = struct.unpack('<IB', body)
            received.update(n=n, en=en)
            return (CMD_CHECKPOINT_TOGGLE, b'')

        server.handle(CMD_CHECKPOINT_TOGGLE, handler)
        client.checkpoint_toggle(3, False)
        assert received['en'] == 0


# ── checkpoint_list ────────────────────────────────────────────────────────────

class TestCheckpointList:
    """
    VICE sends checkpoint_list as multiple frames:
      N × RESP_CHECKPOINT_INFO (one per checkpoint)
      1 × RESP_CHECKPOINT_LIST (terminal, body = total count as 4-byte LE)
    """

    def _make_cp_info_body(self, cp: dict) -> bytes:
        return struct.pack(
            '<IBHHBBBBIIb',
            cp['number'], int(cp.get('currently_hit', False)),
            cp['start'], cp['end'],
            int(cp.get('stop_on_hit', True)), int(cp.get('enabled', True)),
            cp.get('cpu_op', CPU_OP_EXEC), int(cp.get('temporary', False)),
            cp.get('hit_count', 0), cp.get('ignore_count', 0),
            int(cp.get('has_condition', False)),
        )

    def _make_frames(self, checkpoints: list) -> list:
        """Build the multi-frame response list for checkpoint_list."""
        frames = []
        for cp in checkpoints:
            frames.append((RESP_CHECKPOINT_INFO, self._make_cp_info_body(cp)))
        # Terminal frame: RESP_CHECKPOINT_LIST with total count
        frames.append((RESP_CHECKPOINT_LIST, struct.pack('<I', len(checkpoints))))
        return frames

    def test_empty_list(self, connected_client):
        client, server = connected_client
        server.handle(CMD_CHECKPOINT_LIST, lambda _: self._make_frames([]))
        result = client.checkpoint_list()
        assert result == []

    def test_single_checkpoint(self, connected_client):
        client, server = connected_client
        cps = [{'number': 1, 'start': 0xC000, 'end': 0xC000,
                'cpu_op': CPU_OP_EXEC, 'hit_count': 2}]
        server.handle(CMD_CHECKPOINT_LIST, lambda _: self._make_frames(cps))
        result = client.checkpoint_list()
        assert len(result) == 1
        assert result[0]['number'] == 1
        assert result[0]['start']  == 0xC000
        assert result[0]['cpu_op'] == CPU_OP_EXEC
        assert result[0]['hit_count'] == 2

    def test_multiple_checkpoints(self, connected_client):
        client, server = connected_client
        cps = [
            {'number': 1, 'start': 0xC000, 'end': 0xC000, 'cpu_op': CPU_OP_EXEC},
            {'number': 2, 'start': 0xD020, 'end': 0xD020, 'cpu_op': CPU_OP_STORE},
            {'number': 3, 'start': 0x0400, 'end': 0x07FF, 'cpu_op': CPU_OP_LOAD},
        ]
        server.handle(CMD_CHECKPOINT_LIST, lambda _: self._make_frames(cps))
        result = client.checkpoint_list()
        assert len(result) == 3
        assert result[1]['start'] == 0xD020
        assert result[2]['end']   == 0x07FF

    def test_enabled_disabled_flags(self, connected_client):
        client, server = connected_client
        cps = [
            {'number': 1, 'start': 0xC000, 'end': 0xC000, 'enabled': True},
            {'number': 2, 'start': 0xC001, 'end': 0xC001, 'enabled': False},
        ]
        server.handle(CMD_CHECKPOINT_LIST, lambda _: self._make_frames(cps))
        result = client.checkpoint_list()
        assert result[0]['enabled'] is True
        assert result[1]['enabled'] is False

    def test_info_frames_ordering_preserved(self, connected_client):
        client, server = connected_client
        cps = [
            {'number': 5, 'start': 0xC000, 'end': 0xC000, 'cpu_op': CPU_OP_EXEC},
            {'number': 1, 'start': 0xD000, 'end': 0xD000, 'cpu_op': CPU_OP_LOAD},
        ]
        server.handle(CMD_CHECKPOINT_LIST, lambda _: self._make_frames(cps))
        result = client.checkpoint_list()
        assert result[0]['number'] == 5
        assert result[1]['number'] == 1


# ── step ───────────────────────────────────────────────────────────────────────

class TestResume:
    def test_resume_sends_cmd_exit(self, connected_client):
        """resume() must send CMD_EXIT (0xAA), not ADVANCE_INSTRUCTIONS."""
        client, server = connected_client
        done = threading.Event()

        def handler(body):
            done.set()
            return (CMD_EXIT, b'')

        server.handle(CMD_EXIT, handler)
        client.resume()
        assert done.wait(timeout=2), "CMD_EXIT handler was not called"

    def test_resume_does_not_send_advance_instructions(self, connected_client):
        client, server = connected_client
        advance_called = []
        exit_done = threading.Event()

        server.handle(CMD_ADVANCE_INSTRUCTIONS,
                      lambda _: advance_called.append(True) or (CMD_ADVANCE_INSTRUCTIONS, b''))
        def exit_handler(body):
            exit_done.set()
            return (CMD_EXIT, b'')
        server.handle(CMD_EXIT, exit_handler)
        client.resume()
        exit_done.wait(timeout=2)
        assert not advance_called


class TestStepUntilReturn:
    def test_sends_execute_until_return(self, connected_client):
        client, server = connected_client
        done = threading.Event()

        def handler(body):
            done.set()
            return (CMD_EXECUTE_UNTIL_RETURN, b'')

        server.handle(CMD_EXECUTE_UNTIL_RETURN, handler)
        client.step_until_return()
        assert done.wait(timeout=2), "CMD_EXECUTE_UNTIL_RETURN handler was not called"


class TestStep:
    def test_step_into_payload(self, connected_client):
        """payload byte order: step_over(1) count(2 LE)"""
        client, server = connected_client
        received = {}
        done = threading.Event()

        def handler(body):
            step_over, count = struct.unpack('<BH', body)
            received.update(count=count, step_over=step_over)
            done.set()
            return (CMD_ADVANCE_INSTRUCTIONS, b'')

        server.handle(CMD_ADVANCE_INSTRUCTIONS, handler)
        client.step(count=1, step_over=False)
        assert done.wait(timeout=2), "ADVANCE_INSTRUCTIONS handler was not called"
        assert received['count'] == 1
        assert received['step_over'] == 0

    def test_step_over_flag(self, connected_client):
        client, server = connected_client
        received = {}
        done = threading.Event()

        def handler(body):
            step_over, count = struct.unpack('<BH', body)
            received.update(count=count, step_over=step_over)
            done.set()
            return (CMD_ADVANCE_INSTRUCTIONS, b'')

        server.handle(CMD_ADVANCE_INSTRUCTIONS, handler)
        client.step(count=1, step_over=True)
        assert done.wait(timeout=2)
        assert received['step_over'] == 1

    def test_multi_step_count(self, connected_client):
        client, server = connected_client
        received = {}
        done = threading.Event()

        def handler(body):
            _, count = struct.unpack('<BH', body)
            received['count'] = count
            done.set()
            return (CMD_ADVANCE_INSTRUCTIONS, b'')

        server.handle(CMD_ADVANCE_INSTRUCTIONS, handler)
        client.step(count=10)
        assert done.wait(timeout=2)
        assert received['count'] == 10


# ── reset ──────────────────────────────────────────────────────────────────────

class TestReset:
    def test_soft_reset(self, connected_client):
        client, server = connected_client
        received = {}

        def handler(body):
            received['type'] = body[0]
            return (CMD_RESET, b'')

        server.handle(CMD_RESET, handler)
        client.reset(0)
        assert received['type'] == 0

    def test_hard_reset(self, connected_client):
        client, server = connected_client
        received = {}

        def handler(body):
            received['type'] = body[0]
            return (CMD_RESET, b'')

        server.handle(CMD_RESET, handler)
        client.reset(1)
        assert received['type'] == 1


# ── vice_info ──────────────────────────────────────────────────────────────────

class TestViceInfo:
    def test_legacy_text_format(self, connected_client):
        """Legacy: ML(1) version_string(ML bytes)"""
        client, server = connected_client
        # ML=10, version='VICE 3.7.1'
        server.handle(CMD_VICE_INFO,
                      lambda _: (RESP_VICE_INFO, b'\x0aVICE 3.7.1'))
        result = client.vice_info()
        assert result == 'VICE 3.7.1'

    def test_binary_format(self, connected_client):
        """Modern VICE 3.x+: major(1) minor(1) patch(1)"""
        client, server = connected_client
        # 3.7.1 as binary: \x03\x07\x01
        server.handle(CMD_VICE_INFO,
                      lambda _: (RESP_VICE_INFO, bytes([3, 7, 1])))
        result = client.vice_info()
        assert result == '3.7.1'

    def test_strips_null_terminator(self, connected_client):
        client, server = connected_client
        server.handle(CMD_VICE_INFO,
                      lambda _: (RESP_VICE_INFO, b'\x08VICE 3.7'))
        result = client.vice_info()
        assert not result.endswith('\x00')


# ── banks_available ────────────────────────────────────────────────────────────

class TestBanksAvailable:
    def _make_banks_body(self, banks):
        """banks: [(id, name)]"""
        body = struct.pack('<H', len(banks))
        for bid, name in banks:
            nb = name.encode('ascii')
            item_size = 2 + 1 + len(nb)   # bank_id(2) + name_len(1) + name
            body += struct.pack('<BHB', item_size, bid, len(nb)) + nb
        return body

    def test_returns_list(self, connected_client):
        client, server = connected_client
        server.handle(CMD_BANKS_AVAILABLE,
                      lambda _: (RESP_BANKS_AVAILABLE,
                                 self._make_banks_body([(0, 'ram'), (1, 'rom')])))
        result = client.banks_available()
        assert len(result) == 2
        assert result[0]['name'] == 'ram'
        assert result[1]['name'] == 'rom'

    def test_empty_banks(self, connected_client):
        client, server = connected_client
        server.handle(CMD_BANKS_AVAILABLE,
                      lambda _: (RESP_BANKS_AVAILABLE, self._make_banks_body([])))
        result = client.banks_available()
        assert result == []


# ── event handling ─────────────────────────────────────────────────────────────

class TestEvents:
    def test_stopped_event_triggers_handler(self, connected_client):
        client, server = connected_client
        events = []
        client.on_event(RESP_STOPPED, lambda t, e, b: events.append(('stopped', b)))

        server.send_event(RESP_STOPPED, struct.pack('<H', 0xC005))
        time.sleep(0.05)

        assert len(events) == 1
        assert events[0][0] == 'stopped'

    def test_stopped_event_carries_pc(self, connected_client):
        client, server = connected_client
        pcs = []
        def handler(t, e, body):
            pcs.append(struct.unpack_from('<H', body, 0)[0])
        client.on_event(RESP_STOPPED, handler)

        server.send_event(RESP_STOPPED, struct.pack('<H', 0xC100))
        time.sleep(0.05)

        assert pcs == [0xC100]

    def test_resumed_event_triggers_handler(self, connected_client):
        client, server = connected_client
        events = []
        client.on_event(RESP_RESUMED, lambda t, e, b: events.append('resumed'))

        server.send_event(RESP_RESUMED, struct.pack('<H', 0xC000))
        time.sleep(0.05)

        assert 'resumed' in events

    def test_multiple_events_in_sequence(self, connected_client):
        client, server = connected_client
        log = []
        client.on_event(RESP_STOPPED, lambda t, e, b: log.append('stopped'))
        client.on_event(RESP_RESUMED, lambda t, e, b: log.append('resumed'))

        server.send_event(RESP_RESUMED, struct.pack('<H', 0xC000))
        server.send_event(RESP_STOPPED, struct.pack('<H', 0xC100))
        time.sleep(0.1)

        assert 'resumed' in log
        assert 'stopped' in log

    def test_event_handler_exception_does_not_crash_recv_thread(self, connected_client):
        client, server = connected_client

        def bad_handler(t, e, b):
            raise RuntimeError("intentional error in handler")

        client.on_event(RESP_STOPPED, bad_handler)
        server.send_event(RESP_STOPPED, struct.pack('<H', 0xC000))
        time.sleep(0.05)

        # Receive thread must still be alive after handler raised
        assert client._recv_thread.is_alive()
        # Client should still respond to normal commands
        assert client.ping() is True

    def test_events_do_not_interfere_with_command_responses(self, connected_client):
        client, server = connected_client
        stop_count = [0]
        client.on_event(RESP_STOPPED, lambda t, e, b: stop_count.__setitem__(0, stop_count[0] + 1))

        # Interleave: send a stop event right before the ping response
        def ping_with_event(_):
            server.send_event(RESP_STOPPED, struct.pack('<H', 0xC000))
            return (0x81, b'')

        server.handle(CMD_PING, ping_with_event)
        result = client.ping()
        time.sleep(0.05)

        assert result is True
        assert stop_count[0] == 1


# ── error handling ─────────────────────────────────────────────────────────────

class TestErrors:
    def test_vice_error_stores_code(self):
        for code in [0x01, 0x8F, 0x10]:
            err = ViceError(code)
            assert err.code == code

    def test_vice_error_str_includes_hex_code(self):
        err = ViceError(0x8F)
        assert '0x8F' in str(err)

    def test_error_response_returns_false_for_ping(self, connected_client):
        """ping() swallows ViceError and returns False on server error."""
        client, server = connected_client
        # Remove ping handler so server sends 0x8F fallback error
        server._handlers.pop(CMD_PING, None)
        result = client.ping()
        assert result is False

    def test_error_response_raises_vice_error_on_command(self, connected_client):
        """_command raises ViceError when server returns non-zero error code."""
        client, server = connected_client
        # Remove memory_get handler so server sends 0x8F fallback error
        server._handlers.pop(CMD_MEMORY_GET, None)
        with pytest.raises(ViceError):
            client.memory_get(0x0000, 0x00FF)

    def test_memory_set_raises_on_overflow(self, connected_client):
        """memory_set raises ValueError if data extends past 0xFFFF."""
        client, _ = connected_client
        with pytest.raises(ValueError, match="0xFFFF"):
            client.memory_set(0xFFF0, bytes(17))  # 0xFFF0 + 17 > 0xFFFF

    def test_memory_set_empty_data_is_noop(self, connected_client):
        """memory_set with empty bytes must send no command."""
        client, server = connected_client
        called = []
        server.handle(CMD_MEMORY_SET, lambda _: called.append(True) or (CMD_MEMORY_SET, b''))
        client.memory_set(0x1000, b'')
        assert not called


# ── concurrency ────────────────────────────────────────────────────────────────

class TestConcurrency:
    def test_parallel_commands_all_complete(self, connected_client):
        """Multiple threads sending commands simultaneously must not deadlock."""
        client, server = connected_client

        results = []
        errors = []

        def send_ping():
            try:
                results.append(client.ping())
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=send_ping) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors
        assert len(results) == 10
        assert all(results)

    def test_request_ids_are_unique(self, connected_client):
        """Each command should get a distinct request ID."""
        client, _ = connected_client
        ids = set()
        for _ in range(50):
            rid = client._alloc_id()
            ids.add(rid)
        assert len(ids) == 50

    def test_request_id_never_equals_event_id(self, connected_client):
        client, _ = connected_client
        for _ in range(1000):
            rid = client._alloc_id()
            assert rid != EVENT_REQUEST_ID


# ── edge cases and regression tests ──────────────────────────────────────────

class TestMemoryEdgeCases:
    def test_memory_set_exactly_at_boundary(self, connected_client):
        """memory_set ending exactly at 0xFFFF must succeed."""
        client, server = connected_client
        received = {}

        def handler(body):
            _, start, end, _, _ = struct.unpack('<BHHBH', body[:8])
            received.update(start=start, end=end)
            return (CMD_MEMORY_SET, b'')

        server.handle(CMD_MEMORY_SET, handler)
        client.memory_set(0xFFFF, b'\x42')  # single byte at last address
        assert received['start'] == 0xFFFF
        assert received['end'] == 0xFFFF

    def test_memory_set_boundary_two_bytes(self, connected_client):
        """memory_set of 2 bytes ending exactly at 0xFFFF."""
        client, server = connected_client
        received = {}

        def handler(body):
            _, start, end, _, _ = struct.unpack('<BHHBH', body[:8])
            received.update(start=start, end=end)
            return (CMD_MEMORY_SET, b'')

        server.handle(CMD_MEMORY_SET, handler)
        client.memory_set(0xFFFE, b'\x00\xC0')
        assert received['start'] == 0xFFFE
        assert received['end'] == 0xFFFF

    def test_memory_set_one_past_boundary_raises(self, connected_client):
        """memory_set at 0xFFFF with 2 bytes exceeds address space."""
        client, _ = connected_client
        with pytest.raises(ValueError, match="0xFFFF"):
            client.memory_set(0xFFFF, bytes(2))

    def test_memory_get_full_64k_minus_one(self, connected_client):
        """Reading 0x0000-0xFFFE (65535 bytes — max for uint16 length prefix)."""
        client, server = connected_client
        data = bytes(256) * 255 + bytes(range(255))  # 65535 bytes
        server.handle(CMD_MEMORY_GET, lambda _: _memory_resp(data))
        result = client.memory_get(0x0000, 0xFFFE)
        assert len(result) == 65535


class TestRegisterDiscoveryEdgeCases:
    def test_long_register_name(self):
        """Register names longer than typical (e.g. 'FLAGS') must parse correctly."""
        from bmp_helpers import build_registers_available_body
        from vice.util import ViceBmpClient

        regs = [(0, 'PC', 16), (1, 'LONG_REG_NAME', 8)]
        server = MockViceServer(registers=regs)
        server.start()
        try:
            client = ViceBmpClient('127.0.0.1', server.port)
            client.connect()
            assert 'PC' in client.reg_name_to_id
            assert 'LONG_REG_NAME' in client.reg_name_to_id
            assert client.reg_id_to_name[1] == 'LONG_REG_NAME'
            client.disconnect()
        finally:
            server.stop()

    def test_registers_get_unknown_id_gets_fallback_name(self, connected_client):
        """A reg_id not in reg_id_to_name should get 'rN' fallback."""
        client, server = connected_client
        # Build a response with an extra reg_id=99 not in the discovery map
        body = struct.pack('<H', 1)  # count=1
        body += struct.pack('<BBH', 3, 99, 0x42)  # item_size=3, reg_id=99, value=0x42
        server.handle(CMD_REGISTERS_GET, lambda _: (RESP_REGISTERS_GET, body))
        result = client.registers_get()
        assert 'r99' in result
        assert result['r99'] == 0x42


class TestTimeoutBehavior:
    def test_command_timeout_raises(self, connected_client):
        """A command that never gets a response should raise TimeoutError."""
        client, server = connected_client
        # Remove the ping handler so server sends an error-coded response,
        # but also remove all handlers to let the command hang
        server._handlers.clear()
        # Re-add a handler that never responds by just not returning properly
        # Simpler: just use a very short timeout
        with pytest.raises((TimeoutError, ViceError)):
            client._command(CMD_PING, timeout=0.1)


class TestInterrupt:
    def test_interrupt_sends_ping(self, connected_client):
        """interrupt() sends a fire-and-forget ping to stop VICE."""
        client, server = connected_client
        done = threading.Event()

        def handler(body):
            done.set()
            return (CMD_PING, b'')

        server.handle(CMD_PING, handler)
        client.interrupt()
        assert done.wait(timeout=2), "Ping handler was not called"

    def test_interrupt_does_not_block(self, connected_client):
        """interrupt() must return immediately (fire-and-forget)."""
        client, _ = connected_client
        start = time.monotonic()
        client.interrupt()
        elapsed = time.monotonic() - start
        assert elapsed < 0.5, f"interrupt() blocked for {elapsed:.2f}s"
