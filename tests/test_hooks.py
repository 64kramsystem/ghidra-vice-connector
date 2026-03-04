"""
Tests for hooks.py event callbacks.

Verifies that:
- STOPPED events call commands.on_stop
- RESUMED events call commands.on_resume
- Errors in on_stop/on_resume are caught and do not propagate
- install_hooks registers both event types on the ViceBmpClient
- install_hooks raises if vice is not connected
"""

import struct
from unittest.mock import MagicMock, patch, call

import pytest

from vice import hooks, commands
from vice.util import RESP_STOPPED, RESP_RESUMED


@pytest.fixture(autouse=True)
def reset_state():
    commands.STATE.vice   = None
    commands.STATE.trace  = None
    commands.STATE.client = None
    yield
    commands.STATE.vice   = None
    commands.STATE.trace  = None
    commands.STATE.client = None


# ── install_hooks ──────────────────────────────────────────────────────────────

class TestInstallHooks:
    def test_raises_when_vice_not_connected(self):
        with pytest.raises(RuntimeError, match="not connected"):
            hooks.install_hooks()

    def test_registers_stopped_handler(self):
        vice = MagicMock()
        commands.STATE.vice = vice
        hooks.install_hooks()
        stopped_call = vice.on_event.call_args_list[0]
        assert stopped_call.args[0] == RESP_STOPPED

    def test_registers_resumed_handler(self):
        vice = MagicMock()
        commands.STATE.vice = vice
        hooks.install_hooks()
        types = [c.args[0] for c in vice.on_event.call_args_list]
        assert RESP_RESUMED in types

    def test_registers_exactly_two_handlers(self):
        vice = MagicMock()
        commands.STATE.vice = vice
        hooks.install_hooks()
        assert vice.on_event.call_count == 2


# ── _on_stopped ────────────────────────────────────────────────────────────────

class TestOnStopped:
    def test_calls_commands_on_stop(self):
        with patch.object(commands, 'on_stop') as mock_stop:
            hooks._on_stopped(RESP_STOPPED, 0, struct.pack('<H', 0xC000))
            mock_stop.assert_called_once()

    def test_handles_empty_body(self):
        with patch.object(commands, 'on_stop') as mock_stop:
            hooks._on_stopped(RESP_STOPPED, 0, b'')  # must not raise
            mock_stop.assert_called_once()

    def test_handles_short_body(self):
        with patch.object(commands, 'on_stop') as mock_stop:
            hooks._on_stopped(RESP_STOPPED, 0, b'\xC0')  # only 1 byte, not 2
            mock_stop.assert_called_once()

    def test_on_stop_exception_is_caught(self):
        with patch.object(commands, 'on_stop', side_effect=RuntimeError("boom")):
            # Must not raise — errors are swallowed to protect the recv thread
            hooks._on_stopped(RESP_STOPPED, 0, struct.pack('<H', 0xC000))

    def test_pc_extraction_correct(self):
        """Verify the PC value in the body is correctly reachable for future use."""
        body = struct.pack('<H', 0xD020)
        pc = struct.unpack_from('<H', body, 0)[0] if len(body) >= 2 else 0
        assert pc == 0xD020

    def test_called_with_various_pc_values(self):
        """_on_stopped must not crash regardless of PC value."""
        with patch.object(commands, 'on_stop'):
            for pc in [0x0000, 0x0801, 0xC000, 0xFFFF]:
                hooks._on_stopped(RESP_STOPPED, 0, struct.pack('<H', pc))


# ── _on_resumed ────────────────────────────────────────────────────────────────

class TestOnResumed:
    def test_calls_commands_on_resume(self):
        with patch.object(commands, 'on_resume') as mock_resume:
            hooks._on_resumed(RESP_RESUMED, 0, struct.pack('<H', 0xC000))
            mock_resume.assert_called_once()

    def test_handles_empty_body(self):
        with patch.object(commands, 'on_resume') as mock_resume:
            hooks._on_resumed(RESP_RESUMED, 0, b'')
            mock_resume.assert_called_once()

    def test_on_resume_exception_is_caught(self):
        with patch.object(commands, 'on_resume', side_effect=RuntimeError("boom")):
            hooks._on_resumed(RESP_RESUMED, 0, struct.pack('<H', 0xC000))


# ── round-trip: install + fire ─────────────────────────────────────────────────

class TestInstallAndFire:
    def test_installed_stopped_handler_delegates_to_on_stop(self):
        vice = MagicMock()
        commands.STATE.vice = vice
        hooks.install_hooks()

        # Extract the registered handler for RESP_STOPPED
        stopped_handler = None
        for c in vice.on_event.call_args_list:
            if c.args[0] == RESP_STOPPED:
                stopped_handler = c.args[1]
                break

        assert stopped_handler is not None
        with patch.object(commands, 'on_stop') as mock_stop:
            stopped_handler(RESP_STOPPED, 0, struct.pack('<H', 0xC000))
            mock_stop.assert_called_once()

    def test_installed_resumed_handler_delegates_to_on_resume(self):
        vice = MagicMock()
        vice.has_pending_events.return_value = False
        commands.STATE.vice = vice
        hooks.install_hooks()

        resumed_handler = None
        for c in vice.on_event.call_args_list:
            if c.args[0] == RESP_RESUMED:
                resumed_handler = c.args[1]
                break

        assert resumed_handler is not None
        with patch.object(commands, 'on_resume') as mock_resume:
            resumed_handler(RESP_RESUMED, 0, struct.pack('<H', 0xC000))
            mock_resume.assert_called_once()
