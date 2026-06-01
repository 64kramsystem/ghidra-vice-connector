"""
Edge-case and error-path tests for the VICE C64 agent.

These exercise branches the happy-path suite does not reach: request-id
wraparound, disconnect tolerance, unhandled events, multi-frame error/timeout
handling, the step-vs-resume optimisation in hooks, and the swallowed
set_process_state failure in commands.on_resume.
"""

import socket
import time

import pytest
from unittest.mock import MagicMock, patch

from vice import hooks, commands
from vice.util import (
    ViceBmpClient, ViceError,
    EVENT_REQUEST_ID,
    CMD_PING, RESP_PING,
    RESP_RESUMED,
)


# ── _alloc_id wraparound ────────────────────────────────────────────────────────

class TestAllocIdWraparound:
    def test_next_id_wraps_to_one_before_reaching_event_id(self, connected_client):
        """The request-id counter must wrap to 1 (never reaching the reserved
        EVENT_REQUEST_ID) so a command id can never collide with an event."""
        client, _ = connected_client
        client._next_id = EVENT_REQUEST_ID - 1

        rid = client._alloc_id()
        assert rid == EVENT_REQUEST_ID - 1   # last usable id is handed out
        assert client._next_id == 1          # counter wrapped instead of hitting EVENT_REQUEST_ID

        assert client._alloc_id() == 1       # next allocation resumes from 1


# ── disconnect tolerance ────────────────────────────────────────────────────────

class TestDisconnect:
    def test_disconnect_swallows_close_oserror(self):
        """A socket whose close() raises must not make disconnect() throw."""
        class _BoomSock:
            def close(self):
                raise OSError("close failed")

        client = ViceBmpClient('127.0.0.1', 9999)   # not connected; no recv threads
        client._sock = _BoomSock()
        client.disconnect()                          # must not raise
        assert client._sock is None

    def test_disconnect_is_idempotent(self):
        client = ViceBmpClient('127.0.0.1', 9999)
        client.disconnect()
        client.disconnect()                          # second call on a None sock is a no-op
        assert client._sock is None

    def test_has_pending_events_false_when_idle(self, connected_client):
        client, _ = connected_client
        assert client.has_pending_events() is False


# ── unhandled events ────────────────────────────────────────────────────────────

class TestUnhandledEvent:
    def test_event_without_handler_does_not_break_connection(self, connected_client):
        """An event whose resp_type has no registered handler is logged and
        dropped; the recv loop must keep serving subsequent commands."""
        client, server = connected_client
        server.send_event(0x7F, b'')   # 0x7F: no handler registered
        time.sleep(0.1)
        assert client.ping() is True   # connection still alive and responsive


# ── _command_multi error / timeout paths ────────────────────────────────────────

class TestCommandMultiErrors:
    def test_error_frame_raises_vice_error(self, connected_client):
        """A multi-frame collect that receives an error frame raises ViceError."""
        client, _ = connected_client
        # CMD 0x77 has no handler → MockViceServer replies with error 0x8F.
        with pytest.raises(ViceError):
            client._command_multi(0x77, terminal_resp_type=0x77)

    def test_expired_deadline_raises_timeout_error(self, connected_client):
        """A non-positive remaining budget raises the explicit TimeoutError
        guard rather than blocking forever on the queue."""
        client, _ = connected_client
        with pytest.raises(TimeoutError):
            client._command_multi(CMD_PING, terminal_resp_type=RESP_PING, timeout=0)


# ── hooks: step skips the resume state change ────────────────────────────────────

class TestResumedStepSkip:
    def setup_method(self):
        commands.STATE.vice = None

    def teardown_method(self):
        commands.STATE.vice = None

    def test_resumed_skips_on_resume_when_stop_already_queued(self):
        """When a STOPPED event is already queued, a RESUMED event is part of a
        step and must NOT trigger the expensive on_resume() state change."""
        vice = MagicMock()
        vice.has_pending_events.return_value = True
        commands.STATE.vice = vice
        with patch.object(commands, 'on_resume') as mock_resume:
            hooks._on_resumed(RESP_RESUMED, 0, b'\x00\xc0')
            mock_resume.assert_not_called()

    def test_resumed_calls_on_resume_when_no_pending_events(self):
        vice = MagicMock()
        vice.has_pending_events.return_value = False
        commands.STATE.vice = vice
        with patch.object(commands, 'on_resume') as mock_resume:
            hooks._on_resumed(RESP_RESUMED, 0, b'\x00\xc0')
            mock_resume.assert_called_once()


# ── commands.on_resume swallows a failed state change ─────────────────────────────

class TestOnResumeStateFailure:
    def test_on_resume_swallows_set_process_state_failure(self):
        """on_resume() may race with a step; a set_process_state failure must be
        caught and logged, not propagated to the event worker."""
        with patch.object(commands, 'set_process_state',
                          side_effect=RuntimeError("races with step")):
            commands.on_resume()   # must not raise


# ── connection lifecycle ─────────────────────────────────────────────────────────

class TestConnectionLifecycle:
    def setup_method(self):
        commands.STATE.vice = None
        commands.STATE.client = None
        commands.STATE.trace = None

    def teardown_method(self):
        if commands.STATE.vice is not None:
            commands.STATE.vice.disconnect()
        commands.STATE.vice = None
        commands.STATE.client = None
        commands.STATE.trace = None

    def test_connect_vice_wires_and_connects_client(self, mock_server):
        """connect_vice() must create the BMP client on STATE and connect it."""
        commands.connect_vice('127.0.0.1', mock_server.port)
        assert isinstance(commands.STATE.vice, ViceBmpClient)
        assert commands.STATE.vice.ping() is True   # proves the socket is live

    def test_start_trace_connects_and_creates_trace(self):
        """start_trace() must open the TraceRmi socket, create the trace via the
        Client, and save it. (ghidratrace.Client is stubbed in conftest.)"""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            commands.start_trace('127.0.0.1', port, MagicMock(name='registry'))
            assert commands.STATE.client is not None
            assert commands.STATE.trace is not None
            commands.STATE.trace.save.assert_called_once()
        finally:
            listener.close()
