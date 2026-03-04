"""
Tests for the State class lifecycle.

Validates the require_*/reset_* pattern, ensuring proper precondition
enforcement and cleanup cascades.
"""

from unittest.mock import MagicMock

import pytest

from vice.commands import State


class TestRequireMethods:
    def test_require_vice_raises_when_none(self):
        s = State()
        with pytest.raises(RuntimeError, match="Not connected to VICE"):
            s.require_vice()

    def test_require_vice_returns_client(self):
        s = State()
        mock = MagicMock()
        s.vice = mock
        assert s.require_vice() is mock

    def test_require_client_raises_when_none(self):
        s = State()
        with pytest.raises(RuntimeError, match="Not connected to Ghidra"):
            s.require_client()

    def test_require_client_returns_client(self):
        s = State()
        mock = MagicMock()
        s.client = mock
        assert s.require_client() is mock

    def test_require_trace_raises_when_none(self):
        s = State()
        with pytest.raises(RuntimeError, match="Trace not started"):
            s.require_trace()

    def test_require_trace_returns_trace(self):
        s = State()
        mock = MagicMock()
        s.trace = mock
        assert s.require_trace() is mock


class TestResetMethods:
    def test_reset_vice_clears_vice(self):
        s = State()
        s.vice = MagicMock()
        s.reset_vice()
        assert s.vice is None

    def test_reset_trace_clears_trace_and_snap(self):
        s = State()
        s.trace = MagicMock()
        s.snap = 5
        s.reset_trace()
        assert s.trace is None
        assert s.snap == 0

    def test_reset_client_cascades(self):
        """reset_client must also reset trace and vice."""
        s = State()
        s.client = MagicMock()
        s.trace = MagicMock()
        s.vice = MagicMock()
        s.snap = 3
        s.reset_client()
        assert s.client is None
        assert s.trace is None
        assert s.vice is None
        assert s.snap == 0


class TestInitialState:
    def test_fresh_state_has_all_none(self):
        s = State()
        assert s.client is None
        assert s.trace is None
        assert s.vice is None
        assert s.snap == 0

    def test_require_vice_then_set_then_require(self):
        """Typical lifecycle: fail → set → succeed."""
        s = State()
        with pytest.raises(RuntimeError):
            s.require_vice()
        s.vice = MagicMock()
        s.require_vice()  # must not raise
