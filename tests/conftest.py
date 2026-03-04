"""
Shared fixtures and infrastructure for the VICE C64 Ghidra agent test suite.

Provides:
  - MockViceServer: a real TCP server speaking BMP so ViceBmpClient tests
    exercise actual socket code rather than mocked sockets
  - ghidratrace stubs: injected into sys.modules before any vice.commands /
    vice.methods / vice.hooks are imported, since those modules are only
    available inside a running Ghidra JVM
"""

import os
import sys
from typing import Callable, Dict
from unittest.mock import MagicMock

import pytest

# ── Path setup ────────────────────────────────────────────────────────────────

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PY_SRC = os.path.join(ROOT, 'src', 'main', 'py', 'src')
TESTS_DIR = os.path.dirname(__file__)
if PY_SRC not in sys.path:
    sys.path.insert(0, PY_SRC)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

# ── Ghidra stub modules ───────────────────────────────────────────────────────
# Must be inserted before any vice.commands / vice.methods / vice.hooks import.

def _build_ghidratrace_stubs():
    """Create minimal MagicMock stubs for all ghidratrace / ghidradbg symbols."""

    # ghidratrace.sch
    sch_mod = MagicMock(name='ghidratrace.sch')

    def _Schema(name):
        """Schema() is used as a type annotation; return a trivial sentinel."""
        m = MagicMock(name=f'Schema({name})')
        m.__name__ = name
        return m

    sch_mod.Schema = _Schema

    # ghidratrace.client
    client_mod = MagicMock(name='ghidratrace.client')

    class _Address:
        def __init__(self, space: str, offset: int):
            self.space = space
            self.offset = offset
        def __repr__(self):
            return f"Address({self.space!r}, 0x{self.offset:04X})"

    class _AddressRange:
        def __init__(self, start: '_Address', length: int):
            self.min = start
            self.max = _Address(start.space, start.offset + length - 1)
        def __repr__(self):
            return f"AddressRange({self.min!r}, len={self.max.offset - self.min.offset + 1})"

        @classmethod
        def extend(cls, start: '_Address', length: int) -> '_AddressRange':
            return cls(start, length)

    # MethodRegistry: collect decorated methods without needing a real executor
    class _MethodRegistry:
        def __init__(self, executor=None):
            self.methods = {}

        def method(self, action=None, display=None):
            def decorator(fn):
                self.methods[fn.__name__] = fn
                return fn
            return decorator

        def publish(self, client):
            pass

    class _RegVal:
        def __init__(self, name: str, value: bytes):
            self.name = name
            self.value = value
        def __repr__(self):
            return f"RegVal({self.name!r}, {self.value.hex()})"

    class _TraceObject:
        """Base class for schema type stubs in methods.py."""
        def __init__(self):
            self.path = ''

    client_mod.Address = _Address
    client_mod.AddressRange = _AddressRange
    client_mod.RegVal = _RegVal
    client_mod.TraceObject = _TraceObject
    client_mod.MethodRegistry = _MethodRegistry
    client_mod.Client = MagicMock(name='Client')
    client_mod.ParamDesc = MagicMock(name='ParamDesc')

    # ghidratrace (top-level)
    ghidratrace_mod = MagicMock(name='ghidratrace')
    ghidratrace_mod.sch = sch_mod
    ghidratrace_mod.client = client_mod

    return ghidratrace_mod, sch_mod, client_mod


_gt, _gt_sch, _gt_client = _build_ghidratrace_stubs()
sys.modules.setdefault('ghidratrace',        _gt)
sys.modules.setdefault('ghidratrace.sch',    _gt_sch)
sys.modules.setdefault('ghidratrace.client', _gt_client)

# ── BMP helpers and MockViceServer ────────────────────────────────────────────
# Imported after path is set up above.

from bmp_helpers import MockViceServer  # noqa: E402


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_server():
    """Start a MockViceServer and yield it; stop it after the test."""
    server = MockViceServer()
    server.start()
    yield server
    server.stop()


@pytest.fixture
def connected_client(mock_server):
    """ViceBmpClient already connected to the MockViceServer."""
    from vice.util import ViceBmpClient
    client = ViceBmpClient('127.0.0.1', mock_server.port)
    client.connect()
    yield client, mock_server
    client.disconnect()
