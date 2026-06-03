"""
VICE event hooks.

Registers callbacks on the ViceBmpClient for unsolicited events:
  - RESP_STOPPED (0x62): CPU has stopped (breakpoint hit, step complete)
  - RESP_RESUMED (0x63): CPU has resumed execution

These are called from ViceBmpClient's event worker thread, so they must not
block for long. Heavy work is deferred to open_tracked_tx which holds the
trace lock briefly for trace updates.
"""

import functools
import logging
import struct

from .util import RESP_STOPPED, RESP_RESUMED
from . import commands

log = logging.getLogger('vice-agent')


def log_errors(func):
    """Decorator that catches and logs exceptions in event handlers.

    Following the GDB agent pattern: event handler exceptions must not
    propagate to the event worker thread, which would kill event processing.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception:
            log.error(f"{func.__name__} raised:", exc_info=True)
    return wrapper


@log_errors
def _on_stopped(resp_type: int, error: int, body: bytes):
    """
    VICE sends this when the CPU stops.

    Body: PC (2 LE)
    """
    pc = struct.unpack_from('<H', body, 0)[0] if len(body) >= 2 else 0
    log.info(f"EVENT stopped: PC=0x{pc:04X}")
    commands.on_stop()


@log_errors
def _on_resumed(resp_type: int, error: int, body: bytes):
    """
    VICE sends this when the CPU resumes.

    Body: PC (2 LE)

    For steps, VICE sends RESUMED immediately followed by STOPPED; the event
    worker coalesces that pair, so reaching this handler means a real resume.
    """
    pc = struct.unpack_from('<H', body, 0)[0] if len(body) >= 2 else 0
    log.info(f"EVENT resumed: PC=0x{pc:04X}")
    commands.on_resume()


def install_hooks():
    """Register all event handlers on the active ViceBmpClient."""
    vice = commands.STATE.vice
    if vice is None:
        raise RuntimeError("Cannot install hooks: not connected to VICE")
    vice.on_event(RESP_STOPPED, _on_stopped)
    vice.on_event(RESP_RESUMED, _on_resumed)
    log.info(f"install_hooks(): registered RESP_STOPPED and RESP_RESUMED")
