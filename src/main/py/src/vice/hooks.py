"""VICE event integration.

The controller installs its lightweight socket-reader callback when it is
constructed. Trace synchronization begins only after initial trace population,
when ``commands.populate_initial_state`` starts the event coordinator.
"""

import functools
import logging

from . import commands

log = logging.getLogger("vice-agent")


def log_errors(func):
    """Log event-integration defects without killing a dispatcher thread."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception:
            log.error("%s raised", func.__name__, exc_info=True)

    return wrapper


def install_hooks():
    """Verify that the one shared controller owns the event sink."""
    controller = commands.STATE.require_controller()
    if controller.client is not commands.STATE.require_vice():
        raise RuntimeError("VICE controller/client identity mismatch")
    log.info("VICE controller event sink is installed")
