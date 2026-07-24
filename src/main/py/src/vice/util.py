"""Compatibility import for the protocol module.

Production code has one BMP implementation in :mod:`vice.protocol`.
"""

from .protocol import *  # noqa: F401,F403
from .protocol import _parse_checkpoint_info  # noqa: F401
