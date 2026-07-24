"""TraceRMI object-schema marker types shared by GUI and automation methods."""

from ghidratrace.client import TraceObject


class C64(TraceObject):
    pass


class C64Thread(TraceObject):
    pass


class C64Frame(TraceObject):
    pass


class RegisterContainer(TraceObject):
    pass


class MemoryRegion(TraceObject):
    pass


class BreakpointContainer(TraceObject):
    pass


class ViceBreakpoint(TraceObject):
    pass
