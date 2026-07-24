"""The single TraceRMI method registry for GUI and automation methods."""

from concurrent.futures import ThreadPoolExecutor

from ghidratrace.client import MethodRegistry

REGISTRY = MethodRegistry(
    ThreadPoolExecutor(max_workers=1, thread_name_prefix="MethodRegistry")
)
