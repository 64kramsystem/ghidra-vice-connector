# Shared setup for the Ghidra 12.2 VICE launchers.
pypath_trace=$(ghidra-module-pypath "Debugger-rmi-trace")
export PYTHONPATH="$EXT_ROOT/src/main/py/src:$pypath_trace"
"$OPT_PYTHON_EXE" - <<'CHECK'
from pathlib import Path
import os
import ghidratrace.client as client
expected = Path(os.environ['MODULE_Debugger_rmi_trace_HOME']).resolve()
actual = Path(client.__file__).resolve()
if client.VERSION != '12.2' or not actual.is_relative_to(expected):
    raise SystemExit(f'Expected Ghidra 12.2 bundled ghidratrace; loaded {actual} ({client.VERSION})')
CHECK
