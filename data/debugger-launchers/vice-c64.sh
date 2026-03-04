#!/usr/bin/env bash
#@title VICE C64 Debugger
#@desc <html><body width="300px">
#@desc   <h3>Connect to VICE C64 via Binary Monitor Protocol</h3>
#@desc   <p>Start VICE with:</p>
#@desc   <p><tt>x64 -binarymonitor -binarymonitoraddress HOST:PORT</tt></p>
#@desc   <p>then launch this connector.</p>
#@desc </body></html>
#@menu-group vice
#@icon icon.debugger
#@help TraceRmiLauncherServicePlugin#vice_c64
#@env OPT_PYTHON_EXE:file="python3" "Python command" "Path to the Python 3 interpreter"
#@env OPT_HOST:str="localhost" "VICE Host" "Hostname or IP of the machine running VICE"
#@env OPT_PORT:int=6502 "VICE Port" "Binary Monitor TCP port (VICE default: 6502)"

# Resolve extension root from this script's location:
# data/debugger-launchers/vice-c64.sh -> up two levels -> extension root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

pypathTrace="$MODULE_Debugger_rmi_trace_HOME/pypkg/src"
pypathVice="$EXT_ROOT/src/main/py/src"

# Discover the Python site-packages path so pip-installed ghidratrace (which
# ships with protobuf) is found ahead of the Ghidra source copy.
VENV_SITE="$("$OPT_PYTHON_EXE" -c 'import site; print(site.getsitepackages()[0])' 2>/dev/null || true)"

export PYTHONPATH="$pypathVice:$VENV_SITE:$pypathTrace:$PYTHONPATH"

"$OPT_PYTHON_EXE" "$EXT_ROOT/data/support/vice-c64.py"
