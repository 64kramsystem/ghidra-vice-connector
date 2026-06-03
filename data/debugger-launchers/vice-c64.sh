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
#@depends Debugger-rmi-trace
#@enum LogLevel:str DEBUG INFO WARNING ERROR
#@env OPT_PYTHON_EXE:file="python3" "Python command" "Path to the Python 3 interpreter"
#@env OPT_LOG_FILE:file="/tmp/vice-agent.log" "Log file" "Agent log file path"
#@env OPT_LOG_LEVEL:LogLevel="DEBUG" "Log level" "Agent log verbosity"
#@env OPT_HOST:str="localhost" "VICE Host" "Hostname or IP of the machine running VICE"
#@env OPT_PORT:int=6502 "VICE Port" "Binary Monitor TCP port (VICE default: 6502)"

. "$MODULE_Debugger_rmi_trace_HOME/data/support/setuputils.sh"

# Resolve extension root from this script's location:
# data/debugger-launchers/vice-c64.sh -> up two levels -> extension root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ghidra-module-pypath resolves installed (pypkg/src) and dev (build/pypkg/src) layouts. The VICE
# package keeps its own path: this extension does not use the pypkg layout.
pypathTrace=$(ghidra-module-pypath "Debugger-rmi-trace")
pypathVice="$EXT_ROOT/src/main/py/src"

# Discover the Python site-packages path so pip-installed ghidratrace (which
# ships with protobuf) is found ahead of the Ghidra source copy.
VENV_SITE="$("$OPT_PYTHON_EXE" -c 'import site; print(site.getsitepackages()[0])' 2>/dev/null || true)"

export PYTHONPATH="$pypathVice:$VENV_SITE:$pypathTrace:$PYTHONPATH"

"$OPT_PYTHON_EXE" "$EXT_ROOT/data/support/vice-c64.py"
