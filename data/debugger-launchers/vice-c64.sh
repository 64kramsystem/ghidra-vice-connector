#!/usr/bin/env bash
#@title VICE C64 Debugger
#@desc <html><body width="300px">
#@desc   <h3>Connect to VICE C64 via Binary Monitor Protocol</h3>
#@desc   <p>Start VICE with:</p>
#@desc   <p><tt>x64 -binarymonitor -binarymonitoraddress ip4://HOST:PORT</tt></p>
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
#@env OPT_HOST:str="127.0.0.1" "VICE Host" "Hostname or IP of the machine running VICE"
#@env OPT_PORT:int=6502 "VICE Port" "Binary Monitor TCP port (VICE default: 6502)"

. "$MODULE_Debugger_rmi_trace_HOME/data/support/setuputils.sh"

# Resolve extension root from this script's location:
# data/debugger-launchers/vice-c64.sh -> up two levels -> extension root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

. "$EXT_ROOT/data/support/prepare-python.sh" || exit $?


"$OPT_PYTHON_EXE" "$EXT_ROOT/data/support/vice-c64.py"
