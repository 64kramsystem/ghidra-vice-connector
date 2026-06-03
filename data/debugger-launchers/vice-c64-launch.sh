#!/usr/bin/env bash
#@title VICE C64 Debugger (launch VICE)
#@desc <html><body width="300px">
#@desc   <h3>Launch VICE and connect via Binary Monitor Protocol</h3>
#@desc   <p>Starts the emulator with the binary monitor enabled (optionally
#@desc   autostarting a PRG image), waits for the monitor port, then attaches
#@desc   the connector.</p>
#@desc </body></html>
#@menu-group vice
#@icon icon.debugger
#@help TraceRmiLauncherServicePlugin#vice_c64
#@depends Debugger-rmi-trace
#@env OPT_VICE_PATH:file="x64sc" "VICE command" "Path to the VICE C64 emulator (x64sc or x64). Omit the full path to resolve using the system PATH."
#@env OPT_PRG_FILE:file="" "PRG image" "Optional .prg program to autostart, empty to just boot BASIC"
#@env OPT_HOST:str="127.0.0.1" "Monitor host" "Address the binary monitor binds to"
#@env OPT_PORT:int=6502 "Monitor port" "Binary Monitor TCP port (VICE default: 6502)"
#@env OPT_EXTRA_VICE_ARGS:str="" "Extra VICE args" "Additional arguments passed to VICE"
#@env OPT_PYTHON_EXE:file="python3" "Python command" "Path to the Python 3 interpreter"

. "$MODULE_Debugger_rmi_trace_HOME/data/support/setuputils.sh"

# Resolve extension root from this script's location:
# data/debugger-launchers/vice-c64-launch.sh -> up two levels -> extension root
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

vice_args=(-binarymonitor -binarymonitoraddress "$OPT_HOST:$OPT_PORT")
if [ -n "$OPT_EXTRA_VICE_ARGS" ]; then
  vice_args+=($OPT_EXTRA_VICE_ARGS)
fi
if [ -n "$OPT_PRG_FILE" ]; then
  vice_args+=(-autostart "$OPT_PRG_FILE")
fi

"$OPT_VICE_PATH" "${vice_args[@]}" &
VICE_PID=$!
trap 'kill "$VICE_PID" 2>/dev/null' EXIT

# Wait for the binary monitor port; bail out early if VICE dies during startup.
deadline=$((SECONDS + 30))
until (exec 3<>"/dev/tcp/$OPT_HOST/$OPT_PORT") 2>/dev/null; do
  if ! kill -0 "$VICE_PID" 2>/dev/null; then
    echo "[vice-c64-launch] VICE exited before opening the binary monitor port" >&2
    exit 1
  fi
  if (( SECONDS >= deadline )); then
    echo "[vice-c64-launch] binary monitor port $OPT_HOST:$OPT_PORT not open after 30s" >&2
    exit 1
  fi
  sleep 0.5
done
exec 3<&- 3>&-

"$OPT_PYTHON_EXE" "$EXT_ROOT/data/support/vice-c64.py"
