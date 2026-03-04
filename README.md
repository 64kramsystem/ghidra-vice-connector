# Ghidra VICE Connector

A Ghidra debugger extension that connects to the [VICE](https://vice-emu.sourceforge.io/) Commodore 64 emulator via its Binary Monitor Protocol. It uses Ghidra's TraceRmi framework (Ghidra 11.3+) to provide live debugging of 6502/6510 code running in VICE.

## Features

- Step into, step over, step out (until RTS/RTI), resume, and interrupt
- Register display and tracking (PC, A, X, Y, S, P)
- Live memory view of the full 64 KB address space
- Breakpoints (execute) and watchpoints (read/write)
- Automatic disassembly around the program counter on stop events
- Soft and hard reset

## Prerequisites

- **Ghidra** 11.3 or later (with TraceRmi support)
- **VICE** with Binary Monitor Protocol enabled
- **Python 3** with the `ghidratrace` package installed (from Ghidra's `Debugger-rmi-trace` module or via pip)

## Building

Set `GHIDRA_INSTALL_DIR` to your Ghidra installation, then build with Gradle:

```sh
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew buildExtension
```

The extension zip will be in `dist/`.

## Installation

Install the built extension zip through **File > Install Extensions** in Ghidra, then restart.

## Usage

1. Start VICE with the binary monitor enabled:

   ```sh
   x64sc -binarymonitor -binarymonitoraddress localhost:6502
   ```

2. In Ghidra, open the **Debugger** tool.

3. From the debugger launch menu, select **VICE C64 Debugger**.

4. Configure the host and port (default: `localhost:6502`) and click **Launch**.

The connector will attach to VICE, read the current CPU state, and populate the trace. You can then use Ghidra's standard debugger controls (step, resume, breakpoints, memory view, etc.).

## Project Structure

```
src/main/java/       Stub Java class (required by the Ghidra extension build)
pypkg/src/vice/      Python TraceRmi agent
  arch.py            Architecture constants (6502 language, registers, memory map)
  commands.py        Trace population — reads state from VICE, writes to Ghidra trace
  methods.py         Remote methods — Ghidra UI actions (step, resume, breakpoints, …)
  hooks.py           Event handlers for VICE stop/resume notifications
  util.py            VICE Binary Monitor Protocol client
data/
  debugger-launchers/  Shell launcher and TraceRmi schema
  support/             Python entry point (vice-c64.py)
```

## Detailed setup/execution

```sh
GHIDRA_PATH=/path/to/ghidra_X.Y.Z_PUBLIC
GHIDRA_VER=$(basename $GHIDRA_PATH)

# Once: install the ghidratrace library

pip install $GHIDRA_PATH/Ghidra/Debug/Debugger-rmi-trace/pypkg/

# Build and (re)install

./gradlew buildExtension
rm -rf $HOME/.config/ghidra/$GHIDRA_VER/Extensions/ghidra-vice-connector
unzip -q dist/$GHIDRA_VER_*_ghidra-vice-connector.zip -d $HOME/.config/ghidra/$GHIDRA_VER/Extensions/

# Once: prepare test program and Ghidra project

python3 -c "
import pathlib
prg = pathlib.Path('data/test.prg').read_bytes()
pathlib.Path('data/test_raw.bin').write_bytes(prg[2:])
"
$GHIDRA_PATH/support/analyzeHeadless \
  data/ghidra-project ViceTest \
  -import data/test_raw.bin \
  -processor "6502:LE:16:default" \
  -cspec default \
  -loader BinaryLoader \
  -postScript RebaseToC64Load.java \
  -scriptPath data/ghidra-scripts \
  -overwrite

# Prepare and open the project
#
# Manual: Right-click test_raw.bin and choose "Open With → Debugger"

x64 -binarymonitor -binarymonitoraddress 127.0.0.1:6502 data/test.prg &
$GHIDRA_PATH/ghidraRun $PWD/data/ghidra-project/ViceTest.gpr

# Attach debugger: Debugger → Configure and Launch… → VICE…
```

## License

See the repository for license information.
