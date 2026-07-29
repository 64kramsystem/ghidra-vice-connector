# Ghidra VICE Connector

A Ghidra 12.1 debugger extension for the Commodore 64. It connects one Ghidra TraceRMI session to one VICE binary-monitor socket and exposes the same controller to Ghidra's debugger UI and MCP automation.

## What it supports

- registers, banks, and the full 64 KiB address space;
- step, next, finish, resume, interrupt, and reset;
- execute breakpoints and read/write watchpoints;
- deterministic keyboard and joystick input;
- VICE snapshots;
- a bounded composited-display capture;
- a small `c64.vice/1` TraceRMI method surface used by `c64-mcp`.

The controller serializes monitor commands and publishes VICE stop/resume events to the trace. Memory and display transfers use 16 KiB chunks so no single TraceRMI value carries a full frame or memory image.

## Requirements

- Ghidra 12.1
- JDK 21 for building
- Python 3 with Ghidra's `ghidratrace` package
- VICE with the binary monitor enabled

Display capture needs a VICE build containing the safe display-command fix (revision r46020 or later, or release 3.11 or later).

## Build and install

```sh
JAVA_HOME=/path/to/jdk-21 \
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1_PUBLIC \
./gradlew buildExtension
```

Install the zip from `dist/` through Ghidra's **File > Install Extensions**, then restart Ghidra.

## Use

Either start VICE yourself:

```sh
x64sc -binarymonitor \
  -binarymonitoraddress ip4://127.0.0.1:6502
```

and choose **VICE C64 Debugger**, or choose **VICE C64 Debugger (launch VICE)** and set the executable path in the launcher. Open Ghidra's Debugger tool before launching.

The monitor must remain on loopback. It is an unauthenticated control channel that can read memory and change emulator state.

Binary-monitor commands stop a running emulator. Automation therefore makes execution transitions explicit: interrupt before reads that require a stable target, then resume afterward. Captured display bytes may be read and discarded after execution resumes because they are already buffered locally.

## Development

```sh
pytest
```

Tests that require a live disposable VICE instance skip when it is absent.

The implementation is under `src/main/py/src/vice/`:

- `protocol.py` implements the strict binary-monitor framing and commands.
- `controller.py` owns serialized state and event coordination.
- `commands.py` synchronizes VICE state into the Ghidra trace.
- `methods.py` exposes debugger UI actions.
- `automation.py` exposes the MCP-facing TraceRMI methods.

Apache-2.0. `NOTICE` records the original project and relicensing.
