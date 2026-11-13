# Ghidra VICE Connector

A Ghidra 12.2 debugger extension for the Commodore 64. It connects one Ghidra TraceRMI session to one VICE binary-monitor socket and exposes the same controller to Ghidra's debugger UI and MCP automation.

## What it supports

- registers, banks, and the full 64 KiB address space;
- step, next, finish, resume, interrupt, and reset;
- conditional execute breakpoints and read/write watchpoints;
- deterministic keyboard and joystick input;
- VICE snapshots, resources, and autostart;
- a bounded composited-display capture;
- a small `c64.vice/1` TraceRMI method surface used by `c64-mcp`.

The controller serializes monitor commands and publishes VICE stop/resume events to the trace. Memory and display transfers use 16 KiB chunks so no single TraceRMI value carries a full frame or memory image.

Automation can read bounded main-CPU instruction history while stopped. VICE must be built with `--enable-cpuhistory`. Entries are oldest to newest, with pre-instruction registers and fetch-start cycles; cycles can decrease across resets or snapshot restores. The three saved instruction-prefix bytes are not a decoded instruction length, and unused operand slots may contain zero or neighboring bytes.

Automation can advance observed frames or run until an address with a frame limit. A frame is the first CPU instruction boundary observed on raster line 0 after a nonzero line; long REU DMA can skip an observation. Both operations start stopped, publish one final stop after helper checkpoint cleanup, and return partial progress on timeout after recovery. An already-current target returns without another stop.

Automation can get and set individual VICE resources while stopped. Writes to monitor-server configuration are blocked, and log resources are protected while a native trace owns them. Checkpoint conditions use native VICE expressions; if VICE rejects a condition, the newly created checkpoint is deleted when possible.

Autostart takes an absolute path on VICE's filesystem and returns when VICE resumes after scheduling the load. `run` controls BASIC RUN after loading. A rejected autostart can also resume execution; snapshot autostart can subsequently stop again. Use execution events and checkpoints to observe readiness.

Automation can start and stop a native monitor log for inclusive main-memory ranges. The controller owns the trace checkpoints and restores the previous monitor log filename on stop.

## Requirements

- Ghidra 12.2
- JDK 25 for building
- Python 3 with Ghidra's `ghidratrace` package
- VICE with the binary monitor enabled

Display capture needs a VICE build containing the safe display-command fix (revision r46020 or later, or release 3.11 or later).

Physical keyboard-matrix input needs a VICE build containing binary-monitor command `0xa3` from the companion patch; stock builds reject it cleanly.

## Build and install

```sh
JAVA_HOME=/path/to/jdk-25 \
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC \
./gradlew buildExtension
```

The wrapper enables Java native access and Gradle's configuration cache by default.
Pass `--no-configuration-cache` to disable the cache for a build.

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

Saved debugger traces from earlier Ghidra versions cannot be opened by 12.2; capture a new trace.

The launchers load `ghidratrace` from the selected Ghidra installation, never from
an older pip installation. Install `protobuf>=6.31.0` in the configured Python.
The build composes `schema-base.xml` with Ghidra's 12.2 schema fragments; do not
edit the generated `schema.xml`.

For the full C64 MCP/TraceRMI integration test, use
`ghidra-mcp-next/tools/test_debugger_stacks.py --stack vice --ghidra "$GHIDRA_INSTALL_DIR"`
with sibling checkouts and a disposable VICE executable.

To run the mutating live tests, start a disposable VICE monitor on a private port and run `REQUIRE_LIVE_VICE=1 VICE_PORT=<port> pytest tests/test_live_vice.py`.
