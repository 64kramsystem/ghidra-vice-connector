# VICE C64 TraceRmi agent — invoked by vice-c64.sh
# PYTHONPATH is set by the shell launcher.

import logging
import os
import sys

# Set up logging FIRST so all modules get it
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s.%(msecs)03d [%(name)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S',
    filename='/tmp/vice-agent.log',
    filemode='w',
)
log = logging.getLogger('vice-agent')
log.setLevel(logging.DEBUG)

log.info("=== VICE C64 TraceRmi agent starting ===")
log.info(f"Python: {sys.executable} {sys.version}")
log.info(f"PYTHONPATH: {os.environ.get('PYTHONPATH', '<not set>')}")

host = os.environ.get('OPT_HOST', 'localhost')
port = int(os.environ.get('OPT_PORT', '6502'))

ghidra_host = os.environ.get('GHIDRA_TRACE_RMI_HOST')
ghidra_port = int(os.environ.get('GHIDRA_TRACE_RMI_PORT', '0'))
log.info(f"VICE target: {host}:{port}")
log.info(f"Ghidra TraceRmi: {ghidra_host}:{ghidra_port}")

if not ghidra_host:
    raise RuntimeError("GHIDRA_TRACE_RMI_HOST is not set — "
                       "this script must be launched by Ghidra.")

from vice import commands, hooks, methods
log.info(f"Modules loaded: commands={commands.__file__}, hooks={hooks.__file__}, methods={methods.__file__}")

# Connect to Ghidra FIRST so we don't time out before the handshake.
log.info(f"Connecting to Ghidra TraceRmi at {ghidra_host}:{ghidra_port} ...")
print(f"[vice-c64] Connecting to Ghidra TraceRmi at {ghidra_host}:{ghidra_port} ...")
commands.start_trace(ghidra_host, ghidra_port, methods.REGISTRY)
log.info("Ghidra TraceRmi connected")

log.info(f"Connecting to VICE at {host}:{port} ...")
print(f"[vice-c64] Connecting to VICE at {host}:{port} ...")
commands.connect_vice(host, port)
log.info("VICE connected")

log.info("Installing event hooks ...")
print("[vice-c64] Installing event hooks ...")
hooks.install_hooks()
log.info("Event hooks installed")

log.info("Populating initial state ...")
print("[vice-c64] Populating initial state ...")
commands.populate_initial_state()
log.info("Initial state populated")

log.info("=== Agent ready, waiting for events ===")
print("[vice-c64] Agent ready.")

try:
    # Block on the VICE receive thread — it runs until the connection drops.
    commands.STATE.vice._recv_thread.join()
except KeyboardInterrupt:
    log.info("KeyboardInterrupt received")
finally:
    commands.STATE.vice.disconnect()
    log.info("Disconnected")
    print("[vice-c64] Disconnected.")
