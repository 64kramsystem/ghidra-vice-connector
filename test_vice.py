#!/usr/bin/env python3
"""
Standalone test of the VICE BMP client (no Ghidra needed).
Run while VICE is running with -binarymonitor -binarymonitoraddress 127.0.0.1:6502
"""

import os
import sys
import struct
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src', 'main', 'py', 'src'))

from vice.util import ViceBmpClient, CPU_OP_EXEC, CPU_OP_LOAD, CPU_OP_STORE

HOST = 'localhost'
PORT = 6502

PASS = '\033[32mPASS\033[0m'
FAIL = '\033[31mFAIL\033[0m'

def check(label, value, expected=None, pred=None):
    if pred is not None:
        ok = pred(value)
    elif expected is not None:
        ok = value == expected
    else:
        ok = value is not None
    status = PASS if ok else FAIL
    print(f"  {status}  {label}: {value!r}")
    return ok

def section(title):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")

# ── Connect ────────────────────────────────────────────────────────────────────
section("Connection")
c = ViceBmpClient(HOST, PORT)
c.connect()
print(f"  {PASS}  Connected to VICE at {HOST}:{PORT}")

# ── VICE info ─────────────────────────────────────────────────────────────────
section("VICE info")
info = c.vice_info()
check("version string", info, pred=lambda v: len(v) > 0 and '.' in v)
print(f"       VICE version: {info}")

# ── Register discovery ────────────────────────────────────────────────────────
section("Register discovery")
check("reg_name_to_id keys", sorted(c.reg_name_to_id.keys()),
      pred=lambda k: 'PC' in k and 'A' in k and 'X' in k and 'Y' in k)
print(f"       registers found: {sorted(c.reg_name_to_id.keys())}")
print(f"       name→id map: {c.reg_name_to_id}")

# ── Read registers ────────────────────────────────────────────────────────────
section("Read registers")
regs = c.registers_get()
print(f"       raw registers: {regs}")
check("PC present",  'PC' in regs)
check("A present",   'A'  in regs)
check("X present",   'X'  in regs)
check("Y present",   'Y'  in regs)
check("SP present",  'SP' in regs)
check("FL present",  'FL' in regs)
pc = regs.get('PC', 0)
check("PC non-zero", pc, pred=lambda v: v != 0)
check("A = 0xAA",    regs.get('A'), pred=lambda v: v == 0xAA)
check("X = 0xBB",    regs.get('X'), pred=lambda v: v == 0xBB)
check("Y = 0xCC",    regs.get('Y'), pred=lambda v: v == 0xCC)

# ── Read memory ───────────────────────────────────────────────────────────────
section("Read memory")
# Read first 16 bytes of our test program at 0x0801
prog = c.memory_get(0x0801, 0x0810)
check("memory_get length", len(prog), 16)
check("BASIC header byte[0] = 0x0B (link lo)", prog[0], 0x0B)
check("BASIC header byte[1] = 0x08 (link hi)", prog[1], 0x08)
print(f"       0x0801-0x0810: {prog.hex()}")

# Read 8 bytes at PC to see current instruction
code = c.memory_get(pc, pc + 7)
print(f"       bytes at PC (0x{pc:04X}): {code.hex()}")

# ── Write memory ──────────────────────────────────────────────────────────────
section("Write memory")
# Write a sentinel, read it back, restore
ADDR = 0x0200
orig = c.memory_get(ADDR, ADDR)
c.memory_set(ADDR, bytes([0xDE]))
readback = c.memory_get(ADDR, ADDR)
check("memory_set / readback", readback, bytes([0xDE]))
c.memory_set(ADDR, orig)  # restore
check("restore original", c.memory_get(ADDR, ADDR), orig)

# ── Banks ─────────────────────────────────────────────────────────────────────
section("Banks available")
banks = c.banks_available()
check("at least one bank", len(banks), pred=lambda n: n > 0)
for b in banks:
    print(f"       bank id={b['id']} name={b['name']!r}")

# ── Checkpoints (breakpoints) ─────────────────────────────────────────────────
section("Checkpoints / breakpoints")
# Start clean
existing = c.checkpoint_list()
print(f"       existing checkpoints: {len(existing)}")

# Set an exec breakpoint at 0x080D (start of our loop)
n = c.checkpoint_set(0x080D, 0x080D, cpu_op=CPU_OP_EXEC)
check("checkpoint_set returns number", n, pred=lambda v: v > 0)

cps = c.checkpoint_list()
check("checkpoint appears in list", any(cp['number'] == n for cp in cps))

# Toggle off
c.checkpoint_toggle(n, False)
cps = c.checkpoint_list()
cp = next(cp for cp in cps if cp['number'] == n)
check("checkpoint disabled", cp['enabled'], False)

# Toggle back on
c.checkpoint_toggle(n, True)
cp = next(cp for cp in c.checkpoint_list() if cp['number'] == n)
check("checkpoint re-enabled", cp['enabled'], True)

# Delete
c.checkpoint_delete(n)
cps = c.checkpoint_list()
check("checkpoint deleted", any(cp['number'] == n for cp in cps), False)

# ── Step ──────────────────────────────────────────────────────────────────────
section("Step")
regs_before = c.registers_get()
pc_before = regs_before.get('PC', 0)
c.step(count=1, step_over=False)
time.sleep(0.2)
regs_after = c.registers_get()
pc_after = regs_after.get('PC', 0)
check("PC changed after step", pc_after, pred=lambda v: v != pc_before)
print(f"       PC: 0x{pc_before:04X} → 0x{pc_after:04X}")

# ── Resume ────────────────────────────────────────────────────────────────────
section("Resume")
c.resume()
time.sleep(0.1)
regs_running = c.registers_get()
check("registers still readable after resume", 'PC' in regs_running)

# ── Stop event hook ───────────────────────────────────────────────────────────
section("Stop event via breakpoint")
from vice.util import RESP_STOPPED
stop_events = []
c.on_event(RESP_STOPPED, lambda t, e, b: stop_events.append(struct.unpack_from('<H', b)[0] if len(b) >= 2 else 0))

n = c.checkpoint_set(0x080D, 0x080D, cpu_op=CPU_OP_EXEC)
c.resume()
deadline = time.monotonic() + 3.0
while not stop_events and time.monotonic() < deadline:
    time.sleep(0.05)
c.checkpoint_delete(n)

check("stop event received", len(stop_events), pred=lambda v: v > 0)
if stop_events:
    check("stop PC = 0x080D", stop_events[0], 0x080D)

# ── Summary ───────────────────────────────────────────────────────────────────
section("Done")
c.disconnect()
print()
