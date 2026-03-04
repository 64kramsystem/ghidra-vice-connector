"""
Architecture constants for the C64 / MOS 6510.

Ghidra language ID: 6502:LE:16:default
(The 6502 processor module ships with Ghidra; the 6510 is compatible.)
"""

# ── Ghidra language / compiler spec ──────────────────────────────────────────

LANGUAGE_ID   = '6502:LE:16:default'
COMPILER_SPEC = 'default'

# ── Address space ─────────────────────────────────────────────────────────────

RAM_START = 0x0000
RAM_END   = 0xFFFF
RAM_SIZE  = 0x10000  # 64 KB

# ── Register names as reported by VICE REGISTERS_AVAILABLE ───────────────────
# These are the canonical BMP names; the mapping to reg_id is discovered at
# runtime via ViceBmpClient._discover_registers().

REG_PC = 'PC'
REG_A  = 'A'
REG_X  = 'X'
REG_Y  = 'Y'
REG_SP = 'SP'
REG_P  = 'FL'   # VICE reports processor status as 'FL'

# All general-purpose registers in display order
ALL_REGS = [REG_PC, REG_A, REG_X, REG_Y, REG_SP, REG_P]

# Registers that map to Ghidra register names
# key = VICE name, value = Ghidra 6502 language register name
VICE_TO_GHIDRA_REG = {
    'PC':  'PC',
    'A':   'A',
    'X':   'X',
    'Y':   'Y',
    'SP':  'S',   # Ghidra 6502 calls it 'S'
    'FL':  'P',   # Ghidra 6502 calls the status register 'P'
}

# ── Memory region definitions ─────────────────────────────────────────────────

MEMORY_REGIONS = [
    {
        'key':        'ram',
        'display':    'RAM [0x0000-0xFFFF]',
        'start':      0x0000,
        'end':        0xFFFF,
        'readable':   True,
        'writable':   True,
        'executable': True,
    }
]
# Note: VICE supports bank switching (BANKS_AVAILABLE).
# Future work: populate multiple regions for ROM/IO/etc. when bank info is available.
