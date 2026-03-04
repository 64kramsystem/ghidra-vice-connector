"""
Sanity checks for arch.py constants.

These tests are fast and have no external dependencies.
"""

import pytest
from vice import arch


class TestLanguageID:
    def test_language_id_set(self):
        assert arch.LANGUAGE_ID
        assert isinstance(arch.LANGUAGE_ID, str)

    def test_language_id_format(self):
        # Ghidra language IDs are "proc:endian:bits:variant"
        parts = arch.LANGUAGE_ID.split(':')
        assert len(parts) == 4, f"Expected 4 colon-separated parts, got {arch.LANGUAGE_ID!r}"

    def test_endianness_is_little_endian(self):
        """6502 is little-endian; verify the language ID matches."""
        endian = arch.LANGUAGE_ID.split(':')[1]
        assert endian == 'LE', f"Expected LE, got {endian!r}"

    def test_compiler_spec_set(self):
        assert arch.COMPILER_SPEC
        assert isinstance(arch.COMPILER_SPEC, str)


class TestAddressSpace:
    def test_ram_start_is_zero(self):
        assert arch.RAM_START == 0x0000

    def test_ram_end_is_ffff(self):
        assert arch.RAM_END == 0xFFFF

    def test_ram_size_is_64k(self):
        assert arch.RAM_SIZE == 0x10000

    def test_ram_size_consistent(self):
        assert arch.RAM_SIZE == arch.RAM_END - arch.RAM_START + 1


class TestRegisterNames:
    def test_all_regs_defined(self):
        assert arch.REG_PC
        assert arch.REG_A
        assert arch.REG_X
        assert arch.REG_Y
        assert arch.REG_SP
        assert arch.REG_P

    def test_all_regs_list_contains_standard_6502_regs(self):
        for name in ('PC', 'A', 'X', 'Y', 'SP'):
            assert any(name in r for r in arch.ALL_REGS), f"{name} missing from ALL_REGS"

    def test_vice_to_ghidra_reg_covers_all_standard_regs(self):
        """Every VICE register name used by REGISTERS_GET must have a Ghidra mapping."""
        # Minimum required: PC, A, X, Y, SP and the status register
        required = {'PC', 'A', 'X', 'Y', 'SP'}
        mapping_keys = set(arch.VICE_TO_GHIDRA_REG.keys())
        assert required.issubset(mapping_keys), (
            f"Missing Ghidra mappings for: {required - mapping_keys}"
        )

    def test_ghidra_reg_names_are_nonempty(self):
        for vice_name, ghidra_name in arch.VICE_TO_GHIDRA_REG.items():
            assert ghidra_name, f"Empty Ghidra name for VICE register {vice_name!r}"

    def test_no_duplicate_ghidra_reg_names(self):
        ghidra_names = list(arch.VICE_TO_GHIDRA_REG.values())
        assert len(ghidra_names) == len(set(ghidra_names)), (
            "Duplicate Ghidra register names in VICE_TO_GHIDRA_REG"
        )


class TestMemoryRegions:
    def test_at_least_one_region(self):
        assert len(arch.MEMORY_REGIONS) >= 1

    def test_ram_region_present(self):
        keys = [r['key'] for r in arch.MEMORY_REGIONS]
        assert 'ram' in keys

    def test_all_regions_have_required_fields(self):
        required = {'key', 'display', 'start', 'end', 'readable', 'writable', 'executable'}
        for region in arch.MEMORY_REGIONS:
            missing = required - set(region.keys())
            assert not missing, f"Region {region.get('key')!r} missing: {missing}"

    def test_region_start_lte_end(self):
        for region in arch.MEMORY_REGIONS:
            assert region['start'] <= region['end'], (
                f"Region {region['key']!r}: start > end"
            )

    def test_region_addresses_in_valid_range(self):
        for region in arch.MEMORY_REGIONS:
            assert 0x0000 <= region['start'] <= 0xFFFF
            assert 0x0000 <= region['end']   <= 0xFFFF

    def test_main_ram_covers_full_address_space(self):
        ram = next(r for r in arch.MEMORY_REGIONS if r['key'] == 'ram')
        assert ram['start'] == arch.RAM_START
        assert ram['end']   == arch.RAM_END

    def test_main_ram_is_executable(self):
        ram = next(r for r in arch.MEMORY_REGIONS if r['key'] == 'ram')
        assert ram['executable'] is True

    def test_all_region_keys_are_strings(self):
        for region in arch.MEMORY_REGIONS:
            assert isinstance(region['key'], str)
            assert region['key']  # non-empty
