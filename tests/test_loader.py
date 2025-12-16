"""Tests for the Mach-O loader."""

import struct

import pytest

from chimera.loader.macho import (
    MH_EXECUTE,
    MH_MAGIC_64,
    CPU_TYPE_ARM64,
    MachOHeader,
)
from chimera.loader.symbols import Symbol, SymbolType, SymbolTable
from chimera.loader.segments import Section, Segment


class TestMachOHeader:
    """Tests for MachOHeader parsing."""

    def test_parse_valid_header(self):
        """Test parsing a valid ARM64 Mach-O header."""
        # Create a minimal valid header
        header_data = struct.pack(
            "<IIIIIIII",
            MH_MAGIC_64,  # magic
            CPU_TYPE_ARM64,  # cputype
            0,  # cpusubtype
            MH_EXECUTE,  # filetype
            0,  # ncmds
            0,  # sizeofcmds
            0,  # flags
            0,  # reserved
        )

        header = MachOHeader.parse(header_data)

        assert header.magic == MH_MAGIC_64
        assert header.cputype == CPU_TYPE_ARM64
        assert header.is_64bit
        assert header.is_arm64

    def test_parse_invalid_header_too_small(self):
        """Test that parsing fails for data too small."""
        with pytest.raises(ValueError, match="too small"):
            MachOHeader.parse(b"\x00" * 10)


class TestSegment:
    """Tests for Segment class."""

    def test_segment_contains_address(self):
        """Test address containment check."""
        seg = Segment(
            name="__TEXT",
            vmaddr=0x100000000,
            vmsize=0x1000,
            fileoff=0,
            filesize=0x1000,
            maxprot=7,
            initprot=5,
            flags=0,
        )

        assert seg.contains_address(0x100000000)
        assert seg.contains_address(0x100000500)
        assert not seg.contains_address(0x100001000)
        assert not seg.contains_address(0x0)

    def test_segment_end_address(self):
        """Test end address calculation."""
        seg = Segment(
            name="__TEXT",
            vmaddr=0x100000000,
            vmsize=0x1000,
            fileoff=0,
            filesize=0x1000,
            maxprot=7,
            initprot=5,
            flags=0,
        )

        assert seg.end_address == 0x100001000


class TestSection:
    """Tests for Section class."""

    def test_section_read(self):
        """Test reading data from section."""
        section = Section(
            name="__text",
            segment_name="__TEXT",
            address=0x100000000,
            size=8,
            offset=0,
            align=4,
            flags=0,
            data=b"\x00\x01\x02\x03\x04\x05\x06\x07",
        )

        assert section.read(0x100000000, 4) == b"\x00\x01\x02\x03"
        assert section.read(0x100000004, 4) == b"\x04\x05\x06\x07"

    def test_section_read_invalid_address(self):
        """Test reading from invalid address."""
        section = Section(
            name="__text",
            segment_name="__TEXT",
            address=0x100000000,
            size=8,
            offset=0,
            align=4,
            flags=0,
            data=b"\x00\x01\x02\x03\x04\x05\x06\x07",
        )

        with pytest.raises(ValueError, match="not in section"):
            section.read(0x200000000, 4)


class TestSymbolTable:
    """Tests for SymbolTable class."""

    def test_add_and_lookup_by_name(self):
        """Test adding symbols and looking up by name."""
        table = SymbolTable()
        sym = Symbol(name="_main", address=0x100000000, symbol_type=SymbolType.GLOBAL)
        table.add(sym)

        result = table.by_name("_main")
        assert result is not None
        assert result.address == 0x100000000

    def test_lookup_by_address(self):
        """Test looking up symbols by address."""
        table = SymbolTable()
        sym1 = Symbol(name="_main", address=0x100000000, symbol_type=SymbolType.GLOBAL)
        sym2 = Symbol(name="_start", address=0x100000000, symbol_type=SymbolType.GLOBAL)
        table.add(sym1)
        table.add(sym2)

        results = table.by_address(0x100000000)
        assert len(results) == 2
        names = {s.name for s in results}
        assert names == {"_main", "_start"}

    def test_closest_symbol(self):
        """Test finding closest symbol."""
        table = SymbolTable()
        table.add(Symbol(name="_func1", address=0x1000, symbol_type=SymbolType.GLOBAL))
        table.add(Symbol(name="_func2", address=0x2000, symbol_type=SymbolType.GLOBAL))

        result = table.closest_symbol(0x1050)
        assert result is not None
        sym, offset = result
        assert sym.name == "_func1"
        assert offset == 0x50

    def test_exports_and_imports(self):
        """Test filtering exports and imports."""
        table = SymbolTable()
        table.add(Symbol(name="_exported", address=0x1000, symbol_type=SymbolType.GLOBAL))
        table.add(Symbol(name="_imported", address=0, symbol_type=SymbolType.UNDEFINED))
        table.add(Symbol(name="_local", address=0x2000, symbol_type=SymbolType.LOCAL))

        exports = table.exports
        imports = table.imports

        assert len(exports) == 1
        assert exports[0].name == "_exported"
        assert len(imports) == 1
        assert imports[0].name == "_imported"
