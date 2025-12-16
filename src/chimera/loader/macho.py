"""Mach-O binary format parser for ARM64 macOS."""

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import BinaryIO

from chimera.loader.segments import Section, Segment
from chimera.loader.symbols import Symbol, SymbolTable, SymbolType


# Mach-O magic numbers
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE  # Byte-swapped

# Fat (Universal) binary magic numbers
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

# CPU types
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64_ALL = 0x00000000
CPU_TYPE_X86_64 = 0x01000007

# File types
MH_EXECUTE = 0x2
MH_DYLIB = 0x6
MH_BUNDLE = 0x8


class LoadCommand(IntEnum):
    """Mach-O load command types."""

    LC_SEGMENT_64 = 0x19
    LC_SYMTAB = 0x02
    LC_DYSYMTAB = 0x0B
    LC_LOAD_DYLIB = 0x0C
    LC_ID_DYLIB = 0x0D
    LC_LOAD_WEAK_DYLIB = 0x80000018
    LC_REEXPORT_DYLIB = 0x8000001F
    LC_LAZY_LOAD_DYLIB = 0x20
    LC_UUID = 0x1B
    LC_MAIN = 0x80000028
    LC_FUNCTION_STARTS = 0x26
    LC_DATA_IN_CODE = 0x29
    LC_SOURCE_VERSION = 0x2A
    LC_BUILD_VERSION = 0x32
    LC_CODE_SIGNATURE = 0x1D
    LC_DYLD_INFO = 0x22
    LC_DYLD_INFO_ONLY = 0x80000022
    LC_DYLD_EXPORTS_TRIE = 0x80000033
    LC_DYLD_CHAINED_FIXUPS = 0x80000034


@dataclass
class MachOHeader:
    """Mach-O 64-bit header."""

    magic: int
    cputype: int
    cpusubtype: int
    filetype: int
    ncmds: int
    sizeofcmds: int
    flags: int
    reserved: int = 0

    @classmethod
    def parse(cls, data: bytes) -> "MachOHeader":
        """Parse header from bytes."""
        if len(data) < 32:
            raise ValueError("Data too small for Mach-O header")

        fields = struct.unpack("<IIIIIIII", data[:32])
        return cls(*fields)

    @property
    def is_64bit(self) -> bool:
        return self.magic == MH_MAGIC_64

    @property
    def is_arm64(self) -> bool:
        return self.cputype == CPU_TYPE_ARM64


@dataclass
class DylibInfo:
    """Information about a loaded dynamic library."""

    name: str
    timestamp: int
    current_version: int
    compat_version: int


@dataclass
class MachOBinary:
    """Parsed Mach-O binary representation."""

    path: Path
    header: MachOHeader
    segments: list[Segment] = field(default_factory=list)
    symbols: SymbolTable = field(default_factory=SymbolTable)
    dylibs: list[DylibInfo] = field(default_factory=list)
    entry_point: int = 0
    uuid: bytes = b""
    _raw_data: bytes = field(default=b"", repr=False)

    @classmethod
    def load(cls, path: str | Path) -> "MachOBinary":
        """Load and parse a Mach-O binary from disk."""
        path = Path(path)
        with open(path, "rb") as f:
            data = f.read()

        return cls.parse(data, path)

    @classmethod
    def _extract_arm64_from_fat(cls, data: bytes) -> bytes:
        """Extract ARM64 slice from a fat (universal) binary."""
        magic = struct.unpack(">I", data[:4])[0]

        if magic == FAT_MAGIC:
            # 32-bit fat header
            nfat_arch = struct.unpack(">I", data[4:8])[0]
            offset = 8

            for _ in range(nfat_arch):
                cputype, cpusubtype, arch_offset, size, align = struct.unpack(
                    ">IIIII", data[offset : offset + 20]
                )
                if cputype == CPU_TYPE_ARM64:
                    return data[arch_offset : arch_offset + size]
                offset += 20

        elif magic == FAT_MAGIC_64:
            # 64-bit fat header
            nfat_arch = struct.unpack(">I", data[4:8])[0]
            offset = 8

            for _ in range(nfat_arch):
                cputype, cpusubtype, arch_offset, size, align = struct.unpack(
                    ">IIQQQ", data[offset : offset + 32]
                )
                if cputype == CPU_TYPE_ARM64:
                    return data[arch_offset : arch_offset + size]
                offset += 32

        raise ValueError("No ARM64 slice found in universal binary")

    @classmethod
    def parse(cls, data: bytes, path: Path | None = None) -> "MachOBinary":
        """Parse Mach-O binary from bytes."""
        # Check for fat (universal) binary
        if len(data) >= 4:
            magic = struct.unpack(">I", data[:4])[0]
            if magic in (FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64):
                data = cls._extract_arm64_from_fat(data)

        header = MachOHeader.parse(data)

        if not header.is_64bit:
            raise ValueError("Only 64-bit Mach-O binaries are supported")

        if not header.is_arm64:
            raise ValueError("Only ARM64 binaries are supported")

        binary = cls(
            path=path or Path("<memory>"),
            header=header,
            _raw_data=data,
        )

        binary._parse_load_commands(data)
        return binary

    def _parse_load_commands(self, data: bytes) -> None:
        """Parse all load commands."""
        offset = 32  # Size of 64-bit header

        # Track symtab/dysymtab info for later processing
        symtab_info: tuple[int, int, int, int] | None = None
        dysymtab_info: dict[str, int] | None = None

        for _ in range(self.header.ncmds):
            if offset + 8 > len(data):
                break

            cmd, cmdsize = struct.unpack("<II", data[offset : offset + 8])

            try:
                cmd_type = LoadCommand(cmd)
            except ValueError:
                cmd_type = None

            if cmd_type == LoadCommand.LC_SEGMENT_64:
                self._parse_segment_64(data, offset)
            elif cmd_type == LoadCommand.LC_SYMTAB:
                symtab_info = self._parse_symtab_cmd(data, offset)
            elif cmd_type == LoadCommand.LC_DYSYMTAB:
                dysymtab_info = self._parse_dysymtab_cmd(data, offset)
            elif cmd_type in (
                LoadCommand.LC_LOAD_DYLIB,
                LoadCommand.LC_LOAD_WEAK_DYLIB,
                LoadCommand.LC_REEXPORT_DYLIB,
                LoadCommand.LC_LAZY_LOAD_DYLIB,
            ):
                self._parse_dylib_cmd(data, offset)
            elif cmd_type == LoadCommand.LC_MAIN:
                self._parse_main_cmd(data, offset)
            elif cmd_type == LoadCommand.LC_UUID:
                self._parse_uuid_cmd(data, offset)

            offset += cmdsize

        # Now process symbols with all info available
        if symtab_info:
            self._process_symbols(data, symtab_info, dysymtab_info)

    def _parse_segment_64(self, data: bytes, offset: int) -> None:
        """Parse LC_SEGMENT_64 command."""
        # struct segment_command_64
        fmt = "<II16sQQQQIIII"
        size = struct.calcsize(fmt)
        fields = struct.unpack(fmt, data[offset : offset + size])

        (
            _cmd,
            _cmdsize,
            segname,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            nsects,
            flags,
        ) = fields

        segname = segname.rstrip(b"\x00").decode("utf-8")

        segment = Segment(
            name=segname,
            vmaddr=vmaddr,
            vmsize=vmsize,
            fileoff=fileoff,
            filesize=filesize,
            maxprot=maxprot,
            initprot=initprot,
            flags=flags,
        )

        # Parse sections
        sect_offset = offset + size
        for _ in range(nsects):
            section = self._parse_section_64(data, sect_offset)
            segment.sections.append(section)
            sect_offset += 80  # Size of section_64

        self.segments.append(segment)

    def _parse_section_64(self, data: bytes, offset: int) -> Section:
        """Parse a section_64 structure."""
        # struct section_64
        fmt = "<16s16sQQIIIIIIII"
        fields = struct.unpack(fmt, data[offset : offset + 80])

        (
            sectname,
            segname,
            addr,
            size,
            sect_offset,
            align,
            reloff,
            nreloc,
            flags,
            reserved1,
            reserved2,
            reserved3,
        ) = fields

        sectname = sectname.rstrip(b"\x00").decode("utf-8")
        segname = segname.rstrip(b"\x00").decode("utf-8")

        # Read section data
        sect_data = b""
        if sect_offset > 0 and size > 0:
            sect_data = data[sect_offset : sect_offset + size]

        return Section(
            name=sectname,
            segment_name=segname,
            address=addr,
            size=size,
            offset=sect_offset,
            align=align,
            flags=flags,
            data=sect_data,
        )

    def _parse_symtab_cmd(
        self, data: bytes, offset: int
    ) -> tuple[int, int, int, int]:
        """Parse LC_SYMTAB command, return (symoff, nsyms, stroff, strsize)."""
        fmt = "<IIIIII"
        fields = struct.unpack(fmt, data[offset : offset + 24])
        _cmd, _cmdsize, symoff, nsyms, stroff, strsize = fields
        return (symoff, nsyms, stroff, strsize)

    def _parse_dysymtab_cmd(self, data: bytes, offset: int) -> dict[str, int]:
        """Parse LC_DYSYMTAB command."""
        fmt = "<IIIIIIIIIIIIIIIIII"
        fields = struct.unpack(fmt, data[offset : offset + 72])

        return {
            "ilocalsym": fields[2],
            "nlocalsym": fields[3],
            "iextdefsym": fields[4],
            "nextdefsym": fields[5],
            "iundefsym": fields[6],
            "nundefsym": fields[7],
        }

    def _parse_dylib_cmd(self, data: bytes, offset: int) -> None:
        """Parse LC_LOAD_DYLIB and related commands."""
        # struct dylib_command
        fmt = "<IIIIII"
        fields = struct.unpack(fmt, data[offset : offset + 24])
        _cmd, cmdsize, str_offset, timestamp, current_ver, compat_ver = fields

        # Name is at offset from start of command
        name_start = offset + str_offset
        name_end = data.find(b"\x00", name_start, offset + cmdsize)
        if name_end == -1:
            name_end = offset + cmdsize
        name = data[name_start:name_end].decode("utf-8", errors="replace")

        self.dylibs.append(
            DylibInfo(
                name=name,
                timestamp=timestamp,
                current_version=current_ver,
                compat_version=compat_ver,
            )
        )

    def _parse_main_cmd(self, data: bytes, offset: int) -> None:
        """Parse LC_MAIN command."""
        fmt = "<IIQQ"
        fields = struct.unpack(fmt, data[offset : offset + 24])
        _cmd, _cmdsize, entryoff, _stacksize = fields

        # Entry offset is relative to __TEXT segment
        text_seg = self.get_segment("__TEXT")
        if text_seg:
            self.entry_point = text_seg.vmaddr + entryoff
        else:
            self.entry_point = entryoff

    def _parse_uuid_cmd(self, data: bytes, offset: int) -> None:
        """Parse LC_UUID command."""
        self.uuid = data[offset + 8 : offset + 24]

    def _process_symbols(
        self,
        data: bytes,
        symtab: tuple[int, int, int, int],
        dysymtab: dict[str, int] | None,
    ) -> None:
        """Process symbol table entries."""
        symoff, nsyms, stroff, strsize = symtab
        strtab = data[stroff : stroff + strsize]

        # nlist_64 structure size
        nlist_size = 16

        for i in range(nsyms):
            entry_offset = symoff + (i * nlist_size)
            if entry_offset + nlist_size > len(data):
                break

            # struct nlist_64
            n_strx, n_type, n_sect, n_desc, n_value = struct.unpack(
                "<IBBHQ", data[entry_offset : entry_offset + nlist_size]
            )

            # Get symbol name from string table
            name_end = strtab.find(b"\x00", n_strx)
            if name_end == -1:
                name_end = len(strtab)
            name = strtab[n_strx:name_end].decode("utf-8", errors="replace")

            # Determine symbol type
            n_type_masked = n_type & 0x0E  # N_TYPE mask
            n_ext = n_type & 0x01  # N_EXT

            if n_type_masked == 0x00:  # N_UNDF
                sym_type = SymbolType.UNDEFINED
            elif n_ext:
                sym_type = SymbolType.GLOBAL
            else:
                sym_type = SymbolType.LOCAL

            # Check for debug symbols
            if n_type & 0xE0:  # N_STAB
                sym_type = SymbolType.DEBUG

            symbol = Symbol(
                name=name,
                address=n_value,
                symbol_type=sym_type,
                section_index=n_sect,
            )

            self.symbols.add(symbol)

    # Public API methods

    def get_segment(self, name: str) -> Segment | None:
        """Get segment by name."""
        for seg in self.segments:
            if seg.name == name:
                return seg
        return None

    def get_section(self, segment: str, section: str) -> Section | None:
        """Get section by segment and section name."""
        seg = self.get_segment(segment)
        if seg:
            return seg.get_section(section)
        return None

    def segment_at_address(self, addr: int) -> Segment | None:
        """Find segment containing address."""
        for seg in self.segments:
            if seg.contains_address(addr):
                return seg
        return None

    def section_at_address(self, addr: int) -> Section | None:
        """Find section containing address."""
        seg = self.segment_at_address(addr)
        if seg:
            return seg.section_at_address(addr)
        return None

    def read(self, addr: int, size: int) -> bytes:
        """Read bytes from virtual address."""
        section = self.section_at_address(addr)
        if section:
            return section.read(addr, size)
        raise ValueError(f"No section at address {addr:#x}")

    @property
    def text_section(self) -> Section | None:
        """Get the __TEXT,__text section (main code)."""
        return self.get_section("__TEXT", "__text")

    @property
    def code_range(self) -> tuple[int, int] | None:
        """Get the address range of executable code."""
        text = self.text_section
        if text:
            return (text.address, text.end_address)
        return None

