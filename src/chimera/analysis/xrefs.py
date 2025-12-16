"""Cross-reference tracking and analysis."""

from dataclasses import dataclass
from enum import IntEnum, auto
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from chimera.arch.arm64.decoder import ARM64Disassembler
    from chimera.loader.macho import MachOBinary


class XRefType(IntEnum):
    """Type of cross-reference."""

    CALL = auto()  # Function call (bl, blr)
    JUMP = auto()  # Unconditional jump (b, br)
    BRANCH = auto()  # Conditional branch
    DATA_READ = auto()  # Load from address
    DATA_WRITE = auto()  # Store to address
    DATA_REF = auto()  # Address reference (adr, adrp)
    POINTER = auto()  # Data pointer


@dataclass(frozen=True)
class XRef:
    """A cross-reference between two addresses."""

    from_addr: int
    to_addr: int
    xref_type: XRefType

    def __repr__(self) -> str:
        type_name = self.xref_type.name.lower()
        return f"XRef({self.from_addr:#x} -> {self.to_addr:#x}, {type_name})"


class XRefManager:
    """Manages cross-references in a binary."""

    def __init__(self) -> None:
        self._xrefs: list[XRef] = []
        self._to_index: dict[int, list[XRef]] = {}
        self._from_index: dict[int, list[XRef]] = {}

    def add(self, xref: XRef) -> None:
        """Add a cross-reference."""
        self._xrefs.append(xref)

        # Index by target
        if xref.to_addr not in self._to_index:
            self._to_index[xref.to_addr] = []
        self._to_index[xref.to_addr].append(xref)

        # Index by source
        if xref.from_addr not in self._from_index:
            self._from_index[xref.from_addr] = []
        self._from_index[xref.from_addr].append(xref)

    def add_xref(
        self, from_addr: int, to_addr: int, xref_type: XRefType
    ) -> XRef:
        """Create and add a cross-reference."""
        xref = XRef(from_addr, to_addr, xref_type)
        self.add(xref)
        return xref

    def xrefs_to(self, address: int) -> list[XRef]:
        """Get all references TO an address."""
        return self._to_index.get(address, [])

    def xrefs_from(self, address: int) -> list[XRef]:
        """Get all references FROM an address."""
        return self._from_index.get(address, [])

    def callers(self, address: int) -> list[int]:
        """Get addresses of all callers to a function."""
        return [
            xref.from_addr
            for xref in self._to_index.get(address, [])
            if xref.xref_type == XRefType.CALL
        ]

    def callees(self, address: int) -> list[int]:
        """Get addresses of all functions called from an address."""
        return [
            xref.to_addr
            for xref in self._from_index.get(address, [])
            if xref.xref_type == XRefType.CALL
        ]

    def data_refs_to(self, address: int) -> list[XRef]:
        """Get all data references to an address."""
        data_types = {XRefType.DATA_READ, XRefType.DATA_WRITE, XRefType.DATA_REF}
        return [
            xref
            for xref in self._to_index.get(address, [])
            if xref.xref_type in data_types
        ]

    def __iter__(self) -> Iterator[XRef]:
        return iter(self._xrefs)

    def __len__(self) -> int:
        return len(self._xrefs)


class XRefAnalyzer:
    """Analyzes binary to extract cross-references."""

    def __init__(
        self, binary: "MachOBinary", disassembler: "ARM64Disassembler"
    ) -> None:
        self.binary = binary
        self.disasm = disassembler
        self.xrefs = XRefManager()

    def analyze(self) -> XRefManager:
        """Analyze binary and extract all cross-references."""
        self._analyze_code_xrefs()
        self._analyze_data_xrefs()
        return self.xrefs

    def _analyze_code_xrefs(self) -> None:
        """Extract cross-references from code."""
        text = self.binary.text_section
        if not text:
            return

        for insn in self.disasm.disassemble(text.data, text.address):
            # Branch/call instructions
            if insn.branch_target is not None:
                if insn.is_call:
                    xref_type = XRefType.CALL
                elif insn.is_unconditional_branch:
                    xref_type = XRefType.JUMP
                elif insn.is_conditional_branch:
                    xref_type = XRefType.BRANCH
                else:
                    continue

                self.xrefs.add_xref(insn.address, insn.branch_target, xref_type)

            # ADRP + ADD pattern for address references
            if insn.mnemonic == "adrp":
                # ADRP loads page-aligned address
                if insn.operands and len(insn.operands) >= 2:
                    if insn.operands[1].is_immediate:
                        target = insn.operands[1].value
                        if isinstance(target, int):
                            self.xrefs.add_xref(
                                insn.address, target, XRefType.DATA_REF
                            )

            # ADR instruction
            elif insn.mnemonic == "adr":
                if insn.operands and len(insn.operands) >= 2:
                    if insn.operands[1].is_immediate:
                        target = insn.operands[1].value
                        if isinstance(target, int):
                            self.xrefs.add_xref(
                                insn.address, target, XRefType.DATA_REF
                            )

            # Load instructions with PC-relative addressing
            elif insn.is_load:
                self._handle_memory_ref(insn, XRefType.DATA_READ)

            # Store instructions
            elif insn.is_store:
                self._handle_memory_ref(insn, XRefType.DATA_WRITE)

    def _handle_memory_ref(
        self, insn: "ARM64Instruction", xref_type: XRefType  # type: ignore
    ) -> None:
        """Handle memory reference instructions."""
        from chimera.arch.arm64.instructions import ARM64Instruction

        # Look for literal pool loads (ldr x0, =label)
        if insn.mnemonic.startswith("ldr") and "=" in insn.op_str:
            # This is a pseudo-instruction for literal pool
            pass

        # Check operands for memory references
        for op in insn.operands:
            if op.is_memory:
                # If we can resolve the address, add xref
                # This requires more context (register values)
                pass

    def _analyze_data_xrefs(self) -> None:
        """Extract pointer cross-references from data sections."""
        # Look for pointers in data sections
        data_seg = self.binary.get_segment("__DATA")
        if not data_seg:
            return

        # Check common pointer sections
        for section in data_seg.sections:
            if section.name in ("__got", "__la_symbol_ptr", "__data"):
                self._scan_pointers(section)

    def _scan_pointers(self, section: "Section") -> None:  # type: ignore
        """Scan section for pointer values."""
        from chimera.loader.segments import Section

        data = section.data
        addr = section.address

        # Scan for 8-byte aligned pointers
        for i in range(0, len(data) - 7, 8):
            ptr = int.from_bytes(data[i : i + 8], "little")

            # Check if it looks like a valid pointer
            if ptr == 0:
                continue

            # Check if pointer is in a valid segment
            target_section = self.binary.section_at_address(ptr)
            if target_section:
                self.xrefs.add_xref(addr + i, ptr, XRefType.POINTER)

