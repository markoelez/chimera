"""Function detection and analysis."""

from typing import TYPE_CHECKING
from dataclasses import dataclass
from collections.abc import Iterator

from chimera.analysis.cfg import BasicBlock, CFGBuilder, ControlFlowGraph
from chimera.arch.arm64.instructions import ARM64Instruction

if TYPE_CHECKING:
    from chimera.loader.macho import MachOBinary
    from chimera.arch.arm64.decoder import ARM64Disassembler


@dataclass
class Function:
    """Represents a detected function."""

    address: int
    name: str
    size: int = 0
    cfg: ControlFlowGraph | None = None
    is_thunk: bool = False
    is_leaf: bool = True  # No calls to other functions

    @property
    def end_address(self) -> int:
        return self.address + self.size

    @property
    def instructions(self) -> Iterator[ARM64Instruction]:
        """Iterate all instructions in function."""
        if self.cfg:
            for block in self.cfg:
                yield from block.instructions

    @property
    def basic_blocks(self) -> list[BasicBlock]:
        """Get all basic blocks."""
        if self.cfg:
            return list(self.cfg)
        return []

    def __repr__(self) -> str:
        return f"Function({self.name!r}, {self.address:#x}, size={self.size})"


class FunctionAnalyzer:
    """Detects and analyzes functions in a binary."""

    def __init__(self, binary: "MachOBinary", disassembler: "ARM64Disassembler") -> None:
        self.binary = binary
        self.disasm = disassembler
        self.cfg_builder = CFGBuilder(disassembler)
        self.functions: dict[int, Function] = {}

    def analyze(self) -> list[Function]:
        """Run function analysis on the binary."""
        # First, add functions from symbol table
        self._add_symbol_functions()

        # Then detect additional functions via prologue scanning
        self._scan_for_prologues()

        # Analyze each function
        for func in self.functions.values():
            self._analyze_function(func)

        return list(self.functions.values())

    def _add_symbol_functions(self) -> None:
        """Add functions from symbol table."""
        from chimera.loader.symbols import SymbolType

        for symbol in self.binary.symbols:
            if symbol.symbol_type in (SymbolType.GLOBAL, SymbolType.LOCAL):
                # Check if address is in code section
                section = self.binary.section_at_address(symbol.address)
                if section and section.name == "__text":
                    if symbol.address not in self.functions:
                        self.functions[symbol.address] = Function(
                            address=symbol.address,
                            name=symbol.name,
                        )

        # Add entry point if not already present
        if self.binary.entry_point and self.binary.entry_point not in self.functions:
            self.functions[self.binary.entry_point] = Function(
                address=self.binary.entry_point,
                name="_start",
            )

    def _scan_for_prologues(self) -> None:
        """Scan for function prologues to find unmarked functions."""
        text = self.binary.text_section
        if not text:
            return

        data = text.data
        addr = text.address
        i = 0

        while i < len(data) - 4:
            # Check for stp x29, x30, [sp, #-N]!
            # Encoding: 1010 1001 01xx xxxx x111 1111 1111 1101
            if i + 4 <= len(data):
                word = int.from_bytes(data[i : i + 4], "little")

                # stp x29, x30, [sp, #imm]! pre-index
                # A9BF7BFD is common: stp x29, x30, [sp, #-0x10]!
                if (word & 0xFFE07FFF) == 0xA9007BFD:
                    func_addr = addr + i
                    if func_addr not in self.functions:
                        name = f"sub_{func_addr:x}"
                        self.functions[func_addr] = Function(
                            address=func_addr,
                            name=name,
                        )

            i += 4  # ARM64 instructions are 4 bytes

    def _analyze_function(self, func: Function) -> None:
        """Analyze a single function."""
        text = self.binary.text_section
        if not text:
            return

        # Find function bounds
        end = self._find_function_end(func.address)
        func.size = end - func.address

        # Build CFG
        offset = func.address - text.address
        data = text.data[offset : offset + func.size]
        func.cfg = self.cfg_builder.build(data, func.address, end)

        # Check if leaf function
        func.is_leaf = self._is_leaf_function(func)

        # Check if thunk
        func.is_thunk = self._is_thunk(func)

    def _find_function_end(self, start: int) -> int:
        """Find the end of a function starting at given address."""
        text = self.binary.text_section
        if not text:
            return start

        # Find next function or section end
        next_func: int | None = None
        for addr in self.functions:
            if addr > start:
                if next_func is None or addr < next_func:
                    next_func = addr

        max_end = min(next_func, text.end_address) if next_func else text.end_address

        # Scan for return instruction
        offset = start - text.address
        data = text.data
        addr = start

        while addr < max_end and (offset + 4) <= len(data):
            insn = self.disasm.disassemble_one(data[offset:], addr)
            if insn is None:
                break

            # Function ends after unconditional return
            if insn.is_return:
                return insn.next_address

            # Also end at unconditional branch that exits function
            if insn.is_unconditional_branch:
                if insn.branch_target is not None:
                    if insn.branch_target < start or insn.branch_target >= max_end:
                        return insn.next_address

            addr += insn.size
            offset += insn.size

        return addr

    def _is_leaf_function(self, func: Function) -> bool:
        """Check if function is a leaf (makes no calls)."""
        for insn in func.instructions:
            if insn.is_call:
                return False
        return True

    def _is_thunk(self, func: Function) -> bool:
        """Check if function is a simple thunk (just a branch)."""
        if func.cfg is None:
            return False

        blocks = list(func.cfg)
        if len(blocks) != 1:
            return False

        block = blocks[0]
        if len(block.instructions) > 2:
            return False

        for insn in block.instructions:
            if insn.is_unconditional_branch or insn.mnemonic == "br":
                return True

        return False
