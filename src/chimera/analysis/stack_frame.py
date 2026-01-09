"""Stack frame analysis for local variable recovery."""

from typing import TYPE_CHECKING
from dataclasses import field, dataclass

from chimera.decompiler.types import INT64, ResolvedType, size_to_int_type

if TYPE_CHECKING:
    from chimera.analysis.functions import Function


@dataclass
class StackVariable:
    """A variable on the stack."""

    offset: int  # Offset from SP (negative for locals, positive for args)
    size: int  # Size in bytes
    name: str  # Generated name (var_8, arg_0, etc.)
    var_type: ResolvedType | None = None
    is_argument: bool = False  # Stack-passed argument (beyond x0-x7)

    def __repr__(self) -> str:
        type_str = str(self.var_type) if self.var_type else "?"
        return f"StackVariable({self.name}: {type_str} @ sp+{self.offset:#x})"


@dataclass
class StackFrame:
    """Stack frame layout for a function."""

    local_size: int = 0  # Total bytes allocated for locals
    saved_regs_size: int = 0  # Bytes for saved registers
    variables: list[StackVariable] = field(default_factory=list)

    def variable_at(self, offset: int) -> StackVariable | None:
        """Get variable at exact offset."""
        for var in self.variables:
            if var.offset == offset:
                return var
        return None

    def variable_containing(self, offset: int) -> StackVariable | None:
        """Get variable that contains the given offset."""
        for var in self.variables:
            if var.offset <= offset < var.offset + var.size:
                return var
        return None

    def add_access(self, offset: int, size: int, is_write: bool = False) -> StackVariable:
        """Record a stack access, creating or updating a variable."""
        # Check for existing variable at this offset
        existing = self.variable_at(offset)
        if existing:
            # Update size if larger access seen
            if size > existing.size:
                existing.size = size
                existing.var_type = size_to_int_type(size)
            return existing

        # Check for overlapping variable
        overlapping = self.variable_containing(offset)
        if overlapping:
            return overlapping

        # Create new variable
        if offset < 0:
            name = f"var_{abs(offset):x}"
        else:
            name = f"arg_{offset:x}"

        var = StackVariable(
            offset=offset,
            size=size,
            name=name,
            var_type=size_to_int_type(size),
            is_argument=offset > 0,
        )
        self.variables.append(var)
        # Keep sorted by offset
        self.variables.sort(key=lambda v: v.offset)
        return var


class StackFrameAnalyzer:
    """Analyzes function to recover stack frame layout."""

    # SP register index
    SP_REG = 31

    def __init__(self, func: "Function") -> None:
        self.func = func
        self.frame = StackFrame()

    def analyze(self) -> StackFrame:
        """Analyze function to extract stack frame information."""
        if not self.func.cfg:
            return self.frame

        # First pass: find stack allocation
        self._find_stack_allocation()

        # Second pass: collect all stack accesses
        self._collect_stack_accesses()

        # Assign default types based on size
        self._assign_types()

        return self.frame

    def _find_stack_allocation(self) -> None:
        """Find stack allocation in prologue."""
        if not self.func.cfg:
            return

        # Get entry block
        entry = self.func.cfg.entry_block
        if not entry:
            return

        for insn in entry.instructions:
            # Look for: sub sp, sp, #N
            if insn.mnemonic == "sub":
                ops = insn.operands
                if len(ops) >= 3:
                    # Check if destination and first source are SP
                    if (
                        ops[0].is_register
                        and ops[0].value == self.SP_REG
                        and ops[1].is_register
                        and ops[1].value == self.SP_REG
                        and ops[2].is_immediate
                    ):
                        alloc_size = ops[2].value
                        if isinstance(alloc_size, int):
                            self.frame.local_size = alloc_size
                            return

            # Also check for: stp x29, x30, [sp, #-N]!
            if insn.mnemonic == "stp":
                ops = insn.operands
                if len(ops) >= 3 and ops[2].is_memory:
                    mem = ops[2]
                    if hasattr(mem, "base") and mem.base == self.SP_REG:
                        # Pre-indexed store
                        if hasattr(mem, "offset") and isinstance(mem.offset, int):
                            self.frame.saved_regs_size = abs(mem.offset)

    def _collect_stack_accesses(self) -> None:
        """Collect all memory accesses relative to SP."""
        if not self.func.cfg:
            return

        for block in self.func.cfg:
            for insn in block.instructions:
                # Check load instructions
                if insn.mnemonic in (
                    "ldr",
                    "ldp",
                    "ldur",
                    "ldrb",
                    "ldrh",
                    "ldrsb",
                    "ldrsh",
                    "ldrsw",
                ):
                    self._process_load(insn)

                # Check store instructions
                if insn.mnemonic in ("str", "stp", "stur", "strb", "strh"):
                    self._process_store(insn)

    def _process_load(self, insn) -> None:
        """Process a load instruction for stack access."""
        ops = insn.operands
        if len(ops) < 2:
            return

        # Get memory operand (usually last or second-to-last)
        mem_op = None
        for op in ops:
            if op.is_memory:
                mem_op = op
                break

        if not mem_op:
            return

        # Check if base is SP
        if hasattr(mem_op, "base") and mem_op.base == self.SP_REG:
            offset = getattr(mem_op, "offset", 0)
            if not isinstance(offset, int):
                offset = 0

            # Determine size from instruction
            size = self._load_size(insn.mnemonic)
            self.frame.add_access(offset, size, is_write=False)

    def _process_store(self, insn) -> None:
        """Process a store instruction for stack access."""
        ops = insn.operands
        if len(ops) < 2:
            return

        # Get memory operand
        mem_op = None
        for op in ops:
            if op.is_memory:
                mem_op = op
                break

        if not mem_op:
            return

        # Check if base is SP
        if hasattr(mem_op, "base") and mem_op.base == self.SP_REG:
            offset = getattr(mem_op, "offset", 0)
            if not isinstance(offset, int):
                offset = 0

            # Determine size from instruction
            size = self._store_size(insn.mnemonic)
            self.frame.add_access(offset, size, is_write=True)

    def _load_size(self, mnemonic: str) -> int:
        """Get size of load in bytes."""
        if mnemonic in ("ldrb", "ldrsb"):
            return 1
        if mnemonic in ("ldrh", "ldrsh"):
            return 2
        if mnemonic in ("ldrsw",):
            return 4
        if mnemonic == "ldp":
            return 16  # Two 8-byte registers
        return 8  # Default 64-bit

    def _store_size(self, mnemonic: str) -> int:
        """Get size of store in bytes."""
        if mnemonic == "strb":
            return 1
        if mnemonic == "strh":
            return 2
        if mnemonic == "stp":
            return 16
        return 8

    def _assign_types(self) -> None:
        """Assign types to variables based on access patterns."""
        for var in self.frame.variables:
            if var.var_type is None:
                var.var_type = INT64  # Default to 64-bit
