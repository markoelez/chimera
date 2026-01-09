"""Intermediate representation for decompilation."""

from enum import IntEnum, auto
from typing import TYPE_CHECKING, Any
from dataclasses import field, dataclass
from collections.abc import Iterator

if TYPE_CHECKING:
    from chimera.decompiler.types import ResolvedType


class IRType(IntEnum):
    """IR value types."""

    VOID = auto()
    I8 = auto()
    I16 = auto()
    I32 = auto()
    I64 = auto()
    PTR = auto()
    BOOL = auto()
    FLOAT = auto()
    DOUBLE = auto()

    @property
    def size(self) -> int:
        """Size in bytes."""
        sizes = {
            IRType.VOID: 0,
            IRType.I8: 1,
            IRType.I16: 2,
            IRType.I32: 4,
            IRType.I64: 8,
            IRType.PTR: 8,
            IRType.BOOL: 1,
            IRType.FLOAT: 4,
            IRType.DOUBLE: 8,
        }
        return sizes.get(self, 0)

    def __str__(self) -> str:
        names = {
            IRType.VOID: "void",
            IRType.I8: "i8",
            IRType.I16: "i16",
            IRType.I32: "i32",
            IRType.I64: "i64",
            IRType.PTR: "ptr",
            IRType.BOOL: "bool",
            IRType.FLOAT: "f32",
            IRType.DOUBLE: "f64",
        }
        return names.get(self, "unknown")


class IROpcode(IntEnum):
    """IR operation codes."""

    # Constants and variables
    CONST = auto()  # Constant value
    VAR = auto()  # Variable reference
    ARG = auto()  # Function argument
    TEMP = auto()  # Temporary value

    # Memory operations
    LOAD = auto()  # Load from memory
    STORE = auto()  # Store to memory
    ALLOCA = auto()  # Stack allocation

    # Arithmetic
    ADD = auto()
    SUB = auto()
    MUL = auto()
    DIV = auto()
    UDIV = auto()
    MOD = auto()
    UMOD = auto()
    NEG = auto()

    # Bitwise
    AND = auto()
    OR = auto()
    XOR = auto()
    NOT = auto()
    SHL = auto()
    SHR = auto()
    SAR = auto()  # Arithmetic shift right
    ROL = auto()
    ROR = auto()

    # Comparison
    EQ = auto()
    NE = auto()
    LT = auto()
    LE = auto()
    GT = auto()
    GE = auto()
    ULT = auto()  # Unsigned less than
    ULE = auto()
    UGT = auto()
    UGE = auto()

    # Control flow
    JUMP = auto()
    BRANCH = auto()  # Conditional branch
    SWITCH = auto()  # Multi-way branch (switch statement)
    CALL = auto()
    RETURN = auto()
    NOP = auto()

    # Type conversions
    ZEXT = auto()  # Zero extend
    SEXT = auto()  # Sign extend
    TRUNC = auto()  # Truncate
    BITCAST = auto()

    # High-level constructs (added during structuring)
    PHI = auto()  # SSA phi node
    SELECT = auto()  # Conditional select


@dataclass
class IRValue:
    """A value in the IR."""

    ir_type: IRType
    name: str = ""
    const_value: int | float | None = None
    version: int = 0  # For SSA
    # Type system fields
    resolved_type: "ResolvedType | None" = None  # Inferred high-level type
    stack_offset: int | None = None  # Offset from SP if stack variable
    is_address: bool = False  # True if this value is an address/pointer

    def __str__(self) -> str:
        if self.const_value is not None:
            return f"{self.const_value}"
        if self.version > 0:
            return f"{self.name}.{self.version}"
        return self.name

    def __hash__(self) -> int:
        return hash((self.name, self.version, self.const_value))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IRValue):
            return False
        return (
            self.name == other.name
            and self.version == other.version
            and self.const_value == other.const_value
        )

    @classmethod
    def constant(cls, value: int, ir_type: IRType = IRType.I64) -> "IRValue":
        """Create a constant value."""
        return cls(ir_type=ir_type, const_value=value)

    @classmethod
    def temp(cls, num: int, ir_type: IRType = IRType.I64) -> "IRValue":
        """Create a temporary value."""
        return cls(ir_type=ir_type, name=f"t{num}")

    @classmethod
    def var(cls, name: str, ir_type: IRType = IRType.I64) -> "IRValue":
        """Create a named variable."""
        return cls(ir_type=ir_type, name=name)

    @property
    def is_const(self) -> bool:
        return self.const_value is not None


@dataclass
class IRInstruction:
    """An IR instruction."""

    opcode: IROpcode
    dest: IRValue | None = None
    operands: list[IRValue] = field(default_factory=list)
    source_addr: int = 0  # Original instruction address
    metadata: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        op_str = ", ".join(str(op) for op in self.operands)
        dest_str = f"{self.dest} = " if self.dest else ""
        return f"{dest_str}{self.opcode.name.lower()} {op_str}"

    @property
    def is_terminator(self) -> bool:
        """Does this instruction terminate a block?"""
        return self.opcode in (
            IROpcode.JUMP,
            IROpcode.BRANCH,
            IROpcode.SWITCH,
            IROpcode.RETURN,
        )

    @property
    def is_branch(self) -> bool:
        return self.opcode == IROpcode.BRANCH

    @property
    def uses(self) -> list[IRValue]:
        """Values used by this instruction."""
        return self.operands

    @property
    def defines(self) -> IRValue | None:
        """Value defined by this instruction."""
        return self.dest


@dataclass
class IRBasicBlock:
    """A basic block in the IR."""

    label: str
    instructions: list[IRInstruction] = field(default_factory=list)
    successors: list[str] = field(default_factory=list)
    predecessors: list[str] = field(default_factory=list)
    source_addr: int = 0

    def append(self, insn: IRInstruction) -> None:
        """Add instruction to block."""
        self.instructions.append(insn)

    def __iter__(self) -> Iterator[IRInstruction]:
        return iter(self.instructions)

    def __len__(self) -> int:
        return len(self.instructions)

    @property
    def terminator(self) -> IRInstruction | None:
        """Get the terminator instruction."""
        if self.instructions and self.instructions[-1].is_terminator:
            return self.instructions[-1]
        return None

    def __str__(self) -> str:
        lines = [f"{self.label}:"]
        for insn in self.instructions:
            lines.append(f"  {insn}")
        return "\n".join(lines)


@dataclass
class IRFunction:
    """A function in IR form."""

    name: str
    entry_block: str = ""
    blocks: dict[str, IRBasicBlock] = field(default_factory=dict)
    params: list[IRValue] = field(default_factory=list)
    return_type: IRType = IRType.I64
    locals: list[IRValue] = field(default_factory=list)
    source_addr: int = 0
    _temp_counter: int = 0

    def add_block(self, block: IRBasicBlock) -> None:
        """Add a basic block to the function."""
        self.blocks[block.label] = block
        if not self.entry_block:
            self.entry_block = block.label

    def get_block(self, label: str) -> IRBasicBlock | None:
        """Get block by label."""
        return self.blocks.get(label)

    def new_temp(self, ir_type: IRType = IRType.I64) -> IRValue:
        """Create a new temporary value."""
        temp = IRValue.temp(self._temp_counter, ir_type)
        self._temp_counter += 1
        return temp

    def __iter__(self) -> Iterator[IRBasicBlock]:
        """Iterate blocks in order."""
        if self.entry_block:
            yield self.blocks[self.entry_block]
        for label, block in self.blocks.items():
            if label != self.entry_block:
                yield block

    def __str__(self) -> str:
        params_str = ", ".join(str(p) for p in self.params)
        lines = [f"func {self.name}({params_str}) -> {self.return_type}:"]
        for block in self:
            lines.append(str(block))
        return "\n".join(lines)
