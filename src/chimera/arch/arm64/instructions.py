"""ARM64 instruction model."""

from enum import IntEnum, auto
from typing import TYPE_CHECKING
from dataclasses import field, dataclass

if TYPE_CHECKING:
    from chimera.arch.arm64.registers import ARM64Register


class OperandType(IntEnum):
    """Type of instruction operand."""

    REGISTER = auto()
    IMMEDIATE = auto()
    MEMORY = auto()
    PC_RELATIVE = auto()
    SHIFT = auto()
    EXTEND = auto()
    CONDITION = auto()


class InstructionGroup(IntEnum):
    """Instruction classification groups."""

    UNKNOWN = auto()
    BRANCH = auto()
    CALL = auto()
    RETURN = auto()
    JUMP = auto()
    LOAD = auto()
    STORE = auto()
    ARITHMETIC = auto()
    LOGIC = auto()
    COMPARE = auto()
    MOVE = auto()
    SHIFT = auto()
    SYSTEM = auto()
    SIMD = auto()
    CRYPTO = auto()


@dataclass
class Operand:
    """Represents an instruction operand."""

    op_type: OperandType
    value: int | str = 0
    register: "ARM64Register | None" = None
    size: int = 64  # Bit size of operand

    # Memory operand fields
    base_reg: "ARM64Register | None" = None
    index_reg: "ARM64Register | None" = None
    disp: int = 0
    shift: int = 0
    shift_type: str = ""

    def __str__(self) -> str:
        if self.op_type == OperandType.REGISTER:
            return str(self.register) if self.register else "?"
        elif self.op_type == OperandType.IMMEDIATE:
            return f"#{self.value:#x}" if isinstance(self.value, int) else f"#{self.value}"
        elif self.op_type == OperandType.MEMORY:
            base = str(self.base_reg) if self.base_reg else ""
            if self.index_reg:
                idx = str(self.index_reg)
                if self.shift:
                    return f"[{base}, {idx}, lsl #{self.shift}]"
                return f"[{base}, {idx}]"
            elif self.disp:
                return f"[{base}, #{self.disp:#x}]"
            return f"[{base}]"
        elif self.op_type == OperandType.PC_RELATIVE:
            return f"{self.value:#x}"
        return str(self.value)

    @property
    def is_register(self) -> bool:
        return self.op_type == OperandType.REGISTER

    @property
    def is_immediate(self) -> bool:
        return self.op_type == OperandType.IMMEDIATE

    @property
    def is_memory(self) -> bool:
        return self.op_type == OperandType.MEMORY


@dataclass
class ARM64Instruction:
    """Represents a decoded ARM64 instruction."""

    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes: bytes
    operands: list[Operand] = field(default_factory=list)
    groups: list[InstructionGroup] = field(default_factory=list)

    # Computed properties
    reads: list["ARM64Register"] = field(default_factory=list)
    writes: list["ARM64Register"] = field(default_factory=list)
    branch_target: int | None = None

    def __str__(self) -> str:
        if self.op_str:
            return f"{self.mnemonic} {self.op_str}"
        return self.mnemonic

    def __repr__(self) -> str:
        return f"ARM64Instruction({self.address:#x}: {self})"

    @property
    def next_address(self) -> int:
        """Address of the following instruction."""
        return self.address + self.size

    @property
    def is_branch(self) -> bool:
        """Is this any kind of branch/jump?"""
        return InstructionGroup.BRANCH in self.groups

    @property
    def is_call(self) -> bool:
        """Is this a function call?"""
        return InstructionGroup.CALL in self.groups

    @property
    def is_return(self) -> bool:
        """Is this a return instruction?"""
        return InstructionGroup.RETURN in self.groups

    @property
    def is_unconditional_branch(self) -> bool:
        """Is this an unconditional branch?"""
        return self.mnemonic in ("b", "br")

    @property
    def is_conditional_branch(self) -> bool:
        """Is this a conditional branch?"""
        cond_branches = {
            "b.eq",
            "b.ne",
            "b.cs",
            "b.hs",
            "b.cc",
            "b.lo",
            "b.mi",
            "b.pl",
            "b.vs",
            "b.vc",
            "b.hi",
            "b.ls",
            "b.ge",
            "b.lt",
            "b.gt",
            "b.le",
            "b.al",
            "cbz",
            "cbnz",
            "tbz",
            "tbnz",
        }
        return self.mnemonic.lower() in cond_branches

    @property
    def is_terminator(self) -> bool:
        """Does this instruction terminate a basic block?"""
        return self.is_branch or self.is_call or self.is_return

    @property
    def is_load(self) -> bool:
        return InstructionGroup.LOAD in self.groups

    @property
    def is_store(self) -> bool:
        return InstructionGroup.STORE in self.groups

    @property
    def falls_through(self) -> bool:
        """Does execution continue to the next instruction?"""
        if self.is_return:
            return False
        if self.is_unconditional_branch:
            return False
        return True

    def format_with_bytes(self) -> str:
        """Format instruction with hex bytes."""
        hex_bytes = " ".join(f"{b:02x}" for b in self.bytes)
        return f"{self.address:016x}  {hex_bytes:<12}  {self}"
