"""ARM64 register model."""

from enum import IntEnum, auto
from dataclasses import dataclass


class RegisterType(IntEnum):
    """Type of ARM64 register."""

    GENERAL = auto()  # X0-X30
    ZERO = auto()  # XZR/WZR
    SP = auto()  # Stack pointer
    PC = auto()  # Program counter
    VECTOR = auto()  # V0-V31 / Q0-Q31 / D0-D31 / S0-S31 / H0-H31 / B0-B31
    SYSTEM = auto()  # System registers
    FLAGS = auto()  # NZCV flags


@dataclass(frozen=True)
class ARM64Register:
    """Represents an ARM64 register."""

    name: str
    index: int
    reg_type: RegisterType
    size: int  # Size in bits

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"ARM64Register({self.name})"

    @property
    def is_64bit(self) -> bool:
        return self.size == 64

    @property
    def is_32bit(self) -> bool:
        return self.size == 32

    @property
    def is_general(self) -> bool:
        return self.reg_type == RegisterType.GENERAL

    @property
    def is_sp(self) -> bool:
        return self.reg_type == RegisterType.SP

    @property
    def is_zero(self) -> bool:
        return self.reg_type == RegisterType.ZERO


# Pre-defined register instances
class Registers:
    """ARM64 register definitions."""

    # 64-bit general purpose registers
    X0 = ARM64Register("x0", 0, RegisterType.GENERAL, 64)
    X1 = ARM64Register("x1", 1, RegisterType.GENERAL, 64)
    X2 = ARM64Register("x2", 2, RegisterType.GENERAL, 64)
    X3 = ARM64Register("x3", 3, RegisterType.GENERAL, 64)
    X4 = ARM64Register("x4", 4, RegisterType.GENERAL, 64)
    X5 = ARM64Register("x5", 5, RegisterType.GENERAL, 64)
    X6 = ARM64Register("x6", 6, RegisterType.GENERAL, 64)
    X7 = ARM64Register("x7", 7, RegisterType.GENERAL, 64)
    X8 = ARM64Register("x8", 8, RegisterType.GENERAL, 64)
    X9 = ARM64Register("x9", 9, RegisterType.GENERAL, 64)
    X10 = ARM64Register("x10", 10, RegisterType.GENERAL, 64)
    X11 = ARM64Register("x11", 11, RegisterType.GENERAL, 64)
    X12 = ARM64Register("x12", 12, RegisterType.GENERAL, 64)
    X13 = ARM64Register("x13", 13, RegisterType.GENERAL, 64)
    X14 = ARM64Register("x14", 14, RegisterType.GENERAL, 64)
    X15 = ARM64Register("x15", 15, RegisterType.GENERAL, 64)
    X16 = ARM64Register("x16", 16, RegisterType.GENERAL, 64)
    X17 = ARM64Register("x17", 17, RegisterType.GENERAL, 64)
    X18 = ARM64Register("x18", 18, RegisterType.GENERAL, 64)
    X19 = ARM64Register("x19", 19, RegisterType.GENERAL, 64)
    X20 = ARM64Register("x20", 20, RegisterType.GENERAL, 64)
    X21 = ARM64Register("x21", 21, RegisterType.GENERAL, 64)
    X22 = ARM64Register("x22", 22, RegisterType.GENERAL, 64)
    X23 = ARM64Register("x23", 23, RegisterType.GENERAL, 64)
    X24 = ARM64Register("x24", 24, RegisterType.GENERAL, 64)
    X25 = ARM64Register("x25", 25, RegisterType.GENERAL, 64)
    X26 = ARM64Register("x26", 26, RegisterType.GENERAL, 64)
    X27 = ARM64Register("x27", 27, RegisterType.GENERAL, 64)
    X28 = ARM64Register("x28", 28, RegisterType.GENERAL, 64)
    X29 = ARM64Register("x29", 29, RegisterType.GENERAL, 64)  # Frame pointer
    X30 = ARM64Register("x30", 30, RegisterType.GENERAL, 64)  # Link register

    # Aliases
    FP = ARM64Register("fp", 29, RegisterType.GENERAL, 64)
    LR = ARM64Register("lr", 30, RegisterType.GENERAL, 64)

    # Special registers
    SP = ARM64Register("sp", 31, RegisterType.SP, 64)
    XZR = ARM64Register("xzr", 31, RegisterType.ZERO, 64)
    WZR = ARM64Register("wzr", 31, RegisterType.ZERO, 32)
    PC = ARM64Register("pc", 32, RegisterType.PC, 64)

    # 32-bit versions
    W0 = ARM64Register("w0", 0, RegisterType.GENERAL, 32)
    W1 = ARM64Register("w1", 1, RegisterType.GENERAL, 32)
    W2 = ARM64Register("w2", 2, RegisterType.GENERAL, 32)
    W3 = ARM64Register("w3", 3, RegisterType.GENERAL, 32)
    W4 = ARM64Register("w4", 4, RegisterType.GENERAL, 32)
    W5 = ARM64Register("w5", 5, RegisterType.GENERAL, 32)
    W6 = ARM64Register("w6", 6, RegisterType.GENERAL, 32)
    W7 = ARM64Register("w7", 7, RegisterType.GENERAL, 32)
    W8 = ARM64Register("w8", 8, RegisterType.GENERAL, 32)
    W9 = ARM64Register("w9", 9, RegisterType.GENERAL, 32)
    W10 = ARM64Register("w10", 10, RegisterType.GENERAL, 32)
    W11 = ARM64Register("w11", 11, RegisterType.GENERAL, 32)
    W12 = ARM64Register("w12", 12, RegisterType.GENERAL, 32)
    W13 = ARM64Register("w13", 13, RegisterType.GENERAL, 32)
    W14 = ARM64Register("w14", 14, RegisterType.GENERAL, 32)
    W15 = ARM64Register("w15", 15, RegisterType.GENERAL, 32)
    W16 = ARM64Register("w16", 16, RegisterType.GENERAL, 32)
    W17 = ARM64Register("w17", 17, RegisterType.GENERAL, 32)
    W18 = ARM64Register("w18", 18, RegisterType.GENERAL, 32)
    W19 = ARM64Register("w19", 19, RegisterType.GENERAL, 32)
    W20 = ARM64Register("w20", 20, RegisterType.GENERAL, 32)
    W21 = ARM64Register("w21", 21, RegisterType.GENERAL, 32)
    W22 = ARM64Register("w22", 22, RegisterType.GENERAL, 32)
    W23 = ARM64Register("w23", 23, RegisterType.GENERAL, 32)
    W24 = ARM64Register("w24", 24, RegisterType.GENERAL, 32)
    W25 = ARM64Register("w25", 25, RegisterType.GENERAL, 32)
    W26 = ARM64Register("w26", 26, RegisterType.GENERAL, 32)
    W27 = ARM64Register("w27", 27, RegisterType.GENERAL, 32)
    W28 = ARM64Register("w28", 28, RegisterType.GENERAL, 32)
    W29 = ARM64Register("w29", 29, RegisterType.GENERAL, 32)
    W30 = ARM64Register("w30", 30, RegisterType.GENERAL, 32)
    WSP = ARM64Register("wsp", 31, RegisterType.SP, 32)

    # Register lookup by name
    _BY_NAME: dict[str, "ARM64Register"] = {}

    @classmethod
    def from_name(cls, name: str) -> "ARM64Register | None":
        """Look up register by name."""
        if not cls._BY_NAME:
            # Initialize lookup table
            for attr_name in dir(cls):
                attr = getattr(cls, attr_name)
                if isinstance(attr, ARM64Register):
                    cls._BY_NAME[attr.name.lower()] = attr
        return cls._BY_NAME.get(name.lower())


# Argument registers for ARM64 calling convention
ARG_REGISTERS = [
    Registers.X0,
    Registers.X1,
    Registers.X2,
    Registers.X3,
    Registers.X4,
    Registers.X5,
    Registers.X6,
    Registers.X7,
]

# Return value registers
RETURN_REGISTERS = [Registers.X0, Registers.X1]

# Callee-saved registers
CALLEE_SAVED = [
    Registers.X19,
    Registers.X20,
    Registers.X21,
    Registers.X22,
    Registers.X23,
    Registers.X24,
    Registers.X25,
    Registers.X26,
    Registers.X27,
    Registers.X28,
    Registers.FP,
]

# Caller-saved (volatile) registers
CALLER_SAVED = [
    Registers.X0,
    Registers.X1,
    Registers.X2,
    Registers.X3,
    Registers.X4,
    Registers.X5,
    Registers.X6,
    Registers.X7,
    Registers.X8,
    Registers.X9,
    Registers.X10,
    Registers.X11,
    Registers.X12,
    Registers.X13,
    Registers.X14,
    Registers.X15,
    Registers.X16,
    Registers.X17,
    Registers.X18,
]
