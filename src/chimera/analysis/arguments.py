"""Function argument detection."""

from typing import TYPE_CHECKING
from dataclasses import dataclass

from chimera.decompiler.types import INT64, ResolvedType

if TYPE_CHECKING:
    from chimera.analysis.functions import Function
    from chimera.arch.arm64.registers import ARM64Register


# ARM64 calling convention: arguments in x0-x7
ARG_REGISTER_NAMES = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"}
ARG_REGISTER_INDICES = {0, 1, 2, 3, 4, 5, 6, 7}


@dataclass
class ArgumentInfo:
    """Information about a function argument."""

    index: int  # Argument index (0-7 for register args)
    register_name: str  # Register name (x0-x7)
    arg_type: ResolvedType | None = None
    name: str = ""  # Inferred name (arg0, arg1, etc.)

    def __post_init__(self) -> None:
        if not self.name:
            self.name = f"arg{self.index}"

    def __repr__(self) -> str:
        type_str = str(self.arg_type) if self.arg_type else "?"
        return f"ArgumentInfo({self.name}: {type_str} in {self.register_name})"


class ArgumentAnalyzer:
    """Detects actual function arguments from register usage.

    An argument register (x0-x7) is considered used as an argument if it is
    read before being written in the function's entry block.
    """

    def __init__(self, func: "Function") -> None:
        self.func = func

    def analyze(self) -> list[ArgumentInfo]:
        """Detect which argument registers are actually used."""
        if not self.func.cfg:
            return []

        # Track which registers are read before written
        read_before_write: set[int] = set()
        written: set[int] = set()

        # Analyze entry block
        entry = self.func.cfg.entry_block
        if not entry:
            return []

        for insn in entry.instructions:
            # Check reads
            for reg in insn.reads:
                reg_idx = self._get_reg_index(reg)
                if reg_idx is not None and reg_idx in ARG_REGISTER_INDICES:
                    if reg_idx not in written:
                        read_before_write.add(reg_idx)

            # Check writes
            for reg in insn.writes:
                reg_idx = self._get_reg_index(reg)
                if reg_idx is not None and reg_idx in ARG_REGISTER_INDICES:
                    written.add(reg_idx)

            # Stop at first call (clobbers argument registers)
            if insn.is_call:
                break

        # Build argument list
        arguments: list[ArgumentInfo] = []
        for idx in sorted(read_before_write):
            arg = ArgumentInfo(
                index=idx,
                register_name=f"x{idx}",
                arg_type=INT64,  # Default type
            )
            arguments.append(arg)

        return arguments

    def _get_reg_index(self, reg: "ARM64Register") -> int | None:
        """Get register index from ARM64Register."""
        if hasattr(reg, "index"):
            return reg.index
        # Try parsing from name
        name = getattr(reg, "name", "").lower()
        if name.startswith("x") and name[1:].isdigit():
            return int(name[1:])
        if name.startswith("w") and name[1:].isdigit():
            return int(name[1:])
        return None


def detect_arguments(func: "Function") -> list[ArgumentInfo]:
    """Convenience function to detect function arguments."""
    analyzer = ArgumentAnalyzer(func)
    return analyzer.analyze()
