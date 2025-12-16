"""Data flow analysis."""

from typing import TYPE_CHECKING
from dataclasses import field, dataclass

if TYPE_CHECKING:
    from chimera.analysis.cfg import BasicBlock, ControlFlowGraph
    from chimera.arch.arm64.registers import ARM64Register


@dataclass
class Definition:
    """A definition of a value."""

    address: int  # Instruction address
    register: "ARM64Register"
    value: int | None = None  # Constant value if known


@dataclass
class ReachingDefinitions:
    """Reaching definitions for a basic block."""

    block_addr: int
    gen: set[Definition] = field(default_factory=set)
    kill: set[Definition] = field(default_factory=set)
    reach_in: set[Definition] = field(default_factory=set)
    reach_out: set[Definition] = field(default_factory=set)


class DataFlowAnalyzer:
    """Performs data flow analysis on a CFG."""

    def __init__(self, cfg: "ControlFlowGraph") -> None:
        self.cfg = cfg
        self._reaching_defs: dict[int, ReachingDefinitions] = {}

    def compute_reaching_definitions(self) -> dict[int, ReachingDefinitions]:
        """Compute reaching definitions for all blocks."""
        # Initialize
        for block in self.cfg:
            rd = ReachingDefinitions(block_addr=block.address)
            self._compute_gen_kill(block, rd)
            self._reaching_defs[block.address] = rd

        # Iterate until fixed point
        changed = True
        while changed:
            changed = False
            for block in self.cfg.reverse_postorder():
                rd = self._reaching_defs[block.address]

                # reach_in = union of reach_out of predecessors
                new_reach_in: set[Definition] = set()
                for pred_addr in block.predecessors:
                    if pred_addr in self._reaching_defs:
                        new_reach_in |= self._reaching_defs[pred_addr].reach_out

                # reach_out = gen ∪ (reach_in - kill)
                new_reach_out = rd.gen | (new_reach_in - rd.kill)

                if new_reach_out != rd.reach_out:
                    rd.reach_in = new_reach_in
                    rd.reach_out = new_reach_out
                    changed = True

        return self._reaching_defs

    def _compute_gen_kill(self, block: "BasicBlock", rd: ReachingDefinitions) -> None:
        """Compute gen and kill sets for a block."""

        for insn in block.instructions:
            # Add definitions to gen
            for reg in insn.writes:
                # Kill any previous definition of this register
                to_kill = {d for d in rd.gen if d.register.index == reg.index}
                rd.gen -= to_kill

                # Add new definition
                defn = Definition(address=insn.address, register=reg)

                # Try to determine constant value
                if insn.mnemonic == "mov" and len(insn.operands) >= 2:
                    op = insn.operands[1]
                    if op.is_immediate and isinstance(op.value, int):
                        defn = Definition(
                            address=insn.address,
                            register=reg,
                            value=op.value,
                        )
                elif insn.mnemonic in ("movz", "movn", "movk"):
                    if len(insn.operands) >= 2:
                        op = insn.operands[1]
                        if op.is_immediate and isinstance(op.value, int):
                            defn = Definition(
                                address=insn.address,
                                register=reg,
                                value=op.value,
                            )

                rd.gen.add(defn)

            # Add to kill set for writes
            for reg in insn.writes:
                rd.kill.add(Definition(address=0, register=reg))

    def get_value_at(self, address: int, register: "ARM64Register") -> int | None:
        """Try to get the constant value of a register at an address."""
        # Find containing block
        block = None
        for b in self.cfg:
            if b.address <= address < b.end_address:
                block = b
                break

        if not block:
            return None

        rd = self._reaching_defs.get(block.address)
        if not rd:
            return None

        # Look through reaching definitions
        for defn in rd.reach_in:
            if defn.register.index == register.index and defn.value is not None:
                return defn.value

        return None


class TypePropagator:
    """Basic type propagation analysis."""

    def __init__(self, cfg: "ControlFlowGraph") -> None:
        self.cfg = cfg
        self._types: dict[tuple[int, int], str] = {}  # (addr, reg_idx) -> type

    def propagate(self) -> dict[tuple[int, int], str]:
        """Propagate types through the CFG."""
        # Initialize known types (e.g., SP is always pointer)

        for block in self.cfg:
            for insn in block.instructions:
                # SP is always a pointer
                for reg in insn.writes:
                    if reg.is_sp:
                        self._types[(insn.address, reg.index)] = "ptr"

                # Result of ADRP/ADR is a pointer
                if insn.mnemonic in ("adrp", "adr"):
                    if insn.writes:
                        reg = insn.writes[0]
                        self._types[(insn.address, reg.index)] = "ptr"

                # Load result depends on size
                if insn.is_load:
                    if insn.writes:
                        reg = insn.writes[0]
                        if reg.is_64bit:
                            self._types[(insn.address, reg.index)] = "i64"
                        else:
                            self._types[(insn.address, reg.index)] = "i32"

        return self._types


class ConstantFolder:
    """Constant folding and propagation."""

    def __init__(self, cfg: "ControlFlowGraph") -> None:
        self.cfg = cfg
        self.dataflow = DataFlowAnalyzer(cfg)

    def fold(self) -> dict[int, int]:
        """Compute constant values for addresses."""
        self.dataflow.compute_reaching_definitions()
        constants: dict[int, int] = {}

        # Look for address computation patterns
        for block in self.cfg:
            adrp_values: dict[int, int] = {}  # reg_idx -> page address

            for insn in block.instructions:
                # ADRP loads page-aligned address
                if insn.mnemonic == "adrp" and insn.writes:
                    reg = insn.writes[0]
                    if insn.operands and len(insn.operands) >= 2:
                        op = insn.operands[1]
                        if op.is_immediate and isinstance(op.value, int):
                            adrp_values[reg.index] = op.value

                # ADD with immediate adds offset to ADRP result
                elif insn.mnemonic == "add":
                    if len(insn.operands) >= 3 and insn.writes:
                        src_op = insn.operands[1]
                        imm_op = insn.operands[2]

                        if src_op.is_register and src_op.register:
                            base_idx = src_op.register.index
                            if base_idx in adrp_values:
                                if imm_op.is_immediate and isinstance(imm_op.value, int):
                                    final_addr = adrp_values[base_idx] + imm_op.value
                                    constants[insn.address] = final_addr

        return constants
