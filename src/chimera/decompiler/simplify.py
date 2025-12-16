"""IR simplification passes."""

from collections.abc import Callable

from chimera.decompiler.ir import (
    IRValue,
    IROpcode,
    IRFunction,
    IRInstruction,
)


class IRSimplifier:
    """Simplifies IR through various optimization passes."""

    def __init__(self, func: IRFunction) -> None:
        self.func = func
        self._changed = False

    def simplify(self) -> IRFunction:
        """Run all simplification passes until fixed point."""
        passes: list[Callable[[], bool]] = [
            self._constant_fold,
            self._copy_propagation,
            self._dead_code_elimination,
            self._algebraic_simplification,
            self._strength_reduction,
        ]

        # Iterate until no changes
        changed = True
        max_iterations = 10
        iteration = 0

        while changed and iteration < max_iterations:
            changed = False
            for pass_fn in passes:
                if pass_fn():
                    changed = True
            iteration += 1

        return self.func

    def _constant_fold(self) -> bool:
        """Fold constant expressions."""
        changed = False

        for block in self.func:
            new_insns: list[IRInstruction] = []

            for insn in block.instructions:
                folded = self._try_fold_constants(insn)
                if folded is not None:
                    new_insns.append(folded)
                    if folded != insn:
                        changed = True
                else:
                    new_insns.append(insn)

            block.instructions = new_insns

        return changed

    def _try_fold_constants(self, insn: IRInstruction) -> IRInstruction | None:
        """Try to fold a single instruction."""
        # Need two constant operands for binary ops
        if len(insn.operands) < 2:
            return insn

        op1 = insn.operands[0]
        op2 = insn.operands[1]

        if not (op1.is_const and op2.is_const):
            return insn

        v1 = op1.const_value
        v2 = op2.const_value

        if v1 is None or v2 is None:
            return insn

        result: int | None = None

        if insn.opcode == IROpcode.ADD:
            result = v1 + v2
        elif insn.opcode == IROpcode.SUB:
            result = v1 - v2
        elif insn.opcode == IROpcode.MUL:
            result = v1 * v2
        elif insn.opcode == IROpcode.DIV and v2 != 0:
            result = v1 // v2
        elif insn.opcode == IROpcode.AND:
            result = v1 & v2
        elif insn.opcode == IROpcode.OR:
            result = v1 | v2
        elif insn.opcode == IROpcode.XOR:
            result = v1 ^ v2
        elif insn.opcode == IROpcode.SHL:
            result = v1 << (v2 & 63)
        elif insn.opcode == IROpcode.SHR:
            result = v1 >> (v2 & 63)

        if result is not None and insn.dest:
            # Replace with constant assignment
            const = IRValue.constant(result & 0xFFFFFFFFFFFFFFFF, insn.dest.ir_type)
            return IRInstruction(
                IROpcode.CONST,
                dest=insn.dest,
                operands=[const],
                source_addr=insn.source_addr,
            )

        return insn

    def _copy_propagation(self) -> bool:
        """Propagate copy assignments."""
        changed = False

        # Build copy map: dest -> source
        copies: dict[str, IRValue] = {}

        for block in self.func:
            for insn in block.instructions:
                # Track simple copies
                if insn.opcode == IROpcode.VAR and insn.dest and len(insn.operands) == 1:
                    copies[insn.dest.name] = insn.operands[0]
                elif insn.opcode == IROpcode.CONST and insn.dest and len(insn.operands) == 1:
                    copies[insn.dest.name] = insn.operands[0]

        # Propagate copies
        for block in self.func:
            for insn in block.instructions:
                new_operands: list[IRValue] = []
                for op in insn.operands:
                    if op.name in copies and not op.is_const:
                        replacement = copies[op.name]
                        # Don't propagate if it creates a cycle
                        if replacement.name != op.name:
                            new_operands.append(replacement)
                            changed = True
                        else:
                            new_operands.append(op)
                    else:
                        new_operands.append(op)
                insn.operands = new_operands

        return changed

    def _dead_code_elimination(self) -> bool:
        """Remove dead code."""
        changed = False

        # Find all used values
        used: set[str] = set()

        for block in self.func:
            for insn in block.instructions:
                # Values used as operands
                for op in insn.operands:
                    if not op.is_const:
                        used.add(op.name)

                # Branch targets, returns, stores always used
                if insn.opcode in (
                    IROpcode.BRANCH,
                    IROpcode.JUMP,
                    IROpcode.RETURN,
                    IROpcode.STORE,
                    IROpcode.CALL,
                ):
                    if insn.dest:
                        used.add(insn.dest.name)

        # Remove dead definitions
        for block in self.func:
            new_insns: list[IRInstruction] = []
            for insn in block.instructions:
                # Keep terminators and side-effecting instructions
                if insn.is_terminator or insn.opcode in (
                    IROpcode.STORE,
                    IROpcode.CALL,
                ):
                    new_insns.append(insn)
                # Keep if destination is used
                elif insn.dest and insn.dest.name in used:
                    new_insns.append(insn)
                # Keep NOPs with metadata (unknown instructions)
                elif insn.opcode == IROpcode.NOP and insn.metadata:
                    new_insns.append(insn)
                else:
                    changed = True

            block.instructions = new_insns

        return changed

    def _algebraic_simplification(self) -> bool:
        """Apply algebraic simplifications."""
        changed = False

        for block in self.func:
            new_insns: list[IRInstruction] = []

            for insn in block.instructions:
                simplified = self._simplify_algebraic(insn)
                if simplified != insn:
                    changed = True
                new_insns.append(simplified)

            block.instructions = new_insns

        return changed

    def _simplify_algebraic(self, insn: IRInstruction) -> IRInstruction:
        """Apply algebraic simplifications to an instruction."""
        if len(insn.operands) < 2 or not insn.dest:
            return insn

        op1 = insn.operands[0]
        op2 = insn.operands[1]

        # x + 0 = x
        if insn.opcode == IROpcode.ADD:
            if op2.is_const and op2.const_value == 0:
                return IRInstruction(
                    IROpcode.VAR,
                    dest=insn.dest,
                    operands=[op1],
                    source_addr=insn.source_addr,
                )
            if op1.is_const and op1.const_value == 0:
                return IRInstruction(
                    IROpcode.VAR,
                    dest=insn.dest,
                    operands=[op2],
                    source_addr=insn.source_addr,
                )

        # x - 0 = x
        if insn.opcode == IROpcode.SUB:
            if op2.is_const and op2.const_value == 0:
                return IRInstruction(
                    IROpcode.VAR,
                    dest=insn.dest,
                    operands=[op1],
                    source_addr=insn.source_addr,
                )
            # x - x = 0
            if op1.name == op2.name and op1.version == op2.version:
                return IRInstruction(
                    IROpcode.CONST,
                    dest=insn.dest,
                    operands=[IRValue.constant(0)],
                    source_addr=insn.source_addr,
                )

        # x * 1 = x
        if insn.opcode == IROpcode.MUL:
            if op2.is_const and op2.const_value == 1:
                return IRInstruction(
                    IROpcode.VAR,
                    dest=insn.dest,
                    operands=[op1],
                    source_addr=insn.source_addr,
                )
            if op1.is_const and op1.const_value == 1:
                return IRInstruction(
                    IROpcode.VAR,
                    dest=insn.dest,
                    operands=[op2],
                    source_addr=insn.source_addr,
                )
            # x * 0 = 0
            if (op1.is_const and op1.const_value == 0) or (op2.is_const and op2.const_value == 0):
                return IRInstruction(
                    IROpcode.CONST,
                    dest=insn.dest,
                    operands=[IRValue.constant(0)],
                    source_addr=insn.source_addr,
                )

        # x / 1 = x
        if insn.opcode in (IROpcode.DIV, IROpcode.UDIV):
            if op2.is_const and op2.const_value == 1:
                return IRInstruction(
                    IROpcode.VAR,
                    dest=insn.dest,
                    operands=[op1],
                    source_addr=insn.source_addr,
                )

        # x & 0 = 0
        if insn.opcode == IROpcode.AND:
            if (op1.is_const and op1.const_value == 0) or (op2.is_const and op2.const_value == 0):
                return IRInstruction(
                    IROpcode.CONST,
                    dest=insn.dest,
                    operands=[IRValue.constant(0)],
                    source_addr=insn.source_addr,
                )
            # x & -1 = x
            if op2.is_const and op2.const_value == -1:
                return IRInstruction(
                    IROpcode.VAR,
                    dest=insn.dest,
                    operands=[op1],
                    source_addr=insn.source_addr,
                )

        # x | 0 = x
        if insn.opcode == IROpcode.OR:
            if op2.is_const and op2.const_value == 0:
                return IRInstruction(
                    IROpcode.VAR,
                    dest=insn.dest,
                    operands=[op1],
                    source_addr=insn.source_addr,
                )
            if op1.is_const and op1.const_value == 0:
                return IRInstruction(
                    IROpcode.VAR,
                    dest=insn.dest,
                    operands=[op2],
                    source_addr=insn.source_addr,
                )

        # x ^ 0 = x
        if insn.opcode == IROpcode.XOR:
            if op2.is_const and op2.const_value == 0:
                return IRInstruction(
                    IROpcode.VAR,
                    dest=insn.dest,
                    operands=[op1],
                    source_addr=insn.source_addr,
                )
            # x ^ x = 0
            if op1.name == op2.name and op1.version == op2.version:
                return IRInstruction(
                    IROpcode.CONST,
                    dest=insn.dest,
                    operands=[IRValue.constant(0)],
                    source_addr=insn.source_addr,
                )

        # x << 0 = x, x >> 0 = x
        if insn.opcode in (IROpcode.SHL, IROpcode.SHR, IROpcode.SAR):
            if op2.is_const and op2.const_value == 0:
                return IRInstruction(
                    IROpcode.VAR,
                    dest=insn.dest,
                    operands=[op1],
                    source_addr=insn.source_addr,
                )

        return insn

    def _strength_reduction(self) -> bool:
        """Reduce strength of operations (e.g., mul by power of 2 to shift)."""
        changed = False

        for block in self.func:
            new_insns: list[IRInstruction] = []

            for insn in block.instructions:
                reduced = self._reduce_strength(insn)
                if reduced != insn:
                    changed = True
                new_insns.append(reduced)

            block.instructions = new_insns

        return changed

    def _reduce_strength(self, insn: IRInstruction) -> IRInstruction:
        """Apply strength reduction to an instruction."""
        if len(insn.operands) < 2 or not insn.dest:
            return insn

        op1 = insn.operands[0]
        op2 = insn.operands[1]

        # x * 2^n -> x << n
        if insn.opcode == IROpcode.MUL:
            if op2.is_const and op2.const_value is not None:
                val = op2.const_value
                if isinstance(val, int) and val > 0 and (val & (val - 1)) == 0:
                    # Power of 2
                    shift = val.bit_length() - 1
                    return IRInstruction(
                        IROpcode.SHL,
                        dest=insn.dest,
                        operands=[op1, IRValue.constant(shift)],
                        source_addr=insn.source_addr,
                    )

        # x / 2^n -> x >> n (for unsigned)
        if insn.opcode == IROpcode.UDIV:
            if op2.is_const and op2.const_value is not None:
                val = op2.const_value
                if isinstance(val, int) and val > 0 and (val & (val - 1)) == 0:
                    shift = val.bit_length() - 1
                    return IRInstruction(
                        IROpcode.SHR,
                        dest=insn.dest,
                        operands=[op1, IRValue.constant(shift)],
                        source_addr=insn.source_addr,
                    )

        return insn
