"""ARM64 instruction decoder using capstone."""

from collections.abc import Iterator

import capstone
from capstone import arm64_const

from chimera.arch.arm64.registers import Registers, ARM64Register
from chimera.arch.arm64.instructions import (
    Operand,
    OperandType,
    ARM64Instruction,
    InstructionGroup,
)


class ARM64Disassembler:
    """ARM64 disassembler wrapper around capstone."""

    def __init__(self) -> None:
        self._cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        self._cs.detail = True

    def disassemble_one(self, data: bytes, address: int) -> ARM64Instruction | None:
        """Disassemble a single instruction."""
        for insn in self._cs.disasm(  # ty: ignore[missing-argument]
            data[:4],  # ty: ignore[invalid-argument-type]
            address,
            count=1,
        ):
            return self._convert_instruction(insn)
        return None

    def disassemble(self, data: bytes, address: int, count: int = 0) -> Iterator[ARM64Instruction]:
        """Disassemble a sequence of instructions."""
        for insn in self._cs.disasm(  # ty: ignore[missing-argument]
            data,  # ty: ignore[invalid-argument-type]
            address,
            count=count,
        ):
            yield self._convert_instruction(insn)

    def disassemble_range(self, data: bytes, start: int, end: int) -> Iterator[ARM64Instruction]:
        """Disassemble all instructions in an address range."""
        offset = 0
        addr = start

        while addr < end and offset < len(data):
            insn = self.disassemble_one(data[offset:], addr)
            if insn is None:
                # Invalid instruction, skip 4 bytes
                addr += 4
                offset += 4
                continue

            yield insn
            addr += insn.size
            offset += insn.size

    def _convert_instruction(self, cs_insn: capstone.CsInsn) -> ARM64Instruction:
        """Convert capstone instruction to our model."""
        operands = []
        reads = []
        writes = []
        groups = []
        branch_target = None

        # Process operands
        if cs_insn.operands:
            for i, op in enumerate(cs_insn.operands):
                operand = self._convert_operand(op, cs_insn)
                operands.append(operand)

                # Track register reads/writes
                if op.type == arm64_const.ARM64_OP_REG:
                    reg = self._get_register(op.reg)
                    if reg:
                        # First operand is usually destination
                        if i == 0 and self._is_write_mnemonic(cs_insn.mnemonic):
                            writes.append(reg)
                        else:
                            reads.append(reg)
                elif op.type == arm64_const.ARM64_OP_MEM:
                    if op.mem.base:
                        base_reg = self._get_register(op.mem.base)
                        if base_reg:
                            reads.append(base_reg)
                    if op.mem.index:
                        idx_reg = self._get_register(op.mem.index)
                        if idx_reg:
                            reads.append(idx_reg)

        # Determine instruction groups
        groups = self._classify_instruction(cs_insn)

        # Extract branch target
        if groups and any(
            g in groups
            for g in [InstructionGroup.BRANCH, InstructionGroup.CALL, InstructionGroup.JUMP]
        ):
            branch_target = self._extract_branch_target(cs_insn)

        return ARM64Instruction(
            address=cs_insn.address,
            size=cs_insn.size,
            mnemonic=cs_insn.mnemonic,
            op_str=cs_insn.op_str,
            bytes=bytes(cs_insn.bytes),
            operands=operands,
            groups=groups,
            reads=reads,
            writes=writes,
            branch_target=branch_target,
        )

    def _convert_operand(self, op: capstone.arm64.Arm64Op, insn: capstone.CsInsn) -> Operand:
        """Convert capstone operand to our model."""
        if op.type == arm64_const.ARM64_OP_REG:
            reg = self._get_register(op.reg)
            return Operand(
                op_type=OperandType.REGISTER,
                register=reg,
                size=64 if reg and reg.is_64bit else 32,
            )

        elif op.type == arm64_const.ARM64_OP_IMM:
            return Operand(
                op_type=OperandType.IMMEDIATE,
                value=op.imm,
            )

        elif op.type == arm64_const.ARM64_OP_MEM:
            base_reg = self._get_register(op.mem.base) if op.mem.base else None
            index_reg = self._get_register(op.mem.index) if op.mem.index else None

            return Operand(
                op_type=OperandType.MEMORY,
                base_reg=base_reg,
                index_reg=index_reg,
                disp=op.mem.disp,
            )

        elif op.type == arm64_const.ARM64_OP_FP:
            return Operand(
                op_type=OperandType.IMMEDIATE,
                value=op.fp,
            )

        # Default fallback
        return Operand(op_type=OperandType.IMMEDIATE, value=0)

    def _get_register(self, reg_id: int) -> ARM64Register | None:
        """Convert capstone register ID to our register model."""
        reg_name = self._cs.reg_name(reg_id)
        if reg_name:
            return Registers.from_name(reg_name)
        return None

    def _classify_instruction(self, insn: capstone.CsInsn) -> list[InstructionGroup]:
        """Classify instruction into groups."""
        groups = []
        mnemonic = insn.mnemonic.lower()

        # Branch instructions
        if mnemonic in ("b", "br"):
            groups.append(InstructionGroup.BRANCH)
            groups.append(InstructionGroup.JUMP)
        elif mnemonic.startswith("b.") or mnemonic in ("cbz", "cbnz", "tbz", "tbnz"):
            groups.append(InstructionGroup.BRANCH)
        elif mnemonic in ("bl", "blr"):
            groups.append(InstructionGroup.CALL)
        elif mnemonic == "ret":
            groups.append(InstructionGroup.RETURN)

        # Load instructions
        elif mnemonic.startswith("ld") or mnemonic.startswith("ldr"):
            groups.append(InstructionGroup.LOAD)
        elif mnemonic in ("ldp", "ldnp", "ldxr", "ldaxr", "ldar"):
            groups.append(InstructionGroup.LOAD)

        # Store instructions
        elif mnemonic.startswith("st") or mnemonic.startswith("str"):
            groups.append(InstructionGroup.STORE)
        elif mnemonic in ("stp", "stnp", "stxr", "stlxr", "stlr"):
            groups.append(InstructionGroup.STORE)

        # Arithmetic
        elif mnemonic in ("add", "adds", "sub", "subs", "adc", "adcs", "sbc", "sbcs"):
            groups.append(InstructionGroup.ARITHMETIC)
        elif mnemonic in ("mul", "madd", "msub", "mneg", "smull", "umull"):
            groups.append(InstructionGroup.ARITHMETIC)
        elif mnemonic in ("sdiv", "udiv"):
            groups.append(InstructionGroup.ARITHMETIC)
        elif mnemonic in ("neg", "negs", "ngc", "ngcs"):
            groups.append(InstructionGroup.ARITHMETIC)

        # Logic
        elif mnemonic in ("and", "ands", "orr", "eor", "eon", "bic", "bics", "orn"):
            groups.append(InstructionGroup.LOGIC)

        # Compare
        elif mnemonic in ("cmp", "cmn", "tst", "ccmp", "ccmn"):
            groups.append(InstructionGroup.COMPARE)

        # Move
        elif mnemonic in ("mov", "movz", "movn", "movk", "mvn"):
            groups.append(InstructionGroup.MOVE)

        # Shift/Rotate
        elif mnemonic in ("lsl", "lsr", "asr", "ror", "extr"):
            groups.append(InstructionGroup.SHIFT)

        # System
        elif mnemonic in ("svc", "hvc", "smc", "brk", "hlt", "nop", "wfi", "wfe"):
            groups.append(InstructionGroup.SYSTEM)
        elif mnemonic.startswith("mrs") or mnemonic.startswith("msr"):
            groups.append(InstructionGroup.SYSTEM)

        if not groups:
            groups.append(InstructionGroup.UNKNOWN)

        return groups

    def _extract_branch_target(self, insn: capstone.CsInsn) -> int | None:
        """Extract branch target address if present."""
        if not insn.operands:
            return None

        for op in insn.operands:
            if op.type == arm64_const.ARM64_OP_IMM:
                return op.imm

        return None

    def _is_write_mnemonic(self, mnemonic: str) -> bool:
        """Check if mnemonic typically writes to first operand."""
        mnemonic = mnemonic.lower()

        # These don't write to first operand
        no_write = {
            "cmp",
            "cmn",
            "tst",
            "b",
            "bl",
            "br",
            "blr",
            "ret",
            "str",
            "strb",
            "strh",
            "stur",
            "stp",
            "stlr",
            "stxr",
            "stlxr",
            "stnp",
            "cbz",
            "cbnz",
            "tbz",
            "tbnz",
        }

        if mnemonic in no_write or mnemonic.startswith("b."):
            return False

        return True
