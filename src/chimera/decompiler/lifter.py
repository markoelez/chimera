"""ARM64 to IR lifter."""

from typing import TYPE_CHECKING

from chimera.decompiler.ir import (
    IRType,
    IRValue,
    IROpcode,
    IRFunction,
    IRBasicBlock,
    IRInstruction,
)

if TYPE_CHECKING:
    from chimera.analysis.cfg import BasicBlock
    from chimera.analysis.functions import Function
    from chimera.arch.arm64.instructions import Operand, ARM64Instruction


class ARM64Lifter:
    """Lifts ARM64 instructions to IR."""

    def __init__(self) -> None:
        self._registers: dict[str, IRValue] = {}
        self._temp_counter = 0
        self._current_func: IRFunction | None = None

    def lift_function(self, func: "Function") -> IRFunction:
        """Lift a function to IR."""
        if not func.cfg:
            raise ValueError(f"Function {func.name} has no CFG")

        ir_func = IRFunction(
            name=func.name,
            source_addr=func.address,
        )
        self._current_func = ir_func
        self._registers = {}
        self._temp_counter = 0

        # Create parameters for argument registers
        for i in range(8):
            param = IRValue.var(f"arg{i}", IRType.I64)
            ir_func.params.append(param)
            self._registers[f"x{i}"] = param

        # Lift each basic block
        for block in func.cfg:
            ir_block = self._lift_block(block)
            ir_func.add_block(ir_block)

        return ir_func

    def _lift_block(self, block: "BasicBlock") -> IRBasicBlock:  # type: ignore
        """Lift a basic block to IR."""

        ir_block = IRBasicBlock(
            label=f"bb_{block.address:x}",
            source_addr=block.address,
        )

        for insn in block.instructions:
            ir_insns = self._lift_instruction(insn)
            for ir_insn in ir_insns:
                ir_block.append(ir_insn)

        # Add successors
        for succ_addr in block.successors:
            ir_block.successors.append(f"bb_{succ_addr:x}")

        return ir_block

    def _lift_instruction(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift a single instruction to IR."""
        mnemonic = insn.mnemonic.lower()

        # Dispatch to specific handlers
        if mnemonic in ("mov", "movz", "movn"):
            return self._lift_mov(insn)
        elif mnemonic == "movk":
            return self._lift_movk(insn)
        elif mnemonic in ("add", "adds"):
            return self._lift_add(insn)
        elif mnemonic in ("sub", "subs"):
            return self._lift_sub(insn)
        elif mnemonic in ("mul", "madd", "msub"):
            return self._lift_mul(insn)
        elif mnemonic in ("sdiv", "udiv"):
            return self._lift_div(insn)
        elif mnemonic in ("and", "ands"):
            return self._lift_and(insn)
        elif mnemonic == "orr":
            return self._lift_or(insn)
        elif mnemonic == "eor":
            return self._lift_xor(insn)
        elif mnemonic in ("lsl", "lslv"):
            return self._lift_shl(insn)
        elif mnemonic in ("lsr", "lsrv"):
            return self._lift_shr(insn)
        elif mnemonic in ("asr", "asrv"):
            return self._lift_sar(insn)
        elif mnemonic in ("ldr", "ldrsw", "ldrb", "ldrh", "ldur"):
            return self._lift_load(insn)
        elif mnemonic in ("str", "strb", "strh", "stur"):
            return self._lift_store(insn)
        elif mnemonic == "stp":
            return self._lift_stp(insn)
        elif mnemonic == "ldp":
            return self._lift_ldp(insn)
        elif mnemonic == "bl":
            return self._lift_call(insn)
        elif mnemonic == "blr":
            return self._lift_call_reg(insn)
        elif mnemonic == "ret":
            return self._lift_return(insn)
        elif mnemonic == "b":
            return self._lift_jump(insn)
        elif mnemonic.startswith("b."):
            return self._lift_cond_branch(insn)
        elif mnemonic in ("cbz", "cbnz"):
            return self._lift_cbz(insn)
        elif mnemonic in ("cmp", "cmn"):
            return self._lift_cmp(insn)
        elif mnemonic == "tst":
            return self._lift_tst(insn)
        elif mnemonic == "adrp":
            return self._lift_adrp(insn)
        elif mnemonic == "adr":
            return self._lift_adr(insn)
        elif mnemonic in ("sxtw", "sxth", "sxtb"):
            return self._lift_sext(insn)
        elif mnemonic in ("uxtw", "uxth", "uxtb"):
            return self._lift_zext(insn)
        elif mnemonic == "nop":
            return [IRInstruction(IROpcode.NOP, source_addr=insn.address)]
        else:
            # Unknown instruction - emit NOP with comment
            return [
                IRInstruction(
                    IROpcode.NOP,
                    source_addr=insn.address,
                    metadata={"unknown": f"{insn.mnemonic} {insn.op_str}"},
                )
            ]

    def _get_reg(self, name: str) -> IRValue:
        """Get or create IR value for a register."""
        name = name.lower()
        if name not in self._registers:
            ir_type = IRType.I32 if name.startswith("w") else IRType.I64
            self._registers[name] = IRValue.var(name, ir_type)
        return self._registers[name]

    def _new_temp(self, ir_type: IRType = IRType.I64) -> IRValue:
        """Create a new temporary."""
        if self._current_func:
            return self._current_func.new_temp(ir_type)
        temp = IRValue.temp(self._temp_counter, ir_type)
        self._temp_counter += 1
        return temp

    def _get_operand_value(self, insn: "ARM64Instruction", idx: int) -> IRValue:
        """Get IR value for an operand."""
        if idx >= len(insn.operands):
            return IRValue.constant(0)

        op = insn.operands[idx]
        if op.is_register and op.register:
            return self._get_reg(op.register.name)
        elif op.is_immediate and isinstance(op.value, int):
            return IRValue.constant(op.value)
        return IRValue.constant(0)

    # Lift handlers

    def _lift_mov(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift MOV instruction."""
        if len(insn.operands) < 2:
            return []

        dest = self._get_operand_value(insn, 0)
        src = self._get_operand_value(insn, 1)

        # For movz/movn with shift, handle specially
        if insn.mnemonic.lower() == "movn":
            temp = self._new_temp()
            return [
                IRInstruction(IROpcode.NOT, dest=temp, operands=[src], source_addr=insn.address),
                IRInstruction(IROpcode.VAR, dest=dest, operands=[temp], source_addr=insn.address),
            ]

        return [IRInstruction(IROpcode.VAR, dest=dest, operands=[src], source_addr=insn.address)]

    def _lift_movk(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift MOVK instruction (insert bits)."""
        if len(insn.operands) < 2:
            return []

        dest = self._get_operand_value(insn, 0)
        imm = self._get_operand_value(insn, 1)

        # MOVK inserts 16 bits at a shifted position
        # This is a simplified version
        return [
            IRInstruction(IROpcode.OR, dest=dest, operands=[dest, imm], source_addr=insn.address)
        ]

    def _lift_add(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift ADD instruction."""
        if len(insn.operands) < 3:
            return []

        dest = self._get_operand_value(insn, 0)
        op1 = self._get_operand_value(insn, 1)
        op2 = self._get_operand_value(insn, 2)

        return [
            IRInstruction(IROpcode.ADD, dest=dest, operands=[op1, op2], source_addr=insn.address)
        ]

    def _lift_sub(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift SUB instruction."""
        if len(insn.operands) < 3:
            return []

        dest = self._get_operand_value(insn, 0)
        op1 = self._get_operand_value(insn, 1)
        op2 = self._get_operand_value(insn, 2)

        return [
            IRInstruction(IROpcode.SUB, dest=dest, operands=[op1, op2], source_addr=insn.address)
        ]

    def _lift_mul(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift MUL instruction."""
        if len(insn.operands) < 3:
            return []

        dest = self._get_operand_value(insn, 0)
        op1 = self._get_operand_value(insn, 1)
        op2 = self._get_operand_value(insn, 2)

        return [
            IRInstruction(IROpcode.MUL, dest=dest, operands=[op1, op2], source_addr=insn.address)
        ]

    def _lift_div(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift DIV instruction."""
        if len(insn.operands) < 3:
            return []

        dest = self._get_operand_value(insn, 0)
        op1 = self._get_operand_value(insn, 1)
        op2 = self._get_operand_value(insn, 2)

        opcode = IROpcode.UDIV if insn.mnemonic.lower() == "udiv" else IROpcode.DIV

        return [IRInstruction(opcode, dest=dest, operands=[op1, op2], source_addr=insn.address)]

    def _lift_and(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift AND instruction."""
        if len(insn.operands) < 3:
            return []

        dest = self._get_operand_value(insn, 0)
        op1 = self._get_operand_value(insn, 1)
        op2 = self._get_operand_value(insn, 2)

        return [
            IRInstruction(IROpcode.AND, dest=dest, operands=[op1, op2], source_addr=insn.address)
        ]

    def _lift_or(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift ORR instruction."""
        if len(insn.operands) < 3:
            return []

        dest = self._get_operand_value(insn, 0)
        op1 = self._get_operand_value(insn, 1)
        op2 = self._get_operand_value(insn, 2)

        return [
            IRInstruction(IROpcode.OR, dest=dest, operands=[op1, op2], source_addr=insn.address)
        ]

    def _lift_xor(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift EOR instruction."""
        if len(insn.operands) < 3:
            return []

        dest = self._get_operand_value(insn, 0)
        op1 = self._get_operand_value(insn, 1)
        op2 = self._get_operand_value(insn, 2)

        return [
            IRInstruction(IROpcode.XOR, dest=dest, operands=[op1, op2], source_addr=insn.address)
        ]

    def _lift_shl(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift LSL instruction."""
        if len(insn.operands) < 3:
            return []

        dest = self._get_operand_value(insn, 0)
        op1 = self._get_operand_value(insn, 1)
        op2 = self._get_operand_value(insn, 2)

        return [
            IRInstruction(IROpcode.SHL, dest=dest, operands=[op1, op2], source_addr=insn.address)
        ]

    def _lift_shr(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift LSR instruction."""
        if len(insn.operands) < 3:
            return []

        dest = self._get_operand_value(insn, 0)
        op1 = self._get_operand_value(insn, 1)
        op2 = self._get_operand_value(insn, 2)

        return [
            IRInstruction(IROpcode.SHR, dest=dest, operands=[op1, op2], source_addr=insn.address)
        ]

    def _lift_sar(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift ASR instruction."""
        if len(insn.operands) < 3:
            return []

        dest = self._get_operand_value(insn, 0)
        op1 = self._get_operand_value(insn, 1)
        op2 = self._get_operand_value(insn, 2)

        return [
            IRInstruction(IROpcode.SAR, dest=dest, operands=[op1, op2], source_addr=insn.address)
        ]

    def _lift_load(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift LDR instruction."""
        if len(insn.operands) < 2:
            return []

        dest = self._get_operand_value(insn, 0)
        mem_op = insn.operands[1]

        # Compute address
        addr = self._compute_memory_address(mem_op)

        return [IRInstruction(IROpcode.LOAD, dest=dest, operands=[addr], source_addr=insn.address)]

    def _lift_store(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift STR instruction."""
        if len(insn.operands) < 2:
            return []

        src = self._get_operand_value(insn, 0)
        mem_op = insn.operands[1]

        # Compute address
        addr = self._compute_memory_address(mem_op)

        return [IRInstruction(IROpcode.STORE, operands=[addr, src], source_addr=insn.address)]

    def _lift_stp(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift STP instruction (store pair)."""
        if len(insn.operands) < 3:
            return []

        src1 = self._get_operand_value(insn, 0)
        src2 = self._get_operand_value(insn, 1)
        mem_op = insn.operands[2]

        addr = self._compute_memory_address(mem_op)

        # Store both values
        addr2 = self._new_temp(IRType.PTR)
        eight = IRValue.constant(8)

        return [
            IRInstruction(IROpcode.STORE, operands=[addr, src1], source_addr=insn.address),
            IRInstruction(
                IROpcode.ADD, dest=addr2, operands=[addr, eight], source_addr=insn.address
            ),
            IRInstruction(IROpcode.STORE, operands=[addr2, src2], source_addr=insn.address),
        ]

    def _lift_ldp(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift LDP instruction (load pair)."""
        if len(insn.operands) < 3:
            return []

        dest1 = self._get_operand_value(insn, 0)
        dest2 = self._get_operand_value(insn, 1)
        mem_op = insn.operands[2]

        addr = self._compute_memory_address(mem_op)

        # Load both values
        addr2 = self._new_temp(IRType.PTR)
        eight = IRValue.constant(8)

        return [
            IRInstruction(IROpcode.LOAD, dest=dest1, operands=[addr], source_addr=insn.address),
            IRInstruction(
                IROpcode.ADD, dest=addr2, operands=[addr, eight], source_addr=insn.address
            ),
            IRInstruction(IROpcode.LOAD, dest=dest2, operands=[addr2], source_addr=insn.address),
        ]

    def _lift_call(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift BL instruction."""
        target = IRValue.constant(insn.branch_target or 0, IRType.PTR)
        ret = self._get_reg("x0")

        return [
            IRInstruction(
                IROpcode.CALL,
                dest=ret,
                operands=[target],
                source_addr=insn.address,
            )
        ]

    def _lift_call_reg(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift BLR instruction."""
        if not insn.operands:
            return []

        target = self._get_operand_value(insn, 0)
        ret = self._get_reg("x0")

        return [
            IRInstruction(
                IROpcode.CALL,
                dest=ret,
                operands=[target],
                source_addr=insn.address,
            )
        ]

    def _lift_return(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift RET instruction."""
        ret_val = self._get_reg("x0")
        return [
            IRInstruction(
                IROpcode.RETURN,
                operands=[ret_val],
                source_addr=insn.address,
            )
        ]

    def _lift_jump(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift B instruction."""
        target = IRValue.constant(insn.branch_target or 0, IRType.PTR)
        return [
            IRInstruction(
                IROpcode.JUMP,
                operands=[target],
                source_addr=insn.address,
            )
        ]

    def _lift_cond_branch(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift conditional branch (b.eq, b.ne, etc.)."""
        target = IRValue.constant(insn.branch_target or 0, IRType.PTR)
        fallthrough = IRValue.constant(insn.next_address, IRType.PTR)

        # Get condition from mnemonic
        cond = insn.mnemonic.split(".")[-1] if "." in insn.mnemonic else "al"
        cond_val = IRValue.var(f"cond_{cond}", IRType.BOOL)

        return [
            IRInstruction(
                IROpcode.BRANCH,
                operands=[cond_val, target, fallthrough],
                source_addr=insn.address,
                metadata={"condition": cond},
            )
        ]

    def _lift_cbz(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift CBZ/CBNZ instruction."""
        if len(insn.operands) < 2:
            return []

        reg = self._get_operand_value(insn, 0)
        target = IRValue.constant(insn.branch_target or 0, IRType.PTR)
        fallthrough = IRValue.constant(insn.next_address, IRType.PTR)

        # Create comparison with zero
        zero = IRValue.constant(0)
        cond = self._new_temp(IRType.BOOL)

        cmp_op = IROpcode.EQ if insn.mnemonic.lower() == "cbz" else IROpcode.NE

        return [
            IRInstruction(cmp_op, dest=cond, operands=[reg, zero], source_addr=insn.address),
            IRInstruction(
                IROpcode.BRANCH,
                operands=[cond, target, fallthrough],
                source_addr=insn.address,
            ),
        ]

    def _lift_cmp(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift CMP instruction."""
        if len(insn.operands) < 2:
            return []

        op1 = self._get_operand_value(insn, 0)
        op2 = self._get_operand_value(insn, 1)

        # CMP sets flags, we track as a comparison result
        flags = IRValue.var("flags", IRType.I64)

        return [
            IRInstruction(IROpcode.SUB, dest=flags, operands=[op1, op2], source_addr=insn.address)
        ]

    def _lift_tst(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift TST instruction."""
        if len(insn.operands) < 2:
            return []

        op1 = self._get_operand_value(insn, 0)
        op2 = self._get_operand_value(insn, 1)

        flags = IRValue.var("flags", IRType.I64)

        return [
            IRInstruction(IROpcode.AND, dest=flags, operands=[op1, op2], source_addr=insn.address)
        ]

    def _lift_adrp(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift ADRP instruction."""
        if len(insn.operands) < 2:
            return []

        dest = self._get_operand_value(insn, 0)
        # ADRP loads page-aligned address
        page_addr = self._get_operand_value(insn, 1)

        return [
            IRInstruction(IROpcode.CONST, dest=dest, operands=[page_addr], source_addr=insn.address)
        ]

    def _lift_adr(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift ADR instruction."""
        if len(insn.operands) < 2:
            return []

        dest = self._get_operand_value(insn, 0)
        addr = self._get_operand_value(insn, 1)

        return [IRInstruction(IROpcode.CONST, dest=dest, operands=[addr], source_addr=insn.address)]

    def _lift_sext(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift sign extension instructions."""
        if len(insn.operands) < 2:
            return []

        dest = self._get_operand_value(insn, 0)
        src = self._get_operand_value(insn, 1)

        return [IRInstruction(IROpcode.SEXT, dest=dest, operands=[src], source_addr=insn.address)]

    def _lift_zext(self, insn: "ARM64Instruction") -> list[IRInstruction]:
        """Lift zero extension instructions."""
        if len(insn.operands) < 2:
            return []

        dest = self._get_operand_value(insn, 0)
        src = self._get_operand_value(insn, 1)

        return [IRInstruction(IROpcode.ZEXT, dest=dest, operands=[src], source_addr=insn.address)]

    def _compute_memory_address(self, mem_op: "Operand") -> IRValue:  # type: ignore
        """Compute address from memory operand."""

        if not mem_op.is_memory:
            return IRValue.constant(0, IRType.PTR)

        # Get base register
        if mem_op.base_reg:
            base = self._get_reg(mem_op.base_reg.name)
            base_name = mem_op.base_reg.name.lower()
        else:
            base = IRValue.constant(0, IRType.PTR)
            base_name = ""

        # Check for SP-relative addressing
        is_sp_relative = base_name in ("sp", "x31", "wsp")

        # Handle displacement
        offset = getattr(mem_op, "offset", 0) or 0
        if not isinstance(offset, int):
            offset = 0

        if offset != 0:
            # Create a composite address value that encodes the offset
            result = IRValue(
                ir_type=IRType.PTR,
                name=f"&[{base.name}+{offset:#x}]",
                stack_offset=offset if is_sp_relative else None,
                is_address=True,
            )
            return result

        # No offset - just the base
        base.is_address = True
        if is_sp_relative:
            base.stack_offset = 0
        return base
