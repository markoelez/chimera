"""Tests for the decompiler module."""

from chimera.decompiler.ir import (
    IRType,
    IRValue,
    IROpcode,
    IRFunction,
    IRBasicBlock,
    IRInstruction,
)
from chimera.decompiler.simplify import IRSimplifier


class TestIRValue:
    """Tests for IR values."""

    def test_constant_value(self):
        """Test constant value creation."""
        val = IRValue.constant(42)

        assert val.is_const
        assert val.const_value == 42
        assert str(val) == "42"

    def test_temp_value(self):
        """Test temporary value creation."""
        val = IRValue.temp(5)

        assert not val.is_const
        assert val.name == "t5"
        assert str(val) == "t5"

    def test_var_value(self):
        """Test variable value creation."""
        val = IRValue.var("x0")

        assert not val.is_const
        assert val.name == "x0"
        assert str(val) == "x0"

    def test_ssa_versioned_value(self):
        """Test SSA versioned value."""
        val = IRValue(ir_type=IRType.I64, name="x", version=3)

        assert str(val) == "x.3"

    def test_value_equality(self):
        """Test value equality."""
        v1 = IRValue.var("x")
        v2 = IRValue.var("x")
        v3 = IRValue.var("y")

        assert v1 == v2
        assert v1 != v3


class TestIRInstruction:
    """Tests for IR instructions."""

    def test_basic_instruction(self):
        """Test basic instruction creation."""
        dest = IRValue.temp(0)
        op1 = IRValue.var("x0")
        op2 = IRValue.constant(1)

        insn = IRInstruction(
            opcode=IROpcode.ADD,
            dest=dest,
            operands=[op1, op2],
        )

        assert insn.opcode == IROpcode.ADD
        assert insn.dest == dest
        assert len(insn.operands) == 2

    def test_terminator_detection(self):
        """Test terminator instruction detection."""
        jump = IRInstruction(IROpcode.JUMP, operands=[IRValue.constant(0x1000)])
        add = IRInstruction(IROpcode.ADD, dest=IRValue.temp(0), operands=[])

        assert jump.is_terminator
        assert not add.is_terminator

    def test_uses_and_defines(self):
        """Test uses and defines properties."""
        dest = IRValue.temp(0)
        op1 = IRValue.var("x0")
        op2 = IRValue.var("x1")

        insn = IRInstruction(
            opcode=IROpcode.ADD,
            dest=dest,
            operands=[op1, op2],
        )

        assert insn.defines == dest
        assert op1 in insn.uses
        assert op2 in insn.uses


class TestIRFunction:
    """Tests for IR functions."""

    def test_empty_function(self):
        """Test empty function creation."""
        func = IRFunction(name="test")

        assert func.name == "test"
        assert len(func.blocks) == 0
        assert func.entry_block == ""

    def test_add_blocks(self):
        """Test adding blocks to function."""
        func = IRFunction(name="test")

        block1 = IRBasicBlock(label="entry")
        block2 = IRBasicBlock(label="exit")

        func.add_block(block1)
        func.add_block(block2)

        assert len(func.blocks) == 2
        assert func.entry_block == "entry"
        assert func.get_block("entry") == block1
        assert func.get_block("exit") == block2

    def test_new_temp(self):
        """Test temporary generation."""
        func = IRFunction(name="test")

        t0 = func.new_temp()
        t1 = func.new_temp()
        t2 = func.new_temp(IRType.I32)

        assert t0.name == "t0"
        assert t1.name == "t1"
        assert t2.name == "t2"
        assert t2.ir_type == IRType.I32


class TestIRSimplifier:
    """Tests for IR simplification."""

    def _make_function(self, instructions: list[IRInstruction]) -> IRFunction:
        """Helper to create a function with a single block."""
        func = IRFunction(name="test")
        block = IRBasicBlock(label="entry")
        for insn in instructions:
            block.append(insn)
        # Add a return using the result to prevent DCE from removing it
        if instructions and instructions[-1].dest:
            block.append(IRInstruction(IROpcode.RETURN, operands=[instructions[-1].dest]))
        func.add_block(block)
        return func

    def test_constant_folding_add(self):
        """Test constant folding for addition."""
        # t0 = 5 + 3 -> t0 = 8, then copy propagation puts 8 in return
        func = self._make_function(
            [
                IRInstruction(
                    IROpcode.ADD,
                    dest=IRValue.temp(0),
                    operands=[IRValue.constant(5), IRValue.constant(3)],
                )
            ]
        )

        simplifier = IRSimplifier(func)
        result = simplifier.simplify()

        block = result.get_block("entry")
        assert block is not None
        # After full simplification, the return should have the constant
        ret_insn = block.instructions[-1]
        assert ret_insn.opcode == IROpcode.RETURN
        assert ret_insn.operands[0].const_value == 8

    def test_algebraic_add_zero(self):
        """Test algebraic simplification: x + 0 = x."""
        x = IRValue.var("x")
        func = self._make_function(
            [
                IRInstruction(
                    IROpcode.ADD,
                    dest=IRValue.temp(0),
                    operands=[x, IRValue.constant(0)],
                )
            ]
        )

        simplifier = IRSimplifier(func)
        result = simplifier.simplify()

        block = result.get_block("entry")
        assert block is not None
        # After simplification, return should have x
        ret_insn = block.instructions[-1]
        assert ret_insn.opcode == IROpcode.RETURN
        assert ret_insn.operands[0] == x

    def test_algebraic_sub_self(self):
        """Test algebraic simplification: x - x = 0."""
        x = IRValue.var("x")
        func = self._make_function(
            [
                IRInstruction(
                    IROpcode.SUB,
                    dest=IRValue.temp(0),
                    operands=[x, x],
                )
            ]
        )

        simplifier = IRSimplifier(func)
        result = simplifier.simplify()

        block = result.get_block("entry")
        assert block is not None
        # After simplification, return should have 0
        ret_insn = block.instructions[-1]
        assert ret_insn.opcode == IROpcode.RETURN
        assert ret_insn.operands[0].const_value == 0

    def test_algebraic_mul_one(self):
        """Test algebraic simplification: x * 1 = x."""
        x = IRValue.var("x")
        func = self._make_function(
            [
                IRInstruction(
                    IROpcode.MUL,
                    dest=IRValue.temp(0),
                    operands=[x, IRValue.constant(1)],
                )
            ]
        )

        simplifier = IRSimplifier(func)
        result = simplifier.simplify()

        block = result.get_block("entry")
        assert block is not None
        # After simplification, return should have x
        ret_insn = block.instructions[-1]
        assert ret_insn.opcode == IROpcode.RETURN
        assert ret_insn.operands[0] == x

    def test_strength_reduction_mul_power_of_two(self):
        """Test strength reduction: x * 8 = x << 3."""
        x = IRValue.var("x")
        func = self._make_function(
            [
                IRInstruction(
                    IROpcode.MUL,
                    dest=IRValue.temp(0),
                    operands=[x, IRValue.constant(8)],
                )
            ]
        )

        simplifier = IRSimplifier(func)
        result = simplifier.simplify()

        block = result.get_block("entry")
        assert block is not None
        # After simplification, we should have: shift instruction then return
        # Check that there's a shift instruction somewhere
        has_shift = any(insn.opcode == IROpcode.SHL for insn in block.instructions)
        assert has_shift, "Expected shift instruction after strength reduction"
