"""Tests for the ARM64 disassembler."""

import pytest

from chimera.arch.arm64.decoder import ARM64Disassembler
from chimera.arch.arm64.registers import Registers
from chimera.arch.arm64.instructions import InstructionGroup


class TestARM64Disassembler:
    """Tests for ARM64 disassembler."""

    @pytest.fixture
    def disasm(self):
        """Create disassembler instance."""
        return ARM64Disassembler()

    def test_disassemble_mov(self, disasm):
        """Test disassembling MOV instruction."""
        # mov x0, #0 -> D2800000
        data = bytes([0x00, 0x00, 0x80, 0xD2])
        insn = disasm.disassemble_one(data, 0x100000)

        assert insn is not None
        assert insn.mnemonic == "mov"
        assert insn.address == 0x100000
        assert insn.size == 4

    def test_disassemble_add(self, disasm):
        """Test disassembling ADD instruction."""
        # add x0, x1, x2 -> 8B020020
        data = bytes([0x20, 0x00, 0x02, 0x8B])
        insn = disasm.disassemble_one(data, 0x100000)

        assert insn is not None
        assert insn.mnemonic == "add"
        assert InstructionGroup.ARITHMETIC in insn.groups

    def test_disassemble_bl(self, disasm):
        """Test disassembling BL (call) instruction."""
        # bl #0x100 -> 94000040
        data = bytes([0x40, 0x00, 0x00, 0x94])
        insn = disasm.disassemble_one(data, 0x100000)

        assert insn is not None
        assert insn.mnemonic == "bl"
        assert insn.is_call
        assert InstructionGroup.CALL in insn.groups

    def test_disassemble_ret(self, disasm):
        """Test disassembling RET instruction."""
        # ret -> D65F03C0
        data = bytes([0xC0, 0x03, 0x5F, 0xD6])
        insn = disasm.disassemble_one(data, 0x100000)

        assert insn is not None
        assert insn.mnemonic == "ret"
        assert insn.is_return
        assert not insn.falls_through

    def test_disassemble_conditional_branch(self, disasm):
        """Test disassembling conditional branch."""
        # b.eq #0x10 -> 54000080
        data = bytes([0x80, 0x00, 0x00, 0x54])
        insn = disasm.disassemble_one(data, 0x100000)

        assert insn is not None
        assert insn.mnemonic.startswith("b.")
        assert insn.is_conditional_branch
        assert insn.falls_through

    def test_disassemble_ldr(self, disasm):
        """Test disassembling LDR instruction."""
        # ldr x0, [x1] -> F9400020
        data = bytes([0x20, 0x00, 0x40, 0xF9])
        insn = disasm.disassemble_one(data, 0x100000)

        assert insn is not None
        assert insn.mnemonic == "ldr"
        assert insn.is_load
        assert InstructionGroup.LOAD in insn.groups

    def test_disassemble_str(self, disasm):
        """Test disassembling STR instruction."""
        # str x0, [x1] -> F9000020
        data = bytes([0x20, 0x00, 0x00, 0xF9])
        insn = disasm.disassemble_one(data, 0x100000)

        assert insn is not None
        assert insn.mnemonic == "str"
        assert insn.is_store
        assert InstructionGroup.STORE in insn.groups

    def test_disassemble_multiple(self, disasm):
        """Test disassembling multiple instructions."""
        # mov x0, #0; mov x1, #1; ret
        data = bytes(
            [
                0x00,
                0x00,
                0x80,
                0xD2,  # mov x0, #0
                0x21,
                0x00,
                0x80,
                0xD2,  # mov x1, #1
                0xC0,
                0x03,
                0x5F,
                0xD6,  # ret
            ]
        )

        instructions = list(disasm.disassemble(data, 0x100000))

        assert len(instructions) == 3
        assert instructions[0].mnemonic == "mov"
        assert instructions[1].mnemonic == "mov"
        assert instructions[2].mnemonic == "ret"

    def test_instruction_next_address(self, disasm):
        """Test next_address property."""
        data = bytes([0x00, 0x00, 0x80, 0xD2])
        insn = disasm.disassemble_one(data, 0x100000)

        assert insn is not None
        assert insn.next_address == 0x100004


class TestRegisters:
    """Tests for register model."""

    def test_register_from_name(self):
        """Test looking up register by name."""
        x0 = Registers.from_name("x0")
        assert x0 is not None
        assert x0.index == 0
        assert x0.is_64bit

        w0 = Registers.from_name("w0")
        assert w0 is not None
        assert w0.index == 0
        assert w0.is_32bit

    def test_special_registers(self):
        """Test special register properties."""
        assert Registers.SP.is_sp
        assert Registers.XZR.is_zero
        assert Registers.FP.is_general

    def test_register_case_insensitive(self):
        """Test case-insensitive lookup."""
        assert Registers.from_name("X0") == Registers.from_name("x0")
        assert Registers.from_name("SP") == Registers.from_name("sp")
