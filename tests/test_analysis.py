"""Tests for the analysis module."""

from chimera.analysis.cfg import EdgeType, BasicBlock, ControlFlowGraph
from chimera.analysis.xrefs import XRefType, XRefManager
from chimera.arch.arm64.decoder import ARM64Disassembler


class TestBasicBlock:
    """Tests for BasicBlock class."""

    def test_empty_block(self):
        """Test empty basic block."""
        block = BasicBlock(address=0x100000)

        assert block.address == 0x100000
        assert block.size == 0
        assert block.end_address == 0x100000
        assert block.last_instruction is None
        assert block.is_entry
        assert block.is_exit

    def test_block_with_instructions(self):
        """Test basic block with instructions."""
        disasm = ARM64Disassembler()

        # mov x0, #0; ret
        data = bytes(
            [
                0x00,
                0x00,
                0x80,
                0xD2,  # mov x0, #0
                0xC0,
                0x03,
                0x5F,
                0xD6,  # ret
            ]
        )

        block = BasicBlock(address=0x100000)
        for insn in disasm.disassemble(data, 0x100000):
            block.instructions.append(insn)

        assert block.size == 8
        assert block.end_address == 0x100008
        assert block.last_instruction is not None
        assert block.last_instruction.mnemonic == "ret"


class TestControlFlowGraph:
    """Tests for ControlFlowGraph class."""

    def test_empty_cfg(self):
        """Test empty CFG."""
        cfg = ControlFlowGraph(entry_address=0x100000)

        assert cfg.entry_address == 0x100000
        assert len(cfg) == 0
        assert cfg.entry_block is None

    def test_add_block(self):
        """Test adding blocks to CFG."""
        cfg = ControlFlowGraph(entry_address=0x100000)

        block1 = BasicBlock(address=0x100000)
        block2 = BasicBlock(address=0x100010)

        cfg.add_block(block1)
        cfg.add_block(block2)

        assert len(cfg) == 2
        assert cfg.entry_block == block1
        assert cfg.get_block(0x100010) == block2

    def test_add_edge(self):
        """Test adding edges between blocks."""
        cfg = ControlFlowGraph(entry_address=0x100000)

        block1 = BasicBlock(address=0x100000)
        block2 = BasicBlock(address=0x100010)

        cfg.add_block(block1)
        cfg.add_block(block2)
        cfg.add_edge(0x100000, 0x100010, EdgeType.FALL_THROUGH)

        assert 0x100010 in block1.successors
        assert 0x100000 in block2.predecessors

    def test_successors_predecessors(self):
        """Test successor and predecessor lookup."""
        cfg = ControlFlowGraph(entry_address=0x100000)

        block1 = BasicBlock(address=0x100000)
        block2 = BasicBlock(address=0x100010)
        block3 = BasicBlock(address=0x100020)

        cfg.add_block(block1)
        cfg.add_block(block2)
        cfg.add_block(block3)

        cfg.add_edge(0x100000, 0x100010, EdgeType.CONDITIONAL_TRUE)
        cfg.add_edge(0x100000, 0x100020, EdgeType.CONDITIONAL_FALSE)

        successors = cfg.successors(0x100000)
        assert len(successors) == 2

        predecessors = cfg.predecessors(0x100010)
        assert len(predecessors) == 1
        assert predecessors[0] == block1


class TestXRefManager:
    """Tests for cross-reference manager."""

    def test_add_xref(self):
        """Test adding cross-references."""
        mgr = XRefManager()

        xref = mgr.add_xref(0x1000, 0x2000, XRefType.CALL)

        assert xref.from_addr == 0x1000
        assert xref.to_addr == 0x2000
        assert xref.xref_type == XRefType.CALL

    def test_xrefs_to(self):
        """Test getting xrefs TO an address."""
        mgr = XRefManager()

        mgr.add_xref(0x1000, 0x3000, XRefType.CALL)
        mgr.add_xref(0x2000, 0x3000, XRefType.CALL)
        mgr.add_xref(0x1000, 0x4000, XRefType.JUMP)

        xrefs = mgr.xrefs_to(0x3000)

        assert len(xrefs) == 2
        from_addrs = {x.from_addr for x in xrefs}
        assert from_addrs == {0x1000, 0x2000}

    def test_xrefs_from(self):
        """Test getting xrefs FROM an address."""
        mgr = XRefManager()

        mgr.add_xref(0x1000, 0x2000, XRefType.CALL)
        mgr.add_xref(0x1000, 0x3000, XRefType.JUMP)
        mgr.add_xref(0x2000, 0x4000, XRefType.CALL)

        xrefs = mgr.xrefs_from(0x1000)

        assert len(xrefs) == 2
        to_addrs = {x.to_addr for x in xrefs}
        assert to_addrs == {0x2000, 0x3000}

    def test_callers(self):
        """Test getting callers to a function."""
        mgr = XRefManager()

        mgr.add_xref(0x1000, 0x5000, XRefType.CALL)
        mgr.add_xref(0x2000, 0x5000, XRefType.CALL)
        mgr.add_xref(0x3000, 0x5000, XRefType.JUMP)  # Not a call

        callers = mgr.callers(0x5000)

        assert len(callers) == 2
        assert set(callers) == {0x1000, 0x2000}

    def test_callees(self):
        """Test getting callees from a function."""
        mgr = XRefManager()

        mgr.add_xref(0x1000, 0x5000, XRefType.CALL)
        mgr.add_xref(0x1000, 0x6000, XRefType.CALL)
        mgr.add_xref(0x1000, 0x7000, XRefType.DATA_READ)  # Not a call

        callees = mgr.callees(0x1000)

        assert len(callees) == 2
        assert set(callees) == {0x5000, 0x6000}
