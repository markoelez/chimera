"""Control flow graph construction and analysis."""

from enum import IntEnum, auto
from typing import TYPE_CHECKING
from dataclasses import field, dataclass
from collections.abc import Iterator

from chimera.arch.arm64.instructions import ARM64Instruction

if TYPE_CHECKING:
    from chimera.arch.arm64.decoder import ARM64Disassembler


class EdgeType(IntEnum):
    """Type of CFG edge."""

    FALL_THROUGH = auto()  # Sequential execution
    UNCONDITIONAL = auto()  # Unconditional branch
    CONDITIONAL_TRUE = auto()  # Conditional branch taken
    CONDITIONAL_FALSE = auto()  # Conditional branch not taken
    CALL = auto()  # Function call
    RETURN = auto()  # Function return


@dataclass
class CFGEdge:
    """Edge in the control flow graph."""

    source: int  # Source basic block address
    target: int  # Target basic block address
    edge_type: EdgeType


@dataclass
class BasicBlock:
    """A basic block in the control flow graph."""

    address: int
    instructions: list[ARM64Instruction] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)

    @property
    def size(self) -> int:
        """Total size of instructions in block."""
        return sum(insn.size for insn in self.instructions)

    @property
    def end_address(self) -> int:
        """Address after last instruction."""
        if self.instructions:
            last = self.instructions[-1]
            return last.address + last.size
        return self.address

    @property
    def last_instruction(self) -> ARM64Instruction | None:
        """Get the terminating instruction."""
        return self.instructions[-1] if self.instructions else None

    @property
    def is_entry(self) -> bool:
        """Is this an entry block (no predecessors)?"""
        return len(self.predecessors) == 0

    @property
    def is_exit(self) -> bool:
        """Is this an exit block (no successors)?"""
        return len(self.successors) == 0

    def __repr__(self) -> str:
        return f"BasicBlock({self.address:#x}, {len(self.instructions)} insns)"

    def __iter__(self) -> Iterator[ARM64Instruction]:
        return iter(self.instructions)


class ControlFlowGraph:
    """Control flow graph for a function or code region."""

    def __init__(self, entry_address: int) -> None:
        self.entry_address = entry_address
        self.blocks: dict[int, BasicBlock] = {}
        self.edges: list[CFGEdge] = []

    def add_block(self, block: BasicBlock) -> None:
        """Add a basic block to the CFG."""
        self.blocks[block.address] = block

    def get_block(self, address: int) -> BasicBlock | None:
        """Get block by start address."""
        return self.blocks.get(address)

    def add_edge(self, source: int, target: int, edge_type: EdgeType) -> None:
        """Add an edge between blocks."""
        self.edges.append(CFGEdge(source, target, edge_type))

        # Update block adjacency lists
        src_block = self.blocks.get(source)
        if src_block and target not in src_block.successors:
            src_block.successors.append(target)

        tgt_block = self.blocks.get(target)
        if tgt_block and source not in tgt_block.predecessors:
            tgt_block.predecessors.append(source)

    @property
    def entry_block(self) -> BasicBlock | None:
        """Get the entry basic block."""
        return self.blocks.get(self.entry_address)

    def __iter__(self) -> Iterator[BasicBlock]:
        """Iterate blocks in address order."""
        for addr in sorted(self.blocks.keys()):
            yield self.blocks[addr]

    def __len__(self) -> int:
        return len(self.blocks)

    def successors(self, address: int) -> list[BasicBlock]:
        """Get successor blocks."""
        block = self.blocks.get(address)
        if not block:
            return []
        return [self.blocks[addr] for addr in block.successors if addr in self.blocks]

    def predecessors(self, address: int) -> list[BasicBlock]:
        """Get predecessor blocks."""
        block = self.blocks.get(address)
        if not block:
            return []
        return [self.blocks[addr] for addr in block.predecessors if addr in self.blocks]

    def postorder(self) -> list[BasicBlock]:
        """Return blocks in postorder traversal."""
        visited: set[int] = set()
        result: list[BasicBlock] = []

        def visit(addr: int) -> None:
            if addr in visited or addr not in self.blocks:
                return
            visited.add(addr)
            block = self.blocks[addr]
            for succ in block.successors:
                visit(succ)
            result.append(block)

        visit(self.entry_address)
        return result

    def reverse_postorder(self) -> list[BasicBlock]:
        """Return blocks in reverse postorder (good for forward analysis)."""
        return list(reversed(self.postorder()))

    def dominators(self) -> dict[int, set[int]]:
        """Compute dominator sets for all blocks."""
        all_blocks = set(self.blocks.keys())
        dom: dict[int, set[int]] = {}

        # Initialize
        dom[self.entry_address] = {self.entry_address}
        for addr in self.blocks:
            if addr != self.entry_address:
                dom[addr] = all_blocks.copy()

        # Iterate until fixed point
        changed = True
        while changed:
            changed = False
            for addr in self.blocks:
                if addr == self.entry_address:
                    continue
                block = self.blocks[addr]
                if block.predecessors:
                    new_dom = set.intersection(*[dom[p] for p in block.predecessors if p in dom])
                    new_dom.add(addr)
                    if new_dom != dom[addr]:
                        dom[addr] = new_dom
                        changed = True

        return dom


class CFGBuilder:
    """Builds control flow graphs from disassembled code."""

    def __init__(self, disassembler: "ARM64Disassembler") -> None:
        from chimera.arch.arm64.decoder import ARM64Disassembler  # noqa: F811

        self.disasm: ARM64Disassembler = disassembler

    def build(
        self, data: bytes, start_address: int, end_address: int | None = None
    ) -> ControlFlowGraph:
        """Build CFG from binary data."""
        if end_address is None:
            end_address = start_address + len(data)

        cfg = ControlFlowGraph(start_address)

        # First pass: identify all leader addresses
        leaders = self._find_leaders(data, start_address, end_address)

        # Second pass: build basic blocks
        self._build_blocks(cfg, data, start_address, end_address, leaders)

        # Third pass: add edges
        self._add_edges(cfg)

        return cfg

    def _find_leaders(self, data: bytes, start: int, end: int) -> set[int]:
        """Find all basic block leader addresses."""
        leaders: set[int] = {start}  # Entry is always a leader

        offset = 0
        addr = start
        while addr < end and offset < len(data):
            insn = self.disasm.disassemble_one(data[offset:], addr)
            if insn is None:
                addr += 4
                offset += 4
                continue

            # After a branch, the next instruction is a leader
            if insn.is_terminator and insn.falls_through:
                leaders.add(insn.next_address)

            # Branch targets are leaders
            if insn.branch_target is not None:
                if start <= insn.branch_target < end:
                    leaders.add(insn.branch_target)

            addr += insn.size
            offset += insn.size

        return leaders

    def _build_blocks(
        self,
        cfg: ControlFlowGraph,
        data: bytes,
        start: int,
        end: int,
        leaders: set[int],
    ) -> None:
        """Build basic blocks from leaders."""
        current_block: BasicBlock | None = None
        offset = 0
        addr = start

        while addr < end and offset < len(data):
            # Check if we're at a leader
            if addr in leaders:
                if current_block is not None:
                    cfg.add_block(current_block)
                current_block = BasicBlock(address=addr)

            if current_block is None:
                current_block = BasicBlock(address=addr)

            insn = self.disasm.disassemble_one(data[offset:], addr)
            if insn is None:
                addr += 4
                offset += 4
                continue

            current_block.instructions.append(insn)

            # End block at terminators or before next leader
            next_addr = addr + insn.size
            if insn.is_terminator or next_addr in leaders:
                cfg.add_block(current_block)
                current_block = None

            addr = next_addr
            offset = next_addr - start

        # Add final block
        if current_block is not None and current_block.instructions:
            cfg.add_block(current_block)

    def _add_edges(self, cfg: ControlFlowGraph) -> None:
        """Add edges between basic blocks."""
        for block in cfg:
            last = block.last_instruction
            if last is None:
                continue

            # Fall-through edge
            if last.falls_through:
                next_addr = last.next_address
                if next_addr in cfg.blocks:
                    if last.is_conditional_branch:
                        cfg.add_edge(block.address, next_addr, EdgeType.CONDITIONAL_FALSE)
                    else:
                        cfg.add_edge(block.address, next_addr, EdgeType.FALL_THROUGH)

            # Branch edge
            if last.branch_target is not None:
                target = last.branch_target
                if target in cfg.blocks:
                    if last.is_call:
                        cfg.add_edge(block.address, target, EdgeType.CALL)
                    elif last.is_unconditional_branch:
                        cfg.add_edge(block.address, target, EdgeType.UNCONDITIONAL)
                    elif last.is_conditional_branch:
                        cfg.add_edge(block.address, target, EdgeType.CONDITIONAL_TRUE)
