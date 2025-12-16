"""SSA (Static Single Assignment) transformation."""

from typing import TYPE_CHECKING
from dataclasses import field, dataclass

from chimera.decompiler.ir import (
    IRValue,
    IROpcode,
    IRFunction,
    IRBasicBlock,
    IRInstruction,
)

if TYPE_CHECKING:
    pass


@dataclass
class SSAContext:
    """Context for SSA transformation."""

    # Current version of each variable
    current_version: dict[str, int] = field(default_factory=dict)
    # Stack of versions for each variable
    version_stack: dict[str, list[int]] = field(default_factory=lambda: {})
    # Phi nodes needed at each block
    phi_nodes: dict[str, dict[str, list[str]]] = field(default_factory=dict)


class SSATransformer:
    """Transforms IR to SSA form."""

    def __init__(self, func: IRFunction) -> None:
        self.func = func
        self.ctx = SSAContext()
        self._dominance_frontier: dict[str, set[str]] = {}

    def transform(self) -> IRFunction:
        """Transform function to SSA form."""
        # Compute dominance frontiers
        self._compute_dominance_frontiers()

        # Insert phi nodes
        self._insert_phi_nodes()

        # Rename variables
        self._rename_variables()

        return self.func

    def _compute_dominance_frontiers(self) -> None:
        """Compute dominance frontier for each block."""
        # Simplified: compute immediate dominators and frontiers
        # For now, use a basic approximation

        for block in self.func:
            self._dominance_frontier[block.label] = set()

        # For each edge (a, b), if a doesn't strictly dominate b,
        # then b is in the dominance frontier of a
        for block in self.func:
            if len(block.predecessors) >= 2:
                for pred in block.predecessors:
                    runner = pred
                    # Walk up dominator tree
                    while runner != block.label:
                        self._dominance_frontier.setdefault(runner, set()).add(block.label)
                        break  # Simplified

    def _insert_phi_nodes(self) -> None:
        """Insert phi nodes where needed."""
        # Find all variables defined in each block
        def_sites: dict[str, set[str]] = {}  # var -> blocks where defined

        for block in self.func:
            for insn in block.instructions:
                if insn.dest and insn.dest.name:
                    var = insn.dest.name
                    if var not in def_sites:
                        def_sites[var] = set()
                    def_sites[var].add(block.label)

        # For each variable, insert phi nodes at dominance frontier
        for var, blocks in def_sites.items():
            worklist = list(blocks)
            processed: set[str] = set()

            while worklist:
                block_label = worklist.pop()
                for frontier_block in self._dominance_frontier.get(block_label, []):
                    if frontier_block not in processed:
                        processed.add(frontier_block)
                        # Add phi node
                        block = self.func.get_block(frontier_block)
                        if block:
                            phi = IRInstruction(
                                IROpcode.PHI,
                                dest=IRValue.var(var),
                                operands=[],
                            )
                            # Insert at beginning
                            block.instructions.insert(0, phi)
                        worklist.append(frontier_block)

    def _rename_variables(self) -> None:
        """Rename variables for SSA."""
        # Initialize version counters
        for block in self.func:
            for insn in block.instructions:
                if insn.dest and insn.dest.name:
                    self.ctx.current_version[insn.dest.name] = 0
                    self.ctx.version_stack[insn.dest.name] = [0]
                for op in insn.operands:
                    if not op.is_const and op.name:
                        self.ctx.current_version.setdefault(op.name, 0)
                        self.ctx.version_stack.setdefault(op.name, [0])

        # Rename starting from entry block
        entry = self.func.get_block(self.func.entry_block)
        if entry:
            self._rename_block(entry)

    def _rename_block(self, block: IRBasicBlock) -> None:
        """Rename variables in a block."""
        # Track versions pushed in this block
        pushed: dict[str, int] = {}

        for insn in block.instructions:
            # Rename uses (except for phi nodes, they're handled separately)
            if insn.opcode != IROpcode.PHI:
                new_operands: list[IRValue] = []
                for op in insn.operands:
                    if not op.is_const and op.name:
                        stack = self.ctx.version_stack.get(op.name, [0])
                        version = stack[-1] if stack else 0
                        new_op = IRValue(
                            ir_type=op.ir_type,
                            name=op.name,
                            version=version,
                        )
                        new_operands.append(new_op)
                    else:
                        new_operands.append(op)
                insn.operands = new_operands

            # Rename definition
            if insn.dest and insn.dest.name:
                var = insn.dest.name
                version = self.ctx.current_version.get(var, 0) + 1
                self.ctx.current_version[var] = version
                self.ctx.version_stack.setdefault(var, []).append(version)
                pushed[var] = pushed.get(var, 0) + 1
                insn.dest = IRValue(
                    ir_type=insn.dest.ir_type,
                    name=var,
                    version=version,
                )

        # Fill in phi operands for successors
        for succ_label in block.successors:
            succ = self.func.get_block(succ_label)
            if succ:
                for insn in succ.instructions:
                    if insn.opcode == IROpcode.PHI and insn.dest:
                        var = insn.dest.name
                        stack = self.ctx.version_stack.get(var, [0])
                        version = stack[-1] if stack else 0
                        insn.operands.append(
                            IRValue(
                                ir_type=insn.dest.ir_type,
                                name=var,
                                version=version,
                            )
                        )

        # Recurse to dominated blocks (simplified: just successors)
        for succ_label in block.successors:
            succ = self.func.get_block(succ_label)
            if succ:
                self._rename_block(succ)

        # Pop versions
        for var, count in pushed.items():
            for _ in range(count):
                self.ctx.version_stack[var].pop()
