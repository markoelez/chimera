"""Control flow structuring for decompilation."""

from enum import IntEnum, auto
from typing import Any
from dataclasses import field, dataclass

from chimera.decompiler.ir import (
    IRValue,
    IROpcode,
    IRFunction,
    IRBasicBlock,
    IRInstruction,
)


class StructureType(IntEnum):
    """Type of control flow structure."""

    SEQUENCE = auto()
    IF_THEN = auto()
    IF_THEN_ELSE = auto()
    WHILE_LOOP = auto()
    DO_WHILE_LOOP = auto()
    FOR_LOOP = auto()
    SWITCH = auto()
    GOTO = auto()


@dataclass
class StructuredBlock:
    """A structured control flow region."""

    structure_type: StructureType
    condition: IRValue | None = None
    children: list["StructuredBlock"] = field(default_factory=list)
    statements: list[IRInstruction] = field(default_factory=list)
    source_block: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"StructuredBlock({self.structure_type.name}, {len(self.children)} children)"


class ControlFlowStructurer:
    """Recovers high-level control flow structures from IR."""

    def __init__(self, func: IRFunction) -> None:
        self.func = func
        self._visited: set[str] = set()
        self._loop_headers: set[str] = set()
        self._loop_exits: dict[str, str] = {}

    def structure(self) -> StructuredBlock:
        """Structure the function's control flow."""
        # Find loops first
        self._find_loops()

        # Structure starting from entry
        entry = self.func.get_block(self.func.entry_block)
        if not entry:
            return StructuredBlock(StructureType.SEQUENCE)

        return self._structure_region(entry.label, set())

    def _find_loops(self) -> None:
        """Identify natural loops in the CFG."""
        # Find back edges (edges from a node to a dominator)
        # Simplified: look for edges where target comes before source

        visited_order: list[str] = []
        visited: set[str] = set()

        def dfs(label: str) -> None:
            if label in visited:
                return
            visited.add(label)
            visited_order.append(label)

            block = self.func.get_block(label)
            if block:
                for succ in block.successors:
                    dfs(succ)

        if self.func.entry_block:
            dfs(self.func.entry_block)

        order_map = {label: i for i, label in enumerate(visited_order)}

        # Find back edges
        for block in self.func:
            for succ in block.successors:
                if succ in order_map and order_map[succ] <= order_map.get(
                    block.label, float("inf")
                ):
                    # Back edge found: succ is loop header
                    self._loop_headers.add(succ)
                    self._loop_exits[succ] = block.label

    def _structure_region(self, start: str, stop_at: set[str]) -> StructuredBlock:
        """Structure a region of the CFG."""
        if start in self._visited:
            # Already processed or loop
            return StructuredBlock(
                StructureType.GOTO,
                metadata={"target": start},
            )

        self._visited.add(start)
        block = self.func.get_block(start)

        if not block:
            return StructuredBlock(StructureType.SEQUENCE)

        # Check if this is a loop header
        if start in self._loop_headers:
            return self._structure_loop(block, stop_at)

        # Get non-terminator statements
        statements = [i for i in block.instructions if not i.is_terminator]
        terminator = block.terminator

        if not terminator:
            # No terminator, just statements
            return StructuredBlock(
                StructureType.SEQUENCE,
                statements=statements,
                source_block=start,
            )

        if terminator.opcode == IROpcode.RETURN:
            # Return statement
            result = StructuredBlock(
                StructureType.SEQUENCE,
                statements=statements + [terminator],
                source_block=start,
            )
            return result

        if terminator.opcode == IROpcode.JUMP:
            # Unconditional jump
            target = block.successors[0] if block.successors else None
            if target and target not in stop_at:
                child = self._structure_region(target, stop_at)
                return StructuredBlock(
                    StructureType.SEQUENCE,
                    statements=statements,
                    children=[child],
                    source_block=start,
                )
            else:
                return StructuredBlock(
                    StructureType.SEQUENCE,
                    statements=statements,
                    source_block=start,
                )

        if terminator.opcode == IROpcode.BRANCH:
            # Conditional branch - structure as if-then-else
            return self._structure_conditional(block, statements, stop_at)

        if terminator.opcode == IROpcode.SWITCH:
            # Multi-way branch - structure as switch
            return self._structure_switch(block, statements, stop_at)

        # Default: sequence
        return StructuredBlock(
            StructureType.SEQUENCE,
            statements=statements,
            source_block=start,
        )

    def _structure_conditional(
        self,
        block: IRBasicBlock,
        statements: list[IRInstruction],
        stop_at: set[str],
    ) -> StructuredBlock:
        """Structure a conditional (if-then-else)."""
        terminator = block.terminator
        if not terminator or len(terminator.operands) < 3:
            return StructuredBlock(
                StructureType.SEQUENCE,
                statements=statements,
                source_block=block.label,
            )

        condition = terminator.operands[0]

        # Get true and false targets
        true_target = block.successors[0] if block.successors else None
        false_target = block.successors[1] if len(block.successors) > 1 else None

        # Find merge point (common successor)
        merge_point = self._find_merge_point(true_target, false_target)

        new_stop = stop_at | ({merge_point} if merge_point else set())

        # Structure branches
        children: list[StructuredBlock] = []

        if true_target and true_target not in stop_at:
            true_block = self._structure_region(true_target, new_stop)
            children.append(true_block)

        if false_target and false_target not in stop_at and false_target != merge_point:
            false_block = self._structure_region(false_target, new_stop)
            children.append(false_block)

        # Determine structure type
        if len(children) == 2:
            struct_type = StructureType.IF_THEN_ELSE
        elif len(children) == 1:
            struct_type = StructureType.IF_THEN
        else:
            struct_type = StructureType.SEQUENCE

        result = StructuredBlock(
            struct_type,
            condition=condition,
            statements=statements,
            children=children,
            source_block=block.label,
        )

        # Continue after merge point
        if merge_point and merge_point not in stop_at:
            continuation = self._structure_region(merge_point, stop_at)
            return StructuredBlock(
                StructureType.SEQUENCE,
                children=[result, continuation],
            )

        return result

    def _structure_loop(self, header: IRBasicBlock, stop_at: set[str]) -> StructuredBlock:
        """Structure a loop."""
        # Find loop exit
        exit_block = None
        for succ in header.successors:
            if succ not in self._loop_headers:
                # Potential exit
                exit_block = succ

        # Get condition from header
        terminator = header.terminator
        condition = None
        if terminator and terminator.opcode == IROpcode.BRANCH:
            if terminator.operands:
                condition = terminator.operands[0]

        # Structure loop body
        body_children: list[StructuredBlock] = []
        statements = [i for i in header.instructions if not i.is_terminator]

        # Mark loop header as stop point for body
        loop_stop = stop_at | {header.label}
        if exit_block:
            loop_stop.add(exit_block)

        # Find body start (successor that's not exit)
        body_start = None
        for succ in header.successors:
            if succ != exit_block:
                body_start = succ
                break

        if body_start and body_start != header.label:
            body = self._structure_region(body_start, loop_stop)
            body_children.append(body)

        loop_block = StructuredBlock(
            StructureType.WHILE_LOOP,
            condition=condition,
            statements=statements,
            children=body_children,
            source_block=header.label,
        )

        # Continue after loop
        if exit_block and exit_block not in stop_at:
            self._visited.discard(exit_block)  # Allow visiting exit
            continuation = self._structure_region(exit_block, stop_at)
            return StructuredBlock(
                StructureType.SEQUENCE,
                children=[loop_block, continuation],
            )

        return loop_block

    def _structure_switch(
        self,
        block: IRBasicBlock,
        statements: list[IRInstruction],
        stop_at: set[str],
    ) -> StructuredBlock:
        """Structure a switch statement."""
        terminator = block.terminator
        if not terminator:
            return StructuredBlock(
                StructureType.SEQUENCE,
                statements=statements,
                source_block=block.label,
            )

        # Get switch index value
        index_val = terminator.operands[0] if terminator.operands else None

        # Get case information from metadata
        cases = terminator.metadata.get("cases", [])
        default_addr = terminator.metadata.get("default")

        # Find merge point (common successor of all cases)
        merge_point = self._find_switch_merge(block.successors)
        new_stop = stop_at | ({merge_point} if merge_point else set())

        # Structure each case
        case_blocks: list[StructuredBlock] = []
        seen_targets: set[str] = set()

        for case_info in cases:
            target_addr = case_info.get("target", 0)
            case_value = case_info.get("value", 0)
            target_label = f"bb_{target_addr:x}"

            # Skip duplicate targets (fall-through cases)
            if target_label in seen_targets:
                continue
            seen_targets.add(target_label)

            if target_label not in stop_at and target_label != merge_point:
                case_body = self._structure_region(target_label, new_stop)
                case_block = StructuredBlock(
                    StructureType.SEQUENCE,
                    children=[case_body],
                    metadata={"case_value": case_value},
                )
                case_blocks.append(case_block)

        # Add default case if present
        if default_addr:
            default_label = f"bb_{default_addr:x}"
            if default_label not in seen_targets and default_label not in stop_at:
                default_body = self._structure_region(default_label, new_stop)
                default_block = StructuredBlock(
                    StructureType.SEQUENCE,
                    children=[default_body],
                    metadata={"is_default": True},
                )
                case_blocks.append(default_block)

        switch_block = StructuredBlock(
            StructureType.SWITCH,
            condition=index_val,
            statements=statements,
            children=case_blocks,
            source_block=block.label,
            metadata={
                "cases": cases,
                "default": default_addr,
            },
        )

        # Continue after merge point
        if merge_point and merge_point not in stop_at:
            self._visited.discard(merge_point)
            continuation = self._structure_region(merge_point, stop_at)
            return StructuredBlock(
                StructureType.SEQUENCE,
                children=[switch_block, continuation],
            )

        return switch_block

    def _find_switch_merge(self, successors: list[str]) -> str | None:
        """Find common merge point for switch cases."""
        if len(successors) < 2:
            return None

        # Get reachable blocks from each case
        reachable_sets: list[set[str]] = []
        for succ in successors:
            reachable_sets.append(self._get_reachable(succ))

        if not reachable_sets:
            return None

        # Find common blocks across all cases
        common = reachable_sets[0].copy()
        for rs in reachable_sets[1:]:
            common &= rs

        if not common:
            return None

        # Return the first common block
        for label in reachable_sets[0]:
            if label in common:
                return label

        return None

    def _find_merge_point(self, branch1: str | None, branch2: str | None) -> str | None:
        """Find common merge point of two branches."""
        if not branch1 or not branch2:
            return None

        # Get reachable blocks from each branch
        reachable1 = self._get_reachable(branch1)
        reachable2 = self._get_reachable(branch2)

        # Find common blocks
        common = reachable1 & reachable2

        if not common:
            return None

        # Return the first common block (closest to branches)
        for label in reachable1:
            if label in common:
                return label

        return None

    def _get_reachable(self, start: str, limit: int = 10) -> set[str]:
        """Get blocks reachable from start (limited depth)."""
        reachable: set[str] = set()
        worklist = [start]
        depth = 0

        while worklist and depth < limit:
            next_worklist: list[str] = []
            for label in worklist:
                if label in reachable:
                    continue
                reachable.add(label)
                block = self.func.get_block(label)
                if block:
                    next_worklist.extend(block.successors)
            worklist = next_worklist
            depth += 1

        return reachable
