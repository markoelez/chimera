"""Switch table detection and analysis for ARM64 binaries."""

import struct
from typing import TYPE_CHECKING
from dataclasses import field, dataclass

if TYPE_CHECKING:
    from chimera.analysis.cfg import BasicBlock, ControlFlowGraph
    from chimera.loader.macho import MachOBinary


@dataclass
class SwitchCase:
    """Represents a single case in a switch statement."""

    value: int  # Case value (0, 1, 2, ...)
    target_address: int  # Address of case handler
    is_default: bool = False

    def __repr__(self) -> str:
        if self.is_default:
            return f"SwitchCase(default -> {self.target_address:#x})"
        return f"SwitchCase({self.value} -> {self.target_address:#x})"


@dataclass
class SwitchTable:
    """Detected switch table information."""

    dispatch_address: int  # Address of 'br xN' instruction
    table_address: int  # Jump table location in memory
    index_register: str  # Register holding index (e.g., "x8")
    cases: list[SwitchCase] = field(default_factory=list)
    default_address: int | None = None
    bounds_check_address: int | None = None  # Address of cmp instruction
    entry_size: int = 8  # Bytes per entry (8 for .quad)

    @property
    def case_count(self) -> int:
        """Number of non-default cases."""
        return sum(1 for c in self.cases if not c.is_default)

    @property
    def targets(self) -> list[int]:
        """All target addresses including default."""
        targets = [c.target_address for c in self.cases]
        if self.default_address and self.default_address not in targets:
            targets.append(self.default_address)
        return targets

    def __repr__(self) -> str:
        return (
            f"SwitchTable(dispatch={self.dispatch_address:#x}, "
            f"table={self.table_address:#x}, cases={self.case_count})"
        )


@dataclass
class _TableLoadInfo:
    """Internal: Info about the table load pattern."""

    adrp_value: int
    add_offset: int
    index_register: str
    entry_size: int
    adrp_address: int


@dataclass
class _BoundsCheckInfo:
    """Internal: Info about the bounds check pattern."""

    case_count: int
    default_target: int | None
    cmp_address: int


class SwitchDetector:
    """Detects switch tables in ARM64 code.

    Recognizes the clang/LLVM ARM64 switch pattern:
        cmp     wN, #<count-1>          ; Bounds check
        b.hi    <default>               ; Branch to default if out of bounds
        adrp    xM, jump_table@PAGE     ; Load page address
        add     xM, xM, jump_table@PAGEOFF
        ldr     xM, [xM, wN, uxtw #3]   ; OR: ldr xM, [xM, xN, lsl #3]
        br      xM                      ; Indirect branch
    """

    def __init__(self, binary: "MachOBinary", cfg: "ControlFlowGraph") -> None:
        self.binary = binary
        self.cfg = cfg

    def detect_all(self) -> list[SwitchTable]:
        """Detect all switch tables in the CFG."""
        switches: list[SwitchTable] = []

        for block in self.cfg:
            last = block.last_instruction
            if last and last.mnemonic == "br":
                switch = self._analyze_indirect_branch(block)
                if switch:
                    switches.append(switch)

        return switches

    def _analyze_indirect_branch(self, block: "BasicBlock") -> SwitchTable | None:
        """Analyze if an indirect branch is a switch dispatch."""
        last = block.last_instruction
        if not last or not last.operands:
            return None

        # Get target register from br instruction
        target_op = last.operands[0]
        if not target_op.is_register:
            return None
        target_reg_idx = target_op.value

        # Backward slice to find table load pattern
        load_info = self._find_table_load(block, target_reg_idx)
        if not load_info:
            return None

        # Compute table address from adrp+add
        table_address = load_info.adrp_value + load_info.add_offset

        # Find bounds check to get case count
        bounds_info = self._find_bounds_check(block, load_info.index_register)

        # Determine case count
        if bounds_info:
            case_count = bounds_info.case_count + 1  # cmp uses count-1
            default_address = bounds_info.default_target
            bounds_check_address = bounds_info.cmp_address
        else:
            # Try to infer from table contents (max 64 cases without bounds check)
            case_count = self._infer_case_count(table_address, load_info.entry_size, 64)
            default_address = None
            bounds_check_address = None

        if case_count == 0:
            return None

        # Parse jump table entries
        cases = self._parse_jump_table(table_address, case_count, load_info.entry_size)
        if not cases:
            return None

        return SwitchTable(
            dispatch_address=last.address,
            table_address=table_address,
            index_register=load_info.index_register,
            cases=cases,
            default_address=default_address,
            bounds_check_address=bounds_check_address,
            entry_size=load_info.entry_size,
        )

    def _find_table_load(self, block: "BasicBlock", target_reg_idx: int) -> _TableLoadInfo | None:
        """Find the table load pattern: adrp + add + ldr."""
        instructions = list(reversed(block.instructions[:-1]))  # Exclude br

        current_reg = target_reg_idx
        base_reg: int | None = None
        index_reg: str | None = None
        shift_amount = 0
        adrp_value: int | None = None
        add_offset = 0
        adrp_address: int | None = None

        for insn in instructions:
            # Look for: ldr xM, [xBase, xIndex, lsl #3]
            if insn.mnemonic in ("ldr", "ldrsw"):
                if insn.operands and len(insn.operands) >= 2:
                    dest_op = insn.operands[0]
                    if dest_op.is_register and dest_op.value == current_reg:
                        mem_op = insn.operands[1]
                        if mem_op.is_memory:
                            base_reg = getattr(mem_op, "base", None)
                            idx_reg = getattr(mem_op, "index", None)
                            if idx_reg is not None:
                                index_reg = f"x{idx_reg}"
                            shift_amount = getattr(mem_op, "shift", 0)
                            if base_reg is not None:
                                current_reg = base_reg

            # Look for: add xM, xM, #offset
            elif insn.mnemonic == "add":
                if len(insn.operands) >= 3:
                    dest_op = insn.operands[0]
                    if dest_op.is_register and dest_op.value == current_reg:
                        src_op = insn.operands[1]
                        imm_op = insn.operands[2]
                        if src_op.is_register and imm_op.is_immediate:
                            add_offset = imm_op.value if isinstance(imm_op.value, int) else 0
                            current_reg = src_op.value

            # Look for: adrp xM, page
            elif insn.mnemonic == "adrp":
                if insn.operands and len(insn.operands) >= 2:
                    dest_op = insn.operands[0]
                    if dest_op.is_register and dest_op.value == current_reg:
                        page_op = insn.operands[1]
                        if page_op.is_immediate:
                            adrp_value = page_op.value if isinstance(page_op.value, int) else None
                            adrp_address = insn.address

        if adrp_value is not None and adrp_address is not None and index_reg:
            entry_size = 1 << shift_amount if shift_amount else 8
            return _TableLoadInfo(
                adrp_value=adrp_value,
                add_offset=add_offset,
                index_register=index_reg,
                entry_size=entry_size,
                adrp_address=adrp_address,
            )

        return None

    def _find_bounds_check(self, block: "BasicBlock", index_reg: str) -> _BoundsCheckInfo | None:
        """Find bounds check pattern: cmp + b.hi/b.hs."""
        # Look in current block and predecessors
        blocks_to_check = [block]
        for pred_addr in block.predecessors:
            pred_block = self.cfg.get_block(pred_addr)
            if pred_block:
                blocks_to_check.append(pred_block)

        for check_block in blocks_to_check:
            cmp_insn = None
            branch_insn = None

            for insn in check_block.instructions:
                # Look for cmp wN, #immediate
                if insn.mnemonic == "cmp":
                    if len(insn.operands) >= 2:
                        reg_op = insn.operands[0]
                        imm_op = insn.operands[1]
                        if reg_op.is_register and imm_op.is_immediate:
                            # Check if it's the index register (w or x version)
                            reg_name = f"x{reg_op.value}"
                            w_name = f"w{reg_op.value}"
                            if reg_name == index_reg or w_name == index_reg.replace("x", "w"):
                                cmp_insn = insn

                # Look for b.hi or b.hs (branch if higher/higher-or-same)
                elif insn.mnemonic in ("b.hi", "b.hs", "b.cs"):
                    if insn.branch_target is not None:
                        branch_insn = insn

            if cmp_insn and branch_insn:
                imm_op = cmp_insn.operands[1]
                case_count = imm_op.value if isinstance(imm_op.value, int) else 0
                return _BoundsCheckInfo(
                    case_count=case_count,
                    default_target=branch_insn.branch_target,
                    cmp_address=cmp_insn.address,
                )

        return None

    def _infer_case_count(self, table_address: int, entry_size: int, max_cases: int) -> int:
        """Infer case count by checking table entries for valid code addresses."""
        text_section = self.binary.text_section
        if not text_section:
            return 0

        text_start = text_section.address
        text_end = text_section.address + len(text_section.data)

        count = 0
        for i in range(max_cases):
            try:
                data = self.binary.read(table_address + i * entry_size, entry_size)
                if entry_size == 8:
                    target = struct.unpack("<Q", data)[0]
                elif entry_size == 4:
                    target = struct.unpack("<I", data)[0]
                else:
                    break

                # Check if target is in text section
                if text_start <= target < text_end:
                    count += 1
                else:
                    break
            except (ValueError, struct.error):
                break

        return count

    def _parse_jump_table(
        self, table_address: int, count: int, entry_size: int
    ) -> list[SwitchCase]:
        """Parse jump table entries from binary."""
        cases: list[SwitchCase] = []

        try:
            data = self.binary.read(table_address, count * entry_size)
        except ValueError:
            return cases

        for i in range(count):
            offset = i * entry_size
            try:
                if entry_size == 8:
                    target = struct.unpack("<Q", data[offset : offset + 8])[0]
                elif entry_size == 4:
                    target = struct.unpack("<I", data[offset : offset + 4])[0]
                else:
                    continue

                cases.append(SwitchCase(value=i, target_address=target))
            except struct.error:
                break

        return cases
