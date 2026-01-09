"""Binary diffing for comparing two binary versions."""

from __future__ import annotations

import hashlib
from enum import IntEnum, auto
from typing import TYPE_CHECKING
from dataclasses import field, dataclass

if TYPE_CHECKING:
    from chimera import Project
    from chimera.analysis.cfg import BasicBlock
    from chimera.analysis.functions import Function


class MatchConfidence(IntEnum):
    """Confidence level of a function match."""

    EXACT = auto()  # Identical hash
    HIGH = auto()  # >0.9 similarity
    MEDIUM = auto()  # 0.7-0.9 similarity
    LOW = auto()  # 0.5-0.7 similarity


class MatchStrategy(IntEnum):
    """Strategy used to match functions."""

    EXACT_HASH = auto()  # Byte-identical
    FUZZY_HASH = auto()  # Similar mnemonic sequence
    NAME_MATCH = auto()  # Same symbol name
    CFG_TOPOLOGY = auto()  # Similar CFG structure
    PROPAGATION = auto()  # Matched via call graph neighbors


class ChangeType(IntEnum):
    """Type of change for a function."""

    UNCHANGED = auto()
    MODIFIED = auto()
    ADDED = auto()
    REMOVED = auto()


@dataclass(frozen=True)
class FunctionMatch:
    """A matched pair of functions between two binaries."""

    primary: Function
    secondary: Function
    similarity: float  # 0.0-1.0
    confidence: MatchConfidence
    strategy: MatchStrategy

    @property
    def is_identical(self) -> bool:
        """Check if functions are byte-identical."""
        return self.similarity >= 1.0 and self.strategy == MatchStrategy.EXACT_HASH

    @property
    def change_type(self) -> ChangeType:
        """Get the type of change."""
        if self.is_identical:
            return ChangeType.UNCHANGED
        return ChangeType.MODIFIED

    def __repr__(self) -> str:
        return (
            f"FunctionMatch({self.primary.name!r} <-> {self.secondary.name!r}, "
            f"sim={self.similarity:.1%}, {self.strategy.name})"
        )


@dataclass(frozen=True)
class BasicBlockMatch:
    """A matched pair of basic blocks."""

    primary: BasicBlock
    secondary: BasicBlock
    similarity: float  # 0.0-1.0
    strategy: MatchStrategy

    def __repr__(self) -> str:
        return (
            f"BasicBlockMatch({self.primary.address:#x} <-> {self.secondary.address:#x}, "
            f"sim={self.similarity:.1%})"
        )


@dataclass(frozen=True)
class UnmatchedFunction:
    """A function that could not be matched."""

    function: Function
    change_type: ChangeType  # ADDED or REMOVED

    def __repr__(self) -> str:
        return f"UnmatchedFunction({self.function.name!r}, {self.change_type.name})"


@dataclass
class FunctionDiff:
    """Detailed diff between two matched functions."""

    match: FunctionMatch
    matched_blocks: list[BasicBlockMatch] = field(default_factory=list)
    unmatched_primary: list[BasicBlock] = field(default_factory=list)
    unmatched_secondary: list[BasicBlock] = field(default_factory=list)

    @property
    def block_similarity(self) -> float:
        """Compute similarity based on matched blocks."""
        total_primary = len(self.matched_blocks) + len(self.unmatched_primary)
        total_secondary = len(self.matched_blocks) + len(self.unmatched_secondary)
        if total_primary == 0 and total_secondary == 0:
            return 1.0
        matched = len(self.matched_blocks)
        return 2 * matched / (total_primary + total_secondary)


@dataclass
class DiffResult:
    """Result of comparing two binaries."""

    primary_path: str
    secondary_path: str
    primary_sha256: str
    secondary_sha256: str
    matched_functions: list[FunctionMatch] = field(default_factory=list)
    unmatched_primary: list[UnmatchedFunction] = field(default_factory=list)
    unmatched_secondary: list[UnmatchedFunction] = field(default_factory=list)

    @property
    def similarity(self) -> float:
        """Overall similarity score (0.0-1.0)."""
        total_primary = len(self.matched_functions) + len(self.unmatched_primary)
        total_secondary = len(self.matched_functions) + len(self.unmatched_secondary)
        if total_primary == 0 and total_secondary == 0:
            return 1.0
        matched = len(self.matched_functions)
        total = total_primary + total_secondary
        # Weighted by similarity of matched functions
        base = 2 * matched / total
        if not self.matched_functions:
            return base
        avg_sim = sum(m.similarity for m in self.matched_functions) / len(self.matched_functions)
        return base * avg_sim

    @property
    def matched_count(self) -> int:
        """Number of matched function pairs."""
        return len(self.matched_functions)

    @property
    def identical_count(self) -> int:
        """Number of byte-identical function pairs."""
        return sum(1 for m in self.matched_functions if m.is_identical)

    @property
    def modified_count(self) -> int:
        """Number of modified (non-identical) matches."""
        return sum(1 for m in self.matched_functions if not m.is_identical)

    @property
    def added_count(self) -> int:
        """Number of functions added in secondary."""
        return len(self.unmatched_secondary)

    @property
    def removed_count(self) -> int:
        """Number of functions removed from primary."""
        return len(self.unmatched_primary)

    def get_modified(self, min_similarity: float = 0.0) -> list[FunctionMatch]:
        """Get modified functions with similarity above threshold."""
        return [
            m
            for m in self.matched_functions
            if not m.is_identical and m.similarity >= min_similarity
        ]


class FunctionHasher:
    """Computes various hashes for function matching."""

    @staticmethod
    def exact_hash(func: Function) -> str:
        """Compute SHA256 of instruction bytes."""
        h = hashlib.sha256()
        for insn in func.instructions:
            h.update(insn.bytes)
        return h.hexdigest()

    @staticmethod
    def mnemonic_hash(func: Function) -> str:
        """Compute hash of mnemonic sequence (position-independent)."""
        h = hashlib.sha256()
        for insn in func.instructions:
            h.update(insn.mnemonic.encode("utf-8"))
        return h.hexdigest()

    @staticmethod
    def cfg_hash(func: Function) -> str:
        """Compute hash of CFG topology (block/edge structure)."""
        if not func.cfg:
            return ""
        h = hashlib.sha256()
        # Hash: (num_blocks, num_edges, edge_pattern)
        blocks = sorted(func.cfg.blocks.keys())
        addr_to_idx = {addr: i for i, addr in enumerate(blocks)}
        h.update(len(blocks).to_bytes(4, "little"))
        h.update(len(func.cfg.edges).to_bytes(4, "little"))
        for edge in sorted(func.cfg.edges, key=lambda e: (e.source, e.target)):
            src_idx = addr_to_idx.get(edge.source, -1)
            tgt_idx = addr_to_idx.get(edge.target, -1)
            h.update(src_idx.to_bytes(4, "little", signed=True))
            h.update(tgt_idx.to_bytes(4, "little", signed=True))
            h.update(edge.edge_type.to_bytes(1, "little"))
        return h.hexdigest()

    @staticmethod
    def mnemonic_sequence(func: Function) -> list[str]:
        """Get mnemonic sequence for similarity computation."""
        return [insn.mnemonic for insn in func.instructions]


def lcs_length(seq1: list[str], seq2: list[str]) -> int:
    """Compute length of longest common subsequence."""
    m, n = len(seq1), len(seq2)
    if m == 0 or n == 0:
        return 0
    # Space-optimized LCS
    prev = [0] * (n + 1)
    curr = [0] * (n + 1)
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if seq1[i - 1] == seq2[j - 1]:
                curr[j] = prev[j - 1] + 1
            else:
                curr[j] = max(prev[j], curr[j - 1])
        prev, curr = curr, prev
    return prev[n]


def compute_similarity(func1: Function, func2: Function) -> float:
    """Compute similarity between two functions using LCS."""
    seq1 = FunctionHasher.mnemonic_sequence(func1)
    seq2 = FunctionHasher.mnemonic_sequence(func2)
    if not seq1 and not seq2:
        return 1.0
    if not seq1 or not seq2:
        return 0.0
    lcs = lcs_length(seq1, seq2)
    return 2 * lcs / (len(seq1) + len(seq2))


def confidence_from_similarity(similarity: float) -> MatchConfidence:
    """Get confidence level from similarity score."""
    if similarity >= 1.0:
        return MatchConfidence.EXACT
    if similarity >= 0.9:
        return MatchConfidence.HIGH
    if similarity >= 0.7:
        return MatchConfidence.MEDIUM
    return MatchConfidence.LOW


class FunctionMatcher:
    """Matches functions between two binaries using multiple strategies."""

    def __init__(
        self,
        primary_funcs: list[Function],
        secondary_funcs: list[Function],
        min_similarity: float = 0.5,
    ) -> None:
        self.primary = primary_funcs
        self.secondary = secondary_funcs
        self.min_similarity = min_similarity
        self._matched_primary: set[int] = set()
        self._matched_secondary: set[int] = set()
        self._matches: list[FunctionMatch] = []

    def match(self) -> list[FunctionMatch]:
        """Run all matching phases and return matches."""
        # Phase 1: Exact hash matching
        self._match_exact_hash()

        # Phase 2: Name matching
        self._match_by_name()

        # Phase 3: Fuzzy hash matching
        self._match_fuzzy_hash()

        # Phase 4: CFG topology matching
        self._match_cfg_topology()

        # Phase 5: Propagation (via call graph)
        self._match_by_propagation()

        return self._matches

    def _add_match(
        self,
        primary: Function,
        secondary: Function,
        strategy: MatchStrategy,
        similarity: float | None = None,
    ) -> None:
        """Add a match if not already matched."""
        if primary.address in self._matched_primary:
            return
        if secondary.address in self._matched_secondary:
            return

        if similarity is None:
            similarity = compute_similarity(primary, secondary)

        if similarity < self.min_similarity:
            return

        confidence = confidence_from_similarity(similarity)
        match = FunctionMatch(primary, secondary, similarity, confidence, strategy)
        self._matches.append(match)
        self._matched_primary.add(primary.address)
        self._matched_secondary.add(secondary.address)

    def _match_exact_hash(self) -> None:
        """Match functions by exact instruction hash."""
        # Build hash index for secondary
        secondary_by_hash: dict[str, list[Function]] = {}
        for func in self.secondary:
            if func.address in self._matched_secondary:
                continue
            h = FunctionHasher.exact_hash(func)
            if h not in secondary_by_hash:
                secondary_by_hash[h] = []
            secondary_by_hash[h].append(func)

        # Match primary functions
        for func in self.primary:
            if func.address in self._matched_primary:
                continue
            h = FunctionHasher.exact_hash(func)
            candidates = secondary_by_hash.get(h, [])
            for cand in candidates:
                if cand.address not in self._matched_secondary:
                    self._add_match(func, cand, MatchStrategy.EXACT_HASH, 1.0)
                    break

    def _match_by_name(self) -> None:
        """Match functions by symbol name."""
        # Build name index for secondary
        secondary_by_name: dict[str, Function] = {}
        for func in self.secondary:
            if func.address in self._matched_secondary:
                continue
            # Skip auto-generated names
            if func.name.startswith("sub_"):
                continue
            if func.name not in secondary_by_name:
                secondary_by_name[func.name] = func

        # Match primary functions
        for func in self.primary:
            if func.address in self._matched_primary:
                continue
            if func.name.startswith("sub_"):
                continue
            if func.name in secondary_by_name:
                cand = secondary_by_name[func.name]
                if cand.address not in self._matched_secondary:
                    self._add_match(func, cand, MatchStrategy.NAME_MATCH)

    def _match_fuzzy_hash(self) -> None:
        """Match functions by mnemonic hash."""
        # Build hash index for secondary
        secondary_by_hash: dict[str, list[Function]] = {}
        for func in self.secondary:
            if func.address in self._matched_secondary:
                continue
            h = FunctionHasher.mnemonic_hash(func)
            if h not in secondary_by_hash:
                secondary_by_hash[h] = []
            secondary_by_hash[h].append(func)

        # Match primary functions
        for func in self.primary:
            if func.address in self._matched_primary:
                continue
            h = FunctionHasher.mnemonic_hash(func)
            candidates = secondary_by_hash.get(h, [])
            for cand in candidates:
                if cand.address not in self._matched_secondary:
                    self._add_match(func, cand, MatchStrategy.FUZZY_HASH)
                    break

    def _match_cfg_topology(self) -> None:
        """Match functions by CFG topology."""
        # Build hash index for secondary
        secondary_by_cfg: dict[str, list[Function]] = {}
        for func in self.secondary:
            if func.address in self._matched_secondary:
                continue
            h = FunctionHasher.cfg_hash(func)
            if not h:
                continue
            if h not in secondary_by_cfg:
                secondary_by_cfg[h] = []
            secondary_by_cfg[h].append(func)

        # Match primary functions
        for func in self.primary:
            if func.address in self._matched_primary:
                continue
            h = FunctionHasher.cfg_hash(func)
            if not h:
                continue
            candidates = secondary_by_cfg.get(h, [])
            for cand in candidates:
                if cand.address not in self._matched_secondary:
                    self._add_match(func, cand, MatchStrategy.CFG_TOPOLOGY)
                    break

    def _match_by_propagation(self) -> None:
        """Match unmatched functions via call graph neighbors."""
        # This is a simplified propagation - matches based on size similarity
        # of remaining functions. A full implementation would use call graph.
        unmatched_primary = [f for f in self.primary if f.address not in self._matched_primary]
        unmatched_secondary = [
            f for f in self.secondary if f.address not in self._matched_secondary
        ]

        # Sort by size for greedy matching
        unmatched_primary.sort(key=lambda f: f.size, reverse=True)
        unmatched_secondary.sort(key=lambda f: f.size, reverse=True)

        for func in unmatched_primary:
            if func.address in self._matched_primary:
                continue
            best_match: Function | None = None
            best_sim = self.min_similarity
            for cand in unmatched_secondary:
                if cand.address in self._matched_secondary:
                    continue
                # Quick size filter
                size_ratio = min(func.size, cand.size) / max(func.size, cand.size, 1)
                if size_ratio < 0.5:
                    continue
                sim = compute_similarity(func, cand)
                if sim > best_sim:
                    best_sim = sim
                    best_match = cand
            if best_match:
                self._add_match(func, best_match, MatchStrategy.PROPAGATION, best_sim)

    def get_unmatched_primary(self) -> list[UnmatchedFunction]:
        """Get unmatched functions from primary (removed)."""
        return [
            UnmatchedFunction(f, ChangeType.REMOVED)
            for f in self.primary
            if f.address not in self._matched_primary
        ]

    def get_unmatched_secondary(self) -> list[UnmatchedFunction]:
        """Get unmatched functions from secondary (added)."""
        return [
            UnmatchedFunction(f, ChangeType.ADDED)
            for f in self.secondary
            if f.address not in self._matched_secondary
        ]


class BasicBlockMatcher:
    """Matches basic blocks within matched functions."""

    def __init__(self, func_match: FunctionMatch) -> None:
        self.func_match = func_match
        self.primary = func_match.primary
        self.secondary = func_match.secondary

    def match(self) -> FunctionDiff:
        """Match basic blocks and return detailed diff."""
        diff = FunctionDiff(match=self.func_match)

        if not self.primary.cfg or not self.secondary.cfg:
            return diff

        primary_blocks = list(self.primary.cfg)
        secondary_blocks = list(self.secondary.cfg)

        matched_primary: set[int] = set()
        matched_secondary: set[int] = set()

        # Phase 1: Match entry blocks
        if primary_blocks and secondary_blocks:
            entry1 = self.primary.cfg.entry_block
            entry2 = self.secondary.cfg.entry_block
            if entry1 and entry2:
                sim = self._block_similarity(entry1, entry2)
                if sim > 0.3:
                    diff.matched_blocks.append(
                        BasicBlockMatch(entry1, entry2, sim, MatchStrategy.EXACT_HASH)
                    )
                    matched_primary.add(entry1.address)
                    matched_secondary.add(entry2.address)

        # Phase 2: Hash-based matching
        secondary_by_hash: dict[str, list[BasicBlock]] = {}
        for block in secondary_blocks:
            if block.address in matched_secondary:
                continue
            h = self._block_hash(block)
            if h not in secondary_by_hash:
                secondary_by_hash[h] = []
            secondary_by_hash[h].append(block)

        for block in primary_blocks:
            if block.address in matched_primary:
                continue
            h = self._block_hash(block)
            candidates = secondary_by_hash.get(h, [])
            for cand in candidates:
                if cand.address not in matched_secondary:
                    sim = self._block_similarity(block, cand)
                    diff.matched_blocks.append(
                        BasicBlockMatch(block, cand, sim, MatchStrategy.EXACT_HASH)
                    )
                    matched_primary.add(block.address)
                    matched_secondary.add(cand.address)
                    break

        # Phase 3: Propagate matches
        changed = True
        while changed:
            changed = False
            for match in list(diff.matched_blocks):
                # Try to match successors
                succs1 = self.primary.cfg.successors(match.primary.address)
                succs2 = self.secondary.cfg.successors(match.secondary.address)
                for s1 in succs1:
                    if s1.address in matched_primary:
                        continue
                    for s2 in succs2:
                        if s2.address in matched_secondary:
                            continue
                        sim = self._block_similarity(s1, s2)
                        if sim > 0.5:
                            diff.matched_blocks.append(
                                BasicBlockMatch(s1, s2, sim, MatchStrategy.PROPAGATION)
                            )
                            matched_primary.add(s1.address)
                            matched_secondary.add(s2.address)
                            changed = True
                            break

        # Collect unmatched blocks
        diff.unmatched_primary = [b for b in primary_blocks if b.address not in matched_primary]
        diff.unmatched_secondary = [
            b for b in secondary_blocks if b.address not in matched_secondary
        ]

        return diff

    def _block_hash(self, block: BasicBlock) -> str:
        """Compute hash of block's mnemonic sequence."""
        h = hashlib.sha256()
        for insn in block.instructions:
            h.update(insn.mnemonic.encode("utf-8"))
        return h.hexdigest()

    def _block_similarity(self, block1: BasicBlock, block2: BasicBlock) -> float:
        """Compute similarity between two blocks."""
        seq1 = [insn.mnemonic for insn in block1.instructions]
        seq2 = [insn.mnemonic for insn in block2.instructions]
        if not seq1 and not seq2:
            return 1.0
        if not seq1 or not seq2:
            return 0.0
        lcs = lcs_length(seq1, seq2)
        return 2 * lcs / (len(seq1) + len(seq2))


class BinaryDiffAnalyzer:
    """Analyzes differences between two binaries."""

    def __init__(self, primary: Project, secondary: Project) -> None:
        self.primary = primary
        self.secondary = secondary

    def analyze(self) -> DiffResult:
        """Run full diff analysis."""
        # Ensure both binaries are analyzed
        if not self.primary._analyzed:
            self.primary.analyze()
        if not self.secondary._analyzed:
            self.secondary.analyze()

        # Get binary info
        primary_info = self.primary.db.get_binary_info() or {}
        secondary_info = self.secondary.db.get_binary_info() or {}
        primary_path = primary_info.get("path", "unknown")
        secondary_path = secondary_info.get("path", "unknown")
        primary_sha = primary_info.get("sha256", "")
        secondary_sha = secondary_info.get("sha256", "")

        # Check if binaries are identical
        if primary_sha and primary_sha == secondary_sha:
            # Same binary - all functions match exactly
            result = DiffResult(
                primary_path=primary_path,
                secondary_path=secondary_path,
                primary_sha256=primary_sha,
                secondary_sha256=secondary_sha,
            )
            for func in self.primary.functions:
                result.matched_functions.append(
                    FunctionMatch(
                        func,
                        func,
                        1.0,
                        MatchConfidence.EXACT,
                        MatchStrategy.EXACT_HASH,
                    )
                )
            return result

        # Run function matching
        primary_funcs = list(self.primary.functions)
        secondary_funcs = list(self.secondary.functions)

        matcher = FunctionMatcher(primary_funcs, secondary_funcs)
        matches = matcher.match()

        return DiffResult(
            primary_path=primary_path,
            secondary_path=secondary_path,
            primary_sha256=primary_sha,
            secondary_sha256=secondary_sha,
            matched_functions=matches,
            unmatched_primary=matcher.get_unmatched_primary(),
            unmatched_secondary=matcher.get_unmatched_secondary(),
        )

    def get_function_diff(self, match: FunctionMatch) -> FunctionDiff:
        """Get detailed diff for a matched function pair."""
        block_matcher = BasicBlockMatcher(match)
        return block_matcher.match()

    def find_security_changes(self) -> list[FunctionMatch]:
        """Find changes in security-relevant functions."""
        result = self.analyze()

        # Security-related keywords in function names
        security_keywords = {
            "valid",
            "verify",
            "check",
            "auth",
            "login",
            "password",
            "crypt",
            "hash",
            "sign",
            "cert",
            "token",
            "session",
            "permission",
            "access",
            "secure",
            "safe",
            "bound",
            "overflow",
            "underflow",
            "size",
            "length",
            "count",
            "limit",
            "max",
            "min",
            "parse",
            "decode",
            "encode",
            "escape",
            "sanitize",
            "filter",
            "input",
        }

        def is_security_relevant(name: str) -> bool:
            name_lower = name.lower()
            return any(kw in name_lower for kw in security_keywords)

        return [
            m
            for m in result.matched_functions
            if not m.is_identical
            and (is_security_relevant(m.primary.name) or is_security_relevant(m.secondary.name))
        ]
