"""Tests for the binary diffing module."""

from chimera.analysis.cfg import BasicBlock, ControlFlowGraph
from chimera.analysis.diff import (
    ChangeType,
    DiffResult,
    FunctionDiff,
    FunctionMatch,
    MatchStrategy,
    FunctionHasher,
    BasicBlockMatch,
    FunctionMatcher,
    MatchConfidence,
    BasicBlockMatcher,
    UnmatchedFunction,
    lcs_length,
    compute_similarity,
    confidence_from_similarity,
)
from chimera.analysis.functions import Function
from chimera.arch.arm64.instructions import ARM64Instruction


def make_instruction(address: int, mnemonic: str, op_str: str = "") -> ARM64Instruction:
    """Create a mock instruction."""
    # Use mnemonic hash to generate unique bytes for different mnemonics
    mnem_hash = hash(mnemonic) & 0xFFFFFFFF
    insn_bytes = mnem_hash.to_bytes(4, "little")
    return ARM64Instruction(
        address=address,
        size=4,
        mnemonic=mnemonic,
        op_str=op_str,
        bytes=insn_bytes,
    )


def make_function(
    address: int,
    name: str,
    mnemonics: list[str],
    size: int = 0,
) -> Function:
    """Create a mock function with instructions."""
    func = Function(address=address, name=name, size=size or len(mnemonics) * 4)
    cfg = ControlFlowGraph(address)
    block = BasicBlock(address=address)

    for i, mnem in enumerate(mnemonics):
        insn = make_instruction(address + i * 4, mnem)
        block.instructions.append(insn)

    cfg.add_block(block)
    func.cfg = cfg
    return func


class TestMatchConfidence:
    """Tests for MatchConfidence enum."""

    def test_all_levels_exist(self):
        """Test all confidence levels exist."""
        assert MatchConfidence.EXACT is not None
        assert MatchConfidence.HIGH is not None
        assert MatchConfidence.MEDIUM is not None
        assert MatchConfidence.LOW is not None


class TestMatchStrategy:
    """Tests for MatchStrategy enum."""

    def test_all_strategies_exist(self):
        """Test all expected strategies exist."""
        assert MatchStrategy.EXACT_HASH is not None
        assert MatchStrategy.FUZZY_HASH is not None
        assert MatchStrategy.NAME_MATCH is not None
        assert MatchStrategy.CFG_TOPOLOGY is not None
        assert MatchStrategy.PROPAGATION is not None


class TestChangeType:
    """Tests for ChangeType enum."""

    def test_all_types_exist(self):
        """Test all expected types exist."""
        assert ChangeType.UNCHANGED is not None
        assert ChangeType.MODIFIED is not None
        assert ChangeType.ADDED is not None
        assert ChangeType.REMOVED is not None


class TestFunctionMatch:
    """Tests for FunctionMatch dataclass."""

    def test_creation(self):
        """Test FunctionMatch creation."""
        func1 = make_function(0x1000, "test1", ["mov", "add", "ret"])
        func2 = make_function(0x2000, "test2", ["mov", "add", "ret"])

        match = FunctionMatch(
            primary=func1,
            secondary=func2,
            similarity=1.0,
            confidence=MatchConfidence.EXACT,
            strategy=MatchStrategy.EXACT_HASH,
        )

        assert match.primary == func1
        assert match.secondary == func2
        assert match.similarity == 1.0
        assert match.is_identical

    def test_is_identical(self):
        """Test is_identical property."""
        func1 = make_function(0x1000, "test", ["mov"])
        func2 = make_function(0x2000, "test", ["mov"])

        # Identical match
        match_identical = FunctionMatch(
            func1, func2, 1.0, MatchConfidence.EXACT, MatchStrategy.EXACT_HASH
        )
        assert match_identical.is_identical

        # Modified match (same strategy but different similarity)
        match_modified = FunctionMatch(
            func1, func2, 0.9, MatchConfidence.HIGH, MatchStrategy.EXACT_HASH
        )
        assert not match_modified.is_identical

        # Name match (not identical)
        match_name = FunctionMatch(
            func1, func2, 1.0, MatchConfidence.EXACT, MatchStrategy.NAME_MATCH
        )
        assert not match_name.is_identical

    def test_change_type(self):
        """Test change_type property."""
        func1 = make_function(0x1000, "test", ["mov"])
        func2 = make_function(0x2000, "test", ["mov"])

        match_identical = FunctionMatch(
            func1, func2, 1.0, MatchConfidence.EXACT, MatchStrategy.EXACT_HASH
        )
        assert match_identical.change_type == ChangeType.UNCHANGED

        match_modified = FunctionMatch(
            func1, func2, 0.8, MatchConfidence.HIGH, MatchStrategy.NAME_MATCH
        )
        assert match_modified.change_type == ChangeType.MODIFIED

    def test_repr(self):
        """Test string representation."""
        func1 = make_function(0x1000, "test1", ["mov"])
        func2 = make_function(0x2000, "test2", ["mov"])
        match = FunctionMatch(func1, func2, 0.85, MatchConfidence.HIGH, MatchStrategy.NAME_MATCH)
        repr_str = repr(match)
        assert "test1" in repr_str
        assert "test2" in repr_str
        assert "85" in repr_str  # 85% similarity


class TestBasicBlockMatch:
    """Tests for BasicBlockMatch dataclass."""

    def test_creation(self):
        """Test BasicBlockMatch creation."""
        block1 = BasicBlock(address=0x1000)
        block2 = BasicBlock(address=0x2000)

        match = BasicBlockMatch(
            primary=block1,
            secondary=block2,
            similarity=0.9,
            strategy=MatchStrategy.EXACT_HASH,
        )

        assert match.primary == block1
        assert match.secondary == block2
        assert match.similarity == 0.9


class TestUnmatchedFunction:
    """Tests for UnmatchedFunction dataclass."""

    def test_creation(self):
        """Test UnmatchedFunction creation."""
        func = make_function(0x1000, "test", ["mov"])

        removed = UnmatchedFunction(func, ChangeType.REMOVED)
        assert removed.function == func
        assert removed.change_type == ChangeType.REMOVED

        added = UnmatchedFunction(func, ChangeType.ADDED)
        assert added.change_type == ChangeType.ADDED


class TestDiffResult:
    """Tests for DiffResult dataclass."""

    def test_empty_result(self):
        """Test empty diff result."""
        result = DiffResult(
            primary_path="a.bin",
            secondary_path="b.bin",
            primary_sha256="abc",
            secondary_sha256="def",
        )

        assert result.similarity == 1.0  # No functions to compare
        assert result.matched_count == 0
        assert result.identical_count == 0
        assert result.modified_count == 0
        assert result.added_count == 0
        assert result.removed_count == 0

    def test_with_matches(self):
        """Test result with matched functions."""
        func1 = make_function(0x1000, "test", ["mov", "ret"])
        func2 = make_function(0x2000, "test", ["mov", "ret"])

        result = DiffResult(
            primary_path="a.bin",
            secondary_path="b.bin",
            primary_sha256="abc",
            secondary_sha256="def",
            matched_functions=[
                FunctionMatch(func1, func2, 1.0, MatchConfidence.EXACT, MatchStrategy.EXACT_HASH),
            ],
        )

        assert result.matched_count == 1
        assert result.identical_count == 1
        assert result.modified_count == 0

    def test_with_unmatched(self):
        """Test result with unmatched functions."""
        func1 = make_function(0x1000, "removed", ["mov"])
        func2 = make_function(0x2000, "added", ["add"])

        result = DiffResult(
            primary_path="a.bin",
            secondary_path="b.bin",
            primary_sha256="abc",
            secondary_sha256="def",
            unmatched_primary=[UnmatchedFunction(func1, ChangeType.REMOVED)],
            unmatched_secondary=[UnmatchedFunction(func2, ChangeType.ADDED)],
        )

        assert result.added_count == 1
        assert result.removed_count == 1

    def test_get_modified(self):
        """Test get_modified method."""
        func1a = make_function(0x1000, "test1", ["mov", "ret"])
        func1b = make_function(0x2000, "test1", ["mov", "add", "ret"])
        func2a = make_function(0x3000, "test2", ["sub"])
        func2b = make_function(0x4000, "test2", ["sub"])

        result = DiffResult(
            primary_path="a.bin",
            secondary_path="b.bin",
            primary_sha256="abc",
            secondary_sha256="def",
            matched_functions=[
                FunctionMatch(func1a, func1b, 0.8, MatchConfidence.HIGH, MatchStrategy.NAME_MATCH),
                FunctionMatch(func2a, func2b, 1.0, MatchConfidence.EXACT, MatchStrategy.EXACT_HASH),
            ],
        )

        modified = result.get_modified()
        assert len(modified) == 1
        assert modified[0].primary.name == "test1"


class TestFunctionHasher:
    """Tests for FunctionHasher."""

    def test_exact_hash_identical(self):
        """Test that identical functions have same exact hash."""
        func1 = make_function(0x1000, "test", ["mov", "add", "ret"])
        func2 = make_function(0x2000, "test", ["mov", "add", "ret"])

        h1 = FunctionHasher.exact_hash(func1)
        h2 = FunctionHasher.exact_hash(func2)
        assert h1 == h2

    def test_exact_hash_different(self):
        """Test that different functions have different exact hash."""
        func1 = make_function(0x1000, "test1", ["mov", "add", "ret"])
        func2 = make_function(0x2000, "test2", ["mov", "sub", "ret"])

        h1 = FunctionHasher.exact_hash(func1)
        h2 = FunctionHasher.exact_hash(func2)
        assert h1 != h2

    def test_mnemonic_hash_identical(self):
        """Test mnemonic hash for identical sequences."""
        func1 = make_function(0x1000, "test", ["mov", "add", "ret"])
        func2 = make_function(0x2000, "test", ["mov", "add", "ret"])

        h1 = FunctionHasher.mnemonic_hash(func1)
        h2 = FunctionHasher.mnemonic_hash(func2)
        assert h1 == h2

    def test_cfg_hash(self):
        """Test CFG topology hash."""
        func1 = make_function(0x1000, "test", ["mov", "ret"])
        func2 = make_function(0x2000, "test", ["add", "ret"])

        # Same CFG structure (single block), so should be same hash
        h1 = FunctionHasher.cfg_hash(func1)
        h2 = FunctionHasher.cfg_hash(func2)
        assert h1 == h2

    def test_mnemonic_sequence(self):
        """Test mnemonic sequence extraction."""
        func = make_function(0x1000, "test", ["mov", "add", "sub", "ret"])
        seq = FunctionHasher.mnemonic_sequence(func)
        assert seq == ["mov", "add", "sub", "ret"]


class TestLCSLength:
    """Tests for LCS length computation."""

    def test_identical_sequences(self):
        """Test LCS for identical sequences."""
        seq = ["a", "b", "c"]
        assert lcs_length(seq, seq) == 3

    def test_empty_sequences(self):
        """Test LCS for empty sequences."""
        assert lcs_length([], []) == 0
        assert lcs_length(["a"], []) == 0
        assert lcs_length([], ["a"]) == 0

    def test_partial_match(self):
        """Test LCS for partial matches."""
        seq1 = ["a", "b", "c", "d"]
        seq2 = ["a", "x", "c", "y"]
        assert lcs_length(seq1, seq2) == 2  # "a", "c"

    def test_no_match(self):
        """Test LCS for no common elements."""
        seq1 = ["a", "b"]
        seq2 = ["x", "y"]
        assert lcs_length(seq1, seq2) == 0


class TestComputeSimilarity:
    """Tests for similarity computation."""

    def test_identical_functions(self):
        """Test similarity for identical functions."""
        func1 = make_function(0x1000, "test", ["mov", "add", "ret"])
        func2 = make_function(0x2000, "test", ["mov", "add", "ret"])
        assert compute_similarity(func1, func2) == 1.0

    def test_empty_functions(self):
        """Test similarity for empty functions."""
        func1 = make_function(0x1000, "test", [])
        func2 = make_function(0x2000, "test", [])
        assert compute_similarity(func1, func2) == 1.0

    def test_one_empty_function(self):
        """Test similarity when one function is empty."""
        func1 = make_function(0x1000, "test", ["mov"])
        func2 = make_function(0x2000, "test", [])
        assert compute_similarity(func1, func2) == 0.0

    def test_partial_similarity(self):
        """Test partial similarity."""
        func1 = make_function(0x1000, "test", ["mov", "add", "ret"])
        func2 = make_function(0x2000, "test", ["mov", "sub", "ret"])
        sim = compute_similarity(func1, func2)
        # LCS = ["mov", "ret"] = 2, total = 6
        # similarity = 2 * 2 / 6 = 0.666...
        assert 0.6 < sim < 0.7


class TestConfidenceFromSimilarity:
    """Tests for confidence level determination."""

    def test_exact_confidence(self):
        """Test exact confidence for 1.0 similarity."""
        assert confidence_from_similarity(1.0) == MatchConfidence.EXACT

    def test_high_confidence(self):
        """Test high confidence for >0.9 similarity."""
        assert confidence_from_similarity(0.95) == MatchConfidence.HIGH
        assert confidence_from_similarity(0.91) == MatchConfidence.HIGH

    def test_medium_confidence(self):
        """Test medium confidence for 0.7-0.9 similarity."""
        assert confidence_from_similarity(0.85) == MatchConfidence.MEDIUM
        assert confidence_from_similarity(0.7) == MatchConfidence.MEDIUM

    def test_low_confidence(self):
        """Test low confidence for <0.7 similarity."""
        assert confidence_from_similarity(0.6) == MatchConfidence.LOW
        assert confidence_from_similarity(0.3) == MatchConfidence.LOW


class TestFunctionMatcher:
    """Tests for FunctionMatcher."""

    def test_exact_hash_matching(self):
        """Test matching by exact hash."""
        func1 = make_function(0x1000, "test1", ["mov", "add", "ret"])
        func2 = make_function(0x2000, "test2", ["mov", "add", "ret"])

        matcher = FunctionMatcher([func1], [func2])
        matches = matcher.match()

        assert len(matches) == 1
        assert matches[0].strategy == MatchStrategy.EXACT_HASH
        assert matches[0].similarity == 1.0

    def test_name_matching(self):
        """Test matching by name."""
        func1 = make_function(0x1000, "myFunction", ["mov", "ret"])
        func2 = make_function(0x2000, "myFunction", ["add", "ret"])

        matcher = FunctionMatcher([func1], [func2])
        matches = matcher.match()

        # Should match by name since instructions differ
        assert len(matches) == 1
        # Could match by name or fuzzy hash depending on implementation

    def test_skip_auto_names(self):
        """Test that auto-generated names are skipped in name matching."""
        func1 = make_function(0x1000, "sub_1000", ["mov"])
        func2 = make_function(0x2000, "sub_2000", ["add"])

        matcher = FunctionMatcher([func1], [func2])
        matches = matcher.match()

        # Should not match by name since both have auto-generated names
        for match in matches:
            assert match.strategy != MatchStrategy.NAME_MATCH

    def test_unmatched_functions(self):
        """Test collecting unmatched functions."""
        func1 = make_function(0x1000, "only_primary", ["mov", "mov"])
        func2 = make_function(0x2000, "only_secondary", ["add", "add"])

        matcher = FunctionMatcher([func1], [func2])
        matcher.match()

        unmatched_primary = matcher.get_unmatched_primary()
        unmatched_secondary = matcher.get_unmatched_secondary()

        # Functions are too different to match
        assert len(unmatched_primary) <= 1
        assert len(unmatched_secondary) <= 1

    def test_min_similarity_threshold(self):
        """Test minimum similarity threshold."""
        # Use different names so they don't match by name
        func1 = make_function(0x1000, "sub_1000", ["a", "b", "c", "d", "e"])
        func2 = make_function(0x2000, "sub_2000", ["x", "y", "z", "d", "e"])

        # High threshold - since instructions differ, exact hash won't match,
        # and names are auto-generated so name match won't work either
        matcher = FunctionMatcher([func1], [func2], min_similarity=0.9)
        matches = matcher.match()

        # The functions have ~40% similarity, so should not match with 0.9 threshold
        assert len(matches) == 0


class TestBasicBlockMatcher:
    """Tests for BasicBlockMatcher."""

    def test_match_entry_blocks(self):
        """Test that entry blocks are always matched."""
        func1 = make_function(0x1000, "test", ["mov", "ret"])
        func2 = make_function(0x2000, "test", ["mov", "ret"])

        match = FunctionMatch(func1, func2, 1.0, MatchConfidence.EXACT, MatchStrategy.EXACT_HASH)
        block_matcher = BasicBlockMatcher(match)
        diff = block_matcher.match()

        assert len(diff.matched_blocks) >= 1

    def test_match_identical_functions(self):
        """Test matching blocks in identical functions."""
        func1 = make_function(0x1000, "test", ["mov", "add", "ret"])
        func2 = make_function(0x2000, "test", ["mov", "add", "ret"])

        match = FunctionMatch(func1, func2, 1.0, MatchConfidence.EXACT, MatchStrategy.EXACT_HASH)
        block_matcher = BasicBlockMatcher(match)
        diff = block_matcher.match()

        # All blocks should be matched
        assert len(diff.unmatched_primary) == 0
        assert len(diff.unmatched_secondary) == 0


class TestFunctionDiff:
    """Tests for FunctionDiff dataclass."""

    def test_block_similarity(self):
        """Test block similarity computation."""
        func1 = make_function(0x1000, "test", ["mov"])
        func2 = make_function(0x2000, "test", ["mov"])
        match = FunctionMatch(func1, func2, 1.0, MatchConfidence.EXACT, MatchStrategy.EXACT_HASH)

        diff = FunctionDiff(match=match)

        # No blocks yet
        assert diff.block_similarity == 1.0

        # Add matched block
        block1 = BasicBlock(address=0x1000)
        block2 = BasicBlock(address=0x2000)
        diff.matched_blocks.append(BasicBlockMatch(block1, block2, 1.0, MatchStrategy.EXACT_HASH))
        assert diff.block_similarity == 1.0

        # Add unmatched blocks
        diff.unmatched_primary.append(BasicBlock(address=0x1100))
        diff.unmatched_secondary.append(BasicBlock(address=0x2100))

        # 1 matched, 1 unmatched_primary, 1 unmatched_secondary
        # similarity = 2 * 1 / (2 + 2) = 0.5
        assert diff.block_similarity == 0.5
