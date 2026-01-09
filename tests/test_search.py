"""Tests for the search module."""

import pytest

from chimera.analysis.search import (
    StringMatch,
    PatternMatch,
    SearchResults,
    PatternScanner,
    StringSearcher,
)


class MockSection:
    """Mock section for testing."""

    def __init__(self, name: str, address: int, data: bytes):
        self.name = name
        self.segment_name = "__TEXT"
        self.address = address
        self.size = len(data)
        self.data = data
        self.offset = 0
        self.align = 0
        self.flags = 0

    @property
    def end_address(self) -> int:
        return self.address + self.size

    def contains_address(self, addr: int) -> bool:
        return self.address <= addr < self.end_address


class MockSegment:
    """Mock segment for testing."""

    def __init__(self, name: str, sections: list[MockSection]):
        self.name = name
        self.sections = sections
        self.vmaddr = sections[0].address if sections else 0
        self.vmsize = sum(s.size for s in sections)


class MockBinary:
    """Mock binary for testing."""

    def __init__(self, segments: list[MockSegment]):
        self.segments = segments


class TestStringMatch:
    """Tests for StringMatch dataclass."""

    def test_creation(self):
        """Test StringMatch creation."""
        match = StringMatch(
            address=0x1000,
            value="Hello",
            encoding="utf-8",
            section="__cstring",
            length=5,
        )

        assert match.address == 0x1000
        assert match.value == "Hello"
        assert match.encoding == "utf-8"
        assert match.section == "__cstring"
        assert match.length == 5

    def test_frozen(self):
        """Test StringMatch is immutable."""
        match = StringMatch(
            address=0x1000,
            value="Hello",
            encoding="utf-8",
            section="__cstring",
            length=5,
        )

        with pytest.raises(AttributeError):
            match.value = "World"  # type: ignore

    def test_repr(self):
        """Test StringMatch repr."""
        match = StringMatch(
            address=0x1000,
            value="Hello, World!",
            encoding="utf-8",
            section="__cstring",
            length=13,
        )

        repr_str = repr(match)
        assert "0x1000" in repr_str
        assert "Hello" in repr_str


class TestPatternMatch:
    """Tests for PatternMatch dataclass."""

    def test_creation(self):
        """Test PatternMatch creation."""
        match = PatternMatch(
            address=0x2000,
            pattern="48 8b",
            matched_bytes=b"\x48\x8b",
            section="__text",
        )

        assert match.address == 0x2000
        assert match.pattern == "48 8b"
        assert match.matched_bytes == b"\x48\x8b"
        assert match.section == "__text"

    def test_frozen(self):
        """Test PatternMatch is immutable."""
        match = PatternMatch(
            address=0x2000,
            pattern="48 8b",
            matched_bytes=b"\x48\x8b",
            section="__text",
        )

        with pytest.raises(AttributeError):
            match.pattern = "ff ff"  # type: ignore


class TestStringSearcher:
    """Tests for StringSearcher class."""

    def test_find_simple_string(self):
        """Test finding a simple null-terminated string."""
        data = b"Hello\x00World\x00"
        section = MockSection("__cstring", 0x1000, data)
        segment = MockSegment("__TEXT", [section])
        binary = MockBinary([segment])

        searcher = StringSearcher(binary)  # type: ignore
        matches = searcher.find_strings(min_length=4)

        assert len(matches) == 2
        assert matches[0].value == "Hello"
        assert matches[0].address == 0x1000
        assert matches[1].value == "World"
        assert matches[1].address == 0x1006

    def test_min_length_filter(self):
        """Test minimum length filtering."""
        data = b"Hi\x00Hello\x00a\x00Test\x00"
        section = MockSection("__cstring", 0x1000, data)
        segment = MockSegment("__TEXT", [section])
        binary = MockBinary([segment])

        searcher = StringSearcher(binary)  # type: ignore

        # Min length 4 should exclude "Hi" and "a"
        matches = searcher.find_strings(min_length=4)
        values = [m.value for m in matches]
        assert "Hello" in values
        assert "Test" in values
        assert "Hi" not in values
        assert "a" not in values

    def test_search_case_sensitive(self):
        """Test case-sensitive string search."""
        data = b"Hello\x00HELLO\x00hello\x00"
        section = MockSection("__cstring", 0x1000, data)
        segment = MockSegment("__TEXT", [section])
        binary = MockBinary([segment])

        searcher = StringSearcher(binary)  # type: ignore

        matches = searcher.search("Hello", case_sensitive=True)
        assert len(matches) == 1
        assert matches[0].value == "Hello"

    def test_search_case_insensitive(self):
        """Test case-insensitive string search."""
        data = b"Hello\x00HELLO\x00hello\x00"
        section = MockSection("__cstring", 0x1000, data)
        segment = MockSegment("__TEXT", [section])
        binary = MockBinary([segment])

        searcher = StringSearcher(binary)  # type: ignore

        matches = searcher.search("hello", case_sensitive=False)
        assert len(matches) == 3

    def test_no_strings_found(self):
        """Test when no strings are found."""
        data = b"\x00\x01\x02\x03"  # Non-printable data
        section = MockSection("__cstring", 0x1000, data)
        segment = MockSegment("__TEXT", [section])
        binary = MockBinary([segment])

        searcher = StringSearcher(binary)  # type: ignore
        matches = searcher.find_strings()

        assert len(matches) == 0

    def test_string_with_whitespace(self):
        """Test strings containing whitespace."""
        data = b"Hello World\x00Tab\there\x00"
        section = MockSection("__cstring", 0x1000, data)
        segment = MockSegment("__TEXT", [section])
        binary = MockBinary([segment])

        searcher = StringSearcher(binary)  # type: ignore
        matches = searcher.find_strings(min_length=4)

        values = [m.value for m in matches]
        assert "Hello World" in values
        assert "Tab\there" in values


class TestPatternScanner:
    """Tests for PatternScanner class."""

    def test_parse_pattern_simple(self):
        """Test parsing simple hex pattern."""
        binary = MockBinary([])
        scanner = PatternScanner(binary)  # type: ignore

        pattern_bytes, mask = scanner._parse_pattern("48 8b c3")

        assert pattern_bytes == b"\x48\x8b\xc3"
        assert mask == [True, True, True]

    def test_parse_pattern_no_spaces(self):
        """Test parsing pattern without spaces."""
        binary = MockBinary([])
        scanner = PatternScanner(binary)  # type: ignore

        pattern_bytes, mask = scanner._parse_pattern("488bc3")

        assert pattern_bytes == b"\x48\x8b\xc3"
        assert mask == [True, True, True]

    def test_parse_pattern_wildcards(self):
        """Test parsing pattern with wildcards."""
        binary = MockBinary([])
        scanner = PatternScanner(binary)  # type: ignore

        pattern_bytes, mask = scanner._parse_pattern("48 ?? c3")

        assert len(pattern_bytes) == 3
        assert pattern_bytes[0] == 0x48
        assert pattern_bytes[2] == 0xC3
        assert mask == [True, False, True]

    def test_parse_pattern_star_wildcards(self):
        """Test parsing pattern with ** wildcards."""
        binary = MockBinary([])
        scanner = PatternScanner(binary)  # type: ignore

        pattern_bytes, mask = scanner._parse_pattern("48 ** c3")

        assert mask == [True, False, True]

    def test_parse_invalid_pattern(self):
        """Test parsing invalid pattern."""
        binary = MockBinary([])
        scanner = PatternScanner(binary)  # type: ignore

        with pytest.raises(ValueError, match="Invalid hex byte"):
            scanner._parse_pattern("48 zz c3")

    def test_parse_odd_length_pattern(self):
        """Test parsing odd-length pattern."""
        binary = MockBinary([])
        scanner = PatternScanner(binary)  # type: ignore

        with pytest.raises(ValueError, match="Invalid pattern length"):
            scanner._parse_pattern("48 8b c")

    def test_scan_exact_match(self):
        """Test scanning for exact byte pattern."""
        data = b"\x00\x00\x48\x8b\xc3\x00\x00"
        section = MockSection("__text", 0x1000, data)
        segment = MockSegment("__TEXT", [section])
        binary = MockBinary([segment])

        scanner = PatternScanner(binary)  # type: ignore
        matches = scanner.scan("48 8b c3")

        assert len(matches) == 1
        assert matches[0].address == 0x1002
        assert matches[0].matched_bytes == b"\x48\x8b\xc3"

    def test_scan_with_wildcard(self):
        """Test scanning with wildcard."""
        data = b"\x48\x00\xc3\x48\xff\xc3\x48\xab\xc3"
        section = MockSection("__text", 0x1000, data)
        segment = MockSegment("__TEXT", [section])
        binary = MockBinary([segment])

        scanner = PatternScanner(binary)  # type: ignore
        matches = scanner.scan("48 ?? c3")

        assert len(matches) == 3
        assert matches[0].address == 0x1000
        assert matches[1].address == 0x1003
        assert matches[2].address == 0x1006

    def test_scan_multiple_matches(self):
        """Test scanning with multiple matches."""
        data = b"\xfd\x7b\x00\xa9\xfd\x7b\x01\xa9\xfd\x7b\x02\xa9"
        section = MockSection("__text", 0x1000, data)
        segment = MockSegment("__TEXT", [section])
        binary = MockBinary([segment])

        scanner = PatternScanner(binary)  # type: ignore
        matches = scanner.scan("fd 7b ?? a9")

        assert len(matches) == 3

    def test_scan_no_matches(self):
        """Test scanning with no matches."""
        data = b"\x00\x01\x02\x03\x04\x05"
        section = MockSection("__text", 0x1000, data)
        segment = MockSegment("__TEXT", [section])
        binary = MockBinary([segment])

        scanner = PatternScanner(binary)  # type: ignore
        matches = scanner.scan("ff ff ff")

        assert len(matches) == 0

    def test_scan_bytes_exact(self):
        """Test scan_bytes method."""
        data = b"\x00\x48\x8b\xc3\x00"
        section = MockSection("__text", 0x1000, data)
        segment = MockSegment("__TEXT", [section])
        binary = MockBinary([segment])

        scanner = PatternScanner(binary)  # type: ignore
        matches = scanner.scan_bytes(b"\x48\x8b\xc3")

        assert len(matches) == 1
        assert matches[0].address == 0x1001


class TestSearchResults:
    """Tests for SearchResults container."""

    def test_add_string(self):
        """Test adding string matches."""
        results = SearchResults()

        match = StringMatch(
            address=0x1000,
            value="Hello",
            encoding="utf-8",
            section="__cstring",
            length=5,
        )

        results.add_string(match)

        assert len(results) == 1
        assert results.strings == [match]

    def test_add_pattern(self):
        """Test adding pattern matches."""
        results = SearchResults()

        match = PatternMatch(
            address=0x2000,
            pattern="48 8b",
            matched_bytes=b"\x48\x8b",
            section="__text",
        )

        results.add_pattern(match)

        assert len(results) == 1
        assert results.patterns == [match]

    def test_at_address(self):
        """Test looking up matches by address."""
        results = SearchResults()

        str_match = StringMatch(
            address=0x1000,
            value="Hello",
            encoding="utf-8",
            section="__cstring",
            length=5,
        )
        pat_match = PatternMatch(
            address=0x1000,
            pattern="48",
            matched_bytes=b"\x48",
            section="__text",
        )

        results.add_string(str_match)
        results.add_pattern(pat_match)

        matches = results.at_address(0x1000)
        assert len(matches) == 2

    def test_iteration(self):
        """Test iterating over all results."""
        results = SearchResults()

        str_match = StringMatch(
            address=0x1000,
            value="Hello",
            encoding="utf-8",
            section="__cstring",
            length=5,
        )
        pat_match = PatternMatch(
            address=0x2000,
            pattern="48",
            matched_bytes=b"\x48",
            section="__text",
        )

        results.add_string(str_match)
        results.add_pattern(pat_match)

        all_matches = list(results)
        assert len(all_matches) == 2
        assert str_match in all_matches
        assert pat_match in all_matches
