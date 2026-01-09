"""String and byte pattern search functionality."""

from typing import TYPE_CHECKING
from dataclasses import dataclass
from collections.abc import Iterator

if TYPE_CHECKING:
    from chimera.loader.macho import MachOBinary
    from chimera.loader.segments import Section


@dataclass(frozen=True)
class StringMatch:
    """A string found in the binary."""

    address: int
    value: str
    encoding: str  # "ascii", "utf-8", "utf-16-le"
    section: str
    length: int  # byte length

    def __repr__(self) -> str:
        preview = self.value[:32] + "..." if len(self.value) > 32 else self.value
        return f"StringMatch({self.address:#x}, {preview!r})"


@dataclass(frozen=True)
class PatternMatch:
    """A byte pattern match in the binary."""

    address: int
    pattern: str  # Original pattern string
    matched_bytes: bytes
    section: str

    def __repr__(self) -> str:
        hex_bytes = " ".join(f"{b:02x}" for b in self.matched_bytes[:8])
        if len(self.matched_bytes) > 8:
            hex_bytes += "..."
        return f"PatternMatch({self.address:#x}, {hex_bytes})"


# Default sections to search for strings
DEFAULT_STRING_SECTIONS: set[str] = {
    "__cstring",
    "__const",
    "__cfstring",
    "__oslogstring",
    "__ustring",
    "__data",
}

# Printable ASCII range
PRINTABLE_MIN = 0x20  # space
PRINTABLE_MAX = 0x7E  # tilde
# Also allow common whitespace
ALLOWED_WHITESPACE = frozenset({0x09, 0x0A, 0x0D})  # tab, newline, carriage return


def _is_printable(b: int) -> bool:
    """Check if byte is printable ASCII or allowed whitespace."""
    return PRINTABLE_MIN <= b <= PRINTABLE_MAX or b in ALLOWED_WHITESPACE


class StringSearcher:
    """Searches for strings in binary sections."""

    def __init__(self, binary: "MachOBinary") -> None:
        self.binary = binary
        self._cache: list[StringMatch] | None = None

    def find_strings(
        self,
        min_length: int = 4,
        sections: set[str] | None = None,
    ) -> list[StringMatch]:
        """Extract printable strings from binary sections.

        Args:
            min_length: Minimum string length to include
            sections: Section names to search (None for defaults)

        Returns:
            List of StringMatch sorted by address
        """
        if sections is None:
            sections = DEFAULT_STRING_SECTIONS

        results: list[StringMatch] = []

        for segment in self.binary.segments:
            for section in segment.sections:
                if section.name not in sections:
                    continue

                matches = self._extract_strings(section, min_length)
                results.extend(matches)

        # Sort by address
        results.sort(key=lambda m: m.address)
        return results

    def _extract_strings(
        self,
        section: "Section",
        min_length: int,
    ) -> list[StringMatch]:
        """Extract strings from a single section."""
        results: list[StringMatch] = []
        data = section.data
        n = len(data)

        i = 0
        while i < n:
            # Skip non-printable bytes
            if not _is_printable(data[i]):
                i += 1
                continue

            # Found start of potential string
            start = i

            # Find end of string (null terminator or non-printable)
            while i < n and data[i] != 0 and _is_printable(data[i]):
                i += 1

            length = i - start

            # Check minimum length
            if length >= min_length:
                try:
                    value = bytes(data[start:i]).decode("utf-8")
                    results.append(
                        StringMatch(
                            address=section.address + start,
                            value=value,
                            encoding="utf-8",
                            section=section.name,
                            length=length,
                        )
                    )
                except UnicodeDecodeError:
                    # Fall back to latin-1 (always succeeds)
                    value = bytes(data[start:i]).decode("latin-1")
                    results.append(
                        StringMatch(
                            address=section.address + start,
                            value=value,
                            encoding="ascii",
                            section=section.name,
                            length=length,
                        )
                    )

            # Skip null terminator
            if i < n and data[i] == 0:
                i += 1

        return results

    def search(
        self,
        query: str,
        case_sensitive: bool = True,
        min_length: int = 4,
        sections: set[str] | None = None,
    ) -> list[StringMatch]:
        """Search for strings containing the query.

        Args:
            query: Text to search for
            case_sensitive: Whether search is case-sensitive
            min_length: Minimum string length
            sections: Section names to search

        Returns:
            List of matching StringMatch sorted by address
        """
        all_strings = self.find_strings(min_length, sections)

        if not case_sensitive:
            query_lower = query.lower()
            return [s for s in all_strings if query_lower in s.value.lower()]
        else:
            return [s for s in all_strings if query in s.value]


class PatternScanner:
    """Scans for byte patterns with wildcard support."""

    def __init__(self, binary: "MachOBinary") -> None:
        self.binary = binary

    def scan(
        self,
        pattern: str,
        sections: set[str] | None = None,
    ) -> list[PatternMatch]:
        """Scan for byte pattern with optional wildcards.

        Pattern format: "48 8b ?? c3" where ?? is wildcard.
        Also supports: "488b??c3" (no spaces)

        Args:
            pattern: Hex byte pattern with optional ?? wildcards
            sections: Section names to search (None for all)

        Returns:
            List of PatternMatch sorted by address
        """
        pattern_bytes, mask = self._parse_pattern(pattern)
        results: list[PatternMatch] = []

        for segment in self.binary.segments:
            for section in segment.sections:
                if sections is not None and section.name not in sections:
                    continue

                matches = self._scan_section(section, pattern_bytes, mask, pattern)
                results.extend(matches)

        results.sort(key=lambda m: m.address)
        return results

    def scan_bytes(
        self,
        pattern: bytes,
        sections: set[str] | None = None,
    ) -> list[PatternMatch]:
        """Scan for exact byte sequence (no wildcards).

        Args:
            pattern: Exact bytes to search for
            sections: Section names to search (None for all)

        Returns:
            List of PatternMatch sorted by address
        """
        pattern_str = " ".join(f"{b:02x}" for b in pattern)
        mask = [True] * len(pattern)
        results: list[PatternMatch] = []

        for segment in self.binary.segments:
            for section in segment.sections:
                if sections is not None and section.name not in sections:
                    continue

                matches = self._scan_section(section, pattern, mask, pattern_str)
                results.extend(matches)

        results.sort(key=lambda m: m.address)
        return results

    def _parse_pattern(self, pattern: str) -> tuple[bytes, list[bool]]:
        """Parse pattern string into bytes and mask.

        Args:
            pattern: Pattern like "48 8b ?? c3" or "488b??c3"

        Returns:
            Tuple of (pattern_bytes, mask) where mask[i] is True if byte should match
        """
        # Normalize: remove spaces, convert to lowercase
        pattern = pattern.replace(" ", "").lower()

        if len(pattern) % 2 != 0:
            raise ValueError(f"Invalid pattern length: {pattern}")

        pattern_bytes = bytearray()
        mask: list[bool] = []

        i = 0
        while i < len(pattern):
            byte_str = pattern[i : i + 2]

            if byte_str == "??" or byte_str == "**":
                # Wildcard
                pattern_bytes.append(0)
                mask.append(False)
            else:
                try:
                    pattern_bytes.append(int(byte_str, 16))
                    mask.append(True)
                except ValueError:
                    raise ValueError(f"Invalid hex byte: {byte_str}") from None

            i += 2

        return bytes(pattern_bytes), mask

    def _scan_section(
        self,
        section: "Section",
        pattern_bytes: bytes,
        mask: list[bool],
        pattern_str: str,
    ) -> list[PatternMatch]:
        """Scan a section for pattern matches."""
        results: list[PatternMatch] = []
        data = section.data
        pattern_len = len(pattern_bytes)

        if pattern_len == 0 or pattern_len > len(data):
            return results

        # Optimization: if no wildcards, use bytes.find()
        if all(mask):
            pos = 0
            while True:
                pos = data.find(pattern_bytes, pos)
                if pos == -1:
                    break

                results.append(
                    PatternMatch(
                        address=section.address + pos,
                        pattern=pattern_str,
                        matched_bytes=data[pos : pos + pattern_len],
                        section=section.name,
                    )
                )
                pos += 1
        else:
            # Sliding window with mask comparison
            for i in range(len(data) - pattern_len + 1):
                if self._matches_at(data, i, pattern_bytes, mask):
                    results.append(
                        PatternMatch(
                            address=section.address + i,
                            pattern=pattern_str,
                            matched_bytes=data[i : i + pattern_len],
                            section=section.name,
                        )
                    )

        return results

    def _matches_at(
        self,
        data: bytes,
        offset: int,
        pattern: bytes,
        mask: list[bool],
    ) -> bool:
        """Check if pattern matches at offset using mask."""
        for i, (p, m) in enumerate(zip(pattern, mask)):
            if m and data[offset + i] != p:
                return False
        return True


class SearchResults:
    """Container for search results with indexing support."""

    def __init__(self) -> None:
        self._strings: list[StringMatch] = []
        self._patterns: list[PatternMatch] = []
        self._by_address: dict[int, list[StringMatch | PatternMatch]] = {}

    def add_string(self, match: StringMatch) -> None:
        """Add a string match."""
        self._strings.append(match)
        if match.address not in self._by_address:
            self._by_address[match.address] = []
        self._by_address[match.address].append(match)

    def add_pattern(self, match: PatternMatch) -> None:
        """Add a pattern match."""
        self._patterns.append(match)
        if match.address not in self._by_address:
            self._by_address[match.address] = []
        self._by_address[match.address].append(match)

    @property
    def strings(self) -> list[StringMatch]:
        """Get all string matches."""
        return self._strings

    @property
    def patterns(self) -> list[PatternMatch]:
        """Get all pattern matches."""
        return self._patterns

    def at_address(self, address: int) -> list[StringMatch | PatternMatch]:
        """Get all matches at an address."""
        return self._by_address.get(address, [])

    def __iter__(self) -> Iterator[StringMatch | PatternMatch]:
        yield from self._strings
        yield from self._patterns

    def __len__(self) -> int:
        return len(self._strings) + len(self._patterns)
