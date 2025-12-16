"""Memory segment and section models."""

from dataclasses import dataclass, field


@dataclass
class Section:
    """Represents a Mach-O section within a segment."""

    name: str
    segment_name: str
    address: int
    size: int
    offset: int
    align: int
    flags: int
    data: bytes = field(default=b"", repr=False)

    @property
    def end_address(self) -> int:
        return self.address + self.size

    def contains_address(self, addr: int) -> bool:
        return self.address <= addr < self.end_address

    def read(self, addr: int, size: int) -> bytes:
        """Read bytes from section at virtual address."""
        if not self.contains_address(addr):
            raise ValueError(f"Address {addr:#x} not in section {self.name}")
        offset = addr - self.address
        if offset + size > len(self.data):
            raise ValueError(f"Read beyond section bounds")
        return self.data[offset : offset + size]


@dataclass
class Segment:
    """Represents a Mach-O segment (e.g., __TEXT, __DATA)."""

    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    flags: int
    sections: list[Section] = field(default_factory=list)

    @property
    def end_address(self) -> int:
        return self.vmaddr + self.vmsize

    def contains_address(self, addr: int) -> bool:
        return self.vmaddr <= addr < self.end_address

    def get_section(self, name: str) -> Section | None:
        """Get section by name."""
        for section in self.sections:
            if section.name == name:
                return section
        return None

    def section_at_address(self, addr: int) -> Section | None:
        """Find section containing the given address."""
        for section in self.sections:
            if section.contains_address(addr):
                return section
        return None

