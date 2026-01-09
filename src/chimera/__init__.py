"""Chimera - A reverse engineering framework for ARM64 macOS binaries."""

from pathlib import Path
from collections.abc import Iterator

from chimera.arch import ARM64Instruction, ARM64Disassembler
from chimera.loader import Symbol, Section, Segment, SymbolType, MachOBinary
from chimera.project import ProjectDatabase
from chimera.analysis import (
    XRef,
    Function,
    XRefType,
    ObjCClass,
    BasicBlock,
    DiffResult,
    ObjCMethod,
    StringMatch,
    XRefManager,
    ObjCAnalyzer,
    ObjCMetadata,
    PatternMatch,
    XRefAnalyzer,
    FunctionMatch,
    PatternScanner,
    StringSearcher,
    ControlFlowGraph,
    FunctionAnalyzer,
    BinaryDiffAnalyzer,
)
from chimera.decompiler.codegen import decompile_function

__version__ = "0.1.0"
__all__ = [
    "Project",
    "MachOBinary",
    "ARM64Disassembler",
    "ARM64Instruction",
    "Function",
    "BasicBlock",
    "ControlFlowGraph",
    "XRef",
    "XRefType",
    "Symbol",
    "SymbolType",
    "Segment",
    "Section",
    "StringMatch",
    "PatternMatch",
    "ObjCClass",
    "ObjCMethod",
    "ObjCMetadata",
    "DiffResult",
    "FunctionMatch",
    "BinaryDiffAnalyzer",
]


class Project:
    """Main entry point for Chimera reverse engineering framework."""

    def __init__(self, binary_path: str | Path | None = None) -> None:
        self.binary: MachOBinary | None = None
        self.disasm = ARM64Disassembler()
        self.db = ProjectDatabase()
        self._functions: dict[int, Function] = {}
        self._xrefs: XRefManager | None = None
        self._objc: ObjCMetadata | None = None
        self._analyzed = False

        if binary_path:
            self.load(binary_path)

    @classmethod
    def load(cls, path: str | Path) -> "Project":
        """Load a binary and create a project."""
        project = cls()
        project._load_binary(path)
        return project

    def _load_binary(self, path: str | Path) -> None:
        """Load a binary file."""
        self.binary = MachOBinary.load(path)

        # Store in database
        import hashlib

        with open(path, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()

        self.db.set_binary_info(
            str(path),
            sha256,
            "arm64",
            self.binary.entry_point,
        )

    def analyze(self) -> None:
        """Run analysis on the loaded binary."""
        if not self.binary:
            raise ValueError("No binary loaded")

        if self._analyzed:
            return

        # Function analysis
        func_analyzer = FunctionAnalyzer(self.binary, self.disasm)
        functions = func_analyzer.analyze()

        for func in functions:
            self._functions[func.address] = func
            self.db.add_function(
                func.address,
                func.name,
                func.size,
                func.end_address,
            )

        # Cross-reference analysis
        xref_analyzer = XRefAnalyzer(self.binary, self.disasm)
        self._xrefs = xref_analyzer.analyze()

        # Store xrefs in database
        for xref in self._xrefs:
            self.db.add_xref(xref.from_addr, xref.to_addr, xref.xref_type.name)

        # Objective-C metadata analysis
        objc_analyzer = ObjCAnalyzer(self.binary)
        self._objc = objc_analyzer.analyze()

        self._analyzed = True

    @property
    def functions(self) -> "FunctionCollection":
        """Get all functions."""
        return FunctionCollection(self._functions, self)

    def get_function(self, address: int) -> Function | None:
        """Get function by address."""
        return self._functions.get(address)

    def get_function_by_name(self, name: str) -> Function | None:
        """Get function by name."""
        for func in self._functions.values():
            if func.name == name:
                return func
        return None

    def xrefs_to(self, address: int) -> list[XRef]:
        """Get cross-references to an address."""
        if self._xrefs:
            return self._xrefs.xrefs_to(address)
        return []

    def xrefs_from(self, address: int) -> list[XRef]:
        """Get cross-references from an address."""
        if self._xrefs:
            return self._xrefs.xrefs_from(address)
        return []

    def disassemble(self, address: int, count: int = 10) -> list[ARM64Instruction]:
        """Disassemble instructions at address."""
        if not self.binary:
            raise ValueError("No binary loaded")

        section = self.binary.section_at_address(address)
        if not section:
            raise ValueError(f"No section at address {address:#x}")

        offset = address - section.address
        data = section.data[offset:]
        return list(self.disasm.disassemble(data, address, count))

    def decompile(self, func_or_name: Function | str | int) -> str:
        """Decompile a function to pseudo-C."""
        if isinstance(func_or_name, str):
            func = self.get_function_by_name(func_or_name)
        elif isinstance(func_or_name, int):
            func = self.get_function(func_or_name)
        else:
            func = func_or_name

        if not func:
            raise ValueError(f"Function not found: {func_or_name}")

        if not self.binary:
            raise ValueError("No binary loaded")

        return decompile_function(func, self.binary.symbols)

    def read(self, address: int, size: int) -> bytes:
        """Read bytes from virtual address."""
        if not self.binary:
            raise ValueError("No binary loaded")
        return self.binary.read(address, size)

    def symbol_at(self, address: int) -> Symbol | None:
        """Get symbol at address."""
        if not self.binary:
            return None
        syms = self.binary.symbols.by_address(address)
        return syms[0] if syms else None

    def closest_symbol(self, address: int) -> tuple[Symbol, int] | None:
        """Get closest symbol to address."""
        if not self.binary:
            return None
        return self.binary.symbols.closest_symbol(address)

    def strings(
        self,
        min_length: int = 4,
        sections: set[str] | None = None,
    ) -> list[StringMatch]:
        """Extract strings from binary.

        Args:
            min_length: Minimum string length to include
            sections: Section names to search (None for defaults)

        Returns:
            List of StringMatch sorted by address
        """
        if not self.binary:
            raise ValueError("No binary loaded")
        searcher = StringSearcher(self.binary)
        return searcher.find_strings(min_length, sections)

    def search_strings(
        self,
        query: str,
        case_sensitive: bool = True,
        min_length: int = 4,
    ) -> list[StringMatch]:
        """Search for strings containing query.

        Args:
            query: Text to search for
            case_sensitive: Whether search is case-sensitive
            min_length: Minimum string length

        Returns:
            List of matching StringMatch sorted by address
        """
        if not self.binary:
            raise ValueError("No binary loaded")
        searcher = StringSearcher(self.binary)
        return searcher.search(query, case_sensitive, min_length)

    def search_bytes(
        self,
        pattern: str,
        sections: set[str] | None = None,
    ) -> list[PatternMatch]:
        """Search for byte pattern with optional wildcards.

        Pattern format: "48 8b ?? c3" where ?? is wildcard.

        Args:
            pattern: Hex byte pattern with optional ?? wildcards
            sections: Section names to search (None for all)

        Returns:
            List of PatternMatch sorted by address
        """
        if not self.binary:
            raise ValueError("No binary loaded")
        scanner = PatternScanner(self.binary)
        return scanner.scan(pattern, sections)

    @property
    def objc(self) -> ObjCMetadata | None:
        """Get Objective-C metadata (requires analyze() first)."""
        return self._objc

    def get_objc_class(self, name: str) -> ObjCClass | None:
        """Get Objective-C class by name."""
        if self._objc:
            return self._objc.get_class(name)
        return None

    def diff(self, other: "Project") -> DiffResult:
        """Compare this project with another and return diff results.

        Args:
            other: Another Project to compare against

        Returns:
            DiffResult containing matched and unmatched functions
        """
        analyzer = BinaryDiffAnalyzer(self, other)
        return analyzer.analyze()

    @classmethod
    def diff_files(cls, primary: str | Path, secondary: str | Path) -> DiffResult:
        """Convenience method to diff two binary files.

        Args:
            primary: Path to the primary (old) binary
            secondary: Path to the secondary (new) binary

        Returns:
            DiffResult comparing the two binaries
        """
        proj1 = cls.load(primary)
        proj2 = cls.load(secondary)
        proj1.analyze()
        proj2.analyze()
        return proj1.diff(proj2)

    @property
    def entry_point(self) -> int:
        """Get binary entry point."""
        if not self.binary:
            return 0
        return self.binary.entry_point

    @property
    def segments(self) -> list[Segment]:
        """Get binary segments."""
        if not self.binary:
            return []
        return self.binary.segments

    @property
    def symbols(self) -> Iterator[Symbol]:
        """Iterate all symbols."""
        if not self.binary:
            return iter([])
        return iter(self.binary.symbols)

    def close(self) -> None:
        """Close the project."""
        self.db.close()

    def __enter__(self) -> "Project":
        return self

    def __exit__(self, *args) -> None:
        self.close()


class FunctionCollection:
    """Collection of functions with convenient access methods."""

    def __init__(self, functions: dict[int, Function], project: "Project") -> None:
        self._functions = functions
        self._project = project

    def __iter__(self) -> Iterator[Function]:
        return iter(self._functions.values())

    def __len__(self) -> int:
        return len(self._functions)

    def __getitem__(self, key: str | int) -> Function:
        """Get function by name or address."""
        if isinstance(key, int):
            if key in self._functions:
                return self._functions[key]
            raise KeyError(f"No function at address {key:#x}")
        else:
            for func in self._functions.values():
                if func.name == key:
                    return func
            raise KeyError(f"No function named {key!r}")

    def __contains__(self, key: str | int) -> bool:
        """Check if function exists."""
        try:
            self[key]
            return True
        except KeyError:
            return False


def main() -> None:
    """Entry point for CLI."""
    from chimera.cli import main as cli_main

    cli_main()
