"""Symbol table handling."""

from dataclasses import dataclass
from enum import IntEnum, auto


class SymbolType(IntEnum):
    """Symbol type classification."""

    UNDEFINED = auto()  # External/imported symbol
    LOCAL = auto()  # Local symbol
    GLOBAL = auto()  # Global/exported symbol
    DEBUG = auto()  # Debug symbol
    SECTION = auto()  # Section symbol


@dataclass
class Symbol:
    """Represents a symbol from the symbol table."""

    name: str
    address: int
    symbol_type: SymbolType
    section_index: int = 0
    library: str | None = None  # For imported symbols

    def __repr__(self) -> str:
        type_str = self.symbol_type.name.lower()
        if self.library:
            return f"Symbol({self.name!r}, {self.address:#x}, {type_str}, lib={self.library!r})"
        return f"Symbol({self.name!r}, {self.address:#x}, {type_str})"


class SymbolTable:
    """Manages symbol lookup and resolution."""

    def __init__(self) -> None:
        self._by_name: dict[str, Symbol] = {}
        self._by_address: dict[int, list[Symbol]] = {}
        self._all: list[Symbol] = []

    def add(self, symbol: Symbol) -> None:
        """Add a symbol to the table."""
        self._all.append(symbol)
        self._by_name[symbol.name] = symbol
        if symbol.address not in self._by_address:
            self._by_address[symbol.address] = []
        self._by_address[symbol.address].append(symbol)

    def by_name(self, name: str) -> Symbol | None:
        """Look up symbol by name."""
        return self._by_name.get(name)

    def by_address(self, address: int) -> list[Symbol]:
        """Get all symbols at an address."""
        return self._by_address.get(address, [])

    def closest_symbol(self, address: int) -> tuple[Symbol, int] | None:
        """Find closest symbol at or before address, returns (symbol, offset)."""
        best: Symbol | None = None
        best_offset = float("inf")

        for sym in self._all:
            if sym.address <= address:
                offset = address - sym.address
                if offset < best_offset:
                    best = sym
                    best_offset = offset

        if best is not None:
            return (best, int(best_offset))
        return None

    def __iter__(self):
        return iter(self._all)

    def __len__(self) -> int:
        return len(self._all)

    @property
    def exports(self) -> list[Symbol]:
        """Get all exported/global symbols."""
        return [s for s in self._all if s.symbol_type == SymbolType.GLOBAL]

    @property
    def imports(self) -> list[Symbol]:
        """Get all imported/undefined symbols."""
        return [s for s in self._all if s.symbol_type == SymbolType.UNDEFINED]

