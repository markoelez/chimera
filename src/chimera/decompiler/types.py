"""Composite type system for decompiler output."""

from enum import IntEnum, auto
from dataclasses import field, dataclass


class TypeKind(IntEnum):
    """Kind of type."""

    VOID = auto()
    BOOL = auto()
    INT = auto()
    FLOAT = auto()
    POINTER = auto()
    ARRAY = auto()
    STRUCT = auto()
    FUNCTION = auto()


@dataclass(frozen=True)
class PrimitiveType:
    """Primitive type (int, float, bool, void)."""

    kind: TypeKind
    size: int  # bytes
    signed: bool = True

    def __str__(self) -> str:
        if self.kind == TypeKind.VOID:
            return "void"
        if self.kind == TypeKind.BOOL:
            return "bool"
        if self.kind == TypeKind.FLOAT:
            if self.size == 4:
                return "float"
            return "double"
        # Integer types
        prefix = "" if self.signed else "u"
        return f"{prefix}int{self.size * 8}_t"


@dataclass(frozen=True)
class PointerType:
    """Pointer type."""

    pointee: "ResolvedType"

    def __str__(self) -> str:
        return f"{self.pointee}*"


@dataclass(frozen=True)
class ArrayType:
    """Array type."""

    element: "ResolvedType"
    count: int | None = None  # None = flexible array

    def __str__(self) -> str:
        if self.count is not None:
            return f"{self.element}[{self.count}]"
        return f"{self.element}[]"


@dataclass(frozen=True)
class StructField:
    """Field within a struct."""

    name: str
    offset: int
    field_type: "ResolvedType"


@dataclass
class StructType:
    """Struct type."""

    name: str | None
    fields: list[StructField] = field(default_factory=list)
    size: int = 0

    def __str__(self) -> str:
        if self.name:
            return f"struct {self.name}"
        return "struct"

    def __hash__(self) -> int:
        return hash((self.name, self.size))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, StructType):
            return False
        return self.name == other.name and self.size == other.size

    def field_at(self, offset: int) -> StructField | None:
        """Get field at specific offset."""
        for f in self.fields:
            if f.offset == offset:
                return f
        return None


@dataclass(frozen=True)
class FunctionType:
    """Function type."""

    return_type: "ResolvedType"
    param_types: tuple["ResolvedType", ...] = ()

    def __str__(self) -> str:
        params = ", ".join(str(p) for p in self.param_types)
        return f"{self.return_type}({params})"


# Type alias for all resolved types
ResolvedType = PrimitiveType | PointerType | ArrayType | StructType | FunctionType


# Common primitive types
VOID = PrimitiveType(TypeKind.VOID, 0)
BOOL = PrimitiveType(TypeKind.BOOL, 1, signed=False)

INT8 = PrimitiveType(TypeKind.INT, 1)
INT16 = PrimitiveType(TypeKind.INT, 2)
INT32 = PrimitiveType(TypeKind.INT, 4)
INT64 = PrimitiveType(TypeKind.INT, 8)

UINT8 = PrimitiveType(TypeKind.INT, 1, signed=False)
UINT16 = PrimitiveType(TypeKind.INT, 2, signed=False)
UINT32 = PrimitiveType(TypeKind.INT, 4, signed=False)
UINT64 = PrimitiveType(TypeKind.INT, 8, signed=False)

FLOAT32 = PrimitiveType(TypeKind.FLOAT, 4)
FLOAT64 = PrimitiveType(TypeKind.FLOAT, 8)

# Pointer to void (generic pointer)
PTR = PointerType(VOID)

# Char types (commonly used)
CHAR = INT8
UCHAR = UINT8


def size_to_int_type(size: int, signed: bool = True) -> PrimitiveType:
    """Get integer type for a given size."""
    if signed:
        return {1: INT8, 2: INT16, 4: INT32, 8: INT64}.get(
            size, PrimitiveType(TypeKind.INT, size, signed=True)
        )
    return {1: UINT8, 2: UINT16, 4: UINT32, 8: UINT64}.get(
        size, PrimitiveType(TypeKind.INT, size, signed=False)
    )


def type_size(t: ResolvedType) -> int:
    """Get size of a type in bytes."""
    if isinstance(t, PrimitiveType):
        return t.size
    if isinstance(t, PointerType):
        return 8  # ARM64 pointers are 8 bytes
    if isinstance(t, ArrayType):
        if t.count is None:
            return 0  # Flexible array
        return type_size(t.element) * t.count
    if isinstance(t, StructType):
        return t.size
    if isinstance(t, FunctionType):
        return 0  # Functions don't have a size
    return 0
