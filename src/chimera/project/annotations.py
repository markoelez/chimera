"""User annotations for reverse engineering."""

from dataclasses import dataclass
from enum import IntEnum, auto
from typing import Any


class AnnotationType(IntEnum):
    """Type of user annotation."""

    COMMENT = auto()  # User comment at address
    NAME = auto()  # Custom name for address/function
    TYPE = auto()  # Type annotation
    BOOKMARK = auto()  # Bookmarked address
    TAG = auto()  # Custom tag


@dataclass
class Annotation:
    """User annotation attached to an address."""

    address: int
    annotation_type: AnnotationType
    value: str
    metadata: dict[str, Any] | None = None

    def __repr__(self) -> str:
        type_str = self.annotation_type.name.lower()
        return f"Annotation({self.address:#x}, {type_str}, {self.value!r})"

