"""SQLite-based project database for persistence."""

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from chimera.project.annotations import Annotation, AnnotationType


@dataclass
class FunctionRecord:
    """Stored function information."""

    address: int
    name: str
    size: int
    end_address: int


@dataclass
class XRefRecord:
    """Stored cross-reference."""

    from_addr: int
    to_addr: int
    xref_type: str


class ProjectDatabase:
    """SQLite database for project persistence."""

    SCHEMA_VERSION = 1

    def __init__(self, db_path: Path | str | None = None) -> None:
        """Initialize database, in-memory if no path given."""
        if db_path:
            self._path = Path(db_path)
            self._conn = sqlite3.connect(str(self._path))
        else:
            self._path = None
            self._conn = sqlite3.connect(":memory:")

        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        """Create database schema."""
        cursor = self._conn.cursor()

        # Metadata table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        # Binary info
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS binary_info (
                id INTEGER PRIMARY KEY,
                path TEXT,
                sha256 TEXT,
                arch TEXT,
                entry_point INTEGER,
                loaded_at TEXT
            )
        """)

        # Segments
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS segments (
                id INTEGER PRIMARY KEY,
                name TEXT,
                vmaddr INTEGER,
                vmsize INTEGER,
                fileoff INTEGER,
                filesize INTEGER
            )
        """)

        # Sections
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sections (
                id INTEGER PRIMARY KEY,
                segment_id INTEGER,
                name TEXT,
                address INTEGER,
                size INTEGER,
                FOREIGN KEY (segment_id) REFERENCES segments(id)
            )
        """)

        # Functions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS functions (
                address INTEGER PRIMARY KEY,
                name TEXT,
                size INTEGER,
                end_address INTEGER,
                calling_convention TEXT,
                metadata TEXT
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name)"
        )

        # Basic blocks
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS basic_blocks (
                address INTEGER PRIMARY KEY,
                function_addr INTEGER,
                size INTEGER,
                end_address INTEGER,
                FOREIGN KEY (function_addr) REFERENCES functions(address)
            )
        """)

        # Cross-references
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS xrefs (
                id INTEGER PRIMARY KEY,
                from_addr INTEGER,
                to_addr INTEGER,
                xref_type TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_xrefs_from ON xrefs(from_addr)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_xrefs_to ON xrefs(to_addr)")

        # Annotations
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS annotations (
                id INTEGER PRIMARY KEY,
                address INTEGER,
                annotation_type INTEGER,
                value TEXT,
                metadata TEXT
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_annotations_addr ON annotations(address)"
        )

        # Disassembly cache
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS disasm_cache (
                address INTEGER PRIMARY KEY,
                mnemonic TEXT,
                operands TEXT,
                size INTEGER,
                bytes BLOB
            )
        """)

        # Set schema version
        cursor.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("schema_version", str(self.SCHEMA_VERSION)),
        )

        self._conn.commit()

    def close(self) -> None:
        """Close database connection."""
        self._conn.close()

    def __enter__(self) -> "ProjectDatabase":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # Binary info methods

    def set_binary_info(
        self,
        path: str,
        sha256: str,
        arch: str,
        entry_point: int,
    ) -> None:
        """Store binary metadata."""
        from datetime import datetime

        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO binary_info (id, path, sha256, arch, entry_point, loaded_at)
            VALUES (1, ?, ?, ?, ?, ?)
            """,
            (path, sha256, arch, entry_point, datetime.now().isoformat()),
        )
        self._conn.commit()

    def get_binary_info(self) -> dict[str, Any] | None:
        """Get stored binary metadata."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM binary_info WHERE id = 1")
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    # Function methods

    def add_function(
        self,
        address: int,
        name: str,
        size: int,
        end_address: int,
        calling_convention: str = "aapcs64",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add or update a function."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO functions 
            (address, name, size, end_address, calling_convention, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                address,
                name,
                size,
                end_address,
                calling_convention,
                json.dumps(metadata) if metadata else None,
            ),
        )
        self._conn.commit()

    def get_function(self, address: int) -> FunctionRecord | None:
        """Get function by address."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT address, name, size, end_address FROM functions WHERE address = ?",
            (address,),
        )
        row = cursor.fetchone()
        if row:
            return FunctionRecord(
                address=row["address"],
                name=row["name"],
                size=row["size"],
                end_address=row["end_address"],
            )
        return None

    def get_function_by_name(self, name: str) -> FunctionRecord | None:
        """Get function by name."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT address, name, size, end_address FROM functions WHERE name = ?",
            (name,),
        )
        row = cursor.fetchone()
        if row:
            return FunctionRecord(
                address=row["address"],
                name=row["name"],
                size=row["size"],
                end_address=row["end_address"],
            )
        return None

    def get_all_functions(self) -> list[FunctionRecord]:
        """Get all functions."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT address, name, size, end_address FROM functions ORDER BY address"
        )
        return [
            FunctionRecord(
                address=row["address"],
                name=row["name"],
                size=row["size"],
                end_address=row["end_address"],
            )
            for row in cursor.fetchall()
        ]

    def rename_function(self, address: int, new_name: str) -> bool:
        """Rename a function."""
        cursor = self._conn.cursor()
        cursor.execute(
            "UPDATE functions SET name = ? WHERE address = ?",
            (new_name, address),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    # Cross-reference methods

    def add_xref(self, from_addr: int, to_addr: int, xref_type: str) -> None:
        """Add a cross-reference."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT INTO xrefs (from_addr, to_addr, xref_type)
            VALUES (?, ?, ?)
            """,
            (from_addr, to_addr, xref_type),
        )
        self._conn.commit()

    def get_xrefs_to(self, address: int) -> list[XRefRecord]:
        """Get all references to an address."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT from_addr, to_addr, xref_type FROM xrefs WHERE to_addr = ?",
            (address,),
        )
        return [
            XRefRecord(
                from_addr=row["from_addr"],
                to_addr=row["to_addr"],
                xref_type=row["xref_type"],
            )
            for row in cursor.fetchall()
        ]

    def get_xrefs_from(self, address: int) -> list[XRefRecord]:
        """Get all references from an address."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT from_addr, to_addr, xref_type FROM xrefs WHERE from_addr = ?",
            (address,),
        )
        return [
            XRefRecord(
                from_addr=row["from_addr"],
                to_addr=row["to_addr"],
                xref_type=row["xref_type"],
            )
            for row in cursor.fetchall()
        ]

    # Annotation methods

    def add_annotation(self, annotation: Annotation) -> int:
        """Add an annotation, returns ID."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT INTO annotations (address, annotation_type, value, metadata)
            VALUES (?, ?, ?, ?)
            """,
            (
                annotation.address,
                annotation.annotation_type.value,
                annotation.value,
                json.dumps(annotation.metadata) if annotation.metadata else None,
            ),
        )
        self._conn.commit()
        return cursor.lastrowid or 0

    def get_annotations(self, address: int) -> list[Annotation]:
        """Get all annotations at an address."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT address, annotation_type, value, metadata FROM annotations WHERE address = ?",
            (address,),
        )
        return [
            Annotation(
                address=row["address"],
                annotation_type=AnnotationType(row["annotation_type"]),
                value=row["value"],
                metadata=json.loads(row["metadata"]) if row["metadata"] else None,
            )
            for row in cursor.fetchall()
        ]

    def set_comment(self, address: int, comment: str) -> None:
        """Set or update comment at address."""
        # Remove existing comments
        cursor = self._conn.cursor()
        cursor.execute(
            "DELETE FROM annotations WHERE address = ? AND annotation_type = ?",
            (address, AnnotationType.COMMENT.value),
        )
        if comment:
            self.add_annotation(
                Annotation(address, AnnotationType.COMMENT, comment)
            )

    def get_comment(self, address: int) -> str | None:
        """Get comment at address."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT value FROM annotations WHERE address = ? AND annotation_type = ?",
            (address, AnnotationType.COMMENT.value),
        )
        row = cursor.fetchone()
        return row["value"] if row else None

    # Basic block methods

    def add_basic_block(
        self, address: int, function_addr: int, size: int, end_address: int
    ) -> None:
        """Add a basic block."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO basic_blocks 
            (address, function_addr, size, end_address)
            VALUES (?, ?, ?, ?)
            """,
            (address, function_addr, size, end_address),
        )
        self._conn.commit()

    def get_basic_blocks(self, function_addr: int) -> list[dict[str, int]]:
        """Get all basic blocks for a function."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT address, size, end_address 
            FROM basic_blocks WHERE function_addr = ? ORDER BY address
            """,
            (function_addr,),
        )
        return [dict(row) for row in cursor.fetchall()]

    # Disassembly cache methods

    def cache_instruction(
        self,
        address: int,
        mnemonic: str,
        operands: str,
        size: int,
        insn_bytes: bytes,
    ) -> None:
        """Cache a disassembled instruction."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO disasm_cache 
            (address, mnemonic, operands, size, bytes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (address, mnemonic, operands, size, insn_bytes),
        )
        self._conn.commit()

    def get_cached_instruction(
        self, address: int
    ) -> dict[str, Any] | None:
        """Get cached instruction."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT * FROM disasm_cache WHERE address = ?",
            (address,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def clear_cache(self) -> None:
        """Clear all cached data."""
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM disasm_cache")
        self._conn.commit()

