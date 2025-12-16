"""Tests for the project database."""

import pytest

from chimera.project.database import ProjectDatabase
from chimera.project.annotations import Annotation, AnnotationType


class TestProjectDatabase:
    """Tests for ProjectDatabase."""

    @pytest.fixture
    def db(self):
        """Create in-memory database."""
        return ProjectDatabase()

    def test_binary_info(self, db):
        """Test storing and retrieving binary info."""
        db.set_binary_info(
            path="/path/to/binary",
            sha256="abc123",
            arch="arm64",
            entry_point=0x100000000,
        )

        info = db.get_binary_info()

        assert info is not None
        assert info["path"] == "/path/to/binary"
        assert info["sha256"] == "abc123"
        assert info["arch"] == "arm64"
        assert info["entry_point"] == 0x100000000

    def test_add_function(self, db):
        """Test adding and retrieving functions."""
        db.add_function(
            address=0x100000000,
            name="_main",
            size=100,
            end_address=0x100000064,
        )

        func = db.get_function(0x100000000)

        assert func is not None
        assert func.name == "_main"
        assert func.size == 100

    def test_get_function_by_name(self, db):
        """Test getting function by name."""
        db.add_function(
            address=0x100000000,
            name="_main",
            size=100,
            end_address=0x100000064,
        )

        func = db.get_function_by_name("_main")

        assert func is not None
        assert func.address == 0x100000000

    def test_rename_function(self, db):
        """Test renaming a function."""
        db.add_function(
            address=0x100000000,
            name="sub_100000000",
            size=100,
            end_address=0x100000064,
        )

        result = db.rename_function(0x100000000, "_main")

        assert result is True
        func = db.get_function(0x100000000)
        assert func is not None
        assert func.name == "_main"

    def test_get_all_functions(self, db):
        """Test getting all functions."""
        db.add_function(0x1000, "func1", 10, 0x100A)
        db.add_function(0x2000, "func2", 20, 0x2014)
        db.add_function(0x3000, "func3", 30, 0x301E)

        funcs = db.get_all_functions()

        assert len(funcs) == 3
        assert funcs[0].address == 0x1000
        assert funcs[1].address == 0x2000
        assert funcs[2].address == 0x3000

    def test_xrefs(self, db):
        """Test cross-reference storage."""
        db.add_xref(0x1000, 0x2000, "CALL")
        db.add_xref(0x1100, 0x2000, "CALL")
        db.add_xref(0x1000, 0x3000, "JUMP")

        to_xrefs = db.get_xrefs_to(0x2000)
        from_xrefs = db.get_xrefs_from(0x1000)

        assert len(to_xrefs) == 2
        assert len(from_xrefs) == 2

    def test_comments(self, db):
        """Test comment annotations."""
        db.set_comment(0x1000, "This is main")

        comment = db.get_comment(0x1000)
        assert comment == "This is main"

        # Update comment
        db.set_comment(0x1000, "Updated comment")
        comment = db.get_comment(0x1000)
        assert comment == "Updated comment"

        # Remove comment
        db.set_comment(0x1000, "")
        comment = db.get_comment(0x1000)
        assert comment is None

    def test_annotations(self, db):
        """Test generic annotations."""
        annotation = Annotation(
            address=0x1000,
            annotation_type=AnnotationType.BOOKMARK,
            value="Important function",
        )

        db.add_annotation(annotation)
        annotations = db.get_annotations(0x1000)

        assert len(annotations) == 1
        assert annotations[0].value == "Important function"
        assert annotations[0].annotation_type == AnnotationType.BOOKMARK

    def test_basic_blocks(self, db):
        """Test basic block storage."""
        db.add_basic_block(0x1000, 0x1000, 20, 0x1014)
        db.add_basic_block(0x1014, 0x1000, 10, 0x101E)

        blocks = db.get_basic_blocks(0x1000)

        assert len(blocks) == 2
        assert blocks[0]["address"] == 0x1000
        assert blocks[1]["address"] == 0x1014

    def test_context_manager(self):
        """Test database context manager."""
        with ProjectDatabase() as db:
            db.set_binary_info("/test", "hash", "arm64", 0x1000)
            info = db.get_binary_info()
            assert info is not None
