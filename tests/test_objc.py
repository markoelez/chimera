"""Tests for the Objective-C metadata parsing module."""

import struct

import pytest

from chimera.analysis.objc import (
    FAST_DATA_MASK,
    ObjCIvar,
    ObjCClass,
    ObjCMethod,
    ObjCAnalyzer,
    ObjCCategory,
    ObjCMetadata,
    ObjCProperty,
    ObjCProtocol,
)


class MockSection:
    """Mock section for testing."""

    def __init__(self, name: str, address: int, data: bytes):
        self.name = name
        self.segment_name = "__DATA"
        self.address = address
        self.size = len(data)
        self.data = data

    @property
    def end_address(self) -> int:
        return self.address + self.size

    def contains_address(self, addr: int) -> bool:
        return self.address <= addr < self.end_address

    def read(self, addr: int, size: int) -> bytes:
        """Read bytes from the section."""
        if not self.contains_address(addr):
            raise ValueError(f"Address {addr:#x} not in section")
        offset = addr - self.address
        return self.data[offset : offset + size]


class MockSegment:
    """Mock segment for testing."""

    def __init__(self, name: str, sections: list[MockSection]):
        self.name = name
        self.sections = sections
        self.vmaddr = sections[0].address if sections else 0
        self.vmsize = sum(s.size for s in sections)

    def contains_address(self, addr: int) -> bool:
        return any(s.contains_address(addr) for s in self.sections)

    def section_at_address(self, addr: int) -> MockSection | None:
        for s in self.sections:
            if s.contains_address(addr):
                return s
        return None

    def get_section(self, name: str) -> MockSection | None:
        for s in self.sections:
            if s.name == name:
                return s
        return None


class MockBinary:
    """Mock binary for testing."""

    def __init__(self, segments: list[MockSegment]):
        self.segments = segments

    def get_section(self, segment_name: str, section_name: str) -> MockSection | None:
        for seg in self.segments:
            if seg.name == segment_name:
                return seg.get_section(section_name)
        return None

    def section_at_address(self, addr: int) -> MockSection | None:
        for seg in self.segments:
            section = seg.section_at_address(addr)
            if section:
                return section
        return None

    def read(self, addr: int, size: int) -> bytes:
        section = self.section_at_address(addr)
        if section:
            return section.read(addr, size)
        raise ValueError(f"No section at address {addr:#x}")


class TestObjCMethod:
    """Tests for ObjCMethod dataclass."""

    def test_creation(self):
        """Test ObjCMethod creation."""
        method = ObjCMethod(
            address=0x1000,
            selector="initWithFrame:",
            type_encoding="@24@0:8{CGRect=dddd}16",
            is_class_method=False,
        )
        assert method.address == 0x1000
        assert method.selector == "initWithFrame:"
        assert method.type_encoding == "@24@0:8{CGRect=dddd}16"
        assert not method.is_class_method

    def test_class_method(self):
        """Test class method creation."""
        method = ObjCMethod(
            address=0x2000,
            selector="alloc",
            type_encoding="@16@0:8",
            is_class_method=True,
        )
        assert method.is_class_method

    def test_repr(self):
        """Test string representation."""
        method = ObjCMethod(
            address=0x1234,
            selector="test",
            type_encoding="v16@0:8",
            is_class_method=False,
        )
        assert "-[test]" in repr(method)
        assert "0x1234" in repr(method)

    def test_frozen(self):
        """Test that ObjCMethod is immutable."""
        method = ObjCMethod(
            address=0x1000,
            selector="test",
            type_encoding="v16@0:8",
            is_class_method=False,
        )
        with pytest.raises(AttributeError):
            method.address = 0x2000  # type: ignore


class TestObjCIvar:
    """Tests for ObjCIvar dataclass."""

    def test_creation(self):
        """Test ObjCIvar creation."""
        ivar = ObjCIvar(
            name="_delegate",
            type_encoding='@"NSObject<DelegateProtocol>"',
            offset=8,
            size=8,
        )
        assert ivar.name == "_delegate"
        assert ivar.offset == 8
        assert ivar.size == 8

    def test_repr(self):
        """Test string representation."""
        ivar = ObjCIvar(name="_value", type_encoding="i", offset=16, size=4)
        assert "_value" in repr(ivar)


class TestObjCProperty:
    """Tests for ObjCProperty dataclass."""

    def test_creation(self):
        """Test ObjCProperty creation."""
        prop = ObjCProperty(
            name="delegate",
            attributes='T@"NSObject",W,N,V_delegate',
        )
        assert prop.name == "delegate"
        assert "NSObject" in prop.attributes

    def test_repr(self):
        """Test string representation."""
        prop = ObjCProperty(name="value", attributes="Ti,N,V_value")
        assert "value" in repr(prop)


class TestObjCProtocol:
    """Tests for ObjCProtocol dataclass."""

    def test_creation(self):
        """Test ObjCProtocol creation."""
        method = ObjCMethod(
            address=0x1000,
            selector="doSomething",
            type_encoding="v16@0:8",
            is_class_method=False,
        )
        proto = ObjCProtocol(
            address=0x5000,
            name="MyProtocol",
            instance_methods=(method,),
            class_methods=(),
            properties=(),
        )
        assert proto.name == "MyProtocol"
        assert len(proto.instance_methods) == 1

    def test_repr(self):
        """Test string representation."""
        proto = ObjCProtocol(address=0x1000, name="TestProtocol")
        assert "TestProtocol" in repr(proto)


class TestObjCCategory:
    """Tests for ObjCCategory dataclass."""

    def test_creation(self):
        """Test ObjCCategory creation."""
        cat = ObjCCategory(
            address=0x6000,
            name="Additions",
            class_name="NSString",
        )
        assert cat.name == "Additions"
        assert cat.class_name == "NSString"

    def test_repr(self):
        """Test string representation."""
        cat = ObjCCategory(address=0x1000, name="Cat", class_name="MyClass")
        assert "MyClass+Cat" in repr(cat)


class TestObjCClass:
    """Tests for ObjCClass dataclass."""

    def test_creation(self):
        """Test ObjCClass creation."""
        cls = ObjCClass(
            address=0x10000,
            name="MyClass",
            superclass="NSObject",
            metaclass_address=0x10100,
            instance_size=48,
            flags=0,
        )
        assert cls.name == "MyClass"
        assert cls.superclass == "NSObject"
        assert cls.instance_size == 48

    def test_is_metaclass(self):
        """Test metaclass detection."""
        cls = ObjCClass(address=0x1000, name="Meta", flags=0x1)  # RO_META
        assert cls.is_metaclass

        cls2 = ObjCClass(address=0x1000, name="Normal", flags=0x0)
        assert not cls2.is_metaclass

    def test_is_root(self):
        """Test root class detection."""
        cls = ObjCClass(address=0x1000, name="Root", flags=0x2)  # RO_ROOT
        assert cls.is_root

    def test_method_count(self):
        """Test method count property."""
        method1 = ObjCMethod(0x1000, "init", "v16@0:8", False)
        method2 = ObjCMethod(0x2000, "alloc", "@16@0:8", True)

        cls = ObjCClass(
            address=0x1000,
            name="Test",
            instance_methods=[method1],
            class_methods=[method2],
        )
        assert cls.method_count == 2

    def test_repr(self):
        """Test string representation."""
        cls = ObjCClass(address=0xABCD, name="TestClass")
        assert "TestClass" in repr(cls)
        assert "0xabcd" in repr(cls)


class TestObjCMetadata:
    """Tests for ObjCMetadata container."""

    def test_empty(self):
        """Test empty metadata."""
        meta = ObjCMetadata()
        assert len(meta) == 0
        assert meta.get_class("Test") is None

    def test_add_class(self):
        """Test adding classes."""
        meta = ObjCMetadata()
        cls = ObjCClass(address=0x1000, name="MyClass")
        meta.add_class(cls)

        assert len(meta) == 1
        assert meta.get_class("MyClass") == cls
        assert meta.get_class_at(0x1000) == cls

    def test_add_protocol(self):
        """Test adding protocols."""
        meta = ObjCMetadata()
        proto = ObjCProtocol(address=0x2000, name="MyProtocol")
        meta.add_protocol(proto)

        assert meta.get_protocol("MyProtocol") == proto
        assert len(meta.protocols) == 1

    def test_add_category(self):
        """Test adding categories."""
        meta = ObjCMetadata()
        cat = ObjCCategory(address=0x3000, name="Cat", class_name="Base")
        meta.add_category(cat)

        assert len(meta.categories) == 1
        assert meta.categories[0] == cat

    def test_add_selector(self):
        """Test adding selectors."""
        meta = ObjCMetadata()
        meta.add_selector(0x1000, "init")
        meta.add_selector(0x1008, "dealloc")

        assert meta.get_selector(0x1000) == "init"
        assert meta.get_selector(0x1008) == "dealloc"
        assert meta.get_selector(0x2000) is None

    def test_classes_implementing(self):
        """Test finding classes implementing a protocol."""
        meta = ObjCMetadata()

        cls1 = ObjCClass(address=0x1000, name="Class1", protocols=["Proto1", "Proto2"])
        cls2 = ObjCClass(address=0x2000, name="Class2", protocols=["Proto1"])
        cls3 = ObjCClass(address=0x3000, name="Class3", protocols=["Proto3"])

        meta.add_class(cls1)
        meta.add_class(cls2)
        meta.add_class(cls3)

        implementers = meta.classes_implementing("Proto1")
        assert len(implementers) == 2
        assert cls1 in implementers
        assert cls2 in implementers

    def test_methods_named(self):
        """Test finding methods by selector."""
        meta = ObjCMetadata()

        method1 = ObjCMethod(0x1000, "init", "v16@0:8", False)
        method2 = ObjCMethod(0x2000, "init", "v16@0:8", False)
        method3 = ObjCMethod(0x3000, "dealloc", "v16@0:8", False)

        cls1 = ObjCClass(address=0x10000, name="Class1", instance_methods=[method1])
        cls2 = ObjCClass(address=0x20000, name="Class2", instance_methods=[method2, method3])

        meta.add_class(cls1)
        meta.add_class(cls2)

        init_methods = meta.methods_named("init")
        assert len(init_methods) == 2

    def test_iteration(self):
        """Test iterating over classes."""
        meta = ObjCMetadata()
        cls1 = ObjCClass(address=0x1000, name="A")
        cls2 = ObjCClass(address=0x2000, name="B")
        meta.add_class(cls1)
        meta.add_class(cls2)

        classes = list(meta)
        assert len(classes) == 2

    def test_classes_sorted(self):
        """Test that classes property returns sorted list."""
        meta = ObjCMetadata()
        meta.add_class(ObjCClass(address=0x3000, name="Zebra"))
        meta.add_class(ObjCClass(address=0x1000, name="Apple"))
        meta.add_class(ObjCClass(address=0x2000, name="Banana"))

        classes = meta.classes
        assert [c.name for c in classes] == ["Apple", "Banana", "Zebra"]


class TestObjCAnalyzer:
    """Tests for ObjCAnalyzer."""

    def test_get_image_base(self):
        """Test image base detection."""
        text_section = MockSection("__text", 0x100001000, b"\x00" * 100)
        text_seg = MockSegment("__TEXT", [text_section])

        binary = MockBinary([text_seg])
        analyzer = ObjCAnalyzer(binary)  # type: ignore[arg-type]

        assert analyzer._image_base == 0x100001000

    def test_decode_ptr_zero(self):
        """Test decoding zero pointer."""
        binary = MockBinary([])
        analyzer = ObjCAnalyzer(binary)  # type: ignore[arg-type]
        analyzer._image_base = 0x100000000

        assert analyzer._decode_ptr(0) == 0

    def test_decode_ptr_normal(self):
        """Test decoding normal pointer (no fixup)."""
        binary = MockBinary([])
        analyzer = ObjCAnalyzer(binary)  # type: ignore[arg-type]
        analyzer._image_base = 0x100000000

        # No high bits set - normal pointer
        assert analyzer._decode_ptr(0x100012345) == 0x100012345

    def test_decode_ptr_chained_fixup(self):
        """Test decoding chained fixup pointer."""
        binary = MockBinary([])
        analyzer = ObjCAnalyzer(binary)  # type: ignore[arg-type]
        analyzer._image_base = 0x100000000

        # High 32 bits set (chained fixup), lower 32 bits = offset
        raw = 0x00080000000E4C40
        decoded = analyzer._decode_ptr(raw)
        assert decoded == 0x100000000 + 0x0E4C40

    def test_decode_ptr_bind_ordinal(self):
        """Test that small offsets (bind ordinals) return 0."""
        binary = MockBinary([])
        analyzer = ObjCAnalyzer(binary)  # type: ignore[arg-type]
        analyzer._image_base = 0x100000000

        # Very small offset indicates bind ordinal, not rebase
        raw = 0xC00DB5AB00000250
        decoded = analyzer._decode_ptr(raw)
        assert decoded == 0  # offset 0x250 < 0x1000

    def test_analyze_empty_binary(self):
        """Test analyzing binary with no ObjC sections."""
        binary = MockBinary([])
        analyzer = ObjCAnalyzer(binary)  # type: ignore[arg-type]
        meta = analyzer.analyze()

        assert len(meta) == 0
        assert len(meta.protocols) == 0
        assert len(meta.categories) == 0

    def test_fast_data_mask(self):
        """Test FAST_DATA_MASK constant."""
        # Should mask off lower 3 bits
        ptr = 0x1000D0568
        masked = ptr & FAST_DATA_MASK
        assert masked == 0x1000D0568 & ~0x7


class TestIntegration:
    """Integration tests with constructed mock data."""

    def _make_class_data(
        self,
        name: str,
        base_addr: int,
        string_addr: int,
    ) -> tuple[bytes, bytes, bytes]:
        """Create mock objc_class and class_ro_t data.

        Returns (class_data, ro_data, name_string).
        """
        # class_ro_t structure
        flags = 0
        instance_start = 8
        instance_size = 48
        reserved = 0
        ivar_layout = 0
        name_ptr = string_addr
        base_methods = 0
        base_protocols = 0
        ivars = 0
        weak_ivar_layout = 0
        base_properties = 0

        ro_data = struct.pack(
            "<IIII QQQQQQQ",
            flags,
            instance_start,
            instance_size,
            reserved,
            ivar_layout,
            name_ptr,
            base_methods,
            base_protocols,
            ivars,
            weak_ivar_layout,
            base_properties,
        )

        # objc_class structure
        ro_addr = base_addr + 0x100  # ro_t follows class
        isa = 0
        superclass = 0
        cache = 0
        vtable = 0
        data = ro_addr

        class_data = struct.pack("<QQQQQ", isa, superclass, cache, vtable, data)

        name_bytes = name.encode("utf-8") + b"\x00"

        return class_data, ro_data, name_bytes
