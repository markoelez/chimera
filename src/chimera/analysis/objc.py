"""Objective-C runtime metadata parsing."""

import struct
from typing import TYPE_CHECKING
from dataclasses import field, dataclass
from collections.abc import Iterator

if TYPE_CHECKING:
    from chimera.loader.macho import MachOBinary
    from chimera.loader.segments import Section


# Objective-C class flags
RO_META = 1 << 0
RO_ROOT = 1 << 1

# Mask to extract class_ro_t pointer from data field
FAST_DATA_MASK = 0x00007FFFFFFFFFF8


@dataclass(frozen=True)
class ObjCMethod:
    """An Objective-C method."""

    address: int  # Implementation address
    selector: str  # Method name (e.g., "initWithFrame:")
    type_encoding: str  # Type signature
    is_class_method: bool  # + vs -

    def __repr__(self) -> str:
        prefix = "+" if self.is_class_method else "-"
        return f"ObjCMethod({prefix}[{self.selector}] @ {self.address:#x})"


@dataclass(frozen=True)
class ObjCIvar:
    """An instance variable."""

    name: str
    type_encoding: str
    offset: int
    size: int

    def __repr__(self) -> str:
        return f"ObjCIvar({self.name}: {self.type_encoding})"


@dataclass(frozen=True)
class ObjCProperty:
    """A declared property."""

    name: str
    attributes: str  # e.g., "T@\"NSString\",&,N,V_name"

    def __repr__(self) -> str:
        return f"ObjCProperty({self.name})"


@dataclass(frozen=True)
class ObjCProtocol:
    """A protocol definition."""

    address: int
    name: str
    instance_methods: tuple[ObjCMethod, ...] = ()
    class_methods: tuple[ObjCMethod, ...] = ()
    properties: tuple[ObjCProperty, ...] = ()

    def __repr__(self) -> str:
        return f"ObjCProtocol({self.name} @ {self.address:#x})"


@dataclass(frozen=True)
class ObjCCategory:
    """A category extension."""

    address: int
    name: str
    class_name: str
    instance_methods: tuple[ObjCMethod, ...] = ()
    class_methods: tuple[ObjCMethod, ...] = ()

    def __repr__(self) -> str:
        return f"ObjCCategory({self.class_name}+{self.name} @ {self.address:#x})"


@dataclass
class ObjCClass:
    """An Objective-C class with all metadata."""

    address: int
    name: str
    superclass: str | None = None
    metaclass_address: int = 0
    instance_size: int = 0
    flags: int = 0

    instance_methods: list[ObjCMethod] = field(default_factory=list)
    class_methods: list[ObjCMethod] = field(default_factory=list)
    ivars: list[ObjCIvar] = field(default_factory=list)
    properties: list[ObjCProperty] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)

    @property
    def is_metaclass(self) -> bool:
        return bool(self.flags & RO_META)

    @property
    def is_root(self) -> bool:
        return bool(self.flags & RO_ROOT)

    @property
    def method_count(self) -> int:
        return len(self.instance_methods) + len(self.class_methods)

    def __repr__(self) -> str:
        return f"ObjCClass({self.name} @ {self.address:#x})"


class ObjCMetadata:
    """Container for all Objective-C metadata."""

    def __init__(self) -> None:
        self._classes: dict[int, ObjCClass] = {}
        self._classes_by_name: dict[str, ObjCClass] = {}
        self._protocols: dict[int, ObjCProtocol] = {}
        self._protocols_by_name: dict[str, ObjCProtocol] = {}
        self._categories: list[ObjCCategory] = []
        self._selectors: dict[int, str] = {}

    def add_class(self, cls: ObjCClass) -> None:
        """Add a class to the metadata."""
        self._classes[cls.address] = cls
        self._classes_by_name[cls.name] = cls

    def add_protocol(self, proto: ObjCProtocol) -> None:
        """Add a protocol to the metadata."""
        self._protocols[proto.address] = proto
        self._protocols_by_name[proto.name] = proto

    def add_category(self, cat: ObjCCategory) -> None:
        """Add a category to the metadata."""
        self._categories.append(cat)

    def add_selector(self, address: int, name: str) -> None:
        """Add a selector reference."""
        self._selectors[address] = name

    def get_class(self, name: str) -> ObjCClass | None:
        """Get class by name."""
        return self._classes_by_name.get(name)

    def get_class_at(self, address: int) -> ObjCClass | None:
        """Get class by address."""
        return self._classes.get(address)

    def get_protocol(self, name: str) -> ObjCProtocol | None:
        """Get protocol by name."""
        return self._protocols_by_name.get(name)

    def get_selector(self, address: int) -> str | None:
        """Get selector name at address."""
        return self._selectors.get(address)

    def classes_implementing(self, protocol: str) -> list[ObjCClass]:
        """Get all classes implementing a protocol."""
        return [cls for cls in self._classes.values() if protocol in cls.protocols]

    def methods_named(self, selector: str) -> list[tuple[ObjCClass, ObjCMethod]]:
        """Find all methods with a given selector name."""
        results: list[tuple[ObjCClass, ObjCMethod]] = []
        for cls in self._classes.values():
            for method in cls.instance_methods + cls.class_methods:
                if method.selector == selector:
                    results.append((cls, method))
        return results

    @property
    def classes(self) -> list[ObjCClass]:
        """Get all classes sorted by name."""
        return sorted(self._classes.values(), key=lambda c: c.name)

    @property
    def protocols(self) -> list[ObjCProtocol]:
        """Get all protocols sorted by name."""
        return sorted(self._protocols.values(), key=lambda p: p.name)

    @property
    def categories(self) -> list[ObjCCategory]:
        """Get all categories."""
        return self._categories

    @property
    def selectors(self) -> dict[int, str]:
        """Get all selector references."""
        return self._selectors

    def __iter__(self) -> Iterator[ObjCClass]:
        return iter(self._classes.values())

    def __len__(self) -> int:
        return len(self._classes)


class ObjCAnalyzer:
    """Parses Objective-C runtime metadata from binary."""

    def __init__(self, binary: "MachOBinary") -> None:
        self.binary = binary
        self.metadata = ObjCMetadata()
        self._parsed_classes: set[int] = set()
        # Get image base for chained fixup resolution
        self._image_base = self._get_image_base()

    def _get_image_base(self) -> int:
        """Get the image base address (vmaddr of __TEXT segment)."""
        for seg in self.binary.segments:
            if seg.name == "__TEXT":
                return seg.vmaddr
        return 0

    def analyze(self) -> ObjCMetadata:
        """Extract all Objective-C metadata."""
        self._parse_classlist()
        self._parse_catlist()
        self._parse_protolist()
        self._parse_selrefs()
        return self.metadata

    def _get_section(self, name: str) -> "Section | None":
        """Get section from __DATA or __DATA_CONST."""
        for seg_name in ("__DATA", "__DATA_CONST"):
            section = self.binary.get_section(seg_name, name)
            if section:
                return section
        return None

    def _read_ptr(self, addr: int) -> int:
        """Read 64-bit pointer at address, decoding chained fixups if needed."""
        try:
            data = self.binary.read(addr, 8)
            raw = struct.unpack("<Q", data)[0]
            return self._decode_ptr(raw)
        except (ValueError, struct.error):
            return 0

    def _decode_ptr(self, raw: int) -> int:
        """Decode a pointer value, handling chained fixups.

        Modern macOS binaries use chained fixups where pointers are encoded:
        - High 32 bits: fixup metadata (pointer format, bind/rebase info)
        - Low 32 bits: offset from image base (for rebases) or ordinal (for binds)
        """
        if raw == 0:
            return 0

        # Check for chained fixup encoding
        # High 32 bits non-zero indicates a chained fixup
        high_32 = (raw >> 32) & 0xFFFFFFFF
        if high_32 == 0:
            # Normal pointer (no fixup metadata)
            return raw

        # This is a chained fixup - extract offset from lower 32 bits
        offset = raw & 0xFFFFFFFF

        # Very small offsets (< 0x1000) are likely bind ordinals, not rebases
        # These reference external symbols and can't be resolved locally
        if offset < 0x1000:
            return 0

        return self._image_base + offset

    def _read_u32(self, addr: int) -> int:
        """Read 32-bit unsigned int at address."""
        return self._read_int(addr, "<I")

    def _read_i32(self, addr: int) -> int:
        """Read 32-bit signed int at address."""
        return self._read_int(addr, "<i")

    def _read_int(self, addr: int, fmt: str) -> int:
        """Read integer at address with given struct format."""
        try:
            size = struct.calcsize(fmt)
            data = self.binary.read(addr, size)
            return struct.unpack(fmt, data)[0]
        except (ValueError, struct.error):
            return 0

    def _read_string(self, addr: int, max_len: int = 256) -> str:
        """Read null-terminated string at address."""
        if addr == 0:
            return ""
        try:
            # Read in chunks to find null terminator
            result = bytearray()
            offset = 0
            while offset < max_len:
                chunk = self.binary.read(addr + offset, min(64, max_len - offset))
                null_idx = chunk.find(b"\x00")
                if null_idx != -1:
                    result.extend(chunk[:null_idx])
                    break
                result.extend(chunk)
                offset += len(chunk)
            return result.decode("utf-8", errors="replace")
        except ValueError:
            return ""

    def _iter_section_ptrs(self, section_name: str) -> Iterator[int]:
        """Iterate decoded pointers from a section."""
        section = self._get_section(section_name)
        if not section:
            return
        for i in range(section.size // 8):
            offset = i * 8
            raw = struct.unpack("<Q", section.data[offset : offset + 8])[0]
            ptr = self._decode_ptr(raw)
            if ptr:
                yield ptr

    def _parse_classlist(self) -> None:
        """Parse __objc_classlist section."""
        for class_ptr in self._iter_section_ptrs("__objc_classlist"):
            if class_ptr not in self._parsed_classes:
                self._parse_class(class_ptr)

    def _parse_class(self, addr: int) -> ObjCClass | None:
        """Parse a single class structure."""
        if addr == 0 or addr in self._parsed_classes:
            return self.metadata.get_class_at(addr)

        self._parsed_classes.add(addr)

        # Read objc_class structure (40 bytes)
        # struct objc_class {
        #     uint64_t isa;        // 0
        #     uint64_t superclass; // 8
        #     uint64_t cache;      // 16 (ignore)
        #     uint64_t vtable;     // 24 (ignore)
        #     uint64_t data;       // 32
        # }
        try:
            isa = self._read_ptr(addr)
            superclass_ptr = self._read_ptr(addr + 8)
            data_ptr = self._read_ptr(addr + 32)
        except ValueError:
            return None

        # Mask off the lower bits to get class_ro_t pointer
        ro_ptr = data_ptr & FAST_DATA_MASK
        if ro_ptr == 0:
            return None

        # Read class_ro_t structure
        # struct class_ro_t {
        #     uint32_t flags;          // 0
        #     uint32_t instanceStart;  // 4
        #     uint32_t instanceSize;   // 8
        #     uint32_t reserved;       // 12
        #     uint64_t ivarLayout;     // 16
        #     uint64_t name;           // 24
        #     uint64_t baseMethods;    // 32
        #     uint64_t baseProtocols;  // 40
        #     uint64_t ivars;          // 48
        #     uint64_t weakIvarLayout; // 56
        #     uint64_t baseProperties; // 64
        # }
        try:
            flags = self._read_u32(ro_ptr)
            instance_size = self._read_u32(ro_ptr + 8)
            name_ptr = self._read_ptr(ro_ptr + 24)
            methods_ptr = self._read_ptr(ro_ptr + 32)
            protocols_ptr = self._read_ptr(ro_ptr + 40)
            ivars_ptr = self._read_ptr(ro_ptr + 48)
            properties_ptr = self._read_ptr(ro_ptr + 64)
        except ValueError:
            return None

        # Read class name
        name = self._read_string(name_ptr)
        if not name:
            return None

        # Skip metaclasses for the main class list
        is_meta = bool(flags & RO_META)

        # Create class object
        cls = ObjCClass(
            address=addr,
            name=name,
            metaclass_address=isa,
            instance_size=instance_size,
            flags=flags,
        )

        # Parse superclass name
        if superclass_ptr:
            # Try to get superclass name from already parsed classes
            super_cls = self.metadata.get_class_at(superclass_ptr)
            if super_cls:
                cls.superclass = super_cls.name
            else:
                # Try to parse superclass
                super_cls = self._parse_class(superclass_ptr)
                if super_cls:
                    cls.superclass = super_cls.name

        # Parse methods
        if methods_ptr:
            methods = self._parse_method_list(methods_ptr, is_class_method=is_meta)
            if is_meta:
                cls.class_methods = methods
            else:
                cls.instance_methods = methods

        # Parse instance variables (only for non-metaclasses)
        if ivars_ptr and not is_meta:
            cls.ivars = self._parse_ivar_list(ivars_ptr)

        # Parse properties
        if properties_ptr:
            cls.properties = self._parse_property_list(properties_ptr)

        # Parse protocols
        if protocols_ptr:
            cls.protocols = self._parse_protocol_refs(protocols_ptr)

        # If this is not a metaclass, also parse the metaclass for class methods
        if not is_meta and isa:
            meta = self._parse_class(isa)
            if meta:
                cls.class_methods = meta.instance_methods

        self.metadata.add_class(cls)
        return cls

    def _parse_method_list(self, addr: int, is_class_method: bool = False) -> list[ObjCMethod]:
        """Parse method_list_t structure."""
        if addr == 0:
            return []

        # struct method_list_t {
        #     uint32_t entsize_and_flags;
        #     uint32_t count;
        #     // method_t entries follow
        # }
        try:
            entsize_and_flags = self._read_u32(addr)
            count = self._read_u32(addr + 4)
        except ValueError:
            return []

        if count == 0 or count > 10000:  # Sanity check
            return []

        # Entry size is in lower 16 bits
        entsize = entsize_and_flags & 0xFFFF

        # Check for relative method list format (entsize == 12, flag 0x80000000)
        # Modern arm64e binaries use relative 32-bit offsets instead of 64-bit pointers
        is_relative = entsize == 12 or (entsize_and_flags & 0x80000000) != 0
        if entsize == 0:
            entsize = 12 if is_relative else 24

        methods: list[ObjCMethod] = []
        base = addr + 8  # Skip header

        for i in range(count):
            method_addr = base + i * entsize

            if is_relative:
                # Relative method list format:
                # struct method_t {
                #     int32_t name;   // Relative offset to selector ref
                #     int32_t types;  // Relative offset to type encoding
                #     int32_t imp;    // Relative offset to implementation
                # }
                try:
                    name_off = self._read_i32(method_addr)
                    types_off = self._read_i32(method_addr + 4)
                    imp_off = self._read_i32(method_addr + 8)
                except ValueError:
                    continue

                # Calculate absolute addresses from relative offsets
                # Each offset is relative to its own field's address
                name_ref_addr = method_addr + name_off
                types_addr = (method_addr + 4) + types_off
                imp = (method_addr + 8) + imp_off

                # name_ref_addr points to __objc_selrefs, which contains
                # a chained fixup pointer to the actual selector string
                selector_ptr = self._read_ptr(name_ref_addr)
                selector = self._read_string(selector_ptr)
                type_encoding = self._read_string(types_addr)
            else:
                # Traditional method list format with 64-bit pointers:
                # struct method_t {
                #     uint64_t name;   // Selector pointer
                #     uint64_t types;  // Type encoding pointer
                #     uint64_t imp;    // Implementation address
                # }
                try:
                    name_ptr = self._read_ptr(method_addr)
                    types_ptr = self._read_ptr(method_addr + 8)
                    imp = self._read_ptr(method_addr + 16)
                except ValueError:
                    continue

                selector = self._read_string(name_ptr)
                type_encoding = self._read_string(types_ptr)

            if selector:
                methods.append(
                    ObjCMethod(
                        address=imp,
                        selector=selector,
                        type_encoding=type_encoding,
                        is_class_method=is_class_method,
                    )
                )

        return methods

    def _parse_ivar_list(self, addr: int) -> list[ObjCIvar]:
        """Parse ivar_list_t structure."""
        if addr == 0:
            return []

        # struct ivar_list_t {
        #     uint32_t entsize;
        #     uint32_t count;
        #     // ivar_t entries follow
        # }
        try:
            entsize = self._read_u32(addr)
            count = self._read_u32(addr + 4)
        except ValueError:
            return []

        if count == 0 or count > 1000:  # Sanity check
            return []

        if entsize == 0:
            entsize = 32  # Default ivar_t size

        ivars: list[ObjCIvar] = []
        base = addr + 8

        for i in range(count):
            ivar_addr = base + i * entsize

            # struct ivar_t {
            #     uint64_t offset_ptr;  // Pointer to offset value
            #     uint64_t name;        // Name pointer
            #     uint64_t type;        // Type encoding pointer
            #     uint32_t alignment;
            #     uint32_t size;
            # }
            try:
                offset_ptr = self._read_ptr(ivar_addr)
                name_ptr = self._read_ptr(ivar_addr + 8)
                type_ptr = self._read_ptr(ivar_addr + 16)
                size = self._read_u32(ivar_addr + 28)
            except ValueError:
                continue

            # Read actual offset value
            offset = self._read_u32(offset_ptr) if offset_ptr else 0
            name = self._read_string(name_ptr)
            type_encoding = self._read_string(type_ptr)

            if name:
                ivars.append(
                    ObjCIvar(
                        name=name,
                        type_encoding=type_encoding,
                        offset=offset,
                        size=size,
                    )
                )

        return ivars

    def _parse_property_list(self, addr: int) -> list[ObjCProperty]:
        """Parse property_list_t structure."""
        if addr == 0:
            return []

        # struct property_list_t {
        #     uint32_t entsize;
        #     uint32_t count;
        #     // property_t entries follow
        # }
        try:
            entsize = self._read_u32(addr)
            count = self._read_u32(addr + 4)
        except ValueError:
            return []

        if count == 0 or count > 1000:  # Sanity check
            return []

        if entsize == 0:
            entsize = 16  # Default property_t size

        properties: list[ObjCProperty] = []
        base = addr + 8

        for i in range(count):
            prop_addr = base + i * entsize

            # struct property_t {
            #     uint64_t name;
            #     uint64_t attributes;
            # }
            try:
                name_ptr = self._read_ptr(prop_addr)
                attrs_ptr = self._read_ptr(prop_addr + 8)
            except ValueError:
                continue

            name = self._read_string(name_ptr)
            attributes = self._read_string(attrs_ptr)

            if name:
                properties.append(
                    ObjCProperty(
                        name=name,
                        attributes=attributes,
                    )
                )

        return properties

    def _parse_protocol_refs(self, addr: int) -> list[str]:
        """Parse protocol_list_t to get protocol names."""
        if addr == 0:
            return []

        # struct protocol_list_t {
        #     uint64_t count;
        #     // protocol_t* entries follow
        # }
        try:
            count = self._read_ptr(addr)
        except ValueError:
            return []

        if count == 0 or count > 100:  # Sanity check
            return []

        protocols: list[str] = []
        base = addr + 8

        for i in range(int(count)):
            proto_ptr = self._read_ptr(base + i * 8)
            if proto_ptr:
                # Read protocol name from protocol_t structure
                # name is at offset 8 in protocol_t
                name_ptr = self._read_ptr(proto_ptr + 8)
                name = self._read_string(name_ptr)
                if name:
                    protocols.append(name)

        return protocols

    def _parse_catlist(self) -> None:
        """Parse __objc_catlist section for categories."""
        for cat_ptr in self._iter_section_ptrs("__objc_catlist"):
            self._parse_category(cat_ptr)

    def _parse_category(self, addr: int) -> ObjCCategory | None:
        """Parse a category structure."""
        # struct category_t {
        #     uint64_t name;
        #     uint64_t cls;
        #     uint64_t instanceMethods;
        #     uint64_t classMethods;
        #     uint64_t protocols;
        # }
        try:
            name_ptr = self._read_ptr(addr)
            cls_ptr = self._read_ptr(addr + 8)
            instance_methods_ptr = self._read_ptr(addr + 16)
            class_methods_ptr = self._read_ptr(addr + 24)
        except ValueError:
            return None

        name = self._read_string(name_ptr)
        if not name:
            return None

        # Get class name
        class_name = ""
        if cls_ptr:
            cls = self.metadata.get_class_at(cls_ptr)
            if cls:
                class_name = cls.name
            else:
                # Try to read class name from the class structure
                try:
                    data_ptr = self._read_ptr(cls_ptr + 32)
                    ro_ptr = data_ptr & FAST_DATA_MASK
                    if ro_ptr:
                        cn_ptr = self._read_ptr(ro_ptr + 24)
                        class_name = self._read_string(cn_ptr)
                except ValueError:
                    pass

        category = ObjCCategory(
            address=addr,
            name=name,
            class_name=class_name,
            instance_methods=tuple(self._parse_method_list(instance_methods_ptr, False)),
            class_methods=tuple(self._parse_method_list(class_methods_ptr, True)),
        )

        self.metadata.add_category(category)
        return category

    def _parse_protolist(self) -> None:
        """Parse __objc_protolist section for protocols."""
        for proto_ptr in self._iter_section_ptrs("__objc_protolist"):
            self._parse_protocol(proto_ptr)

    def _parse_protocol(self, addr: int) -> ObjCProtocol | None:
        """Parse a protocol structure."""
        # struct protocol_t {
        #     uint64_t isa;
        #     uint64_t name;
        #     uint64_t protocols;
        #     uint64_t instanceMethods;
        #     uint64_t classMethods;
        #     uint64_t optionalInstanceMethods;
        #     uint64_t optionalClassMethods;
        #     uint64_t instanceProperties;
        # }
        try:
            name_ptr = self._read_ptr(addr + 8)
            instance_methods_ptr = self._read_ptr(addr + 24)
            class_methods_ptr = self._read_ptr(addr + 32)
            properties_ptr = self._read_ptr(addr + 56)
        except ValueError:
            return None

        name = self._read_string(name_ptr)
        if not name:
            return None

        protocol = ObjCProtocol(
            address=addr,
            name=name,
            instance_methods=tuple(self._parse_method_list(instance_methods_ptr, False)),
            class_methods=tuple(self._parse_method_list(class_methods_ptr, True)),
            properties=tuple(self._parse_property_list(properties_ptr)),
        )
        self.metadata.add_protocol(protocol)
        return protocol

    def _parse_selrefs(self) -> None:
        """Parse __objc_selrefs section for selector references."""
        section = self._get_section("__objc_selrefs")
        if not section:
            return
        for i in range(section.size // 8):
            offset = i * 8
            raw = struct.unpack("<Q", section.data[offset : offset + 8])[0]
            sel_ptr = self._decode_ptr(raw)
            if sel_ptr:
                name = self._read_string(sel_ptr)
                if name:
                    self.metadata.add_selector(section.address + offset, name)
