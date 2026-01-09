```
   ██████╗██╗  ██╗██╗███╗   ███╗███████╗██████╗  █████╗
  ██╔════╝██║  ██║██║████╗ ████║██╔════╝██╔══██╗██╔══██╗
  ██║     ███████║██║██╔████╔██║█████╗  ██████╔╝███████║
  ██║     ██╔══██║██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║
  ╚██████╗██║  ██║██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║
   ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
```

A reverse engineering framework for ARM64 macOS binaries.

## Features

- **Mach-O Loader** — Parse Mach-O binaries including universal (fat) binaries
- **ARM64 Disassembler** — Full instruction decoding with operand and register models
- **Analysis Engine** — Control flow graphs, function detection, cross-references
- **Decompiler** — Lift to IR, simplify, and generate pseudo-C output
- **Type System** — Composite types, stack frame analysis, argument detection, type inference
- **Binary Diffing** — BinDiff-style comparison with function matching and similarity scoring
- **Objective-C Analysis** — Parse classes, methods, protocols, and selectors
- **Search** — String extraction and byte pattern scanning with wildcards
- **CLI & API** — Interactive terminal interface and clean Python API

## Installation

Requires Python 3.12+ and [uv](https://github.com/astral-sh/uv).

```bash
git clone https://github.com/markoelez/chimera.git
cd chimera
uv sync
```

## Usage

### CLI

```bash
# Binary info
chimera info ./binary

# List functions
chimera funcs ./binary

# Disassemble at address or function name
chimera disasm ./binary 0x100000000
chimera disasm ./binary _main

# Decompile a function
chimera decomp ./binary _main

# Show cross-references
chimera xrefs ./binary 0x100000000

# Search strings
chimera strings ./binary
chimera strings ./binary --search "password"

# Byte pattern search (supports ?? wildcards)
chimera search ./binary "48 8b ?? c3"

# Compare two binaries (diff)
chimera diff ./old_binary ./new_binary
chimera diff ./old_binary ./new_binary -v  # verbose

# Objective-C analysis
chimera objc ./binary
chimera objc ./binary --class NSObject

# Interactive mode
chimera interactive ./binary
```

### Python API

```python
from chimera import Project

# Load and analyze
proj = Project.load("./binary")
proj.analyze()

# List functions
for func in proj.functions:
    print(f"{func.name} @ {func.address:#x}")

# Disassemble
for insn in proj.disassemble(0x100000000, count=10):
    print(f"{insn.address:#x}: {insn}")

# Decompile
print(proj.decompile("_main"))

# Cross-references
for xref in proj.xrefs_to(0x100000000):
    print(f"{xref.from_addr:#x} -> {xref.to_addr:#x}")

# String search
for s in proj.strings(min_length=8):
    print(f"{s.address:#x}: {s.value}")

# Pattern search with wildcards
for match in proj.search_bytes("48 8b ?? c3"):
    print(f"{match.address:#x}: {match.matched_bytes.hex()}")

# Binary diffing
proj2 = Project.load("./binary_v2")
proj2.analyze()
diff = proj.diff(proj2)
print(f"Similarity: {diff.similarity:.1%}")
print(f"Modified functions: {diff.modified_count}")

# Objective-C metadata
if proj.objc:
    for cls in proj.objc.classes:
        print(f"@interface {cls.name}")
        for method in cls.methods:
            print(f"  {method}")
```

## Dev

```bash
# Install with dev dependencies
uv sync --all-extras

# Run tests
uv run pytest tests -v

# Lint & format
uv run ruff check src tests --fix
uv run ruff format src tests

# Type check
uv run ty check src

# Install pre-commit hooks
uv run pre-commit install
```

## License

MIT

