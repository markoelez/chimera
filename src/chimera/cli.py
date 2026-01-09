"""Command-line interface for Chimera."""

from pathlib import Path

import click
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.console import Console

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def main() -> None:
    """Chimera - ARM64 macOS reverse engineering framework."""
    pass


@main.command()
@click.argument("binary", type=click.Path(exists=True))
def info(binary: str) -> None:
    """Display binary information."""
    from chimera import Project

    with Project.load(binary) as proj:
        if not proj.binary:
            console.print("[red]Failed to load binary[/red]")
            return

        b = proj.binary

        console.print(Panel.fit(f"[bold]{Path(binary).name}[/bold]", title="Binary Info"))

        table = Table(show_header=False)
        table.add_column("Property", style="cyan")
        table.add_column("Value")

        table.add_row("Path", str(b.path))
        table.add_row("Entry Point", f"{b.entry_point:#x}")
        table.add_row("UUID", b.uuid.hex() if b.uuid else "N/A")
        table.add_row("Segments", str(len(b.segments)))
        table.add_row("Symbols", str(len(b.symbols)))
        table.add_row("Libraries", str(len(b.dylibs)))

        console.print(table)

        # Show segments
        console.print("\n[bold]Segments:[/bold]")
        seg_table = Table()
        seg_table.add_column("Name")
        seg_table.add_column("Address", style="green")
        seg_table.add_column("Size")
        seg_table.add_column("Sections")

        for seg in b.segments:
            seg_table.add_row(
                seg.name,
                f"{seg.vmaddr:#x}",
                f"{seg.vmsize:#x}",
                str(len(seg.sections)),
            )

        console.print(seg_table)


@main.command()
@click.argument("binary", type=click.Path(exists=True))
def funcs(binary: str) -> None:
    """List all detected functions."""
    from chimera import Project

    with Project.load(binary) as proj:
        proj.analyze()

        table = Table(title="Functions")
        table.add_column("Address", style="green")
        table.add_column("Name", style="cyan")
        table.add_column("Size")
        table.add_column("Blocks")
        table.add_column("Leaf")

        for func in sorted(proj.functions, key=lambda f: f.address):
            blocks = len(func.basic_blocks) if func.cfg else 0
            leaf = "✓" if func.is_leaf else ""
            table.add_row(
                f"{func.address:#x}",
                func.name,
                f"{func.size}",
                str(blocks),
                leaf,
            )

        console.print(table)
        console.print(f"\nTotal: {len(proj.functions)} functions")


@main.command()
@click.argument("binary", type=click.Path(exists=True))
@click.argument("target")
@click.option("-n", "--count", default=20, help="Number of instructions")
def disasm(binary: str, target: str, count: int) -> None:
    """Disassemble at address or function name."""
    from chimera import Project

    with Project.load(binary) as proj:
        proj.analyze()

        # Parse target as address or function name
        addr: int | None = None
        func_name: str | None = None

        try:
            addr = int(target, 0)
        except ValueError:
            func_name = target

        if func_name:
            func = proj.get_function_by_name(func_name)
            if not func:
                console.print(f"[red]Function not found: {func_name}[/red]")
                return
            addr = func.address
            console.print(f"[bold]{func.name}[/bold] @ {addr:#x}\n")

        if addr is None:
            console.print("[red]Invalid target[/red]")
            return

        # Get symbol info
        sym_info = proj.closest_symbol(addr)
        if sym_info and func_name is None:
            sym, offset = sym_info
            if offset == 0:
                console.print(f"[bold]{sym.name}[/bold]:\n")
            else:
                console.print(f"[bold]{sym.name}+{offset:#x}[/bold]:\n")

        # Disassemble
        try:
            instructions = proj.disassemble(addr, count)
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            return

        for insn in instructions:
            # Format: address  bytes  mnemonic operands
            hex_bytes = " ".join(f"{b:02x}" for b in insn.bytes)

            # Check for xrefs
            xrefs = proj.xrefs_to(insn.address)
            xref_str = ""
            if xrefs:
                xref_str = f"  ; {len(xrefs)} xref(s)"

            # Color based on instruction type
            if insn.is_call:
                style = "yellow"
            elif insn.is_branch or insn.is_return:
                style = "magenta"
            elif insn.is_load or insn.is_store:
                style = "blue"
            else:
                style = "white"

            line = f"[green]{insn.address:016x}[/green]  {hex_bytes:<12}  [{style}]{insn.mnemonic:<8}[/{style}] {insn.op_str}{xref_str}"
            console.print(line)


@main.command()
@click.argument("binary", type=click.Path(exists=True))
@click.argument("target")
def decomp(binary: str, target: str) -> None:
    """Decompile a function."""
    from chimera import Project

    with Project.load(binary) as proj:
        proj.analyze()

        # Parse target
        func = None
        try:
            addr = int(target, 0)
            func = proj.get_function(addr)
        except ValueError:
            func = proj.get_function_by_name(target)

        if not func:
            console.print(f"[red]Function not found: {target}[/red]")
            return

        try:
            code = proj.decompile(func)
            syntax = Syntax(code, "c", theme="monokai", line_numbers=True)
            console.print(Panel(syntax, title=f"{func.name}", subtitle=f"{func.address:#x}"))
        except Exception as e:
            console.print(f"[red]Decompilation failed: {e}[/red]")


@main.command()
@click.argument("binary", type=click.Path(exists=True))
@click.argument("address")
def xrefs(binary: str, address: str) -> None:
    """Show cross-references to/from an address."""
    from chimera import Project

    with Project.load(binary) as proj:
        proj.analyze()

        try:
            addr = int(address, 0)
        except ValueError:
            console.print(f"[red]Invalid address: {address}[/red]")
            return

        # Show symbol at address
        sym = proj.symbol_at(addr)
        if sym:
            console.print(f"[bold]{sym.name}[/bold] @ {addr:#x}\n")
        else:
            console.print(f"Address: [green]{addr:#x}[/green]\n")

        # Xrefs TO this address
        to_xrefs = proj.xrefs_to(addr)
        if to_xrefs:
            console.print("[bold]References TO this address:[/bold]")
            table = Table()
            table.add_column("From", style="green")
            table.add_column("Type", style="cyan")
            table.add_column("Function")

            for xref in to_xrefs:
                # Find containing function
                func_name = ""
                for func in proj.functions:
                    if func.address <= xref.from_addr < func.end_address:
                        func_name = func.name
                        break

                table.add_row(
                    f"{xref.from_addr:#x}",
                    xref.xref_type.name,
                    func_name,
                )

            console.print(table)
        else:
            console.print("[dim]No references to this address[/dim]")

        console.print()

        # Xrefs FROM this address
        from_xrefs = proj.xrefs_from(addr)
        if from_xrefs:
            console.print("[bold]References FROM this address:[/bold]")
            table = Table()
            table.add_column("To", style="green")
            table.add_column("Type", style="cyan")
            table.add_column("Symbol")

            for xref in from_xrefs:
                sym = proj.symbol_at(xref.to_addr)
                sym_name = sym.name if sym else ""

                table.add_row(
                    f"{xref.to_addr:#x}",
                    xref.xref_type.name,
                    sym_name,
                )

            console.print(table)
        else:
            console.print("[dim]No references from this address[/dim]")


@main.command()
@click.argument("binary", type=click.Path(exists=True))
def symbols(binary: str) -> None:
    """List symbols in binary."""
    from chimera import Project
    from chimera.loader.symbols import SymbolType

    with Project.load(binary) as proj:
        if not proj.binary:
            console.print("[red]Failed to load binary[/red]")
            return

        table = Table(title="Symbols")
        table.add_column("Address", style="green")
        table.add_column("Type", style="cyan")
        table.add_column("Name")

        for sym in proj.symbols:
            if sym.symbol_type == SymbolType.DEBUG:
                continue  # Skip debug symbols

            type_style = {
                SymbolType.GLOBAL: "green",
                SymbolType.LOCAL: "yellow",
                SymbolType.UNDEFINED: "red",
            }.get(sym.symbol_type, "white")

            table.add_row(
                f"{sym.address:#x}" if sym.address else "--------",
                f"[{type_style}]{sym.symbol_type.name}[/{type_style}]",
                sym.name,
            )

        console.print(table)


@main.command("strings")
@click.argument("binary", type=click.Path(exists=True))
@click.option("-n", "--min-length", default=4, help="Minimum string length")
@click.option("-s", "--search", "query", default=None, help="Filter strings containing text")
@click.option("-i", "--ignore-case", is_flag=True, help="Case-insensitive search")
@click.option("--section", default=None, help="Limit to specific section")
@click.option("--limit", default=100, help="Maximum results to show")
def strings_cmd(
    binary: str,
    min_length: int,
    query: str | None,
    ignore_case: bool,
    section: str | None,
    limit: int,
) -> None:
    """Extract and search strings in binary."""
    from chimera import Project

    with Project.load(binary) as proj:
        if not proj.binary:
            console.print("[red]Failed to load binary[/red]")
            return

        sections = {section} if section else None

        if query:
            # Search mode
            matches = proj.search_strings(
                query,
                case_sensitive=not ignore_case,
                min_length=min_length,
            )
            # Filter by section if specified
            if section:
                matches = [m for m in matches if m.section == section]
        else:
            # List all strings
            matches = proj.strings(min_length, sections)

        if not matches:
            console.print("[dim]No strings found[/dim]")
            return

        table = Table(title=f"Strings ({len(matches)} found)")
        table.add_column("Address", style="green")
        table.add_column("Section", style="cyan")
        table.add_column("String")

        for match in matches[:limit]:
            # Truncate long strings for display
            value = match.value
            if len(value) > 60:
                value = value[:57] + "..."
            # Escape control characters for display
            value = value.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")

            table.add_row(
                f"{match.address:#x}",
                match.section,
                value,
            )

        console.print(table)

        if len(matches) > limit:
            console.print(
                f"\n[dim]Showing {limit} of {len(matches)} results. Use --limit to see more.[/dim]"
            )


@main.command("search")
@click.argument("binary", type=click.Path(exists=True))
@click.argument("pattern")
@click.option("--section", default=None, help="Limit to specific section")
@click.option("--limit", default=50, help="Maximum results to show")
@click.option("-c", "--context", default=0, help="Bytes of context to show before/after")
def search_cmd(
    binary: str,
    pattern: str,
    section: str | None,
    limit: int,
    context: int,
) -> None:
    """Search for byte patterns in binary.

    PATTERN is a hex string with optional wildcards (??).

    Examples:

        chimera search binary "48 8b"           # Exact bytes

        chimera search binary "fd 7b ?? a9"     # With wildcard

        chimera search binary "ff4300"          # No spaces
    """
    from chimera import Project

    with Project.load(binary) as proj:
        if not proj.binary:
            console.print("[red]Failed to load binary[/red]")
            return

        sections = {section} if section else None

        try:
            matches = proj.search_bytes(pattern, sections)
        except ValueError as e:
            console.print(f"[red]Invalid pattern: {e}[/red]")
            return

        if not matches:
            console.print("[dim]No matches found[/dim]")
            return

        console.print(f"[bold]Pattern:[/bold] {pattern}\n")

        table = Table(title=f"Matches ({len(matches)} found)")
        table.add_column("Address", style="green")
        table.add_column("Section", style="cyan")
        table.add_column("Bytes")

        for match in matches[:limit]:
            hex_bytes = " ".join(f"{b:02x}" for b in match.matched_bytes)

            # Add context if requested
            if context > 0:
                try:
                    before = proj.read(match.address - context, context)
                    after = proj.read(match.address + len(match.matched_bytes), context)
                    before_hex = " ".join(f"{b:02x}" for b in before)
                    after_hex = " ".join(f"{b:02x}" for b in after)
                    hex_bytes = f"[dim]{before_hex}[/dim] {hex_bytes} [dim]{after_hex}[/dim]"
                except ValueError:
                    pass  # Can't read context at boundaries

            table.add_row(
                f"{match.address:#x}",
                match.section,
                hex_bytes,
            )

        console.print(table)

        if len(matches) > limit:
            console.print(
                f"\n[dim]Showing {limit} of {len(matches)} results. Use --limit to see more.[/dim]"
            )


@main.command("objc")
@click.argument("binary", type=click.Path(exists=True))
@click.option("--classes", "list_classes", is_flag=True, help="List all classes")
@click.option("--class", "class_name", default=None, help="Show details for a class")
@click.option("--protocols", is_flag=True, help="List all protocols")
@click.option("--categories", is_flag=True, help="List all categories")
@click.option("--selector", default=None, help="Find methods by selector name")
def objc_cmd(
    binary: str,
    list_classes: bool,
    class_name: str | None,
    protocols: bool,
    categories: bool,
    selector: str | None,
) -> None:
    """Analyze Objective-C metadata."""
    from chimera import Project

    with Project.load(binary) as proj:
        proj.analyze()

        if not proj.objc:
            console.print("[dim]No Objective-C metadata found[/dim]")
            return

        objc = proj.objc

        if class_name:
            # Show details for a specific class
            cls = objc.get_class(class_name)
            if not cls:
                console.print(f"[red]Class not found: {class_name}[/red]")
                return

            console.print(f"\n[bold]Class: {cls.name}[/bold] @ {cls.address:#x}")
            console.print(f"Superclass: {cls.superclass or 'None'}")
            console.print(f"Instance Size: {cls.instance_size} bytes")

            if cls.protocols:
                console.print(f"Protocols: {', '.join(cls.protocols)}")

            if cls.instance_methods:
                console.print("\n[bold]Instance Methods:[/bold]")
                for method in cls.instance_methods:
                    console.print(
                        f"  [cyan]-[{cls.name} {method.selector}][/cyan] @ {method.address:#x}"
                    )

            if cls.class_methods:
                console.print("\n[bold]Class Methods:[/bold]")
                for method in cls.class_methods:
                    console.print(
                        f"  [cyan]+[{cls.name} {method.selector}][/cyan] @ {method.address:#x}"
                    )

            if cls.properties:
                console.print("\n[bold]Properties:[/bold]")
                for prop in cls.properties:
                    console.print(f"  {prop.name}: {prop.attributes}")

            if cls.ivars:
                console.print("\n[bold]Instance Variables:[/bold]")
                for ivar in cls.ivars:
                    console.print(
                        f"  {ivar.name}: {ivar.type_encoding} (offset: {ivar.offset}, size: {ivar.size})"
                    )

        elif selector:
            # Find methods by selector
            matches = objc.methods_named(selector)
            if not matches:
                console.print(f"[dim]No methods found with selector: {selector}[/dim]")
                return

            console.print(f"\n[bold]Methods matching '{selector}':[/bold]\n")
            table = Table()
            table.add_column("Class", style="cyan")
            table.add_column("Type")
            table.add_column("Address", style="green")

            for cls, method in matches:
                prefix = "+" if method.is_class_method else "-"
                table.add_row(cls.name, prefix, f"{method.address:#x}")

            console.print(table)

        elif protocols:
            # List all protocols
            proto_list = objc.protocols
            if not proto_list:
                console.print("[dim]No protocols found[/dim]")
                return

            table = Table(title=f"Protocols ({len(proto_list)} found)")
            table.add_column("Address", style="green")
            table.add_column("Name", style="cyan")
            table.add_column("Methods")

            for proto in proto_list:
                method_count = len(proto.instance_methods) + len(proto.class_methods)
                table.add_row(f"{proto.address:#x}", proto.name, str(method_count))

            console.print(table)

        elif categories:
            # List all categories
            cat_list = objc.categories
            if not cat_list:
                console.print("[dim]No categories found[/dim]")
                return

            table = Table(title=f"Categories ({len(cat_list)} found)")
            table.add_column("Address", style="green")
            table.add_column("Category", style="cyan")
            table.add_column("Class", style="yellow")
            table.add_column("Methods")

            for cat in cat_list:
                method_count = len(cat.instance_methods) + len(cat.class_methods)
                table.add_row(f"{cat.address:#x}", cat.name, cat.class_name, str(method_count))

            console.print(table)

        else:
            # Default: list all classes (or if --classes flag)
            classes = objc.classes
            if not classes:
                console.print("[dim]No Objective-C classes found[/dim]")
                return

            table = Table(title=f"Objective-C Classes ({len(classes)} found)")
            table.add_column("Address", style="green")
            table.add_column("Class", style="cyan")
            table.add_column("Superclass")
            table.add_column("Methods", justify="right")
            table.add_column("Ivars", justify="right")

            for cls in classes:
                table.add_row(
                    f"{cls.address:#x}",
                    cls.name,
                    cls.superclass or "",
                    str(cls.method_count),
                    str(len(cls.ivars)),
                )

            console.print(table)


@main.command("diff")
@click.argument("primary", type=click.Path(exists=True))
@click.argument("secondary", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("-t", "--threshold", default=0.5, help="Minimum similarity threshold (0.0-1.0)")
@click.option("-v", "--verbose", is_flag=True, help="Show detailed output")
def diff_cmd(
    primary: str,
    secondary: str,
    as_json: bool,
    threshold: float,
    verbose: bool,
) -> None:
    """Compare two binaries and show differences.

    Performs BinDiff-style analysis to match functions between two binary
    versions and identify what has changed.
    """
    import json as json_mod

    from chimera import Project

    console.print("Comparing binaries...")
    console.print(f"  Primary:   {primary}")
    console.print(f"  Secondary: {secondary}\n")

    proj1 = Project.load(primary)
    proj2 = Project.load(secondary)
    proj1.analyze()
    proj2.analyze()

    result = proj1.diff(proj2)

    if as_json:
        # JSON output
        data = {
            "primary": result.primary_path,
            "secondary": result.secondary_path,
            "primary_sha256": result.primary_sha256,
            "secondary_sha256": result.secondary_sha256,
            "similarity": result.similarity,
            "matched": result.matched_count,
            "identical": result.identical_count,
            "modified": result.modified_count,
            "added": result.added_count,
            "removed": result.removed_count,
            "matched_functions": [
                {
                    "primary_name": m.primary.name,
                    "primary_addr": f"{m.primary.address:#x}",
                    "secondary_name": m.secondary.name,
                    "secondary_addr": f"{m.secondary.address:#x}",
                    "similarity": m.similarity,
                    "strategy": m.strategy.name,
                }
                for m in result.matched_functions
            ],
            "added_functions": [
                {"name": u.function.name, "addr": f"{u.function.address:#x}"}
                for u in result.unmatched_secondary
            ],
            "removed_functions": [
                {"name": u.function.name, "addr": f"{u.function.address:#x}"}
                for u in result.unmatched_primary
            ],
        }
        console.print(json_mod.dumps(data, indent=2))
        proj1.close()
        proj2.close()
        return

    # Summary panel
    summary = Panel.fit(
        f"Similarity: [bold]{result.similarity:.1%}[/bold]\n\n"
        f"Matched:   {result.matched_count}\n"
        f"Identical: {result.identical_count}\n"
        f"Modified:  {result.modified_count}\n"
        f"Added:     {result.added_count}\n"
        f"Removed:   {result.removed_count}",
        title="Diff Summary",
    )
    console.print(summary)

    # Modified functions
    modified = result.get_modified(min_similarity=threshold)
    if modified:
        console.print("\n[bold]Modified Functions:[/bold]")
        table = Table()
        table.add_column("Primary", style="cyan")
        table.add_column("Secondary", style="cyan")
        table.add_column("Similarity")
        table.add_column("Strategy")

        for match in sorted(modified, key=lambda m: m.similarity):
            sim_color = (
                "green" if match.similarity > 0.8 else "yellow" if match.similarity > 0.6 else "red"
            )
            table.add_row(
                match.primary.name,
                match.secondary.name if match.secondary.name != match.primary.name else "",
                f"[{sim_color}]{match.similarity:.1%}[/{sim_color}]",
                match.strategy.name,
            )

        console.print(table)

    # Added functions
    if result.unmatched_secondary and verbose:
        console.print("\n[bold green]Added Functions:[/bold green]")
        for u in result.unmatched_secondary[:20]:
            console.print(f"  + {u.function.name} @ {u.function.address:#x}")
        if len(result.unmatched_secondary) > 20:
            console.print(f"  ... and {len(result.unmatched_secondary) - 20} more")

    # Removed functions
    if result.unmatched_primary and verbose:
        console.print("\n[bold red]Removed Functions:[/bold red]")
        for u in result.unmatched_primary[:20]:
            console.print(f"  - {u.function.name} @ {u.function.address:#x}")
        if len(result.unmatched_primary) > 20:
            console.print(f"  ... and {len(result.unmatched_primary) - 20} more")

    proj1.close()
    proj2.close()


@main.command("diff-func")
@click.argument("primary", type=click.Path(exists=True))
@click.argument("secondary", type=click.Path(exists=True))
@click.argument("function_name")
def diff_func_cmd(primary: str, secondary: str, function_name: str) -> None:
    """Show detailed diff for a specific function.

    Compares a function between two binary versions and shows basic block
    level changes.
    """
    from chimera import Project
    from chimera.analysis.diff import BinaryDiffAnalyzer

    console.print(f"Comparing function: [bold]{function_name}[/bold]\n")

    proj1 = Project.load(primary)
    proj2 = Project.load(secondary)
    proj1.analyze()
    proj2.analyze()

    analyzer = BinaryDiffAnalyzer(proj1, proj2)
    result = analyzer.analyze()

    # Find the match for this function
    match = None
    for m in result.matched_functions:
        if m.primary.name == function_name or m.secondary.name == function_name:
            match = m
            break

    if not match:
        # Check if it was added or removed
        for u in result.unmatched_primary:
            if u.function.name == function_name:
                console.print(
                    f"[red]Function '{function_name}' was removed in secondary binary[/red]"
                )
                proj1.close()
                proj2.close()
                return
        for u in result.unmatched_secondary:
            if u.function.name == function_name:
                console.print(
                    f"[green]Function '{function_name}' was added in secondary binary[/green]"
                )
                proj1.close()
                proj2.close()
                return
        console.print(f"[red]Function not found: {function_name}[/red]")
        proj1.close()
        proj2.close()
        return

    # Get detailed block diff
    func_diff = analyzer.get_function_diff(match)

    # Show function info
    console.print(
        f"[cyan]Primary:[/cyan]   {match.primary.name} @ {match.primary.address:#x} ({match.primary.size} bytes)"
    )
    console.print(
        f"[cyan]Secondary:[/cyan] {match.secondary.name} @ {match.secondary.address:#x} ({match.secondary.size} bytes)"
    )
    console.print(f"[cyan]Similarity:[/cyan] {match.similarity:.1%}")
    console.print(f"[cyan]Strategy:[/cyan]   {match.strategy.name}")

    if match.is_identical:
        console.print("\n[green]Functions are byte-identical[/green]")
    else:
        # Show block comparison
        console.print("\n[bold]Basic Block Analysis:[/bold]")
        console.print(f"  Matched blocks: {len(func_diff.matched_blocks)}")
        console.print(f"  Primary-only:   {len(func_diff.unmatched_primary)}")
        console.print(f"  Secondary-only: {len(func_diff.unmatched_secondary)}")

        if func_diff.matched_blocks:
            console.print("\n[bold]Matched Blocks:[/bold]")
            table = Table()
            table.add_column("Primary", style="green")
            table.add_column("Secondary", style="green")
            table.add_column("Similarity")

            for bm in func_diff.matched_blocks:
                sim_color = "green" if bm.similarity > 0.9 else "yellow"
                table.add_row(
                    f"{bm.primary.address:#x}",
                    f"{bm.secondary.address:#x}",
                    f"[{sim_color}]{bm.similarity:.1%}[/{sim_color}]",
                )
            console.print(table)

        if func_diff.unmatched_primary:
            console.print("\n[bold red]Removed Blocks (in primary only):[/bold red]")
            for b in func_diff.unmatched_primary:
                console.print(f"  - {b.address:#x} ({len(b.instructions)} insns)")

        if func_diff.unmatched_secondary:
            console.print("\n[bold green]Added Blocks (in secondary only):[/bold green]")
            for b in func_diff.unmatched_secondary:
                console.print(f"  + {b.address:#x} ({len(b.instructions)} insns)")

    proj1.close()
    proj2.close()


@main.command("patch-analysis")
@click.argument("primary", type=click.Path(exists=True))
@click.argument("secondary", type=click.Path(exists=True))
@click.option("-v", "--verbose", is_flag=True, help="Show all modified functions")
def patch_analysis_cmd(primary: str, secondary: str, verbose: bool) -> None:
    """Analyze security-relevant changes between two binaries.

    Identifies modifications to functions that may be security-relevant based
    on their names (validation, authentication, parsing, etc.).
    """
    from chimera import Project
    from chimera.analysis.diff import BinaryDiffAnalyzer

    console.print("[bold]Security Patch Analysis[/bold]\n")
    console.print(f"  Primary:   {primary}")
    console.print(f"  Secondary: {secondary}\n")

    proj1 = Project.load(primary)
    proj2 = Project.load(secondary)
    proj1.analyze()
    proj2.analyze()

    analyzer = BinaryDiffAnalyzer(proj1, proj2)
    security_changes = analyzer.find_security_changes()

    if not security_changes:
        console.print("[dim]No security-relevant changes detected[/dim]")
        proj1.close()
        proj2.close()
        return

    console.print(
        f"[bold yellow]Found {len(security_changes)} security-relevant changes:[/bold yellow]\n"
    )

    table = Table(title="Security-Relevant Modified Functions")
    table.add_column("Function", style="cyan")
    table.add_column("Similarity")
    table.add_column("Strategy")
    table.add_column("Category")

    # Categorize security functions
    categories = {
        "auth": ["auth", "login", "password", "credential", "session", "token"],
        "validation": ["valid", "verify", "check", "sanitize", "escape", "filter"],
        "bounds": ["bound", "overflow", "underflow", "size", "length", "limit", "max", "min"],
        "parsing": ["parse", "decode", "encode", "input"],
        "crypto": ["crypt", "hash", "sign", "cert", "key"],
    }

    for match in sorted(security_changes, key=lambda m: m.similarity):
        name_lower = match.primary.name.lower()
        category = "other"
        for cat, keywords in categories.items():
            if any(kw in name_lower for kw in keywords):
                category = cat
                break

        cat_colors = {
            "auth": "red",
            "validation": "yellow",
            "bounds": "magenta",
            "parsing": "blue",
            "crypto": "cyan",
            "other": "white",
        }
        cat_color = cat_colors.get(category, "white")

        sim_color = (
            "green" if match.similarity > 0.8 else "yellow" if match.similarity > 0.6 else "red"
        )
        table.add_row(
            match.primary.name,
            f"[{sim_color}]{match.similarity:.1%}[/{sim_color}]",
            match.strategy.name,
            f"[{cat_color}]{category}[/{cat_color}]",
        )

    console.print(table)

    # Show recommendations
    console.print("\n[bold]Recommendations:[/bold]")
    auth_changes = [
        m
        for m in security_changes
        if any(k in m.primary.name.lower() for k in ["auth", "login", "password"])
    ]
    if auth_changes:
        console.print("[red]  ! Authentication-related changes detected - review carefully[/red]")

    bounds_changes = [
        m
        for m in security_changes
        if any(k in m.primary.name.lower() for k in ["bound", "size", "length", "overflow"])
    ]
    if bounds_changes:
        console.print(
            "[yellow]  ! Bounds-checking changes detected - potential memory safety fix[/yellow]"
        )

    console.print("\n[dim]Use 'chimera diff-func' to examine specific function changes.[/dim]")

    proj1.close()
    proj2.close()


@main.command("callgraph")
@click.argument("binary", type=click.Path(exists=True))
@click.option("--roots", is_flag=True, help="Show root functions (not called by others)")
@click.option("--leaves", is_flag=True, help="Show leaf functions (don't call anything)")
@click.option("--recursive", is_flag=True, help="Show recursive functions")
@click.option("--function", "func_addr", default=None, help="Show callers/callees of function")
@click.option("--path", "path_pair", nargs=2, default=None, help="Find call path FROM TO")
@click.option("--depth", is_flag=True, help="Show call depth for each function")
@click.option("--stats", is_flag=True, help="Show call graph statistics")
@click.option("--dot", is_flag=True, help="Output DOT format for Graphviz")
@click.option("--limit", default=50, help="Maximum results to show")
def callgraph_cmd(
    binary: str,
    roots: bool,
    leaves: bool,
    recursive: bool,
    func_addr: str | None,
    path_pair: tuple[str, str] | None,
    depth: bool,
    stats: bool,
    dot: bool,
    limit: int,
) -> None:
    """Analyze function call graph.

    Shows inter-procedural call relationships between functions.
    """
    from chimera import Project

    with Project.load(binary) as proj:
        proj.analyze()

        cg = proj.call_graph
        if cg is None or len(cg) == 0:
            console.print("[dim]No call graph available[/dim]")
            return

        if dot:
            # Output DOT format
            console.print(cg.to_dot())
            return

        if stats:
            # Show statistics
            cg.compute_depths()
            recursive_funcs = cg.recursive_functions()
            root_funcs = cg.root_functions()
            leaf_funcs = cg.leaf_functions()
            max_depth = max((n.depth for n in cg.nodes.values() if n.depth >= 0), default=0)

            console.print(
                Panel.fit(
                    f"Total functions: [bold]{len(cg.nodes)}[/bold]\n"
                    f"Total call edges: [bold]{len(cg.edges)}[/bold]\n"
                    f"Root functions: [bold]{len(root_funcs)}[/bold]\n"
                    f"Leaf functions: [bold]{len(leaf_funcs)}[/bold]\n"
                    f"Recursive functions: [bold]{len(recursive_funcs)}[/bold]\n"
                    f"Max call depth: [bold]{max_depth}[/bold]",
                    title="Call Graph Statistics",
                )
            )
            return

        if func_addr:
            # Show callers/callees of a specific function
            try:
                addr = int(func_addr, 0)
            except ValueError:
                # Try to find by name
                func = proj.get_function_by_name(func_addr)
                if not func:
                    console.print(f"[red]Function not found: {func_addr}[/red]")
                    return
                addr = func.address

            if addr not in cg.nodes:
                console.print(f"[red]Function not in call graph: {addr:#x}[/red]")
                return

            node = cg.nodes[addr]
            func = proj.get_function(addr)
            func_name = func.name if func else node.name

            console.print(f"\n[bold]Function: {func_name}[/bold] @ {addr:#x}")
            console.print(f"Depth: {node.depth}")
            console.print(f"Recursive: {'Yes' if node.is_recursive else 'No'}")

            if node.callers:
                console.print("\n[bold]Called by:[/bold]")
                for caller_addr in sorted(node.callers):
                    caller_func = proj.get_function(caller_addr)
                    caller_name = caller_func.name if caller_func else f"sub_{caller_addr:x}"
                    console.print(f"  {caller_addr:#x}  {caller_name}")

            if node.callees:
                console.print("\n[bold]Calls:[/bold]")
                for callee_addr in sorted(node.callees):
                    callee_func = proj.get_function(callee_addr)
                    callee_name = callee_func.name if callee_func else f"sub_{callee_addr:x}"
                    console.print(f"  {callee_addr:#x}  {callee_name}")

            return

        if path_pair:
            # Find path between two functions
            from_str, to_str = path_pair

            # Parse from address
            try:
                from_addr = int(from_str, 0)
            except ValueError:
                func = proj.get_function_by_name(from_str)
                if not func:
                    console.print(f"[red]Function not found: {from_str}[/red]")
                    return
                from_addr = func.address

            # Parse to address
            try:
                to_addr = int(to_str, 0)
            except ValueError:
                func = proj.get_function_by_name(to_str)
                if not func:
                    console.print(f"[red]Function not found: {to_str}[/red]")
                    return
                to_addr = func.address

            path = cg.shortest_path(from_addr, to_addr)
            if path:
                console.print(f"\n[bold]Call path ({len(path)} hops):[/bold]\n")
                for i, addr in enumerate(path):
                    func = proj.get_function(addr)
                    name = func.name if func else f"sub_{addr:x}"
                    prefix = "  " if i == 0 else "  -> "
                    console.print(f"{prefix}[cyan]{name}[/cyan] @ {addr:#x}")
            else:
                console.print("[dim]No call path found between these functions[/dim]")
            return

        if roots:
            # Show root functions
            root_addrs = cg.root_functions()
            console.print(f"\n[bold]Root Functions ({len(root_addrs)} found):[/bold]\n")

            table = Table()
            table.add_column("Address", style="green")
            table.add_column("Name", style="cyan")
            table.add_column("Callees", justify="right")

            for addr in sorted(root_addrs)[:limit]:
                func = proj.get_function(addr)
                name = func.name if func else f"sub_{addr:x}"
                callees = len(cg.nodes[addr].callees) if addr in cg.nodes else 0
                table.add_row(f"{addr:#x}", name, str(callees))

            console.print(table)
            if len(root_addrs) > limit:
                console.print(
                    f"\n[dim]Showing {limit} of {len(root_addrs)}. Use --limit to see more.[/dim]"
                )
            return

        if leaves:
            # Show leaf functions
            leaf_addrs = cg.leaf_functions()
            console.print(f"\n[bold]Leaf Functions ({len(leaf_addrs)} found):[/bold]\n")

            table = Table()
            table.add_column("Address", style="green")
            table.add_column("Name", style="cyan")
            table.add_column("Callers", justify="right")

            for addr in sorted(leaf_addrs)[:limit]:
                func = proj.get_function(addr)
                name = func.name if func else f"sub_{addr:x}"
                callers = len(cg.nodes[addr].callers) if addr in cg.nodes else 0
                table.add_row(f"{addr:#x}", name, str(callers))

            console.print(table)
            if len(leaf_addrs) > limit:
                console.print(
                    f"\n[dim]Showing {limit} of {len(leaf_addrs)}. Use --limit to see more.[/dim]"
                )
            return

        if recursive:
            # Show recursive functions
            recursive_addrs = cg.recursive_functions()
            if not recursive_addrs:
                console.print("[dim]No recursive functions found[/dim]")
                return

            console.print(f"\n[bold]Recursive Functions ({len(recursive_addrs)} found):[/bold]\n")

            table = Table()
            table.add_column("Address", style="green")
            table.add_column("Name", style="cyan")
            table.add_column("Type")

            for addr in sorted(recursive_addrs)[:limit]:
                func = proj.get_function(addr)
                name = func.name if func else f"sub_{addr:x}"
                # Check if self-recursive or mutually recursive
                is_self = addr in cg.nodes[addr].callees
                rec_type = "self" if is_self else "mutual"
                table.add_row(f"{addr:#x}", name, rec_type)

            console.print(table)
            if len(recursive_addrs) > limit:
                console.print(
                    f"\n[dim]Showing {limit} of {len(recursive_addrs)}. Use --limit to see more.[/dim]"
                )
            return

        if depth:
            # Show all functions with their depth
            cg.compute_depths()
            console.print("\n[bold]Functions by Call Depth:[/bold]\n")

            table = Table()
            table.add_column("Depth", justify="right")
            table.add_column("Address", style="green")
            table.add_column("Name", style="cyan")
            table.add_column("Callers", justify="right")
            table.add_column("Callees", justify="right")

            sorted_nodes = sorted(cg.nodes.values(), key=lambda n: (n.depth, n.address))
            for node in sorted_nodes[:limit]:
                func = proj.get_function(node.address)
                name = func.name if func else node.name
                depth_str = str(node.depth) if node.depth >= 0 else "?"
                table.add_row(
                    depth_str,
                    f"{node.address:#x}",
                    name,
                    str(len(node.callers)),
                    str(len(node.callees)),
                )

            console.print(table)
            if len(cg.nodes) > limit:
                console.print(
                    f"\n[dim]Showing {limit} of {len(cg.nodes)}. Use --limit to see more.[/dim]"
                )
            return

        # Default: show stats
        cg.compute_depths()
        recursive_funcs = cg.recursive_functions()
        root_funcs = cg.root_functions()
        leaf_funcs = cg.leaf_functions()
        max_depth = max((n.depth for n in cg.nodes.values() if n.depth >= 0), default=0)

        console.print(
            Panel.fit(
                f"Total functions: [bold]{len(cg.nodes)}[/bold]\n"
                f"Total call edges: [bold]{len(cg.edges)}[/bold]\n"
                f"Root functions: [bold]{len(root_funcs)}[/bold]\n"
                f"Leaf functions: [bold]{len(leaf_funcs)}[/bold]\n"
                f"Recursive functions: [bold]{len(recursive_funcs)}[/bold]\n"
                f"Max call depth: [bold]{max_depth}[/bold]",
                title="Call Graph Statistics",
            )
        )

        console.print(
            "\n[dim]Use --roots, --leaves, --recursive, --function, --path, or --dot for more details.[/dim]"
        )


@main.command("interactive")
@click.argument("binary", type=click.Path(exists=True))
def interactive_mode(binary: str) -> None:
    """Start interactive analysis session."""
    from chimera import Project

    proj = Project.load(binary)
    proj.analyze()

    console.print(f"[bold green]Chimera[/bold green] - Loaded: {binary}")
    console.print("Type 'help' for commands, 'quit' to exit.\n")

    commands = {
        "help": "Show this help",
        "info": "Show binary info",
        "funcs": "List functions",
        "disasm <addr|name>": "Disassemble at address/function",
        "decomp <addr|name>": "Decompile function",
        "xrefs <addr>": "Show cross-references",
        "symbols": "List symbols",
        "quit": "Exit",
    }

    while True:
        try:
            line = console.input("[bold]chimera>[/bold] ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("quit", "exit", "q"):
            break
        elif cmd == "help":
            for c, desc in commands.items():
                console.print(f"  [cyan]{c:<20}[/cyan] {desc}")
        elif cmd == "info":
            _interactive_info(proj)
        elif cmd == "funcs":
            _interactive_funcs(proj)
        elif cmd == "disasm" and args:
            _interactive_disasm(proj, args[0])
        elif cmd == "decomp" and args:
            _interactive_decomp(proj, args[0])
        elif cmd == "xrefs" and args:
            _interactive_xrefs(proj, args[0])
        elif cmd == "symbols":
            _interactive_symbols(proj)
        else:
            console.print(f"[red]Unknown command: {cmd}[/red]")

    proj.close()
    console.print("Goodbye!")


def _interactive_info(proj) -> None:  # type: ignore[no-untyped-def]
    """Show info in interactive mode."""
    if not proj.binary:
        return
    b = proj.binary
    console.print(f"Path: {b.path}")
    console.print(f"Entry: {b.entry_point:#x}")
    console.print(f"Segments: {len(b.segments)}")
    console.print(f"Functions: {len(proj.functions)}")


def _interactive_funcs(proj) -> None:  # type: ignore[no-untyped-def]
    """List functions in interactive mode."""
    for func in sorted(proj.functions, key=lambda f: f.address)[:20]:
        console.print(f"  {func.address:#x}  {func.name}")
    if len(proj.functions) > 20:
        console.print(f"  ... and {len(proj.functions) - 20} more")


def _interactive_disasm(proj, target: str) -> None:  # type: ignore[no-untyped-def]
    """Disassemble in interactive mode."""
    try:
        addr = int(target, 0)
    except ValueError:
        func = proj.get_function_by_name(target)
        if not func:
            console.print(f"[red]Not found: {target}[/red]")
            return
        addr = func.address

    try:
        for insn in proj.disassemble(addr, 10):
            console.print(f"  {insn.address:#x}  {insn}")
    except ValueError as e:
        console.print(f"[red]{e}[/red]")


def _interactive_decomp(proj, target: str) -> None:  # type: ignore[no-untyped-def]
    """Decompile in interactive mode."""
    try:
        code = proj.decompile(target)
        syntax = Syntax(code, "c", theme="monokai")
        console.print(syntax)
    except Exception as e:
        console.print(f"[red]{e}[/red]")


def _interactive_xrefs(proj, address: str) -> None:  # type: ignore[no-untyped-def]
    """Show xrefs in interactive mode."""
    try:
        addr = int(address, 0)
    except ValueError:
        console.print(f"[red]Invalid address: {address}[/red]")
        return

    to_xrefs = proj.xrefs_to(addr)
    from_xrefs = proj.xrefs_from(addr)

    if to_xrefs:
        console.print("References TO:")
        for xref in to_xrefs[:10]:
            console.print(f"  {xref.from_addr:#x} ({xref.xref_type.name})")

    if from_xrefs:
        console.print("References FROM:")
        for xref in from_xrefs[:10]:
            console.print(f"  {xref.to_addr:#x} ({xref.xref_type.name})")


def _interactive_symbols(proj) -> None:  # type: ignore[no-untyped-def]
    """Show symbols in interactive mode."""
    from chimera.loader.symbols import SymbolType

    count = 0
    for sym in proj.symbols:
        if sym.symbol_type == SymbolType.DEBUG:
            continue
        if count >= 20:
            console.print("  ... (truncated)")
            break
        addr_str = f"{sym.address:#x}" if sym.address else "--------"
        console.print(f"  {addr_str}  {sym.name}")
        count += 1


if __name__ == "__main__":
    main()
