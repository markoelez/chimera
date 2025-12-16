"""Command-line interface for Chimera."""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from rich.panel import Panel

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


def _interactive_info(proj: "Project") -> None:
    """Show info in interactive mode."""
    from chimera import Project
    if not proj.binary:
        return
    b = proj.binary
    console.print(f"Path: {b.path}")
    console.print(f"Entry: {b.entry_point:#x}")
    console.print(f"Segments: {len(b.segments)}")
    console.print(f"Functions: {len(proj.functions)}")


def _interactive_funcs(proj: "Project") -> None:
    """List functions in interactive mode."""
    from chimera import Project
    for func in sorted(proj.functions, key=lambda f: f.address)[:20]:
        console.print(f"  {func.address:#x}  {func.name}")
    if len(proj.functions) > 20:
        console.print(f"  ... and {len(proj.functions) - 20} more")


def _interactive_disasm(proj: "Project", target: str) -> None:
    """Disassemble in interactive mode."""
    from chimera import Project
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


def _interactive_decomp(proj: "Project", target: str) -> None:
    """Decompile in interactive mode."""
    from chimera import Project
    try:
        code = proj.decompile(target)
        syntax = Syntax(code, "c", theme="monokai")
        console.print(syntax)
    except Exception as e:
        console.print(f"[red]{e}[/red]")


def _interactive_xrefs(proj: "Project", address: str) -> None:
    """Show xrefs in interactive mode."""
    from chimera import Project
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


def _interactive_symbols(proj: "Project") -> None:
    """Show symbols in interactive mode."""
    from chimera import Project
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

