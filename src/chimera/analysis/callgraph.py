"""Call graph analysis for inter-procedural analysis."""

from enum import IntEnum, auto
from typing import TYPE_CHECKING
from collections import deque
from dataclasses import field, dataclass

if TYPE_CHECKING:
    from chimera.analysis.xrefs import XRefManager
    from chimera.analysis.functions import Function


class CallType(IntEnum):
    """Type of function call."""

    DIRECT = auto()  # bl target
    INDIRECT = auto()  # blr register
    EXTERNAL = auto()  # Call to imported function
    THUNK = auto()  # Call through thunk


@dataclass
class CallEdge:
    """Represents a call relationship between functions."""

    caller: int  # Caller function address
    callee: int  # Callee function address
    call_site: int  # Address of call instruction
    call_type: CallType = CallType.DIRECT

    def __repr__(self) -> str:
        return f"CallEdge({self.caller:#x} -> {self.callee:#x})"


@dataclass
class CallGraphNode:
    """A node in the call graph representing a function."""

    address: int
    name: str
    callers: set[int] = field(default_factory=set)  # Functions that call this
    callees: set[int] = field(default_factory=set)  # Functions called by this
    is_recursive: bool = False
    depth: int = -1  # Distance from roots (-1 = unknown)

    def __repr__(self) -> str:
        return f"CallGraphNode({self.name}, depth={self.depth})"


@dataclass
class StronglyConnectedComponent:
    """A strongly connected component in the call graph."""

    functions: frozenset[int]  # Function addresses in SCC
    is_recursive: bool = False  # True if size > 1 or self-loop

    def __repr__(self) -> str:
        return f"SCC({len(self.functions)} functions, recursive={self.is_recursive})"


class CallGraph:
    """Call graph representing inter-procedural call relationships."""

    def __init__(self) -> None:
        self.nodes: dict[int, CallGraphNode] = {}
        self.edges: list[CallEdge] = []
        self.sccs: list[StronglyConnectedComponent] = []
        self._depths_computed = False

    def add_node(self, address: int, name: str) -> CallGraphNode:
        """Add a node to the call graph."""
        if address not in self.nodes:
            self.nodes[address] = CallGraphNode(address=address, name=name)
        return self.nodes[address]

    def add_edge(self, edge: CallEdge) -> None:
        """Add an edge to the call graph."""
        self.edges.append(edge)

        # Ensure nodes exist
        if edge.caller not in self.nodes:
            self.nodes[edge.caller] = CallGraphNode(
                address=edge.caller, name=f"sub_{edge.caller:x}"
            )
        if edge.callee not in self.nodes:
            self.nodes[edge.callee] = CallGraphNode(
                address=edge.callee, name=f"sub_{edge.callee:x}"
            )

        # Update caller/callee sets
        self.nodes[edge.caller].callees.add(edge.callee)
        self.nodes[edge.callee].callers.add(edge.caller)

    def root_functions(self) -> list[int]:
        """Get functions that are not called by any other function."""
        return [addr for addr, node in self.nodes.items() if not node.callers]

    def leaf_functions(self) -> list[int]:
        """Get functions that don't call any other functions."""
        return [addr for addr, node in self.nodes.items() if not node.callees]

    def all_callers(self, address: int) -> set[int]:
        """Get all callers transitively (all functions that can reach this one)."""
        if address not in self.nodes:
            return set()

        result: set[int] = set()
        queue = deque([address])
        visited: set[int] = set()

        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)

            if current in self.nodes:
                for caller in self.nodes[current].callers:
                    if caller not in visited:
                        result.add(caller)
                        queue.append(caller)

        return result

    def all_callees(self, address: int) -> set[int]:
        """Get all callees transitively (all functions reachable from this one)."""
        if address not in self.nodes:
            return set()

        result: set[int] = set()
        queue = deque([address])
        visited: set[int] = set()

        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)

            if current in self.nodes:
                for callee in self.nodes[current].callees:
                    if callee not in visited:
                        result.add(callee)
                        queue.append(callee)

        return result

    def shortest_path(self, from_addr: int, to_addr: int) -> list[int] | None:
        """Find shortest call path between two functions using BFS."""
        if from_addr not in self.nodes or to_addr not in self.nodes:
            return None

        if from_addr == to_addr:
            return [from_addr]

        # BFS to find shortest path
        queue: deque[list[int]] = deque([[from_addr]])
        visited: set[int] = {from_addr}

        while queue:
            path = queue.popleft()
            current = path[-1]

            for callee in self.nodes[current].callees:
                if callee == to_addr:
                    return path + [callee]

                if callee not in visited:
                    visited.add(callee)
                    queue.append(path + [callee])

        return None

    def compute_sccs(self) -> list[StronglyConnectedComponent]:
        """Compute strongly connected components using Tarjan's algorithm."""
        index = 0
        stack: list[int] = []
        indices: dict[int, int] = {}
        lowlinks: dict[int, int] = {}
        on_stack: set[int] = set()
        sccs: list[StronglyConnectedComponent] = []

        def strongconnect(v: int) -> None:
            nonlocal index
            indices[v] = index
            lowlinks[v] = index
            index += 1
            stack.append(v)
            on_stack.add(v)

            for w in self.nodes[v].callees:
                if w not in self.nodes:
                    continue
                if w not in indices:
                    strongconnect(w)
                    lowlinks[v] = min(lowlinks[v], lowlinks[w])
                elif w in on_stack:
                    lowlinks[v] = min(lowlinks[v], indices[w])

            if lowlinks[v] == indices[v]:
                scc: set[int] = set()
                while True:
                    w = stack.pop()
                    on_stack.remove(w)
                    scc.add(w)
                    if w == v:
                        break

                # Check if recursive: SCC size > 1 or self-loop
                is_recursive = len(scc) > 1
                if len(scc) == 1:
                    addr = next(iter(scc))
                    is_recursive = addr in self.nodes[addr].callees

                sccs.append(
                    StronglyConnectedComponent(functions=frozenset(scc), is_recursive=is_recursive)
                )

        for v in self.nodes:
            if v not in indices:
                strongconnect(v)

        self.sccs = sccs

        # Mark recursive functions
        for scc in self.sccs:
            if scc.is_recursive:
                for addr in scc.functions:
                    if addr in self.nodes:
                        self.nodes[addr].is_recursive = True

        return sccs

    def recursive_functions(self) -> list[int]:
        """Get all recursive functions (self-recursive or mutually recursive)."""
        if not self.sccs:
            self.compute_sccs()
        return [addr for addr, node in self.nodes.items() if node.is_recursive]

    def compute_depths(self) -> None:
        """Compute call depth for each function (distance from roots)."""
        if self._depths_computed:
            return

        roots = self.root_functions()
        queue: deque[tuple[int, int]] = deque((r, 0) for r in roots)
        visited: set[int] = set()

        while queue:
            addr, depth = queue.popleft()
            if addr in visited:
                continue
            visited.add(addr)

            if addr in self.nodes:
                self.nodes[addr].depth = depth
                for callee in self.nodes[addr].callees:
                    if callee not in visited:
                        queue.append((callee, depth + 1))

        self._depths_computed = True

    def to_dot(self, show_external: bool = True) -> str:
        """Export call graph to DOT format for Graphviz visualization."""
        lines = [
            "digraph callgraph {",
            "  rankdir=TB;",
            '  node [shape=box, fontname="Helvetica"];',
            '  edge [fontname="Helvetica"];',
            "",
        ]

        # Compute SCCs if not done
        if not self.sccs:
            self.compute_sccs()

        # Node definitions with colors based on properties
        for _addr, node in self.nodes.items():
            attrs = []

            # Color based on properties
            if node.is_recursive:
                attrs.append('color="red"')
                attrs.append('style="bold"')
            elif not node.callers:
                attrs.append('color="blue"')  # Root
            elif not node.callees:
                attrs.append('color="green"')  # Leaf

            attr_str = f" [{', '.join(attrs)}]" if attrs else ""
            # Escape special characters in names
            safe_name = node.name.replace('"', '\\"')
            lines.append(f'  "{safe_name}"{attr_str};')

        lines.append("")

        # Edges
        seen_edges: set[tuple[int, int]] = set()
        for edge in self.edges:
            if (edge.caller, edge.callee) in seen_edges:
                continue
            seen_edges.add((edge.caller, edge.callee))

            if edge.caller not in self.nodes or edge.callee not in self.nodes:
                continue

            caller_name = self.nodes[edge.caller].name.replace('"', '\\"')
            callee_name = self.nodes[edge.callee].name.replace('"', '\\"')

            edge_attrs = []
            if edge.call_type == CallType.INDIRECT:
                edge_attrs.append('style="dashed"')
            elif edge.call_type == CallType.THUNK:
                edge_attrs.append('color="gray"')
            elif edge.call_type == CallType.EXTERNAL:
                if not show_external:
                    continue
                edge_attrs.append('color="purple"')

            attr_str = f" [{', '.join(edge_attrs)}]" if edge_attrs else ""
            lines.append(f'  "{caller_name}" -> "{callee_name}"{attr_str};')

        lines.append("}")
        return "\n".join(lines)

    def __len__(self) -> int:
        return len(self.nodes)

    def __contains__(self, address: int) -> bool:
        return address in self.nodes


class CallGraphBuilder:
    """Builds a call graph from function and cross-reference analysis."""

    def __init__(
        self,
        functions: dict[int, "Function"],
        xrefs: "XRefManager",
    ) -> None:
        self.functions = functions
        self.xrefs = xrefs

    def build(self) -> CallGraph:
        """Build the call graph."""
        cg = CallGraph()

        # Add all functions as nodes
        for addr, func in self.functions.items():
            cg.add_node(addr, func.name)

        # Add edges from xrefs
        for func_addr, func in self.functions.items():
            # Get all call targets from this function's address range
            for call_site in range(func.address, func.end_address, 4):
                callees = self.xrefs.callees(call_site)
                for callee in callees:
                    # Determine call type
                    call_type = CallType.DIRECT

                    # Check if callee is a known function
                    if callee in self.functions:
                        target_func = self.functions[callee]
                        if target_func.is_thunk:
                            call_type = CallType.THUNK
                    else:
                        # External or unknown
                        call_type = CallType.EXTERNAL

                    edge = CallEdge(
                        caller=func_addr,
                        callee=callee,
                        call_site=call_site,
                        call_type=call_type,
                    )
                    cg.add_edge(edge)

        # Compute SCCs and depths
        cg.compute_sccs()
        cg.compute_depths()

        return cg


def build_call_graph(
    functions: dict[int, "Function"],
    xrefs: "XRefManager",
) -> CallGraph:
    """Convenience function to build a call graph."""
    builder = CallGraphBuilder(functions, xrefs)
    return builder.build()
