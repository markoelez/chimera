"""Tests for call graph analysis."""

from chimera.analysis.xrefs import XRefType, XRefManager
from chimera.analysis.callgraph import (
    CallEdge,
    CallType,
    CallGraph,
    CallGraphNode,
    CallGraphBuilder,
    StronglyConnectedComponent,
)
from chimera.analysis.functions import Function


class TestCallGraphNode:
    """Tests for CallGraphNode class."""

    def test_node_creation(self):
        """Test creating a call graph node."""
        node = CallGraphNode(address=0x1000, name="test_func")

        assert node.address == 0x1000
        assert node.name == "test_func"
        assert len(node.callers) == 0
        assert len(node.callees) == 0
        assert not node.is_recursive
        assert node.depth == -1


class TestCallEdge:
    """Tests for CallEdge class."""

    def test_edge_creation(self):
        """Test creating a call edge."""
        edge = CallEdge(
            caller=0x1000,
            callee=0x2000,
            call_site=0x1004,
            call_type=CallType.DIRECT,
        )

        assert edge.caller == 0x1000
        assert edge.callee == 0x2000
        assert edge.call_site == 0x1004
        assert edge.call_type == CallType.DIRECT


class TestCallGraph:
    """Tests for CallGraph class."""

    def test_empty_graph(self):
        """Test empty call graph."""
        cg = CallGraph()

        assert len(cg) == 0
        assert len(cg.edges) == 0
        assert cg.root_functions() == []
        assert cg.leaf_functions() == []

    def test_add_node(self):
        """Test adding nodes to call graph."""
        cg = CallGraph()

        node = cg.add_node(0x1000, "func1")

        assert len(cg) == 1
        assert 0x1000 in cg
        assert node.name == "func1"

    def test_add_edge(self):
        """Test adding edges to call graph."""
        cg = CallGraph()

        cg.add_node(0x1000, "caller")
        cg.add_node(0x2000, "callee")

        edge = CallEdge(
            caller=0x1000,
            callee=0x2000,
            call_site=0x1004,
        )
        cg.add_edge(edge)

        assert len(cg.edges) == 1
        assert 0x2000 in cg.nodes[0x1000].callees
        assert 0x1000 in cg.nodes[0x2000].callers

    def test_root_functions(self):
        """Test finding root functions (not called by others)."""
        cg = CallGraph()

        # Create a simple call tree: main -> helper1 -> helper2
        cg.add_node(0x1000, "main")
        cg.add_node(0x2000, "helper1")
        cg.add_node(0x3000, "helper2")

        cg.add_edge(CallEdge(caller=0x1000, callee=0x2000, call_site=0x1004))
        cg.add_edge(CallEdge(caller=0x2000, callee=0x3000, call_site=0x2004))

        roots = cg.root_functions()

        assert len(roots) == 1
        assert 0x1000 in roots

    def test_leaf_functions(self):
        """Test finding leaf functions (don't call anything)."""
        cg = CallGraph()

        # Create a simple call tree: main -> helper1 -> helper2
        cg.add_node(0x1000, "main")
        cg.add_node(0x2000, "helper1")
        cg.add_node(0x3000, "helper2")

        cg.add_edge(CallEdge(caller=0x1000, callee=0x2000, call_site=0x1004))
        cg.add_edge(CallEdge(caller=0x2000, callee=0x3000, call_site=0x2004))

        leaves = cg.leaf_functions()

        assert len(leaves) == 1
        assert 0x3000 in leaves

    def test_all_callers_transitive(self):
        """Test getting all callers transitively."""
        cg = CallGraph()

        # Chain: main -> a -> b -> c
        cg.add_node(0x1000, "main")
        cg.add_node(0x2000, "a")
        cg.add_node(0x3000, "b")
        cg.add_node(0x4000, "c")

        cg.add_edge(CallEdge(caller=0x1000, callee=0x2000, call_site=0x1004))
        cg.add_edge(CallEdge(caller=0x2000, callee=0x3000, call_site=0x2004))
        cg.add_edge(CallEdge(caller=0x3000, callee=0x4000, call_site=0x3004))

        all_callers = cg.all_callers(0x4000)

        assert 0x1000 in all_callers
        assert 0x2000 in all_callers
        assert 0x3000 in all_callers
        assert 0x4000 not in all_callers

    def test_all_callees_transitive(self):
        """Test getting all callees transitively."""
        cg = CallGraph()

        # Chain: main -> a -> b -> c
        cg.add_node(0x1000, "main")
        cg.add_node(0x2000, "a")
        cg.add_node(0x3000, "b")
        cg.add_node(0x4000, "c")

        cg.add_edge(CallEdge(caller=0x1000, callee=0x2000, call_site=0x1004))
        cg.add_edge(CallEdge(caller=0x2000, callee=0x3000, call_site=0x2004))
        cg.add_edge(CallEdge(caller=0x3000, callee=0x4000, call_site=0x3004))

        all_callees = cg.all_callees(0x1000)

        assert 0x2000 in all_callees
        assert 0x3000 in all_callees
        assert 0x4000 in all_callees
        assert 0x1000 not in all_callees

    def test_shortest_path(self):
        """Test finding shortest call path."""
        cg = CallGraph()

        # Create graph: main -> a -> c, main -> b -> c
        cg.add_node(0x1000, "main")
        cg.add_node(0x2000, "a")
        cg.add_node(0x3000, "b")
        cg.add_node(0x4000, "c")

        cg.add_edge(CallEdge(caller=0x1000, callee=0x2000, call_site=0x1004))
        cg.add_edge(CallEdge(caller=0x1000, callee=0x3000, call_site=0x1008))
        cg.add_edge(CallEdge(caller=0x2000, callee=0x4000, call_site=0x2004))
        cg.add_edge(CallEdge(caller=0x3000, callee=0x4000, call_site=0x3004))

        path = cg.shortest_path(0x1000, 0x4000)

        assert path is not None
        assert len(path) == 3  # main -> a/b -> c
        assert path[0] == 0x1000
        assert path[-1] == 0x4000

    def test_shortest_path_same_node(self):
        """Test shortest path when start and end are same."""
        cg = CallGraph()
        cg.add_node(0x1000, "main")

        path = cg.shortest_path(0x1000, 0x1000)

        assert path == [0x1000]

    def test_shortest_path_no_path(self):
        """Test when no path exists between nodes."""
        cg = CallGraph()
        cg.add_node(0x1000, "a")
        cg.add_node(0x2000, "b")
        # No edges - disconnected

        path = cg.shortest_path(0x1000, 0x2000)

        assert path is None

    def test_self_recursive_detection(self):
        """Test detecting self-recursive functions."""
        cg = CallGraph()

        cg.add_node(0x1000, "recursive_func")
        cg.add_edge(CallEdge(caller=0x1000, callee=0x1000, call_site=0x1004))

        cg.compute_sccs()
        recursive = cg.recursive_functions()

        assert len(recursive) == 1
        assert 0x1000 in recursive
        assert cg.nodes[0x1000].is_recursive

    def test_mutual_recursive_detection(self):
        """Test detecting mutually recursive functions."""
        cg = CallGraph()

        # a calls b, b calls a
        cg.add_node(0x1000, "a")
        cg.add_node(0x2000, "b")
        cg.add_edge(CallEdge(caller=0x1000, callee=0x2000, call_site=0x1004))
        cg.add_edge(CallEdge(caller=0x2000, callee=0x1000, call_site=0x2004))

        cg.compute_sccs()
        recursive = cg.recursive_functions()

        assert len(recursive) == 2
        assert 0x1000 in recursive
        assert 0x2000 in recursive

    def test_compute_depths(self):
        """Test computing call depth from roots."""
        cg = CallGraph()

        # Chain: main (depth 0) -> a (depth 1) -> b (depth 2)
        cg.add_node(0x1000, "main")
        cg.add_node(0x2000, "a")
        cg.add_node(0x3000, "b")

        cg.add_edge(CallEdge(caller=0x1000, callee=0x2000, call_site=0x1004))
        cg.add_edge(CallEdge(caller=0x2000, callee=0x3000, call_site=0x2004))

        cg.compute_depths()

        assert cg.nodes[0x1000].depth == 0
        assert cg.nodes[0x2000].depth == 1
        assert cg.nodes[0x3000].depth == 2

    def test_to_dot_basic(self):
        """Test DOT export."""
        cg = CallGraph()

        cg.add_node(0x1000, "main")
        cg.add_node(0x2000, "helper")
        cg.add_edge(CallEdge(caller=0x1000, callee=0x2000, call_site=0x1004))

        dot = cg.to_dot()

        assert "digraph callgraph" in dot
        assert "main" in dot
        assert "helper" in dot
        assert "->" in dot


class TestCallGraphBuilder:
    """Tests for CallGraphBuilder class."""

    def test_build_from_xrefs(self):
        """Test building call graph from xrefs."""
        # Create mock functions
        functions = {
            0x1000: Function(address=0x1000, name="main", size=16),
            0x2000: Function(address=0x2000, name="helper", size=16),
        }

        # Create xrefs
        xrefs = XRefManager()
        xrefs.add_xref(0x1004, 0x2000, XRefType.CALL)

        builder = CallGraphBuilder(functions, xrefs)
        cg = builder.build()

        assert len(cg) == 2
        assert 0x2000 in cg.nodes[0x1000].callees
        assert 0x1000 in cg.nodes[0x2000].callers

    def test_build_with_multiple_calls(self):
        """Test building with multiple call sites."""
        functions = {
            0x1000: Function(address=0x1000, name="main", size=32),
            0x2000: Function(address=0x2000, name="func_a", size=16),
            0x3000: Function(address=0x3000, name="func_b", size=16),
        }

        xrefs = XRefManager()
        xrefs.add_xref(0x1004, 0x2000, XRefType.CALL)
        xrefs.add_xref(0x1008, 0x3000, XRefType.CALL)
        xrefs.add_xref(0x1010, 0x2000, XRefType.CALL)  # Second call to func_a

        builder = CallGraphBuilder(functions, xrefs)
        cg = builder.build()

        assert len(cg.nodes[0x1000].callees) == 2
        assert 0x2000 in cg.nodes[0x1000].callees
        assert 0x3000 in cg.nodes[0x1000].callees


class TestStronglyConnectedComponent:
    """Tests for StronglyConnectedComponent class."""

    def test_scc_creation(self):
        """Test creating an SCC."""
        scc = StronglyConnectedComponent(
            functions=frozenset({0x1000, 0x2000}),
            is_recursive=True,
        )

        assert len(scc.functions) == 2
        assert scc.is_recursive
        assert 0x1000 in scc.functions

    def test_non_recursive_scc(self):
        """Test non-recursive SCC (single function, no self-loop)."""
        scc = StronglyConnectedComponent(
            functions=frozenset({0x1000}),
            is_recursive=False,
        )

        assert len(scc.functions) == 1
        assert not scc.is_recursive
