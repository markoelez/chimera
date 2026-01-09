"""Static analysis module."""

from chimera.analysis.cfg import EdgeType, BasicBlock, ControlFlowGraph
from chimera.analysis.diff import (
    ChangeType,
    DiffResult,
    FunctionDiff,
    FunctionMatch,
    MatchStrategy,
    FunctionHasher,
    BasicBlockMatch,
    FunctionMatcher,
    MatchConfidence,
    BasicBlockMatcher,
    UnmatchedFunction,
    BinaryDiffAnalyzer,
)
from chimera.analysis.objc import (
    ObjCIvar,
    ObjCClass,
    ObjCMethod,
    ObjCAnalyzer,
    ObjCCategory,
    ObjCMetadata,
    ObjCProperty,
    ObjCProtocol,
)
from chimera.analysis.xrefs import XRef, XRefType, XRefManager, XRefAnalyzer
from chimera.analysis.search import (
    StringMatch,
    PatternMatch,
    SearchResults,
    PatternScanner,
    StringSearcher,
)
from chimera.analysis.dataflow import DataFlowAnalyzer, ReachingDefinitions
from chimera.analysis.arguments import ArgumentInfo, ArgumentAnalyzer
from chimera.analysis.callgraph import (
    CallEdge,
    CallType,
    CallGraph,
    CallGraphNode,
    CallGraphBuilder,
    StronglyConnectedComponent,
    build_call_graph,
)
from chimera.analysis.functions import Function, FunctionAnalyzer
from chimera.analysis.stack_frame import StackFrame, StackVariable, StackFrameAnalyzer
from chimera.analysis.switch_table import SwitchCase, SwitchTable, SwitchDetector

__all__ = [
    "BasicBlock",
    "ControlFlowGraph",
    "EdgeType",
    "Function",
    "FunctionAnalyzer",
    "XRef",
    "XRefType",
    "XRefManager",
    "XRefAnalyzer",
    "DataFlowAnalyzer",
    "ReachingDefinitions",
    "StringMatch",
    "PatternMatch",
    "StringSearcher",
    "PatternScanner",
    "SearchResults",
    "ObjCMethod",
    "ObjCIvar",
    "ObjCProperty",
    "ObjCProtocol",
    "ObjCCategory",
    "ObjCClass",
    "ObjCMetadata",
    "ObjCAnalyzer",
    "DiffResult",
    "FunctionMatch",
    "FunctionDiff",
    "BasicBlockMatch",
    "UnmatchedFunction",
    "MatchConfidence",
    "MatchStrategy",
    "ChangeType",
    "FunctionHasher",
    "FunctionMatcher",
    "BasicBlockMatcher",
    "BinaryDiffAnalyzer",
    # Stack frame analysis
    "StackVariable",
    "StackFrame",
    "StackFrameAnalyzer",
    # Argument detection
    "ArgumentInfo",
    "ArgumentAnalyzer",
    # Call graph analysis
    "CallType",
    "CallEdge",
    "CallGraph",
    "CallGraphNode",
    "CallGraphBuilder",
    "build_call_graph",
    "StronglyConnectedComponent",
    # Switch table detection
    "SwitchCase",
    "SwitchTable",
    "SwitchDetector",
]
