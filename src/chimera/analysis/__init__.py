"""Static analysis module."""

from chimera.analysis.cfg import EdgeType, BasicBlock, ControlFlowGraph
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
from chimera.analysis.functions import Function, FunctionAnalyzer

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
]
