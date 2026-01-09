"""Type inference engine for IR values."""

from enum import IntEnum, auto
from dataclasses import field, dataclass

from chimera.decompiler.ir import IRType, IRValue, IROpcode, IRFunction
from chimera.decompiler.types import (
    PTR,
    BOOL,
    INT8,
    VOID,
    INT16,
    INT32,
    INT64,
    FLOAT32,
    FLOAT64,
    TypeKind,
    PointerType,
    ResolvedType,
    PrimitiveType,
)


class ConstraintKind(IntEnum):
    """Kind of type constraint."""

    EXACT = auto()  # Must be this exact type
    SUBTYPE = auto()  # Must be subtype of
    SUPERTYPE = auto()  # Must be supertype of
    SAME_AS = auto()  # Must be same type as another value
    POINTER_TO = auto()  # Must be pointer to something


@dataclass
class TypeConstraint:
    """A constraint on a value's type."""

    value: IRValue
    kind: ConstraintKind
    constraint_type: ResolvedType | None = None
    related_value: IRValue | None = None  # For SAME_AS constraints
    source: str = ""  # Where this constraint came from

    def __repr__(self) -> str:
        if self.kind == ConstraintKind.SAME_AS and self.related_value:
            return f"Constraint({self.value.name} == {self.related_value.name}, {self.source})"
        return f"Constraint({self.value.name}: {self.constraint_type}, {self.source})"


@dataclass
class InferenceContext:
    """Context for type inference."""

    types: dict[str, ResolvedType] = field(default_factory=dict)  # value name -> type
    constraints: list[TypeConstraint] = field(default_factory=list)


class TypeInferenceEngine:
    """Constraint-based type inference for IR values."""

    def __init__(self, func: IRFunction) -> None:
        self.func = func
        self.ctx = InferenceContext()

    def infer(self) -> dict[str, ResolvedType]:
        """Run type inference and return mapping of value names to types."""
        # Phase 1: Initialize from IR types
        self._initialize_types()

        # Phase 2: Collect constraints from instructions
        self._collect_constraints()

        # Phase 3: Propagate types until fixed point
        self._propagate()

        return self.ctx.types

    def _initialize_types(self) -> None:
        """Initialize types from IR type information."""
        # Parameters
        for param in self.func.params:
            self.ctx.types[param.name] = self._ir_type_to_resolved(param.ir_type)

        # Walk all instructions and initialize types
        for block in self.func:
            for insn in block:
                if insn.dest:
                    self.ctx.types[insn.dest.name] = self._ir_type_to_resolved(insn.dest.ir_type)

    def _ir_type_to_resolved(self, ir_type: IRType) -> ResolvedType:
        """Convert IR type to resolved type."""
        mapping: dict[IRType, ResolvedType] = {
            IRType.VOID: VOID,
            IRType.I8: INT8,
            IRType.I16: INT16,
            IRType.I32: INT32,
            IRType.I64: INT64,
            IRType.PTR: PTR,
            IRType.BOOL: BOOL,
            IRType.FLOAT: FLOAT32,
            IRType.DOUBLE: FLOAT64,
        }
        return mapping.get(ir_type, INT64)

    def _collect_constraints(self) -> None:
        """Collect type constraints from IR instructions."""
        for block in self.func:
            for insn in block:
                self._constraint_from_instruction(insn)

    def _constraint_from_instruction(self, insn) -> None:
        """Extract constraints from a single instruction."""
        op = insn.opcode

        # Load/Store: pointer operand
        if op == IROpcode.LOAD:
            if insn.operands:
                addr = insn.operands[0]
                self._add_constraint(addr, ConstraintKind.SUBTYPE, PTR, source="load_addr")
                # Result type depends on address type
                if insn.dest:
                    self._add_constraint(
                        insn.dest,
                        ConstraintKind.EXACT,
                        self._ir_type_to_resolved(insn.dest.ir_type),
                        source="load_result",
                    )

        elif op == IROpcode.STORE:
            if len(insn.operands) >= 2:
                addr = insn.operands[0]
                self._add_constraint(addr, ConstraintKind.SUBTYPE, PTR, source="store_addr")

        # Comparison: both operands same type, result is bool
        elif op in (
            IROpcode.EQ,
            IROpcode.NE,
            IROpcode.LT,
            IROpcode.LE,
            IROpcode.GT,
            IROpcode.GE,
            IROpcode.ULT,
            IROpcode.ULE,
            IROpcode.UGT,
            IROpcode.UGE,
        ):
            if insn.dest:
                self._add_constraint(insn.dest, ConstraintKind.EXACT, BOOL, source="cmp_result")
            if len(insn.operands) >= 2:
                self._add_constraint(
                    insn.operands[0],
                    ConstraintKind.SAME_AS,
                    related=insn.operands[1],
                    source="cmp_operands",
                )

        # Call: result type from callee
        elif op == IROpcode.CALL:
            if insn.dest:
                # Default to int64 return
                self._add_constraint(insn.dest, ConstraintKind.EXACT, INT64, source="call_return")

        # Arithmetic: result same type as operands
        elif op in (
            IROpcode.ADD,
            IROpcode.SUB,
            IROpcode.MUL,
            IROpcode.DIV,
            IROpcode.UDIV,
            IROpcode.MOD,
            IROpcode.UMOD,
        ):
            if insn.dest and insn.operands:
                self._add_constraint(
                    insn.dest,
                    ConstraintKind.SAME_AS,
                    related=insn.operands[0],
                    source="arith_result",
                )

        # Bitwise: result same type as operands
        elif op in (
            IROpcode.AND,
            IROpcode.OR,
            IROpcode.XOR,
            IROpcode.SHL,
            IROpcode.SHR,
            IROpcode.SAR,
        ):
            if insn.dest and insn.operands:
                self._add_constraint(
                    insn.dest,
                    ConstraintKind.SAME_AS,
                    related=insn.operands[0],
                    source="bitwise_result",
                )

        # Extension: result is larger type
        elif op == IROpcode.ZEXT:
            if insn.dest:
                self._add_constraint(
                    insn.dest,
                    ConstraintKind.EXACT,
                    self._ir_type_to_resolved(insn.dest.ir_type),
                    source="zext_result",
                )

        elif op == IROpcode.SEXT:
            if insn.dest:
                self._add_constraint(
                    insn.dest,
                    ConstraintKind.EXACT,
                    self._ir_type_to_resolved(insn.dest.ir_type),
                    source="sext_result",
                )

    def _add_constraint(
        self,
        value: IRValue,
        kind: ConstraintKind,
        constraint_type: ResolvedType | None = None,
        related: IRValue | None = None,
        source: str = "",
    ) -> None:
        """Add a type constraint."""
        constraint = TypeConstraint(
            value=value,
            kind=kind,
            constraint_type=constraint_type,
            related_value=related,
            source=source,
        )
        self.ctx.constraints.append(constraint)

    def _propagate(self) -> None:
        """Propagate types until fixed point."""
        max_iterations = 10
        for _ in range(max_iterations):
            changed = False

            for constraint in self.ctx.constraints:
                if self._apply_constraint(constraint):
                    changed = True

            if not changed:
                break

    def _apply_constraint(self, constraint: TypeConstraint) -> bool:
        """Apply a constraint, return True if types changed."""
        value_name = constraint.value.name

        if constraint.kind == ConstraintKind.EXACT:
            if constraint.constraint_type:
                if value_name not in self.ctx.types:
                    self.ctx.types[value_name] = constraint.constraint_type
                    return True
                # Check if we're refining
                current = self.ctx.types[value_name]
                if self._is_more_specific(constraint.constraint_type, current):
                    self.ctx.types[value_name] = constraint.constraint_type
                    return True

        elif constraint.kind == ConstraintKind.SAME_AS:
            if constraint.related_value:
                related_name = constraint.related_value.name
                if related_name in self.ctx.types:
                    related_type = self.ctx.types[related_name]
                    if value_name not in self.ctx.types:
                        self.ctx.types[value_name] = related_type
                        return True

        elif constraint.kind == ConstraintKind.SUBTYPE:
            # For pointer constraints, mark as pointer type
            if constraint.constraint_type == PTR:
                if value_name not in self.ctx.types:
                    self.ctx.types[value_name] = PTR
                    return True

        return False

    def _is_more_specific(self, new: ResolvedType, old: ResolvedType) -> bool:
        """Check if new type is more specific than old."""
        # Pointer to concrete is more specific than void*
        if isinstance(new, PointerType) and isinstance(old, PointerType):
            if old.pointee == VOID and new.pointee != VOID:
                return True

        # Sized int is more specific than default
        if isinstance(new, PrimitiveType) and isinstance(old, PrimitiveType):
            if new.kind == TypeKind.INT and old.kind == TypeKind.INT:
                if new.size < old.size:
                    return True  # More precise size

        return False


def infer_types(func: IRFunction) -> dict[str, ResolvedType]:
    """Convenience function to run type inference on a function."""
    engine = TypeInferenceEngine(func)
    return engine.infer()
