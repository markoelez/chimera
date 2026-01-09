"""Pseudo-C code generator."""

from typing import TYPE_CHECKING

from chimera.decompiler.ir import (
    IRType,
    IRValue,
    IROpcode,
    IRFunction,
    IRInstruction,
)
from chimera.decompiler.types import PointerType, ResolvedType, PrimitiveType
from chimera.decompiler.structuring import StructureType, StructuredBlock

if TYPE_CHECKING:
    from chimera.loader.symbols import SymbolTable
    from chimera.analysis.functions import Function
    from chimera.analysis.stack_frame import StackFrame


class CCodeGenerator:
    """Generates pseudo-C code from structured IR."""

    def __init__(
        self,
        ir_func: IRFunction,
        symbols: "SymbolTable | None" = None,
        type_map: dict[str, ResolvedType] | None = None,
        stack_frame: "StackFrame | None" = None,
    ) -> None:
        self.ir_func = ir_func
        self.symbols = symbols
        self.type_map = type_map or {}
        self.stack_frame = stack_frame
        self._indent = 0
        self._output: list[str] = []
        self._var_types: dict[str, str] = {}
        self._temp_names: dict[str, str] = {}
        self._name_counter = 0
        self._declared_locals: set[str] = set()
        self._stack_var_map: dict[int, str] = {}  # offset -> var name

        # Build stack variable map
        if stack_frame:
            for var in stack_frame.variables:
                self._stack_var_map[var.offset] = var.name

    def generate(self, structured: StructuredBlock | None = None) -> str:
        """Generate C code."""
        self._output = []
        self._indent = 0

        # Generate function signature
        self._emit_function_header()

        # Generate body
        self._emit("{")
        self._indent += 1

        # Emit local variable declarations
        self._emit_local_declarations()

        if structured:
            self._emit_structured(structured)
        else:
            # Fall back to basic block output
            self._emit_basic_blocks()

        self._indent -= 1
        self._emit("}")

        return "\n".join(self._output)

    def _emit_local_declarations(self) -> None:
        """Emit local variable declarations at start of function."""
        declarations: list[str] = []

        # Add stack variables
        if self.stack_frame:
            for var in self.stack_frame.variables:
                if not var.is_argument:
                    type_str = self._resolved_type_to_c(var.var_type) if var.var_type else "int64_t"
                    declarations.append(f"{type_str} {var.name};")
                    self._declared_locals.add(var.name)

        # Emit declarations
        if declarations:
            for decl in declarations:
                self._emit(decl)
            self._emit("")  # Blank line after declarations

    def _resolved_type_to_c(self, resolved_type: ResolvedType | None) -> str:
        """Convert resolved type to C type string."""
        if resolved_type is None:
            return "int64_t"

        if isinstance(resolved_type, PrimitiveType):
            return str(resolved_type)

        if isinstance(resolved_type, PointerType):
            pointee = self._resolved_type_to_c(resolved_type.pointee)
            return f"{pointee}*"

        return "int64_t"

    def _emit(self, line: str) -> None:
        """Emit a line of code."""
        indent = "    " * self._indent
        self._output.append(f"{indent}{line}")

    def _emit_function_header(self) -> None:
        """Emit function signature."""
        ret_type = self._type_to_c(self.ir_func.return_type)
        params = []
        for param in self.ir_func.params:
            param_type = self._type_to_c(param.ir_type)
            param_name = self._get_var_name(param)
            params.append(f"{param_type} {param_name}")

        params_str = ", ".join(params) if params else "void"
        self._emit(f"{ret_type} {self.ir_func.name}({params_str})")

    def _emit_structured(self, block: StructuredBlock) -> None:
        """Emit structured code."""
        # Emit statements
        for stmt in block.statements:
            self._emit_statement(stmt)

        # Dispatch to structure-specific emitters
        emitters = {
            StructureType.IF_THEN: self._emit_if_then,
            StructureType.IF_THEN_ELSE: self._emit_if_else,
            StructureType.WHILE_LOOP: self._emit_while,
            StructureType.DO_WHILE_LOOP: self._emit_do_while,
            StructureType.SWITCH: self._emit_switch,
        }

        emitter = emitters.get(block.structure_type)
        if emitter:
            emitter(block)
        elif block.structure_type == StructureType.SEQUENCE:
            for child in block.children:
                self._emit_structured(child)
        elif block.structure_type == StructureType.GOTO:
            target = block.metadata.get("target", "unknown")
            self._emit(f"goto {target};")

    def _emit_if_then(self, block: StructuredBlock) -> None:
        """Emit if-then statement."""
        cond = self._value_to_c(block.condition) if block.condition else "1"
        self._emit(f"if ({cond}) {{")
        self._indent += 1
        if block.children:
            self._emit_structured(block.children[0])
        self._indent -= 1
        self._emit("}")

    def _emit_if_else(self, block: StructuredBlock) -> None:
        """Emit if-then-else statement."""
        cond = self._value_to_c(block.condition) if block.condition else "1"
        self._emit(f"if ({cond}) {{")
        self._indent += 1
        if block.children:
            self._emit_structured(block.children[0])
        self._indent -= 1
        self._emit("} else {")
        self._indent += 1
        if len(block.children) > 1:
            self._emit_structured(block.children[1])
        self._indent -= 1
        self._emit("}")

    def _emit_while(self, block: StructuredBlock) -> None:
        """Emit while loop."""
        cond = self._value_to_c(block.condition) if block.condition else "1"
        self._emit(f"while ({cond}) {{")
        self._indent += 1
        for child in block.children:
            self._emit_structured(child)
        self._indent -= 1
        self._emit("}")

    def _emit_do_while(self, block: StructuredBlock) -> None:
        """Emit do-while loop."""
        self._emit("do {")
        self._indent += 1
        for child in block.children:
            self._emit_structured(child)
        self._indent -= 1
        cond = self._value_to_c(block.condition) if block.condition else "1"
        self._emit(f"}} while ({cond});")

    def _emit_switch(self, block: StructuredBlock) -> None:
        """Emit switch statement."""
        index_expr = self._value_to_c(block.condition) if block.condition else "0"
        self._emit(f"switch ({index_expr}) {{")

        # Emit each case
        for child in block.children:
            case_meta = child.metadata
            if case_meta.get("is_default"):
                self._emit("default:")
            else:
                case_value = case_meta.get("case_value", 0)
                self._emit(f"case {case_value}:")

            self._indent += 1
            # Emit case body
            for case_child in child.children:
                self._emit_structured(case_child)
            self._emit("break;")
            self._indent -= 1

        self._emit("}")

    def _emit_basic_blocks(self) -> None:
        """Emit basic blocks as fallback."""
        for block in self.ir_func:
            self._emit(f"// Block {block.label}")
            for insn in block.instructions:
                self._emit_statement(insn)
            self._emit("")

    def _emit_statement(self, insn: IRInstruction) -> None:
        """Emit a single statement."""
        # Handle NOP with optional comment
        if insn.opcode == IROpcode.NOP:
            if "unknown" in insn.metadata:
                self._emit(f"// {insn.metadata['unknown']}")
            return

        # Handle return statements
        if insn.opcode == IROpcode.RETURN:
            if insn.operands:
                val = self._value_to_c(insn.operands[0])
                self._emit(f"return {val};")
            else:
                self._emit("return;")
            return

        # Dispatch to specific emitters for complex operations
        special_emitters = {
            IROpcode.CALL: self._emit_call,
            IROpcode.STORE: self._emit_store,
            IROpcode.LOAD: self._emit_load,
        }

        emitter = special_emitters.get(insn.opcode)
        if emitter:
            emitter(insn)
            return

        # Control flow is handled by structuring, skip here
        if insn.opcode in (IROpcode.JUMP, IROpcode.BRANCH, IROpcode.SWITCH):
            return

        # General assignment statement
        if insn.dest:
            dest = self._get_var_name(insn.dest)
            expr = self._insn_to_expr(insn)
            if expr:
                self._emit(f"{dest} = {expr};")

    def _emit_call(self, insn: IRInstruction) -> None:
        """Emit a function call."""
        if not insn.operands:
            return

        target = insn.operands[0]

        # Try to resolve function name
        func_name = "func"
        if target.is_const and target.const_value is not None:
            addr = target.const_value
            if self.symbols:
                syms = self.symbols.by_address(addr)
                if syms:
                    func_name = syms[0].name
                else:
                    func_name = f"sub_{addr:x}"
            else:
                func_name = f"sub_{addr:x}"
        else:
            func_name = self._value_to_c(target)

        # Build argument list (arg0-arg7)
        args = ["arg0", "arg1", "arg2", "arg3"]  # Simplified
        args_str = ", ".join(args[:2])  # Just show first 2 for brevity

        if insn.dest:
            dest = self._get_var_name(insn.dest)
            self._emit(f"{dest} = {func_name}({args_str});")
        else:
            self._emit(f"{func_name}({args_str});")

    def _emit_store(self, insn: IRInstruction) -> None:
        """Emit a store operation."""
        if len(insn.operands) < 2:
            return

        addr_val = insn.operands[0]
        val = self._value_to_c(insn.operands[1])

        # Check for stack variable
        if addr_val.stack_offset is not None and addr_val.stack_offset in self._stack_var_map:
            var_name = self._stack_var_map[addr_val.stack_offset]
            self._emit(f"{var_name} = {val};")
        else:
            addr = self._value_to_c(addr_val)
            self._emit(f"*({addr}) = {val};")

    def _emit_load(self, insn: IRInstruction) -> None:
        """Emit a load operation."""
        if not insn.dest or not insn.operands:
            return

        dest = self._get_var_name(insn.dest)
        addr_val = insn.operands[0]

        # Check for stack variable
        if addr_val.stack_offset is not None and addr_val.stack_offset in self._stack_var_map:
            var_name = self._stack_var_map[addr_val.stack_offset]
            self._emit(f"{dest} = {var_name};")
        else:
            addr = self._value_to_c(addr_val)
            self._emit(f"{dest} = *({addr});")

    def _insn_to_expr(self, insn: IRInstruction) -> str:
        """Convert instruction to C expression."""
        if insn.opcode == IROpcode.CONST:
            if insn.operands:
                return self._value_to_c(insn.operands[0])
            return "0"

        if insn.opcode == IROpcode.VAR:
            if insn.operands:
                return self._value_to_c(insn.operands[0])
            return "0"

        if insn.opcode == IROpcode.PHI:
            # Phi nodes get converted to the first operand (simplified)
            if insn.operands:
                return self._value_to_c(insn.operands[0])
            return "0"

        # Binary operations
        op_map = {
            IROpcode.ADD: "+",
            IROpcode.SUB: "-",
            IROpcode.MUL: "*",
            IROpcode.DIV: "/",
            IROpcode.UDIV: "/",
            IROpcode.MOD: "%",
            IROpcode.AND: "&",
            IROpcode.OR: "|",
            IROpcode.XOR: "^",
            IROpcode.SHL: "<<",
            IROpcode.SHR: ">>",
            IROpcode.SAR: ">>",
            IROpcode.EQ: "==",
            IROpcode.NE: "!=",
            IROpcode.LT: "<",
            IROpcode.LE: "<=",
            IROpcode.GT: ">",
            IROpcode.GE: ">=",
            IROpcode.ULT: "<",
            IROpcode.ULE: "<=",
            IROpcode.UGT: ">",
            IROpcode.UGE: ">=",
        }

        if insn.opcode in op_map and len(insn.operands) >= 2:
            op = op_map[insn.opcode]
            left = self._value_to_c(insn.operands[0])
            right = self._value_to_c(insn.operands[1])
            return f"({left} {op} {right})"

        # Unary operations
        if insn.opcode == IROpcode.NEG and insn.operands:
            val = self._value_to_c(insn.operands[0])
            return f"(-{val})"

        if insn.opcode == IROpcode.NOT and insn.operands:
            val = self._value_to_c(insn.operands[0])
            return f"(~{val})"

        # Type conversions
        if insn.opcode in (IROpcode.ZEXT, IROpcode.SEXT, IROpcode.TRUNC):
            if insn.operands:
                return self._value_to_c(insn.operands[0])
            return "0"

        if insn.opcode == IROpcode.SELECT and len(insn.operands) >= 3:
            cond = self._value_to_c(insn.operands[0])
            true_val = self._value_to_c(insn.operands[1])
            false_val = self._value_to_c(insn.operands[2])
            return f"({cond} ? {true_val} : {false_val})"

        return "/* unknown */"

    def _value_to_c(self, value: IRValue | None) -> str:
        """Convert IR value to C expression."""
        if value is None:
            return "0"

        if value.is_const:
            val = value.const_value
            if val is None:
                return "0"
            if isinstance(val, int):
                if val < 0:
                    return str(val)
                elif val > 0xFFFF:
                    return f"0x{val:x}"
                return str(val)
            return str(val)

        return self._get_var_name(value)

    def _get_var_name(self, value: IRValue) -> str:
        """Get C variable name for IR value."""
        base_name = value.name

        # Generate readable names for temporaries
        if base_name.startswith("t"):
            if base_name not in self._temp_names:
                self._name_counter += 1
                self._temp_names[base_name] = f"v{self._name_counter}"
            base_name = self._temp_names[base_name]

        # Add SSA version if needed
        if value.version > 0:
            return f"{base_name}_{value.version}"
        return base_name

    def _type_to_c(self, ir_type: IRType) -> str:
        """Convert IR type to C type."""
        type_map = {
            IRType.VOID: "void",
            IRType.I8: "int8_t",
            IRType.I16: "int16_t",
            IRType.I32: "int32_t",
            IRType.I64: "int64_t",
            IRType.PTR: "void*",
            IRType.BOOL: "bool",
            IRType.FLOAT: "float",
            IRType.DOUBLE: "double",
        }
        return type_map.get(ir_type, "int64_t")


def decompile_function(
    func: "Function",
    symbols: "SymbolTable | None" = None,
) -> str:
    """High-level decompilation function."""
    from chimera.decompiler.lifter import ARM64Lifter
    from chimera.decompiler.simplify import IRSimplifier
    from chimera.analysis.stack_frame import StackFrameAnalyzer
    from chimera.decompiler.structuring import ControlFlowStructurer
    from chimera.decompiler.type_inference import infer_types

    # Analyze stack frame
    stack_analyzer = StackFrameAnalyzer(func)
    stack_frame = stack_analyzer.analyze()

    # Lift to IR
    lifter = ARM64Lifter()
    ir_func = lifter.lift_function(func)

    # Run type inference
    type_map = infer_types(ir_func)

    # Simplify
    simplifier = IRSimplifier(ir_func)
    ir_func = simplifier.simplify()

    # Structure control flow
    structurer = ControlFlowStructurer(ir_func)
    structured = structurer.structure()

    # Generate code with type information
    codegen = CCodeGenerator(ir_func, symbols, type_map, stack_frame)
    return codegen.generate(structured)
