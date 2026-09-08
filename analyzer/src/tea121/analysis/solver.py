"""Forward worklist interpreter for the deliberately small MiniIR subset."""

from __future__ import annotations

from dataclasses import dataclass, replace
import re
from typing import Any

from tea121.domain import Interval, MemoryObject, PointerValue, State
from .models import LibraryModelRegistry


@dataclass(frozen=True)
class AnalysisConfig:
    widen_after: int = 3
    mode: str = "normal"
    max_call_depth: int = 8
    models: tuple[str, ...] = ("memcpy", "memmove", "memset", "strcpy", "strncpy")


@dataclass
class AnalysisOutput:
    alarms: list[dict[str, Any]]
    diagnostics: list[dict[str, Any]]
    cfg: list[dict[str, Any]]
    block_states: list[dict[str, Any]]
    trace: list[dict[str, Any]]


@dataclass(frozen=True)
class FunctionSummary:
    return_interval: Interval | None = None
    return_pointer: PointerValue | None = None


class AnalysisEngine:
    def __init__(self, module: dict[str, Any], config: AnalysisConfig | None = None):
        self.module = module
        self.config = config or AnalysisConfig()
        self.output = AnalysisOutput([], [], [], [], [])
        self._objects: dict[str, MemoryObject] = {}
        self._library_models = LibraryModelRegistry().with_enabled(self.config.models)
        self._functions = {str(item.get("name")): item for item in module.get("functions", []) if item.get("name")}
        self._summaries: dict[tuple[str, tuple[str, ...]], FunctionSummary] = {}
        self._global_objects = {
            str(item["id"]): MemoryObject(str(item["id"]), Interval.const(int(item.get("size_bytes", 0))), {"kind": "global"})
            for item in module.get("globals", [])
            if "id" in item and "size_bytes" in item
        }
        self._global_strings = {
            str(item["id"]): Interval.const(int(item["string_length"]))
            for item in module.get("globals", [])
            if "id" in item and "string_length" in item
        }
        self._global_string_values = {
            str(item["id"]): str(item["string_value"])
            for item in module.get("globals", [])
            if "id" in item and "string_value" in item
        }

    def run(self) -> AnalysisOutput:
        called = {str(inst.get("callee")) for fn in self._functions.values() for block in fn.get("blocks", []) for inst in block.get("instructions", []) if inst.get("op") == "call" and inst.get("callee") in self._functions}
        roots = [fn for name, fn in self._functions.items() if name not in called] or list(self._functions.values())
        for function in roots:
            self._analyze_function(function)
        return self.output

    def _analyze_function(self, function: dict[str, Any], initial_state: State | None = None, call_stack: tuple[str, ...] = ()) -> FunctionSummary:
        blocks = function.get("blocks", [])
        if not blocks:
            return FunctionSummary()
        by_id = {str(block.get("id")): block for block in blocks}
        entry = str(function.get("entry", blocks[0].get("id")))
        predecessors: dict[str, list[str]] = {key: [] for key in by_id}
        successors: dict[str, list[str]] = {}
        for block in blocks:
            bid = str(block.get("id"))
            succ = [str(x) for x in block.get("successors", [])]
            term = block.get("terminator", {})
            if term.get("op") == "br":
                succ = [str(term["target"])] if "target" in term else [str(term[k]) for k in ("true", "false") if k in term]
            successors[bid] = succ
            for target in succ:
                if target in predecessors:
                    predecessors[target].append(bid)
                    self.output.cfg.append({"function_name": function.get("name", ""), "source_block": bid, "target_block": target, "condition": term.get("condition"), "polarity": "true" if target == str(term.get("true")) else "false" if target == str(term.get("false")) else None})
        entry_states: dict[str, State] = {bid: State.unreachable() for bid in by_id}
        exit_states: dict[str, State] = {bid: State.unreachable() for bid in by_id}
        entry_states[entry] = initial_state or self._initial_state()
        queue = [entry]
        visits: dict[str, int] = {bid: 0 for bid in by_id}
        while queue:
            bid = queue.pop(0)
            block = by_id[bid]
            if bid != entry:
                incoming = [self._edge_state(exit_states[p], by_id[p].get("terminator", {}), bid) for p in predecessors[bid]]
                state = State.unreachable()
                for candidate in incoming:
                    state = state.join(candidate)
                if state == entry_states[bid] and state.reachable:
                    continue
                entry_states[bid] = state
            state = entry_states[bid]
            visits[bid] += 1
            new_state = self._transfer_block(function, block, state, call_stack)
            if visits[bid] > self.config.widen_after:
                new_state = exit_states[bid].widen(new_state)
            if new_state == exit_states[bid] and visits[bid] > 1:
                continue
            exit_states[bid] = new_state
            queue.extend(target for target in successors[bid] if target in by_id and target not in queue)
        for bid in by_id:
            self.output.block_states.append({"function_name": function.get("name", ""), "block_id": bid, "entry_state": _state_json(entry_states[bid]), "exit_state": _state_json(exit_states[bid])})
        returned = State.unreachable()
        for bid, block in by_id.items():
            if block.get("terminator", {}).get("op") == "ret": returned = returned.join(exit_states[bid])
        value = None
        for block in blocks:
            if block.get("terminator", {}).get("op") == "ret" and block["terminator"].get("value") is not None:
                value = block["terminator"]["value"]
                break
        if value is None: return FunctionSummary()
        if value in returned.pointers: return FunctionSummary(return_pointer=returned.pointers[value])
        return FunctionSummary(return_interval=returned.get_int(value))

    def _edge_state(self, state: State, term: dict[str, Any], target: str) -> State:
        if not state.reachable or term.get("op") != "br" or "condition" not in term:
            return state
        condition = term["condition"]
        cmp = state.get_int(condition) if isinstance(condition, (int, str)) else Interval.top()
        # A branch condition can be represented as a comparison result with metadata.
        if isinstance(condition, dict) and condition.get("op") == "icmp":
            left, right = state.get_int(condition.get("left")), state.get_int(condition.get("right"))
            return _refine_cmp(state, condition.get("predicate", "eq"), left, right, target == str(term.get("true")), condition.get("left"), condition.get("right"))
        if isinstance(condition, str) and condition in state.integers:
            if target == str(term.get("true")):
                return state.with_int(condition, cmp.meet(Interval(1, None)))
            return state.with_int(condition, cmp.meet(Interval(None, 0)))
        return state

    def _transfer_block(self, function: dict[str, Any], block: dict[str, Any], state: State, call_stack: tuple[str, ...]) -> State:
        for instruction in block.get("instructions", []):
            before = state
            state = self._transfer(instruction, state, function, block, call_stack)
            if self.config.mode == "trace":
                self.output.trace.append({"sequence_no": len(self.output.trace), "event_type": "instruction", "function_name": function.get("name", ""), "block_id": block.get("id"), "instruction_id": instruction.get("id"), "before_state": _state_json(before), "after_state": _state_json(state), "explanation": instruction.get("op", "")})
        return state

    def _transfer(self, inst: dict[str, Any], state: State, function: dict[str, Any], block: dict[str, Any], call_stack: tuple[str, ...]) -> State:
        op, result = inst.get("op"), inst.get("result")
        if op in {"const", "constant"} and result:
            return state.with_int(result, Interval.const(int(inst.get("value", 0))))
        if op in {"add", "sub", "mul"} and result:
            left, right = state.get_int(inst.get("left")), state.get_int(inst.get("right"))
            value = getattr(left, op)(right, bits=inst.get("bits"), signed=inst.get("signed", True))
            return state.with_int(result, value)
        if op == "phi" and result:
            value = Interval.bottom_value()
            for incoming in inst.get("incoming", []):
                value = value.join(state.get_int(incoming.get("value")))
            return state.with_int(result, value)
        if op == "select" and result:
            return state.with_int(result, state.get_int(inst.get("true_value")).join(state.get_int(inst.get("false_value"))))
        if op == "icmp" and result:
            return state.with_int(result, _comparison_interval(inst.get("predicate", "eq"), state.get_int(inst.get("left")), state.get_int(inst.get("right"))))
        if op == "copy" and result:
            source = str(inst.get("value"))
            if source in state.pointers:
                return state.with_pointer(result, state.pointers[source])
            return state.with_int(result, state.get_int(inst.get("value")))
        if op == "alloca" and result:
            count = state.get_int(inst.get("count", 1))
            element_size = int(inst.get("element_size", 1))
            size = count.mul(Interval.const(element_size))
            object_id = str(inst.get("object_id", f"{function.get('name','')}/{result}"))
            obj = MemoryObject(object_id, size, {"function": function.get("name"), "block": block.get("id"), "instruction": inst.get("id")})
            self._objects[object_id] = obj
            return state.with_object(obj).with_pointer(result, PointerValue(frozenset({object_id}), Interval.const(0)))
        if op in {"gep", "getelementptr"} and result:
            base = state.get_pointer(inst.get("base"))
            index = state.get_int(inst.get("index", 0))
            scale = int(inst.get("element_size", 1))
            return state.with_pointer(result, PointerValue(base.bases, base.offset_bytes.add(index.mul(Interval.const(scale))), base.unknown_base))
        if op in {"load", "store"}:
            pointer = state.get_pointer(inst.get("pointer"))
            width = int(inst.get("width", 1))
            # Loading a pointer from an external declaration (stdin, socket
            # handles, etc.) does not dereference the pointed-to object yet.
            # Preserve it as an unknown pointer without manufacturing an
            # access diagnostic; the eventual write model will report an
            # unknown destination if it matters.
            if not (op == "load" and inst.get("pointer_result") and (pointer.unknown_base or not pointer.bases)):
                self._check_access(inst, pointer, width, state, function, block, write=op == "store")
            if op == "load" and inst.get("pointer_result") and result:
                return state.with_pointer(result, PointerValue.unknown())
            if op == "load" and result and not pointer.unknown_base and pointer.offset_bytes.is_singleton and len(pointer.bases) == 1:
                return state.with_int(result, state.get_memory_int(next(iter(pointer.bases)), pointer.offset_bytes.lower or 0))
            if op == "store" and not pointer.unknown_base and pointer.offset_bytes.is_singleton and inst.get("value") is not None:
                value = state.get_int(inst.get("value"))
                for object_id in pointer.bases:
                    state = state.with_memory_int(object_id, value, pointer.offset_bytes.lower or 0)
            return state.with_int(result, Interval.top()) if op == "load" and result else state
        if op == "call":
            return self._call_model(inst, state, function, block, call_stack)
        if op == "unsupported":
            self._diagnostic("UNSUPPORTED_INSTRUCTION", "unsupported MiniIR instruction", "unsupported", inst, function, block, "instruction semantics are not implemented")
        return state

    def _check_access(self, inst, pointer, width, state, function, block, write):
        if pointer.unknown_base or not pointer.bases:
            self._diagnostic("UNKNOWN_BASE", "pointer base cannot be resolved", "unknown_effect", inst, function, block, "access may refer to an unknown object")
            return
        for object_id in pointer.bases:
            obj = state.memory_objects.get(object_id) or self._objects.get(object_id)
            if obj is None:
                self._diagnostic("UNKNOWN_OBJECT", "memory object is unavailable", "unknown_effect", inst, function, block, "cannot establish object bounds")
                continue
            offset = pointer.offset_bytes
            safe = width is not None and offset.lower is not None and offset.lower >= 0 and offset.upper is not None and obj.size_bytes.lower is not None and offset.upper + width <= obj.size_bytes.lower
            definite = width is not None and offset.lower is not None and obj.size_bytes.upper is not None and (offset.lower < 0 or offset.lower + width > obj.size_bytes.upper)
            if not safe:
                severity = "definite" if definite else "possible"
                self.output.alarms.append({"alarm_key": f"{function.get('name','')}:{inst.get('id', len(self.output.alarms))}:{object_id}", "detector_id": "stack-bounds", "detector_version": "0.1.0", "rule_pack_id": "cwe121-core", "rule_pack_version": "0.1.0", "cwe_id": "CWE-121", "family": None, "violation_kind": "out_of_bounds", "severity": severity, "function_name": function.get("name", ""), "block_id": block.get("id"), "instruction_id": inst.get("id"), "instruction_text": inst.get("text", inst.get("op", "")), "memory_object_id": object_id, "object_size": _interval_json(obj.size_bytes), "offset": _interval_json(offset), "access_size": width if width is not None else 0, "safe_condition": "offset.lower >= 0 and offset.upper + access_size <= object_size.lower", "reason": ["access range is not provably inside the stack object", "access width is unknown" if width is None else "access width exceeds object bounds"], "source_location": inst.get("location")})

    def _call_model(self, inst, state, function, block, call_stack):
        name = inst.get("callee", "")
        # Clang lowers the standard memory routines to target-suffixed LLVM
        # intrinsics (for example ``llvm.memcpy.p0.p0.i64``). Keep the
        # intrinsic spelling in diagnostics but dispatch it to the same model.
        model_name = name
        if str(name).startswith("__isoc99_fscanf"):
            model_name = "fscanf"
        for intrinsic in ("memcpy", "memmove", "memset"):
            if str(name).startswith(f"llvm.{intrinsic}"):
                model_name = intrinsic
                break
        args = inst.get("args", [])
        if name in self._functions:
            result = inst.get("result")
            if name in call_stack:
                self._diagnostic("RECURSIVE_CALL", f"recursive call: {name}", "unknown_effect", inst, function, block, "recursive function summary is conservatively unknown")
                return state.with_int(result, Interval.top()) if result else state
            if len(call_stack) >= self.config.max_call_depth:
                self._diagnostic("MAX_CALL_DEPTH", f"maximum call depth exceeded at {name}", "unknown_effect", inst, function, block, "call graph exploration was bounded by max_call_depth")
                return state.with_int(result, Interval.top()) if result else state
            callee = self._functions[name]
            parameters = [str(item) for item in callee.get("parameters", [])]
            callee_state = State(dict(state.integers), dict(state.pointers), dict(state.memory_objects), dict(state.string_lengths), state.reachable, state.reasons)
            for parameter, argument in zip(parameters, args):
                if argument in state.pointers:
                    callee_state = callee_state.with_pointer(parameter, state.pointers[argument])
                else:
                    callee_state = callee_state.with_int(parameter, state.get_int(argument))
            key = (name, f"{function.get('name', '')}:{inst.get('id', '')}")
            summary = self._summaries.get(key)
            if summary is None:
                summary = self._analyze_function(callee, callee_state, call_stack + (name,))
                self._summaries[key] = summary
            if result and summary.return_pointer is not None:
                return state.with_pointer(result, summary.return_pointer)
            if result:
                return state.with_int(result, summary.return_interval or Interval.top())
            return state
        if model_name in {"memcpy", "memmove", "memset", "strncpy"} and len(args) >= 3:
            dest, length = state.get_pointer(args[0]), state.get_int(args[2])
            self._check_access(inst, dest, length.lower if length.is_singleton else None, state, function, block, write=True)
            if length.is_singleton:
                return state
            self._diagnostic("UNKNOWN_LENGTH", f"{name} length is not bounded", "unknown_effect", inst, function, block, "copy width is not a known constant")
            return state
        if name == "strcpy" and len(args) >= 2:
            dest, source = state.get_pointer(args[0]), state.get_pointer(args[1])
            lengths = [state.string_lengths.get(base) for base in source.bases]
            known = [x for x in lengths if x is not None and x.is_singleton]
            if known:
                self._check_access(inst, dest, known[0].lower + 1, state, function, block, write=True)
            else:
                self._check_access(inst, dest, None, state, function, block, write=True)
                self._diagnostic("UNKNOWN_STRING_LENGTH", "source string length is unknown", "unknown_effect", inst, function, block, "strcpy writes an unbounded string")
            return state
        if self._library_models.is_input(model_name):
            return self._input_model(inst, state, function, block, model_name)
        if self._library_models.is_pure(name):
            # These calls do not write through pointer arguments in the
            # supported model. Scalar results still need to be propagated;
            # otherwise ``atoi``/``rand`` incorrectly retain an initializer.
            result = inst.get("result")
            if result:
                if name in {"strlen", "wcslen"} and args:
                    lengths = [state.string_lengths.get(base) for base in state.get_pointer(args[0]).bases]
                    known = [value for value in lengths if value is not None and value.is_singleton]
                    if known:
                        return state.with_int(result, known[0])
                return state.with_int(result, Interval.top())
            return state
        if name not in self._library_models.names and name:
            objects = dict(state.memory_objects)
            for arg in args:
                pointer = state.get_pointer(arg)
                for object_id in pointer.bases:
                    if object_id in objects:
                        objects[object_id] = replace(objects[object_id], escaped=True)
            state = replace(state, memory_objects=objects)
            self._diagnostic("UNKNOWN_CALL", f"unknown call: {name}", "unknown_effect", inst, function, block, "pointer arguments may escape")
        return state

    def _input_model(self, inst, state, function, block, name):
        """Model bounded reads and scanf-style input conservatively."""
        args = inst.get("args", [])
        result = inst.get("result")
        if name == "fgets" and len(args) >= 2:
            dest = state.get_pointer(args[0])
            size = state.get_int(args[1])
            if size.is_singleton:
                width = max(0, size.lower or 0)
                if width:
                    self._check_access(inst, dest, width, state, function, block, write=True)
            else:
                self._check_access(inst, dest, None, state, function, block, write=True)
                self._diagnostic("UNKNOWN_INPUT_LENGTH", "fgets bound is not known", "unknown_effect", inst, function, block, "cannot establish the maximum input write width")
            if result:
                return state.with_pointer(result, dest)
            return state
        if name == "recv" and len(args) >= 3:
            dest = state.get_pointer(args[1])
            size = state.get_int(args[2])
            if size.is_singleton:
                width = max(0, size.lower or 0)
                if width:
                    self._check_access(inst, dest, width, state, function, block, write=True)
                returned = Interval(-1, width)
            else:
                self._check_access(inst, dest, None, state, function, block, write=True)
                self._diagnostic("UNKNOWN_INPUT_LENGTH", "recv bound is not known", "unknown_effect", inst, function, block, "cannot establish the maximum network write width")
                returned = Interval.top()
            return state.with_int(result, returned) if result else state
        if name == "fscanf" and len(args) >= 3:
            format_text = self._format_text(args[1])
            conversions = re.findall(r"%(?!%)(?:[-+0-9.*lhjztL]*)([diouxXfFeEgGaAcsp\[])", format_text or "")
            destinations = args[2:]
            if not conversions:
                for destination in destinations:
                    self._check_access(inst, state.get_pointer(destination), None, state, function, block, write=True)
                self._diagnostic("UNKNOWN_SCANF_FORMAT", "fscanf format is unknown", "unknown_effect", inst, function, block, "cannot establish input destination width")
            else:
                for index, destination in enumerate(destinations):
                    conversion = conversions[min(index, len(conversions) - 1)]
                    if conversion in {"s", "[", "c"}:
                        self._check_access(inst, state.get_pointer(destination), None, state, function, block, write=True)
                        self._diagnostic("UNKNOWN_INPUT_LENGTH", "fscanf string input is unbounded", "unknown_effect", inst, function, block, "conversion may write an arbitrarily long token")
                    else:
                        width = {"f": 4, "e": 4, "g": 4, "a": 4, "d": 4, "i": 4, "o": 4, "u": 4, "x": 4, "X": 4}.get(conversion, 4)
                        destination_pointer = state.get_pointer(destination)
                        self._check_access(inst, destination_pointer, width, state, function, block, write=True)
                        if not destination_pointer.unknown_base and destination_pointer.offset_bytes.is_singleton:
                            for object_id in destination_pointer.bases:
                                state = state.with_memory_int(object_id, Interval.top(), destination_pointer.offset_bytes.lower or 0)
            if result:
                return state.with_int(result, Interval(0, len(destinations)))
            return state
        self._diagnostic("UNKNOWN_INPUT_SIGNATURE", f"{name} call signature is unsupported", "unknown_effect", inst, function, block, "input destination arguments are unavailable")
        return state

    def _format_text(self, value: Any) -> str | None:
        if isinstance(value, str):
            return self._global_string_values.get(value)
        return None

    def _initial_state(self) -> State:
        pointers = {object_id: PointerValue(frozenset({object_id}), Interval.const(0)) for object_id in self._global_objects}
        return State(pointers=pointers, memory_objects=dict(self._global_objects), string_lengths=dict(self._global_strings))

    def _diagnostic(self, code, message, severity, inst, function, block, impact):
        self.output.diagnostics.append({"diagnostic_id": f"d-{len(self.output.diagnostics)+1}", "code": code, "severity": severity, "message": message, "impact": impact, "function_name": function.get("name", ""), "block_id": block.get("id"), "instruction_id": inst.get("id"), "location": inst.get("location")})


def _comparison_interval(predicate: str, left: Interval, right: Interval) -> Interval:
    if predicate in {"eq", "ne"} and left.is_singleton and right.is_singleton:
        value = int((left.lower == right.lower) if predicate == "eq" else (left.lower != right.lower))
        return Interval.const(value)
    if predicate in {"slt", "ult", "lt"} and left.upper is not None and right.lower is not None and left.upper < right.lower:
        return Interval.const(1)
    if predicate in {"sge", "uge", "ge"} and left.lower is not None and right.upper is not None and left.lower >= right.upper:
        return Interval.const(1)
    return Interval(0, 1)


def _refine_cmp(state, predicate, left, right, truth, left_name, right_name):
    if not isinstance(left_name, str) or not isinstance(right_name, str):
        return state
    if predicate in {"slt", "ult", "lt"}:
        if truth:
            return state.with_int(left_name, left.refine_upper((right.upper - 1) if right.upper is not None else left.upper or 0)).with_int(right_name, right.refine_lower((left.lower + 1) if left.lower is not None else right.lower or 0))
        return state
    if predicate in {"sge", "uge", "ge"} and truth and right.lower is not None:
        return state.with_int(left_name, left.refine_lower(right.lower))
    if predicate in {"eq"} and truth:
        common = left.meet(right)
        return state.with_int(left_name, common).with_int(right_name, common)
    return state


def _interval_json(value: Interval) -> dict[str, Any]:
    return {"lower": value.lower, "upper": value.upper, "is_bottom": value.bottom}


def _state_json(state: State) -> dict[str, Any]:
    return {"reachable": state.reachable, "integers": {k: _interval_json(v) for k, v in state.integers.items()}, "pointers": {k: {"bases": sorted(v.bases), "offset_bytes": _interval_json(v.offset_bytes), "unknown_base": v.unknown_base} for k, v in state.pointers.items()}, "memory_objects": {k: {"size_bytes": _interval_json(v.size_bytes), "escaped": v.escaped} for k, v in state.memory_objects.items()}}
