"""Forward worklist interpreter for the deliberately small MiniIR subset."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import re
from typing import Any

from tea121.domain import Interval, MemoryObject, PointerValue, State
from .models import (
    CWE_INTEGER_OVERFLOW,
    CWE_STACK_BOUNDS,
    DETECTOR_ID,
    DETECTOR_VERSION,
    RULE_PACK_ID,
    RULE_PACK_VERSION,
    LibraryModelRegistry,
)


@dataclass(frozen=True)
class AnalysisConfig:
    widen_after: int = 3
    narrowing_rounds: int = 1
    mode: str = "normal"
    max_call_depth: int = 8
    models: tuple[str, ...] = ("memcpy", "memmove", "memset", "strcpy", "strncpy")
    # Report when a fixed-width integer operation provably leaves the range of
    # the variable's type (CWE-190 integer overflow / wraparound).
    check_integer_overflow: bool = True


@dataclass
class AnalysisOutput:
    alarms: list[dict[str, Any]]
    diagnostics: list[dict[str, Any]]
    cfg: list[dict[str, Any]]
    block_states: list[dict[str, Any]]
    trace: list[dict[str, Any]]
    # CFG nodes are kept separate from the legacy edge-only ``cfg`` payload so
    # older consumers can continue to read the result while the workbench can
    # render the actual IR contained by each block.
    cfg_nodes: list[dict[str, Any]] = field(default_factory=list)


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
        self._emitted_cfg_nodes: set[tuple[str, str]] = set()
        self._emitted_alarm_keys: set[str] = set()
        # Worklist iterations compute states first; effects are replayed once on
        # the narrowed fixed point so stale intermediate alarms cannot survive.
        self._record_effects = True
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
        self._global_scalars = {
            str(item["id"]): Interval.const(int(item["integer_value"]))
            for item in module.get("globals", [])
            if "id" in item and "integer_value" in item
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
        for ordinal, block in enumerate(blocks, start=1):
            bid = str(block.get("id"))
            succ = [str(x) for x in block.get("successors", [])]
            term = block.get("terminator", {})
            if term.get("op") == "br":
                succ = [str(term["target"])] if "target" in term else [str(term[k]) for k in ("true", "false") if k in term]
            successors[bid] = succ
            node_key = (str(function.get("name", "")), bid)
            if node_key not in self._emitted_cfg_nodes:
                self._emitted_cfg_nodes.add(node_key)
                instructions = [
                    {
                        "id": str(inst.get("id", "")),
                        "text": _instruction_text(inst),
                        "op": inst.get("op"),
                        "location": inst.get("location"),
                    }
                    for inst in block.get("instructions", [])
                    if inst.get("op") != "nop"
                ]
                source_lines = sorted(
                    {
                        int(inst["location"]["line"])
                        for inst in block.get("instructions", [])
                        if isinstance(inst.get("location"), dict)
                        and isinstance(inst["location"].get("line"), int)
                        and inst["location"]["line"] > 0
                    }
                )
                self.output.cfg_nodes.append(
                    {
                        "function_name": function.get("name", ""),
                        "block_id": bid,
                        "label": block.get("label") or bid,
                        "display_index": ordinal,
                        "instructions": instructions,
                        "terminator": term,
                        "source_lines": source_lines,
                    }
                )
            for target in succ:
                if target in predecessors:
                    predecessors[target].append(bid)
                    self.output.cfg.append({"function_name": function.get("name", ""), "source_block": bid, "target_block": target, "condition": term.get("condition"), "polarity": "true" if target == str(term.get("true")) else "false" if target == str(term.get("false")) else None})
        entry_states: dict[str, State] = {bid: State.unreachable() for bid in by_id}
        exit_states: dict[str, State] = {bid: State.unreachable() for bid in by_id}
        entry_states[entry] = initial_state or self._initial_state()
        queue = [entry]
        visits: dict[str, int] = {bid: 0 for bid in by_id}
        widened: set[str] = set()
        record_effects = self._record_effects
        self._record_effects = False
        try:
            while queue:
                bid = queue.pop(0)
                block = by_id[bid]
                incoming_states: dict[str, State] | None = None
                if bid != entry:
                    state, incoming_states = self._block_input_state(bid, entry, by_id, predecessors, entry_states, exit_states)
                    if state == entry_states[bid] and state.reachable:
                        continue
                    entry_states[bid] = state
                state = entry_states[bid]
                visits[bid] += 1
                new_state = self._transfer_block(function, block, state, call_stack, incoming_states)
                if visits[bid] > self.config.widen_after:
                    new_state = exit_states[bid].widen(new_state)
                    widened.add(bid)
                if new_state == exit_states[bid] and visits[bid] > 1:
                    continue
                exit_states[bid] = new_state
                queue.extend(target for target in successors[bid] if target in by_id and target not in queue)

            if widened and self.config.narrowing_rounds > 0:
                self._narrow_states(function, by_id, predecessors, entry, entry_states, exit_states, call_stack)

            returned = State.unreachable()
            for bid, block in by_id.items():
                if block.get("terminator", {}).get("op") == "ret":
                    returned = returned.join(exit_states[bid])
            value = None
            for block in blocks:
                if block.get("terminator", {}).get("op") == "ret" and block["terminator"].get("value") is not None:
                    value = block["terminator"]["value"]
                    break
            if value is None:
                summary = FunctionSummary()
            elif value in returned.pointers:
                summary = FunctionSummary(return_pointer=returned.pointers[value])
            else:
                summary = FunctionSummary(return_interval=returned.get_int(value))
        finally:
            self._record_effects = record_effects

        if record_effects:
            # Replay only on the final states. In particular, an alarm seen
            # while the loop head was temporarily widened to Top must not leak
            # into the result if narrowing later proves the access safe.
            self._record_effects = True
            try:
                for bid in by_id:
                    if not entry_states[bid].reachable:
                        continue
                    _, incoming_states = self._block_input_state(bid, entry, by_id, predecessors, entry_states, exit_states)
                    self._transfer_block(function, by_id[bid], entry_states[bid], call_stack, incoming_states)
            finally:
                self._record_effects = record_effects

        for bid in by_id:
            self.output.block_states.append({"function_name": function.get("name", ""), "block_id": bid, "entry_state": _state_json(entry_states[bid]), "exit_state": _state_json(exit_states[bid])})
        return summary

    def _block_input_state(
        self,
        bid: str,
        entry: str,
        by_id: dict[str, dict[str, Any]],
        predecessors: dict[str, list[str]],
        entry_states: dict[str, State],
        exit_states: dict[str, State],
    ) -> tuple[State, dict[str, State] | None]:
        if bid == entry:
            return entry_states[bid], None
        incoming_states: dict[str, State] = {}
        state = State.unreachable()
        for predecessor in predecessors[bid]:
            edge_state = self._edge_state(exit_states[predecessor], by_id[predecessor].get("terminator", {}), bid)
            if edge_state.reachable:
                incoming_states[predecessor] = edge_state
                state = state.join(edge_state)
        return state, incoming_states

    def _narrow_states(
        self,
        function: dict[str, Any],
        by_id: dict[str, dict[str, Any]],
        predecessors: dict[str, list[str]],
        entry: str,
        entry_states: dict[str, State],
        exit_states: dict[str, State],
        call_stack: tuple[str, ...],
    ) -> None:
        """Run a bounded narrowing phase after interval widening.

        Each pass is a meet-only update, so states can only shrink and the
        phase terminates. Repeating passes within one configured round lets a
        narrowed loop head propagate its recovered bounds around the backedge.
        """
        order = [bid for bid in reversed(list(by_id)) if bid != entry]
        for _ in range(max(1, self.config.narrowing_rounds)):
            for _pass in range(len(order) + 2):
                changed = False
                for bid in order:
                    state, incoming_states = self._block_input_state(bid, entry, by_id, predecessors, entry_states, exit_states)
                    narrowed_entry = entry_states[bid].narrow(state)
                    if narrowed_entry != entry_states[bid]:
                        entry_states[bid] = narrowed_entry
                        changed = True
                    if not narrowed_entry.reachable:
                        if exit_states[bid].reachable:
                            exit_states[bid] = State.unreachable()
                            changed = True
                        continue
                    new_state = self._transfer_block(function, by_id[bid], narrowed_entry, call_stack, incoming_states)
                    narrowed_exit = exit_states[bid].narrow(new_state)
                    if narrowed_exit != exit_states[bid]:
                        exit_states[bid] = narrowed_exit
                        changed = True
                if not changed:
                    break

    def _edge_state(self, state: State, term: dict[str, Any], target: str) -> State:
        if not state.reachable or term.get("op") != "br" or "condition" not in term:
            return state
        if target == str(term.get("true")):
            truth = True
        elif target == str(term.get("false")):
            truth = False
        else:
            return state
        condition = term["condition"]
        cmp = state.get_int(condition) if isinstance(condition, (int, str)) else Interval.top()
        # A branch condition can be represented as a comparison result with metadata.
        if isinstance(condition, dict) and condition.get("op") == "icmp":
            left, right = state.get_int(condition.get("left")), state.get_int(condition.get("right"))
            return _refine_cmp(state, condition.get("predicate", "eq"), left, right, truth, condition.get("left"), condition.get("right"))
        if isinstance(condition, str) and condition in state.integers:
            return _refine_name(state, condition, cmp.meet(Interval(1, None) if truth else Interval(None, 0)))
        return state

    def _transfer_block(
        self,
        function: dict[str, Any],
        block: dict[str, Any],
        state: State,
        call_stack: tuple[str, ...],
        incoming_states: dict[str, State] | None = None,
    ) -> State:
        for instruction in block.get("instructions", []):
            before = state
            state = self._transfer(instruction, state, function, block, call_stack, incoming_states)
            if self._record_effects and self.config.mode == "trace":
                self.output.trace.append({"sequence_no": len(self.output.trace), "event_type": "instruction", "function_name": function.get("name", ""), "block_id": block.get("id"), "instruction_id": instruction.get("id"), "before_state": _state_json(before), "after_state": _state_json(state), "explanation": instruction.get("op", "")})
        return state

    def _transfer(
        self,
        inst: dict[str, Any],
        state: State,
        function: dict[str, Any],
        block: dict[str, Any],
        call_stack: tuple[str, ...],
        incoming_states: dict[str, State] | None = None,
    ) -> State:
        op, result = inst.get("op"), inst.get("result")
        if op in {"const", "constant"} and result:
            return state.with_int(result, Interval.const(int(inst.get("value", 0))))
        if op in {"add", "sub", "mul"} and result:
            left, right = state.get_int(inst.get("left")), state.get_int(inst.get("right"))
            bits, signed = inst.get("bits"), inst.get("signed", True)
            if self.config.check_integer_overflow and isinstance(bits, int) and bits > 0:
                # Recompute with mathematical integers so an out-of-range
                # result is still visible before ``_bounded`` degrades it.
                exact = getattr(left, op)(right)
                self._check_integer_overflow(inst, exact, bits, signed, function, block, result)
            value = getattr(left, op)(right, bits=bits, signed=signed)
            return state.with_int(result, value)
        if op == "phi" and result:
            value = Interval.bottom_value()
            for incoming in inst.get("incoming", []):
                predecessor = str(incoming.get("block", ""))
                edge_state = incoming_states.get(predecessor) if incoming_states is not None else None
                if edge_state is not None and edge_state.reachable:
                    value = value.join(edge_state.get_int(incoming.get("value")))
                elif incoming_states is None:
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
            obj = MemoryObject(object_id, size, {"function": function.get("name"), "block": block.get("id"), "instruction": inst.get("id"), "element_size": element_size})
            self._objects[object_id] = obj
            return state.with_object(obj).with_pointer(result, PointerValue(frozenset({object_id}), Interval.const(0)))
        if op in {"gep", "getelementptr"} and result:
            base = state.get_pointer(inst.get("base"))
            index = state.get_int(inst.get("index", 0))
            scale = int(inst.get("element_size", 1))
            delta = index.mul(Interval.const(scale))
            offset = base.offset_bytes.add(delta)
            bound_size = base.bound_size_bytes
            if bound_size is None and isinstance(inst.get("bound_size"), int):
                bound_size = Interval.const(int(inst["bound_size"]))
            elif bound_size is not None:
                bound_size = bound_size.sub(delta)
            return state.with_pointer(result, PointerValue(base.bases, offset, base.unknown_base, bound_size))
        if op in {"load", "store"}:
            pointer = state.get_pointer(inst.get("pointer"))
            width = int(inst.get("width", 1))
            # Narrowing assignments (``char c = c + 1``) are lowered as a wider
            # arithmetic op followed by a truncating store. The truncation
            # itself is not modelled, so check the stored value against the
            # destination type width at the store.
            if op == "store" and self.config.check_integer_overflow and isinstance(inst.get("width"), int) and inst["width"] > 0:
                self._check_value_fits_type(inst, state.get_int(inst.get("value")), inst["width"] * 8, inst.get("signed", True), function, block, inst.get("value"))
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
                offset = pointer.offset_bytes.lower or 0
                for object_id in pointer.bases:
                    state = state.with_memory_int(object_id, value, offset)
                    if value.is_singleton and value.lower == 0 and len(pointer.bases) == 1:
                        obj = state.memory_objects.get(object_id)
                        allocation_element_size = int((obj.allocation_site if obj else {}).get("element_size", 1))
                        # The store width identifies the character width even
                        # when ALLOCA lowered the object as a byte array.
                        element_size = int(inst.get("width", allocation_element_size)) or allocation_element_size
                        if offset >= 0 and element_size > 0 and offset % element_size == 0:
                            state = state.with_string_length(object_id, Interval.const(offset // element_size))
            return state.with_int(result, Interval.top()) if op == "load" and result else state
        if op == "call":
            return self._call_model(inst, state, function, block, call_stack)
        if op == "unsupported":
            # The extractor marks instruction kinds without a dedicated
            # transfer function as unsupported. Treating a scalar result as
            # Top is a sound over-approximation and lets downstream bounds
            # checks report possible violations instead of degrading the whole
            # side to unsupported. Pointer-valued unknown operations remain
            # unresolved and are diagnosed when they are actually dereferenced.
            if result:
                return state.with_int(result, Interval.top())
            return state
        return state

    def _check_value_fits_type(self, inst, value, bits, signed, function, block, name):
        """Check a stored value against the destination type of a ``store``.

        This catches conversions that preserve the source range because the
        extractor collapses ``trunc``/``sext`` into ``copy``: the value is
        still abstracted with its wide-type interval when it reaches the store.
        """
        self._emit_overflow_alarm(inst, value, bits, signed, function, block, name, source="stored value range")

    def _check_integer_overflow(self, inst, value, bits, signed, function, block, result):
        """Emit an alarm when a typed integer value leaves its type range.

        ``value`` is the *unbounded* interval of the operation; ``bits`` and
        ``signed`` describe the destination type. The report reuses the alarm
        contract: ``memory_object_id`` names the SSA value, ``object_size`` is
        the representable range of the type, ``offset`` is the computed value
        range, and ``access_size`` is the storage width in bytes.
        """
        self._emit_overflow_alarm(inst, value, bits, signed, function, block, result, source="computed value range")

    def _emit_overflow_alarm(self, inst, value, bits, signed, function, block, name, *, source):
        if not self._record_effects:
            return
        kind = value.overflow_kind(bits, signed)
        if kind is None:
            return
        type_range = Interval.type_range(bits, signed)
        alarm_key = f"{function.get('name', '')}:{inst.get('id', '')}:{name}:integer_overflow"
        if alarm_key in self._emitted_alarm_keys:
            return
        self._emitted_alarm_keys.add(alarm_key)
        width = max(1, (bits + 7) // 8)
        sign = "signed" if signed else "unsigned"
        below = value.lower is not None and value.lower < type_range.lower
        above = value.upper is not None and value.upper > type_range.upper
        if below and above:
            direction = "wraps around both type bounds"
        elif below:
            direction = "wraps below the type minimum"
        else:
            direction = "exceeds the type maximum"
        self.output.alarms.append(
            {
                "alarm_key": alarm_key,
                "detector_id": DETECTOR_ID,
                "detector_version": DETECTOR_VERSION,
                "rule_pack_id": RULE_PACK_ID,
                "rule_pack_version": RULE_PACK_VERSION,
                "cwe_id": CWE_INTEGER_OVERFLOW,
                "family": None,
                "violation_kind": "integer_overflow",
                "severity": kind,
                "function_name": function.get("name", ""),
                "block_id": block.get("id"),
                "instruction_id": inst.get("id"),
                "instruction_text": inst.get("text", inst.get("op", "")),
                "memory_object_id": str(name),
                "object_size": _interval_json(type_range),
                "offset": _interval_json(value),
                "access_size": width,
                "safe_condition": f"value.lower >= {type_range.lower} and value.upper <= {type_range.upper}",
                "reason": [
                    f"{source} {value} {direction} of the {sign} {bits}-bit type {type_range}",
                    "every value in the range overflows the type" if kind == "definite" else "part of the range overflows the type",
                ],
                "source_location": inst.get("location"),
                "evidence": {"value_range": _interval_json(value), "type_bits": bits, "type_signed": signed},
            }
        )

    def _check_access(self, inst, pointer, width, state, function, block, write):
        if not self._record_effects:
            return
        if pointer.unknown_base or not pointer.bases:
            self._diagnostic("UNKNOWN_BASE", "pointer base cannot be resolved", "unknown_effect", inst, function, block, "access may refer to an unknown object")
            return
        for object_id in pointer.bases:
            obj = state.memory_objects.get(object_id) or self._objects.get(object_id)
            if obj is None:
                self._diagnostic("UNKNOWN_OBJECT", "memory object is unavailable", "unknown_effect", inst, function, block, "cannot establish object bounds")
                continue
            offset = pointer.offset_bytes
            limit_lower = obj.size_bytes.lower
            limit_upper = obj.size_bytes.upper
            subobject_size = pointer.bound_size_bytes
            safe = (
                width is not None
                and offset.lower is not None
                and offset.lower >= 0
                and offset.upper is not None
                and limit_lower is not None
                and offset.upper + width <= limit_lower
                and (subobject_size is None or (subobject_size.lower is not None and width <= subobject_size.lower))
            )
            definite = width is not None and offset.lower is not None and limit_upper is not None and (offset.lower < 0 or offset.lower + width > limit_upper)
            if width is not None and subobject_size is not None and subobject_size.upper is not None:
                definite = definite or width > subobject_size.upper
            if not safe:
                alarm_key = f"{function.get('name','')}:{inst.get('id', len(self.output.alarms))}:{object_id}"
                if alarm_key in self._emitted_alarm_keys:
                    continue
                self._emitted_alarm_keys.add(alarm_key)
                severity = "definite" if definite else "possible"
                self.output.alarms.append({"alarm_key": alarm_key, "detector_id": DETECTOR_ID, "detector_version": DETECTOR_VERSION, "rule_pack_id": RULE_PACK_ID, "rule_pack_version": RULE_PACK_VERSION, "cwe_id": CWE_STACK_BOUNDS, "family": None, "violation_kind": "out_of_bounds", "severity": severity, "function_name": function.get("name", ""), "block_id": block.get("id"), "instruction_id": inst.get("id"), "instruction_text": inst.get("text", inst.get("op", "")), "memory_object_id": object_id, "object_size": _interval_json(obj.size_bytes), "offset": _interval_json(offset), "access_size": width if width is not None else 0, "safe_condition": "offset.lower >= 0 and offset.upper + access_size <= object_size.lower", "reason": ["access range is not provably inside the stack object", "access width is unknown" if width is None else "access width exceeds object bounds"], "source_location": inst.get("location")})

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
            callee_state = State(dict(state.integers), dict(state.pointers), dict(state.memory_objects), dict(state.string_lengths), state.reachable, state.reasons, dict(state.scalar_memory))
            for parameter, argument in zip(parameters, args):
                if argument in state.pointers:
                    callee_state = callee_state.with_pointer(parameter, state.pointers[argument])
                else:
                    callee_state = callee_state.with_int(parameter, state.get_int(argument))
            key = (name, f"{function.get('name', '')}:{inst.get('id', '')}")
            summary = self._summaries.get(key)
            # During the final effect replay, revisit user calls instead of
            # reusing the silent summary from the state-only worklist. This
            # records alarms/diagnostics produced inside callees as well.
            if summary is None or self._record_effects:
                summary = self._analyze_function(callee, callee_state, call_stack + (name,))
                self._summaries[key] = summary
            if result and summary.return_pointer is not None:
                return state.with_pointer(result, summary.return_pointer)
            if result:
                return state.with_int(result, summary.return_interval or Interval.top())
            return state
        if model_name in {"memcpy", "memmove"} and len(args) >= 3:
            dest, source = state.get_pointer(args[0]), state.get_pointer(args[1])
            length = state.get_int(args[2])
            self._check_access(inst, dest, length.lower if length.is_singleton else None, state, function, block, write=True)
            if length.is_singleton:
                source_length = self._known_string_length(state, source)
                if (
                    source_length is not None
                    and source_length.is_singleton
                    and length.lower == source_length.lower + 1
                ):
                    state = self._set_pointer_string_length(state, dest, source_length)
                return state
            self._diagnostic("UNKNOWN_LENGTH", f"{name} length is not bounded", "unknown_effect", inst, function, block, "copy width is not a known constant")
            return state
        if model_name in {"memset", "wmemset"} and len(args) >= 3:
            dest = state.get_pointer(args[0])
            value, count = state.get_int(args[1]), state.get_int(args[2])
            element_size = 4 if model_name == "wmemset" else 1
            width = count.mul(Interval.const(element_size)) if count.is_singleton else None
            self._check_access(inst, dest, width.lower if width is not None and width.is_singleton else None, state, function, block, write=True)
            if not count.is_singleton:
                self._diagnostic("UNKNOWN_LENGTH", f"{name} length is not bounded", "unknown_effect", inst, function, block, "copy width is not a known constant")
            elif value.is_singleton and value.lower == 0 and dest.offset_bytes.is_singleton and len(dest.bases) == 1:
                object_id = next(iter(dest.bases))
                offset = dest.offset_bytes.lower or 0
                if offset >= 0 and offset % element_size == 0:
                    state = state.with_string_length(object_id, Interval.const(offset // element_size))
            result = inst.get("result")
            return state.with_pointer(result, dest) if result else state
        if model_name in {"strcpy", "wcscpy"} and len(args) >= 2:
            dest, source = state.get_pointer(args[0]), state.get_pointer(args[1])
            element_size = 4 if model_name == "wcscpy" else 1
            source_length = self._known_string_length(state, source)
            if source_length is not None:
                width = source_length.add(Interval.const(1)).mul(Interval.const(element_size))
                self._check_access(inst, dest, width.lower if width.is_singleton else None, state, function, block, write=True)
                state = self._set_pointer_string_length(state, dest, source_length)
            else:
                self._check_access(inst, dest, None, state, function, block, write=True)
                self._diagnostic("UNKNOWN_STRING_LENGTH", "source string length is unknown", "unknown_effect", inst, function, block, f"{model_name} writes an unbounded string")
            result = inst.get("result")
            return state.with_pointer(result, dest) if result else state
        if model_name in {"strncpy", "wcsncpy"} and len(args) >= 3:
            dest, source, count = state.get_pointer(args[0]), state.get_pointer(args[1]), state.get_int(args[2])
            element_size = 4 if model_name == "wcsncpy" else 1
            width = count.mul(Interval.const(element_size)) if count.is_singleton else None
            self._check_access(inst, dest, width.lower if width is not None and width.is_singleton else None, state, function, block, write=True)
            source_length = self._known_string_length(state, source)
            if count.is_singleton and source_length is not None and source_length.is_singleton:
                state = self._set_pointer_string_length(state, dest, Interval.const(min(count.lower or 0, source_length.lower or 0)))
            elif not count.is_singleton:
                self._diagnostic("UNKNOWN_LENGTH", f"{name} length is not bounded", "unknown_effect", inst, function, block, "copy width is not a known constant")
            result = inst.get("result")
            return state.with_pointer(result, dest) if result else state
        if model_name in {"strcat", "wcscat", "strncat", "wcsncat"} and len(args) >= 2:
            dest, source = state.get_pointer(args[0]), state.get_pointer(args[1])
            element_size = 4 if model_name.startswith("wcs") else 1
            dest_length = self._known_string_length(state, dest)
            source_length = self._known_string_length(state, source)
            count = state.get_int(args[2]) if len(args) >= 3 else None
            if dest_length is not None and source_length is not None and (count is None or count.is_singleton):
                appended = source_length if count is None else Interval.const(min(source_length.lower or 0, count.lower or 0))
                width = dest_length.add(appended).add(Interval.const(1)).mul(Interval.const(element_size))
                self._check_access(inst, dest, width.lower if width.is_singleton else None, state, function, block, write=True)
                state = self._set_pointer_string_length(state, dest, dest_length.add(appended))
            else:
                self._check_access(inst, dest, None, state, function, block, write=True)
                self._diagnostic("UNKNOWN_STRING_LENGTH", "destination or source string length is unknown", "unknown_effect", inst, function, block, f"{model_name} writes based on an unknown string length")
            result = inst.get("result")
            return state.with_pointer(result, dest) if result else state
        if model_name in {"snprintf", "swprintf"} and len(args) >= 2:
            dest, count = state.get_pointer(args[0]), state.get_int(args[1])
            element_size = 4 if model_name == "swprintf" else 1
            width = count.mul(Interval.const(element_size)) if count.is_singleton else None
            self._check_access(inst, dest, width.lower if width is not None and width.is_singleton else None, state, function, block, write=True)
            if not count.is_singleton:
                self._diagnostic("UNKNOWN_LENGTH", f"{name} length is not bounded", "unknown_effect", inst, function, block, "output width is not a known constant")
            result = inst.get("result")
            return state.with_int(result, Interval.top()) if result else state
        if self._library_models.is_input(model_name):
            return self._input_model(inst, state, function, block, model_name)
        if name in {"globalReturnsTrue", "globalReturnsFalse", "globalReturnsTrueOrFalse"}:
            result = inst.get("result")
            value = {
                "globalReturnsTrue": Interval.const(1),
                "globalReturnsFalse": Interval.const(0),
                "globalReturnsTrueOrFalse": Interval(0, 1),
            }[name]
            return state.with_int(result, value) if result else state
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
            tracked_pointer_args = [
                arg for arg in args
                if isinstance(arg, str)
                and arg in state.pointers
                and not state.pointers[arg].is_unknown
            ]
            if not tracked_pointer_args:
                # With no tracked pointer arguments, a scalar/void external
                # call cannot mutate the stack/global objects modeled by this
                # analysis. Its result is conservatively Top; if that value is
                # later used as a pointer, the usual unknown-base diagnostic
                # still prevents an unsound clean verdict.
                result = inst.get("result")
                return state.with_int(result, Interval.top()) if result else state
            objects = dict(state.memory_objects)
            for arg in tracked_pointer_args:
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

    def _known_string_length(self, state: State, pointer: PointerValue) -> Interval | None:
        if pointer.unknown_base or not pointer.bases:
            return None
        lengths = [state.string_lengths.get(base) for base in pointer.bases]
        if any(value is None for value in lengths):
            return None
        value = next(iter(lengths))
        for other in list(lengths)[1:]:
            value = value.join(other)
        return value

    def _set_pointer_string_length(self, state: State, pointer: PointerValue, length: Interval) -> State:
        if pointer.unknown_base:
            return state
        for object_id in pointer.bases:
            state = state.with_string_length(object_id, length)
        return state

    def _format_text(self, value: Any) -> str | None:
        if isinstance(value, str):
            return self._global_string_values.get(value)
        return None

    def _initial_state(self) -> State:
        pointers = {object_id: PointerValue(frozenset({object_id}), Interval.const(0)) for object_id in self._global_objects}
        scalar_memory = {(object_id, 0): value for object_id, value in self._global_scalars.items()}
        return State(
            pointers=pointers,
            memory_objects=dict(self._global_objects),
            string_lengths=dict(self._global_strings),
            scalar_memory=scalar_memory,
        )

    def _diagnostic(self, code, message, severity, inst, function, block, impact):
        if not self._record_effects:
            return
        self.output.diagnostics.append({"diagnostic_id": f"d-{len(self.output.diagnostics)+1}", "code": code, "severity": severity, "message": message, "impact": impact, "function_name": function.get("name", ""), "block_id": block.get("id"), "instruction_id": inst.get("id"), "location": inst.get("location")})


def _comparison_interval(predicate: str, left: Interval, right: Interval) -> Interval:
    if left.bottom or right.bottom:
        return Interval.bottom_value()
    relation = predicate[1:] if predicate[:1] in {"s", "u"} else predicate
    if relation == "eq":
        if left.is_singleton and right.is_singleton:
            return Interval.const(int(left.lower == right.lower))
        if _intervals_disjoint(left, right):
            return Interval.const(0)
    elif relation == "ne":
        if left.is_singleton and right.is_singleton:
            return Interval.const(int(left.lower != right.lower))
        if _intervals_disjoint(left, right):
            return Interval.const(1)
    elif relation == "lt":
        if left.upper is not None and right.lower is not None and left.upper < right.lower:
            return Interval.const(1)
        if left.lower is not None and right.upper is not None and left.lower >= right.upper:
            return Interval.const(0)
    elif relation == "le":
        if left.upper is not None and right.lower is not None and left.upper <= right.lower:
            return Interval.const(1)
        if left.lower is not None and right.upper is not None and left.lower > right.upper:
            return Interval.const(0)
    elif relation == "gt":
        if left.lower is not None and right.upper is not None and left.lower > right.upper:
            return Interval.const(1)
        if left.upper is not None and right.lower is not None and left.upper <= right.lower:
            return Interval.const(0)
    elif relation == "ge":
        if left.lower is not None and right.upper is not None and left.lower >= right.upper:
            return Interval.const(1)
        if left.upper is not None and right.lower is not None and left.upper < right.lower:
            return Interval.const(0)
    return Interval(0, 1)


def _refine_cmp(state, predicate, left, right, truth, left_name, right_name):
    predicate = str(predicate)
    outcome = _comparison_interval(predicate, left, right)
    if outcome.is_singleton and outcome.lower != int(truth):
        return State.unreachable()
    if not truth:
        predicate = _negate_predicate(predicate)
    relation = predicate[1:] if predicate[:1] in {"s", "u"} else predicate
    left_var = isinstance(left_name, str) and left_name in state.integers
    right_var = isinstance(right_name, str) and right_name in state.integers

    if relation == "eq":
        common = left.meet(right)
        if common.bottom:
            return State.unreachable()
        if left_var:
            state = _refine_name(state, left_name, common)
        if right_var:
            state = _refine_name(state, right_name, common)
        return state
    if relation == "ne":
        if left.is_singleton and right.is_singleton and left.lower == right.lower:
            return State.unreachable()
        if left_var and right.is_singleton:
            state = _refine_name(state, left_name, _exclude_value(left, right.lower))
        if right_var and left.is_singleton:
            state = _refine_name(state, right_name, _exclude_value(right, left.lower))
        return state
    if relation not in {"lt", "le", "gt", "ge"}:
        return state

    if relation in {"lt", "le"}:
        if left_var and right.upper is not None:
            upper = right.upper - (1 if relation == "lt" else 0)
            state = _refine_name(state, left_name, Interval(None, upper))
        if right_var and left.lower is not None:
            lower = left.lower + (1 if relation == "lt" else 0)
            state = _refine_name(state, right_name, Interval(lower, None))
    else:
        if left_var and right.lower is not None:
            lower = right.lower + (1 if relation == "gt" else 0)
            state = _refine_name(state, left_name, Interval(lower, None))
        if right_var and left.upper is not None:
            upper = left.upper - (1 if relation == "gt" else 0)
            state = _refine_name(state, right_name, Interval(None, upper))
    return state


def _negate_predicate(predicate: str) -> str:
    relation = predicate[1:] if predicate[:1] in {"s", "u"} else predicate
    prefix = predicate[:1] if predicate[:1] in {"s", "u"} else ""
    negated = {
        "eq": "ne",
        "ne": "eq",
        "lt": "ge",
        "le": "gt",
        "gt": "le",
        "ge": "lt",
    }.get(relation, relation)
    return prefix + negated


def _refine_name(state: State, name: str, constraint: Interval) -> State:
    if name not in state.integers:
        return state
    refined = state.get_int(name).meet(constraint)
    if refined.bottom:
        return State.unreachable()
    return state.with_int(name, refined)


def _exclude_value(interval: Interval, value: int | None) -> Interval:
    if value is None or interval.bottom or not interval.contains(value):
        return interval
    if interval.is_singleton:
        return Interval.bottom_value()
    if interval.lower == value:
        return Interval(value + 1, interval.upper)
    if interval.upper == value:
        return Interval(interval.lower, value - 1)
    return interval


def _intervals_disjoint(left: Interval, right: Interval) -> bool:
    if left.bottom or right.bottom:
        return True
    return (left.upper is not None and right.lower is not None and left.upper < right.lower) or (right.upper is not None and left.lower is not None and right.upper < left.lower)


def _interval_json(value: Interval) -> dict[str, Any]:
    return {"lower": value.lower, "upper": value.upper, "is_bottom": value.bottom}


def _state_json(state: State) -> dict[str, Any]:
    return {"reachable": state.reachable, "integers": {k: _interval_json(v) for k, v in state.integers.items()}, "pointers": {k: {"bases": sorted(v.bases), "offset_bytes": _interval_json(v.offset_bytes), "unknown_base": v.unknown_base} for k, v in state.pointers.items()}, "memory_objects": {k: {"size_bytes": _interval_json(v.size_bytes), "escaped": v.escaped} for k, v in state.memory_objects.items()}}


def _instruction_text(inst: dict[str, Any]) -> str:
    """Return a compact IR line even for hand-authored MiniIR fixtures."""
    if inst.get("text"):
        return str(inst["text"])
    op = str(inst.get("op", "instruction"))
    result = f"{inst['result']} = " if inst.get("result") else ""
    if op in {"const", "constant"}:
        return f"{result}const {inst.get('value', 0)}"
    if op in {"add", "sub", "mul", "icmp"}:
        operands = ", ".join(str(inst.get(key, "?")) for key in ("left", "right"))
        return f"{result}{op} {operands}"
    if op in {"gep", "getelementptr"}:
        return f"{result}gep {inst.get('base', '?')} + {inst.get('index', '?')}"
    if op in {"load", "store"}:
        return f"{result}{op} {inst.get('pointer', '?')}"
    if op == "call":
        return f"{result}call @{inst.get('callee', '?')}"
    return f"{result}{op}"
