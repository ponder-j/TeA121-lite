from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from .interval import Interval
from .pointer import PointerValue


@dataclass(frozen=True)
class MemoryObject:
    id: str
    size_bytes: Interval
    allocation_site: dict[str, Any] = field(default_factory=dict)
    escaped: bool = False


@dataclass(frozen=True)
class State:
    integers: dict[str, Interval] = field(default_factory=dict)
    pointers: dict[str, PointerValue] = field(default_factory=dict)
    memory_objects: dict[str, MemoryObject] = field(default_factory=dict)
    string_lengths: dict[str, Interval] = field(default_factory=dict)
    reachable: bool = True
    reasons: tuple[str, ...] = ()
    scalar_memory: dict[tuple[str, int], Interval] = field(default_factory=dict)

    @classmethod
    def unreachable(cls) -> "State":
        return cls(reachable=False)

    def get_int(self, value: Any) -> Interval:
        if isinstance(value, bool):
            return Interval.const(int(value))
        if isinstance(value, int):
            return Interval.const(value)
        if isinstance(value, str):
            try:
                return Interval.const(int(value, 0))
            except ValueError:
                pass
        key = str(value)
        return self.integers.get(key, Interval.top())

    def get_pointer(self, value: Any) -> PointerValue:
        if isinstance(value, PointerValue):
            return value
        return self.pointers.get(str(value), PointerValue.unknown())

    def with_int(self, name: str, value: Interval) -> "State":
        ints = dict(self.integers)
        ints[name] = value
        return replace(self, integers=ints)

    def get_memory_int(self, object_id: str, offset: int = 0) -> Interval:
        return self.scalar_memory.get((object_id, offset), Interval.top())

    def with_memory_int(self, object_id: str, value: Interval, offset: int = 0) -> "State":
        memory = dict(self.scalar_memory)
        memory[(object_id, offset)] = value
        return replace(self, scalar_memory=memory)

    def with_pointer(self, name: str, value: PointerValue) -> "State":
        ptrs = dict(self.pointers)
        ptrs[name] = value
        return replace(self, pointers=ptrs)

    def with_object(self, obj: MemoryObject) -> "State":
        objects = dict(self.memory_objects)
        objects[obj.id] = obj
        return replace(self, memory_objects=objects)

    def join(self, other: "State") -> "State":
        if not self.reachable:
            return other
        if not other.reachable:
            return self
        ints = {k: self.integers.get(k, Interval.top()).join(other.integers.get(k, Interval.top())) for k in self.integers.keys() | other.integers.keys()}
        ptrs = {k: self.pointers[k].join(other.pointers[k]) for k in self.pointers.keys() & other.pointers.keys()}
        ptrs.update({k: v for k, v in self.pointers.items() if k not in other.pointers})
        ptrs.update({k: v for k, v in other.pointers.items() if k not in self.pointers})
        objects = dict(self.memory_objects)
        for key, obj in other.memory_objects.items():
            if key in objects:
                current = objects[key]
                objects[key] = replace(current, size_bytes=current.size_bytes.join(obj.size_bytes), escaped=current.escaped or obj.escaped)
            else:
                objects[key] = obj
        strings = {k: self.string_lengths.get(k, Interval.top()).join(other.string_lengths.get(k, Interval.top())) for k in self.string_lengths.keys() | other.string_lengths.keys()}
        scalar_memory = {
            key: self.scalar_memory.get(key, Interval.top()).join(other.scalar_memory.get(key, Interval.top()))
            for key in self.scalar_memory.keys() | other.scalar_memory.keys()
        }
        return State(ints, ptrs, objects, strings, True, tuple(dict.fromkeys(self.reasons + other.reasons)), scalar_memory)

    def widen(self, other: "State") -> "State":
        joined = self.join(other)
        ints = {k: self.integers.get(k, Interval.top()).widen(joined.integers.get(k, Interval.top())) for k in joined.integers}
        return replace(joined, integers=ints)
