from __future__ import annotations

from dataclasses import dataclass, field

from .interval import Interval


@dataclass(frozen=True)
class PointerValue:
    """Pointer bases plus a byte offset interval."""

    bases: frozenset[str] = field(default_factory=frozenset)
    offset_bytes: Interval = field(default_factory=Interval.top)
    unknown_base: bool = False

    @classmethod
    def unknown(cls) -> "PointerValue":
        return cls(unknown_base=True, offset_bytes=Interval.top())

    def join(self, other: "PointerValue") -> "PointerValue":
        return PointerValue(self.bases | other.bases, self.offset_bytes.join(other.offset_bytes), self.unknown_base or other.unknown_base)

    @property
    def is_unknown(self) -> bool:
        return self.unknown_base
