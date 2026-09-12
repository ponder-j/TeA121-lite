from __future__ import annotations

from dataclasses import dataclass, field

from .interval import Interval


@dataclass(frozen=True)
class PointerValue:
    """Pointer bases plus a byte offset interval."""

    bases: frozenset[str] = field(default_factory=frozenset)
    offset_bytes: Interval = field(default_factory=Interval.top)
    unknown_base: bool = False
    # Absolute end (relative to each base object's start) of an aggregate
    # subobject selected by a GEP. ``None`` means the full allocation bounds.
    bound_end_bytes: Interval | None = None

    @classmethod
    def unknown(cls) -> "PointerValue":
        return cls(unknown_base=True, offset_bytes=Interval.top())

    def join(self, other: "PointerValue") -> "PointerValue":
        if self.bound_end_bytes is None or other.bound_end_bytes is None:
            bound_end = None
        else:
            bound_end = self.bound_end_bytes.join(other.bound_end_bytes)
        return PointerValue(
            self.bases | other.bases,
            self.offset_bytes.join(other.offset_bytes),
            self.unknown_base or other.unknown_base,
            bound_end,
        )

    @property
    def is_unknown(self) -> bool:
        return self.unknown_base
