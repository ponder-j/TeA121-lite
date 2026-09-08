"""Integer interval lattice used by the forward abstract interpreter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Interval:
    """A closed interval, with ``None`` as an open infinity.

    ``bottom`` is kept explicit so Bottom is never confused with Top.
    """

    lower: Optional[int] = None
    upper: Optional[int] = None
    bottom: bool = False

    @classmethod
    def top(cls) -> "Interval":
        return cls()

    @classmethod
    def bottom_value(cls) -> "Interval":
        return cls(bottom=True)

    @classmethod
    def bottom_interval(cls) -> "Interval":
        """Readable alias for callers that avoid the lattice term."""
        return cls.bottom_value()

    @classmethod
    def const(cls, value: int) -> "Interval":
        return cls(value, value)

    @classmethod
    def range(cls, lower: int, upper: int) -> "Interval":
        if lower > upper:
            return cls.bottom_value()
        return cls(lower, upper)

    @property
    def is_top(self) -> bool:
        return not self.bottom and self.lower is None and self.upper is None

    @property
    def is_bottom(self) -> bool:
        return self.bottom

    @property
    def is_singleton(self) -> bool:
        return not self.bottom and self.lower is not None and self.lower == self.upper

    def __str__(self) -> str:
        if self.bottom:
            return "Bottom"
        return f"[{self.lower if self.lower is not None else '-inf'}, {self.upper if self.upper is not None else '+inf'}]"

    def join(self, other: "Interval") -> "Interval":
        if self.bottom:
            return other
        if other.bottom:
            return self
        lower = self.lower if other.lower is None else other.lower if self.lower is None else min(self.lower, other.lower)
        upper = self.upper if other.upper is None else other.upper if self.upper is None else max(self.upper, other.upper)
        return Interval(lower, upper)

    def meet(self, other: "Interval") -> "Interval":
        if self.bottom or other.bottom:
            return Interval.bottom_value()
        lower = other.lower if self.lower is None else self.lower if other.lower is None else max(self.lower, other.lower)
        upper = other.upper if self.upper is None else self.upper if other.upper is None else min(self.upper, other.upper)
        return Interval.range(lower, upper) if lower is not None and upper is not None and lower > upper else Interval(lower, upper)

    def contains(self, value: int) -> bool:
        return not self.bottom and (self.lower is None or value >= self.lower) and (self.upper is None or value <= self.upper)

    def subset_of(self, other: "Interval") -> bool:
        if self.bottom:
            return True
        if other.bottom:
            return False
        return (other.lower is None or (self.lower is not None and self.lower >= other.lower)) and (other.upper is None or (self.upper is not None and self.upper <= other.upper))

    def add(self, other: "Interval", *, bits: int | None = None, signed: bool = True) -> "Interval":
        return self._arithmetic(other, lambda a, b: a + b, bits=bits, signed=signed)

    def sub(self, other: "Interval", *, bits: int | None = None, signed: bool = True) -> "Interval":
        if self.bottom or other.bottom:
            return Interval.bottom_value()
        if None in (self.lower, self.upper, other.lower, other.upper):
            return Interval.top()
        return self._bounded(self.lower - other.upper, self.upper - other.lower, bits, signed)

    def mul(self, other: "Interval", *, bits: int | None = None, signed: bool = True) -> "Interval":
        if self.bottom or other.bottom:
            return Interval.bottom_value()
        if None in (self.lower, self.upper, other.lower, other.upper):
            return Interval.top()
        values = [self.lower * other.lower, self.lower * other.upper, self.upper * other.lower, self.upper * other.upper]
        return self._bounded(min(values), max(values), bits, signed)

    def widen(self, other: "Interval") -> "Interval":
        if self.bottom:
            return other
        if other.bottom:
            return self
        lower = self.lower if other.lower is not None and self.lower is not None and other.lower >= self.lower else None
        upper = self.upper if other.upper is not None and self.upper is not None and other.upper <= self.upper else None
        return Interval(lower, upper)

    def refine_lower(self, value: int) -> "Interval":
        return self.meet(Interval(value, None))

    def refine_upper(self, value: int) -> "Interval":
        return self.meet(Interval(None, value))

    def _arithmetic(self, other: "Interval", operation, *, bits: int | None, signed: bool) -> "Interval":
        if self.bottom or other.bottom:
            return Interval.bottom_value()
        if None in (self.lower, self.upper, other.lower, other.upper):
            return Interval.top()
        return self._bounded(operation(self.lower, other.lower), operation(self.upper, other.upper), bits, signed)

    @staticmethod
    def _bounded(lower: int, upper: int, bits: int | None, signed: bool) -> "Interval":
        if bits is None:
            return Interval(lower, upper)
        if signed:
            lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
        else:
            lo, hi = 0, (1 << bits) - 1
        if lower < lo or upper > hi:
            return Interval.top()
        return Interval(lower, upper)


TOP = Interval.top()
BOTTOM = Interval.bottom_value()
