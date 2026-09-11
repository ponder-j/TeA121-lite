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
        if self.is_top or other.is_top:
            return Interval.top()
        lower = min(self.lower, other.lower) if self.lower is not None and other.lower is not None else None
        upper = max(self.upper, other.upper) if self.upper is not None and other.upper is not None else None
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
        if self.bottom or other.bottom:
            return Interval.bottom_value()
        lower = self.lower + other.lower if self.lower is not None and other.lower is not None else None
        upper = self.upper + other.upper if self.upper is not None and other.upper is not None else None
        return self._bounded(lower, upper, bits, signed)

    def sub(self, other: "Interval", *, bits: int | None = None, signed: bool = True) -> "Interval":
        if self.bottom or other.bottom:
            return Interval.bottom_value()
        lower = self.lower - other.upper if self.lower is not None and other.upper is not None else None
        upper = self.upper - other.lower if self.upper is not None and other.lower is not None else None
        return self._bounded(lower, upper, bits, signed)

    def mul(self, other: "Interval", *, bits: int | None = None, signed: bool = True) -> "Interval":
        if self.bottom or other.bottom:
            return Interval.bottom_value()
        if self.is_singleton:
            return other._scale(self.lower, bits=bits, signed=signed)
        if other.is_singleton:
            return self._scale(other.lower, bits=bits, signed=signed)
        if None in (self.lower, self.upper, other.lower, other.upper):
            return Interval.top()
        values = [self.lower * other.lower, self.lower * other.upper, self.upper * other.lower, self.upper * other.upper]
        return self._bounded(min(values), max(values), bits, signed)

    def _scale(self, factor: int, *, bits: int | None, signed: bool) -> "Interval":
        if factor == 0:
            return Interval.const(0)
        if factor > 0:
            lower = self.lower * factor if self.lower is not None else None
            upper = self.upper * factor if self.upper is not None else None
        else:
            lower = self.upper * factor if self.upper is not None else None
            upper = self.lower * factor if self.lower is not None else None
        return self._bounded(lower, upper, bits, signed)

    def widen(self, other: "Interval") -> "Interval":
        if self.bottom:
            return other
        if other.bottom:
            return self
        lower = self.lower if other.lower is not None and self.lower is not None and other.lower >= self.lower else None
        upper = self.upper if other.upper is not None and self.upper is not None and other.upper <= self.upper else None
        return Interval(lower, upper)

    def narrow(self, other: "Interval") -> "Interval":
        """Return the greatest common lower approximation used by narrowing.

        For the interval lattice this is intersection: narrowing may only
        remove values from the widened candidate and never re-introduces a
        bound that widening already discarded.
        """
        return self.meet(other)

    def refine_lower(self, value: int) -> "Interval":
        return self.meet(Interval(value, None))

    def refine_upper(self, value: int) -> "Interval":
        return self.meet(Interval(None, value))

    @classmethod
    def type_range(cls, bits: int, signed: bool = True) -> "Interval":
        """Representable range of a ``bits``-wide integer type.

        ``signed`` selects the two's-complement signed range (for example
        ``[-128, 127]`` for 8 bits) or the unsigned range (``[0, 255]``).
        A non-positive width has no usable range and degrades to Top.
        """
        if bits <= 0:
            return cls.top()
        if signed:
            return cls(-(1 << (bits - 1)), (1 << (bits - 1)) - 1)
        return cls(0, (1 << bits) - 1)

    def overflow_kind(self, bits: int, signed: bool = True) -> Optional[str]:
        """Classify how ``self`` relates to a fixed-width integer range.

        Returns ``"definite"`` when every value in the interval lies outside
        the type range (a guaranteed overflow/underflow), ``"possible"`` when
        the interval straddles a bound (only some values overflow), and
        ``None`` when no overflow is provable (including Top and Bottom).
        """
        if self.bottom or bits <= 0:
            return None
        limits = Interval.type_range(bits, signed)
        low, high = limits.lower, limits.upper
        if self.upper is not None and self.upper < low:
            return "definite"
        if self.lower is not None and self.lower > high:
            return "definite"
        lower_outside = self.lower is not None and self.lower < low
        upper_outside = self.upper is not None and self.upper > high
        if lower_outside or upper_outside:
            return "possible"
        return None

    @staticmethod
    def _bounded(lower: int | None, upper: int | None, bits: int | None, signed: bool) -> "Interval":
        if bits is None:
            return Interval(lower, upper)
        limits = Interval.type_range(bits, signed)
        lo, hi = limits.lower, limits.upper
        if not signed:
            lower = lo if lower is None else lower
            upper = hi if upper is None else upper
        if (lower is not None and lower < lo) or (upper is not None and upper > hi):
            return Interval.top()
        return Interval(lower, upper)


TOP = Interval.top()
BOTTOM = Interval.bottom_value()
