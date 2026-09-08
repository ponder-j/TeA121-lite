from tea121.domain import Interval


def test_lattice_and_arithmetic():
    assert Interval.const(2).join(Interval.const(4)) == Interval.range(2, 4)
    assert Interval.range(1, 5).meet(Interval.range(3, 8)) == Interval.range(3, 5)
    assert Interval.range(1, 2).sub(Interval.range(3, 4)) == Interval.range(-3, -1)
    assert Interval.range(1, 2).mul(Interval.range(3, 4)) == Interval.range(3, 8)


def test_bottom_top_are_distinct():
    assert Interval.bottom_value().is_bottom
    assert Interval.top().is_top
    assert Interval.bottom_value().join(Interval.const(1)) == Interval.const(1)


def test_overflow_loses_precision():
    assert Interval.const(127).add(Interval.const(1), bits=8, signed=True).is_top
