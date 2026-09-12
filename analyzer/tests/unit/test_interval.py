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


def test_narrow_recovers_finite_bounds_from_widened_top():
    assert Interval(0, None).narrow(Interval.range(0, 9)) == Interval.range(0, 9)
    assert Interval.top().narrow(Interval.range(2, 4)) == Interval.range(2, 4)


def test_open_interval_arithmetic_preserves_single_sided_bounds():
    assert Interval(None, 9).add(Interval.const(1)) == Interval(None, 10)
    assert Interval(None, 9).mul(Interval.const(4)) == Interval(None, 36)
    assert Interval(None, 9).mul(Interval.const(-4)) == Interval(-36, None)


def test_overflow_returns_full_type_range():
    assert Interval.const(127).add(Interval.const(1), bits=8, signed=True) == Interval(-128, 127)


def test_join_is_commutative_and_top_is_absorbing():
    bounded = Interval.range(0, 2)
    top = Interval.top()
    assert bounded.join(top).is_top
    assert top.join(bounded).is_top
    assert bounded.join(top) == top.join(bounded)


def test_type_range_reflects_signedness():
    assert Interval.type_range(8, signed=True) == Interval.range(-128, 127)
    assert Interval.type_range(8, signed=False) == Interval.range(0, 255)
    assert Interval.type_range(0).is_top


def test_overflow_kind_classifies_definite_and_possible():
    assert Interval.const(128).overflow_kind(8) == "definite"
    assert Interval.const(127).overflow_kind(8) is None
    assert Interval.const(-129).overflow_kind(8) == "definite"
    assert Interval.range(100, 200).overflow_kind(8) == "possible"
    assert Interval.range(-200, 0).overflow_kind(8) == "possible"
    assert Interval.top().overflow_kind(8) is None
    assert Interval.bottom_value().overflow_kind(8) is None


def test_unsigned_type_range_is_not_signed_overflow():
    assert Interval.const(200).overflow_kind(8, signed=False) is None
    assert Interval.const(256).overflow_kind(8, signed=False) == "definite"
