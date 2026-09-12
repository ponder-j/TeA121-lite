# Analyzer semantics (iteration I1-I4)

The Python engine uses closed integer intervals and half-open byte ranges. A
width-`w` access at offset `o` covers `[o, o + w)`. It is silent only when the
lower and upper bounds prove the whole range lies inside the object's minimum
size. Any uncertain range becomes a `possible` alarm; a range that is outside
for every value becomes `definite`.

`Bottom` means an unreachable path and `Top` means an unknown value. Integer
operations whose mathematical result leaves the recorded type range are
checked against that range. A result above the type maximum raises a
`CWE-190` `integer_overflow` alarm; a result below the minimum raises a
`CWE-191` `integer_underflow` alarm (`definite` when every value leaves the
range, `possible` when the interval straddles a bound). After the check, the
abstract value is conservatively clamped to the complete type range rather
than discarded as `Top`, so downstream `trunc`/store checks retain the type
width. ``store`` instructions are checked the same way against their
destination width, which catches narrowing assignments such as
``char c = c + 1`` that LLVM lowers as a wide operation plus a truncating
store. LLVM IR integer types are signless; ``zext``/``sext``/``trunc`` and
unsigned comparison predicates are modelled explicitly, and callers may
provide a fallback signedness when DWARF information is unavailable.
Unknown calls mark pointer arguments' stack objects as escaped and emit an
`unknown_effect` diagnostic. Unsupported instructions emit `unsupported`
diagnostics and are never counted as clean cases. Bounded input routines model
their maximum destination write (`fgets`, `recv`); `fscanf` numeric conversions
use a fixed scalar width while string conversions stay unknown. Pointer loads
from external declarations produce an unknown pointer value without an access
diagnostic until that pointer is dereferenced.
