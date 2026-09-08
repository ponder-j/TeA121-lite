# Analyzer semantics (iteration I1-I4)

The Python engine uses closed integer intervals and half-open byte ranges. A
width-`w` access at offset `o` covers `[o, o + w)`. It is silent only when the
lower and upper bounds prove the whole range lies inside the object's minimum
size. Any uncertain range becomes a `possible` alarm; a range that is outside
for every value becomes `definite`.

`Bottom` means an unreachable path and `Top` means an unknown value. Integer
operations with a possible fixed-width overflow conservatively return `Top`.
Unknown calls mark pointer arguments' stack objects as escaped and emit an
`unknown_effect` diagnostic. Unsupported instructions emit `unsupported`
diagnostics and are never counted as clean cases. Bounded input routines model
their maximum destination write (`fgets`, `recv`); `fscanf` numeric conversions
use a fixed scalar width while string conversions stay unknown. Pointer loads
from external declarations produce an unknown pointer value without an access
diagnostic until that pointer is dereferenced.
