# Analyzer semantics (iteration I1-I4)

The Python engine uses closed integer intervals and half-open byte ranges. A
width-`w` access at offset `o` covers `[o, o + w)`. It is silent only when the
lower and upper bounds prove the whole range lies inside the object's minimum
size. Any uncertain range becomes a `possible` alarm; a range that is outside
for every value becomes `definite`.

`Bottom` means an unreachable path and `Top` means an unknown value. Integer
operations with a possible fixed-width overflow conservatively return `Top`.
Before degrading, the engine checks the mathematical result against the
type range recorded on the instruction (`bits`, and `signed` when present):
`add`/`sub`/`mul` that leave the range raise a `CWE-190` `integer_overflow`
alarm (`definite` when every value overflows, `possible` when the interval
straddles a bound). ``store`` instructions are checked the same way against
their destination width, which catches narrowing assignments such as
``char c = c + 1`` that LLVM lowers as a wide operation plus a truncating
store. Both directions are reported as CWE-190 (CWE-191 is the related
underflow-specific weakness). LLVM IR is signless, so when the extractor does
not record ``signed`` the engine assumes a signed type; this can misjudge
unsigned wraparound until per-variable signedness is carried through MiniIR.
Unknown calls mark pointer arguments' stack objects as escaped and emit an
`unknown_effect` diagnostic. Unsupported instructions emit `unsupported`
diagnostics and are never counted as clean cases. Bounded input routines model
their maximum destination write (`fgets`, `recv`); `fscanf` numeric conversions
use a fixed scalar width while string conversions stay unknown. Pointer loads
from external declarations produce an unknown pointer value without an access
diagnostic until that pointer is dereferenced.
