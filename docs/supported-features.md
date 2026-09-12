# Supported features

| Feature | Status | Notes |
| --- | --- | --- |
| MiniIR JSON 1.0.0 loading | supported | Schema checked before analysis |
| Interval join/meet/widen/narrow | supported | Single-sided infinities are preserved; fixed-width overflow retains the full type range |
| Typed integer overflow/underflow (CWE-190/CWE-191) | supported | `add`/`sub`/`mul` and narrowing casts are checked against explicit signed/unsigned type ranges; overflow and underflow receive separate CWEs |
| alloca, GEP, load, store | supported | Byte offsets and stack object evidence |
| Scalar store/load summaries | partial | Constant values tracked by object and byte offset; joins remain conservative |
| icmp branch refinement | supported | All signed/unsigned ordering predicates, both true and false edges, variables and constants |
| phi/select and worklist CFG | supported | Edge-sensitive PHI, loop widening, bounded narrowing, and alarm replay on the final fixed point |
| memcpy/memmove/memset/strncpy | supported | Unknown lengths are conservative |
| strcpy | supported | Exact only with a known source string length |
| fgets/recv input writes | partial | Constant maximum count is checked; unknown bounds remain unsupported |
| fscanf input | partial | Numeric conversions use destination element widths; `%s`/`%[` remain unbounded |
| Scalar library returns | partial | `atoi`/`rand`/`strlen`/socket returns are abstracted and propagated |
| Unknown calls/instructions | conservative | Diagnostic plus pointer escape where applicable |
| C/LLVM source input | supported | Docker image provides LLVM 15 compiler, optimizer, extractor, and CLI bridge |
| Juliet s01 evaluation | partial | 532 manifest cases, four-state JSON/CSV, split-file linking, SHA-256 and `--jobs` parallelism; unsupported semantics remain explicit |
