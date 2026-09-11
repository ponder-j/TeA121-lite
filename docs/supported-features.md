# Supported features

| Feature | Status | Notes |
| --- | --- | --- |
| MiniIR JSON 1.0.0 loading | supported | Schema checked before analysis |
| Interval join/meet/widen | supported | Fixed-width overflow degrades to Top |
| Typed integer overflow (CWE-190) | supported | `add`/`sub`/`mul` whose result provably leaves the type range emit an alarm; signed 8/16/32/64-bit by default |
| alloca, GEP, load, store | supported | Byte offsets and stack object evidence |
| Scalar store/load summaries | partial | Constant values tracked by object and byte offset; joins remain conservative |
| icmp branch refinement | supported | Explicit comparison terminator metadata |
| phi/select and worklist CFG | supported | Loop widening after configurable iterations |
| memcpy/memmove/memset/strncpy | supported | Unknown lengths are conservative |
| strcpy | supported | Exact only with a known source string length |
| fgets/recv input writes | partial | Constant maximum count is checked; unknown bounds remain unsupported |
| fscanf input | partial | Numeric conversions use fixed scalar widths; string conversions remain unbounded |
| Scalar library returns | partial | `atoi`/`rand`/`strlen`/socket returns are abstracted and propagated |
| Unknown calls/instructions | conservative | Diagnostic plus pointer escape where applicable |
| C/LLVM source input | supported | Docker image provides LLVM 15 compiler, optimizer, extractor, and CLI bridge |
| Juliet s01 evaluation | partial | 532 manifest cases, four-state JSON/CSV, split-file linking, SHA-256 and `--jobs` parallelism; unsupported semantics remain explicit |
