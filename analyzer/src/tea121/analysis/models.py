"""Registry boundary for conservative library summaries."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

# Detector / rule-pack identity stamped onto every alarm and onto the top-level
# result. The engine still ships as a single "core" detector, but individual
# alarms carry their own CWE so new checks (for example CWE-190 integer
# overflow) can be added without changing the run-level snapshot.
DETECTOR_ID = "stack-bounds"
DETECTOR_VERSION = "0.1.0"
RULE_PACK_ID = "cwe121-core"
RULE_PACK_VERSION = "0.1.0"

CWE_STACK_BOUNDS = "CWE-121"
CWE_INTEGER_OVERFLOW = "CWE-190"


class FunctionModel(Protocol):
    name: str

    def apply(self, call: dict[str, Any], state: Any) -> Any:
        ...


@dataclass(frozen=True)
class LibraryModelRegistry:
    """Names known to the solver; model behavior stays replaceable."""

    names: frozenset[str] = field(default_factory=lambda: frozenset({"memcpy", "memmove", "memset", "wmemset", "strcpy", "strncpy", "strcat", "strncat", "wcscpy", "wcsncpy", "wcscat", "wcsncat", "snprintf", "swprintf"}))
    # Input routines have dedicated conservative transfer functions in the
    # solver. Keeping them separate from ``names`` means the user-facing
    # ``--models`` switch continues to control copy/string models only.
    input_names: frozenset[str] = field(default_factory=lambda: frozenset({"fgets", "fscanf", "recv"}))
    # Calls in this set are observational or return an abstract value without
    # mutating pointer arguments. They must not turn an otherwise analyzable
    # case into ``unknown_effect`` merely because Juliet prints diagnostics.
    pure_names: frozenset[str] = field(default_factory=lambda: frozenset({
        "strlen", "wcslen", "rand", "atoi", "time", "htons", "inet_addr",
        "socket", "connect", "bind", "listen", "accept", "CLOSE_SOCKET",
        "WSAStartup", "WSACleanup", "MAKEWORD", "exit", "free",
        "printLine", "printIntLine", "printLongLongLine", "printStructLine",
        "printWLine", "printBytesLine", "__cxa_begin_catch", "_ZSt9terminatev",
        "_ZdlPv",
    }))

    def supports(self, name: str) -> bool:
        return name in self.names

    def is_pure(self, name: str) -> bool:
        return name in self.pure_names

    def is_input(self, name: str) -> bool:
        return name in self.input_names

    def with_enabled(self, enabled: tuple[str, ...] | list[str]) -> "LibraryModelRegistry":
        return LibraryModelRegistry(
            frozenset(name for name in enabled if name in self.names),
            self.input_names,
            self.pure_names,
        )
