"""Registry boundary for conservative library summaries."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class FunctionModel(Protocol):
    name: str

    def apply(self, call: dict[str, Any], state: Any) -> Any:
        ...


@dataclass(frozen=True)
class LibraryModelRegistry:
    """Names known to the solver; model behavior stays replaceable."""

    names: frozenset[str] = field(default_factory=lambda: frozenset({"memcpy", "memmove", "memset", "strcpy", "strncpy"}))
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
        "printLine", "printIntLine", "printWLine", "printBytesLine",
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
