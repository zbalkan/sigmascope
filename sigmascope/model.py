from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal, NamedTuple, Union


@dataclass(frozen=True)
class CollectionError:
    source_id: str
    message: str
    resource: str = ""


@dataclass(frozen=True)
class Origin:
    resource: str
    locator: str


Determinacy = Literal["effective", "unknown"]


@dataclass(frozen=True)
class Gate:
    key: str
    value: str | int | bool
    determinacy: Determinacy
    origin: Origin


PredicateOp = Literal[
    "eq",
    "ne",
    "lt",
    "le",
    "gt",
    "ge",
    "bitand",
    "bitest",
    "contains",
]


@dataclass(frozen=True)
class Predicate:
    field: str
    op: PredicateOp
    value: str
    raw: str


class Effect(Enum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class SyscallSelector(NamedTuple):
    syscalls: frozenset[str]
    scope: str


class EventTypeSelector(NamedTuple):
    event_type: str


Selector = Union[SyscallSelector, EventTypeSelector]


@dataclass(frozen=True)
class Rule:
    effect: Effect
    selector: Selector
    predicates: tuple[Predicate, ...]
    order: int
    complete: bool
    origin: Origin
    raw: str


@dataclass(frozen=True)
class Diagnostic:
    severity: Literal["warn", "error"]
    message: str
    origin: Origin
    raw: str


@dataclass(frozen=True)
class ParseResult:
    source_id: str
    determinacy: Determinacy
    gates: tuple[Gate, ...] = ()
    rules: tuple[Rule, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()


class Verdict(Enum):
    COVERED = "covered"
    DEGRADED = "degraded"
    NOT_COVERED = "not_covered"
    INDETERMINATE = "indeterminate"

    @property
    def satisfied(self) -> bool:
        return self is Verdict.COVERED
