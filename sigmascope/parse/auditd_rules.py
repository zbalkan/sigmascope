from __future__ import annotations

import re

from sigmascope.model import (
    Diagnostic,
    Effect,
    Origin,
    ParseResult,
    Predicate,
    Rule,
    SyscallSelector,
)


_OPTION_BOUNDARY = re.compile(r"(?<!\S)-[A-Za-z](?=\s|$)")
_FILTER = re.compile(
    r"^(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<op>!=|<=|>=|&=|=|<|>|&)\s*(?P<value>.*)$"
)
_ACTIONS = {
    "always": Effect.INCLUDE,
    "never": Effect.EXCLUDE,
}
_OPS = {
    "=": "eq",
    "!=": "ne",
    "<": "lt",
    "<=": "le",
    ">": "gt",
    ">=": "ge",
    "&": "bitand",
    "&=": "bitest",
}


def split_options(line: str) -> tuple[str, ...]:
    starts = [match.start() for match in _OPTION_BOUNDARY.finditer(line)]
    if not starts:
        return (line,)
    if starts[0] != 0:
        starts.insert(0, 0)
    return tuple(
        line[start : starts[index + 1] if index + 1 < len(starts) else len(line)]
        for index, start in enumerate(starts)
    )


def _filter(raw: str) -> Predicate | None:
    match = _FILTER.match(raw)
    if match is None:
        return None
    field = match.group("field").lower()
    value = match.group("value")
    if field == "auid" and value in {"-1", "4294967295"}:
        value = "unset"
    return Predicate(field, _OPS[match.group("op")], value)


def parse_auditd_rules(source_id: str, data: str | bytes) -> ParseResult:
    text = (
        data.decode("utf-8", "surrogateescape")
        if isinstance(data, bytes)
        else data
    )
    rules: list[Rule] = []
    diagnostics: list[Diagnostic] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        origin = Origin(source_id, f"line {line_number}")
        tokens = [part.strip() for part in split_options(line) if part.strip()]
        rule, issues = _parse_rule(line, tokens, len(rules) + 1, origin)
        diagnostics.extend(issues)
        if rule is not None:
            rules.append(rule)

    return ParseResult(
        "unknown" if diagnostics else "effective",
        rules=tuple(rules),
        diagnostics=tuple(diagnostics),
    )


def _parse_rule(
    raw_line: str,
    tokens: list[str],
    order: int,
    origin: Origin,
) -> tuple[Rule | None, list[Diagnostic]]:
    diagnostics: list[Diagnostic] = []
    effect: Effect | None = None
    scope = "exit"
    syscalls: set[str] = set()
    predicates: list[Predicate] = []
    watch_path: str | None = None
    watch_perms: str | None = None

    for token in tokens:
        option, _, value = token.partition(" ")
        value = value.strip()
        if option in {"-a", "-A"}:
            if "," not in value:
                diagnostics.append(
                    Diagnostic("warn", f"invalid {option} value {value!r}", origin, token)
                )
                continue
            first, second = (
                part.strip().lower() for part in value.split(",", 1)
            )
            # auditctl accepts -a <action>,<list> and -a <list>,<action>;
            # auditctl -l normalises to the former, rule files need not.
            if (first in _ACTIONS) == (second in _ACTIONS):
                diagnostics.append(
                    Diagnostic(
                        "warn",
                        f"unrecognised audit action in {value!r}",
                        origin,
                        token,
                    )
                )
                continue
            action, scope = (
                (first, second) if first in _ACTIONS else (second, first)
            )
            effect = _ACTIONS[action]
        elif option == "-S":
            syscalls.update(
                syscall.strip()
                for syscall in value.split(",")
                if syscall.strip()
            )
        elif option == "-F":
            predicate = _filter(value)
            if predicate is None:
                diagnostics.append(
                    Diagnostic(
                        "warn",
                        f"unrecognised -F expression {value!r}",
                        origin,
                        token,
                    )
                )
            else:
                predicates.append(predicate)
        elif option == "-w":
            watch_path = value
        elif option == "-p":
            watch_perms = value
        elif option == "-k":
            predicates.append(Predicate("key", "eq", value))
        else:
            diagnostics.append(
                Diagnostic(
                    "warn",
                    f"unrecognised audit option {option}",
                    origin,
                    token,
                )
            )

    if watch_path is not None:
        effect = Effect.INCLUDE
        predicates.insert(0, Predicate("path", "eq", watch_path))
        if watch_perms is not None:
            predicates.insert(1, Predicate("perm", "eq", watch_perms))
    elif watch_perms is not None:
        diagnostics.append(Diagnostic("warn", "-p without -w", origin, raw_line))

    if effect is None:
        diagnostics.append(
            Diagnostic(
                "warn",
                "rule has no recognised action or watch",
                origin,
                raw_line,
            )
        )
        return None, diagnostics

    return (
        Rule(
            effect=effect,
            selector=SyscallSelector(frozenset(syscalls), scope),
            predicates=tuple(predicates),
            order=order,
            origin=origin,
            raw=raw_line,
        ),
        diagnostics,
    )
