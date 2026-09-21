from __future__ import annotations

from sigmascope.model import (
    Effect,
    ParseResult,
    Predicate,
    Rule,
    SyscallSelector,
    Verdict,
)


_TARGET_SYSCALLS = frozenset({"execve", "execveat"})
_NON_NARROWING_FIELDS = frozenset({"arch", "key"})


def _predicate(rule: Rule, field: str) -> list[Predicate]:
    return [item for item in rule.predicates if item.field == field]


def _selected_syscalls(rule: Rule) -> set[str]:
    if not isinstance(rule.selector, SyscallSelector):
        return set()
    if "all" in rule.selector.syscalls:
        return set(_TARGET_SYSCALLS)
    return set(rule.selector.syscalls) & set(_TARGET_SYSCALLS)


def _arches(rule: Rule) -> set[str]:
    return {
        predicate.value
        for predicate in _predicate(rule, "arch")
        if predicate.op == "eq"
    }


def _restrictive(rule: Rule) -> bool:
    return any(
        predicate.field not in _NON_NARROWING_FIELDS
        for predicate in rule.predicates
    )


def _exit_rule_suppresses(rule: Rule, arch: str, syscall: str) -> bool:
    if (
        not isinstance(rule.selector, SyscallSelector)
        or rule.effect is not Effect.EXCLUDE
        or rule.selector.scope != "exit"
    ):
        return False
    selected = set(rule.selector.syscalls)
    if selected and "all" not in selected and syscall not in selected:
        return False
    arches = _arches(rule)
    return not arches or arch in arches


def evaluate_process_creation(
    parsed: ParseResult,
    *,
    machine_arch: str = "x86_64",
) -> tuple[Verdict, str]:
    rules = list(parsed.rules)
    if parsed.determinacy == "unknown" or any(not rule.complete for rule in rules):
        return (
            Verdict.INDETERMINATE,
            "auditd process-creation rules are incomplete or could not be parsed safely.",
        )

    candidates = [
        rule
        for rule in rules
        if isinstance(rule.selector, SyscallSelector)
        and rule.selector.scope == "exit"
        and rule.effect is Effect.INCLUDE
        and _selected_syscalls(rule)
    ]
    if not candidates:
        numeric = [
            rule
            for rule in rules
            if isinstance(rule.selector, SyscallSelector)
            and rule.selector.scope == "exit"
            and rule.effect is Effect.INCLUDE
            and rule.selector.syscalls
            and all(item.isdigit() for item in rule.selector.syscalls)
        ]
        if numeric:
            return (
                Verdict.INDETERMINATE,
                "auditd uses numeric syscall selectors; architecture-specific "
                "syscall numbers are not guessed.",
            )
        return (
            Verdict.NOT_COVERED,
            "No active always,exit rule selects execve or execveat.",
        )

    task_suppressors = [
        rule
        for rule in rules
        if rule.effect is Effect.EXCLUDE
        and isinstance(rule.selector, SyscallSelector)
        and rule.selector.scope == "task"
    ]
    if any(
        not [predicate for predicate in rule.predicates if predicate.field != "key"]
        for rule in task_suppressors
    ):
        return (
            Verdict.NOT_COVERED,
            "An unconditional auditd never,task rule causes new processes to "
            "skip syscall-rule processing.",
        )
    if task_suppressors:
        return (
            Verdict.DEGRADED,
            "A scoped auditd never,task rule can suppress process-creation "
            "events for matching tasks.",
        )
    if any(
        rule.effect is Effect.EXCLUDE
        and isinstance(rule.selector, SyscallSelector)
        and rule.selector.scope == "exclude"
        for rule in rules
    ):
        return (
            Verdict.DEGRADED,
            "An auditd exclude rule can suppress a subset of audit events.",
        )

    if machine_arch in {"x86_64", "amd64"}:
        if any(not _arches(rule) for rule in candidates):
            return (
                Verdict.DEGRADED,
                "auditd exec rules omit an explicit arch selector; "
                "32-bit compatibility coverage cannot be established.",
            )

        required = {
            (arch, syscall)
            for arch in ("b64", "b32")
            for syscall in _TARGET_SYSCALLS
        }
        coverage: dict[tuple[str, str], Rule] = {}
        restrictive = False
        for rule in candidates:
            if _restrictive(rule):
                restrictive = True
                continue
            for arch in _arches(rule) & {"b64", "b32"}:
                for syscall in _selected_syscalls(rule):
                    coverage.setdefault((arch, syscall), rule)

        missing = sorted(required - set(coverage))
        if missing:
            detail = ", ".join(f"{arch}/{syscall}" for arch, syscall in missing)
            suffix = (
                " Restrictive predicates on candidate rules prevent generic coverage."
                if restrictive
                else ""
            )
            return (
                Verdict.DEGRADED,
                f"auditd process-creation coverage is incomplete; missing {detail}."
                f"{suffix}",
            )

        for (arch, syscall), include_rule in coverage.items():
            if any(
                rule.order < include_rule.order
                and _exit_rule_suppresses(rule, arch, syscall)
                for rule in rules
            ):
                return (
                    Verdict.DEGRADED,
                    "An earlier auditd never,exit rule may suppress process-creation "
                    "events before an always rule can match.",
                )

        return (
            Verdict.COVERED,
            "Active auditd rules cover execve and execveat independently for "
            "b64 and b32 without narrowing predicates.",
        )

    broad = {
        syscall
        for rule in candidates
        if not _restrictive(rule)
        for syscall in _selected_syscalls(rule)
    }
    missing = sorted(_TARGET_SYSCALLS - broad)
    if missing:
        return (
            Verdict.DEGRADED,
            "auditd does not select all process-creation syscalls; missing "
            + ", ".join(missing)
            + ".",
        )
    return (
        Verdict.COVERED,
        "Active auditd rules cover execve and execveat without narrowing predicates.",
    )


def evaluate_file_watch(parsed: ParseResult) -> tuple[Verdict, str]:
    if parsed.determinacy == "unknown" or any(
        not rule.complete for rule in parsed.rules
    ):
        return (
            Verdict.INDETERMINATE,
            "auditd file watch rules are incomplete or could not be parsed safely.",
        )

    watches = [
        path.value
        for rule in parsed.rules
        if rule.effect is Effect.INCLUDE
        for path in _predicate(rule, "path")
        if any(
            "w" in permissions.value and "a" in permissions.value
            for permissions in _predicate(rule, "perm")
        )
    ]
    if not watches:
        return (
            Verdict.NOT_COVERED,
            "No active auditd watch with write and attribute permissions was found.",
        )
    return (
        Verdict.DEGRADED,
        f"auditd file monitoring is path-scoped ({len(watches)} watch path(s)); "
        "generic file_event coverage is not global.",
    )
