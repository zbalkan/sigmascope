from __future__ import annotations

from dataclasses import dataclass
import subprocess

from sigmascope.model import CollectionError


@dataclass(frozen=True)
class AuditdCollection:
    effective_rules: str | None
    status: str | None
    errors: tuple[CollectionError, ...]


def _auditctl(*args: str) -> tuple[str | None, CollectionError | None]:
    command = ("auditctl", *args)
    try:
        proc = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        return None, CollectionError("auditd", str(exc), " ".join(command))
    if proc.returncode != 0:
        message = (
            proc.stderr.decode("utf-8", "surrogateescape").strip()
            or f"auditctl exited {proc.returncode}"
        )
        return None, CollectionError("auditd", message, " ".join(command))
    return proc.stdout.decode("utf-8", "surrogateescape"), None


def collect_auditd() -> AuditdCollection:
    errors: list[CollectionError] = []
    rules, error = _auditctl("-l")
    if error is not None:
        errors.append(error)
    status, error = _auditctl("-s")
    if error is not None:
        errors.append(error)
    return AuditdCollection(rules, status, tuple(errors))
