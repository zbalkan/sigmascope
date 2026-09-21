from __future__ import annotations

from dataclasses import dataclass
import shutil
import subprocess

from sigmascope.model import CollectionError


@dataclass(frozen=True)
class AuditdCollection:
    installed: bool
    effective_rules: str | None
    status: str | None
    errors: tuple[CollectionError, ...]


def _auditctl(
    executable: str,
    *args: str,
) -> tuple[str | None, CollectionError | None]:
    command = (executable, *args)
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
    executable = shutil.which("auditctl")
    if executable is None:
        return AuditdCollection(False, None, None, ())

    errors: list[CollectionError] = []
    rules, error = _auditctl(executable, "-l")
    if error is not None:
        errors.append(error)
    status, error = _auditctl(executable, "-s")
    if error is not None:
        errors.append(error)
    return AuditdCollection(True, rules, status, tuple(errors))
