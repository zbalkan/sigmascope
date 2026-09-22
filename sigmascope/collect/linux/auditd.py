from __future__ import annotations

from dataclasses import dataclass
import os
import shutil
import subprocess

from sigmascope.model import CollectionError


_TIMEOUT_SECONDS = 15

# auditctl ships in an sbin directory that a non-root or service PATH routinely
# omits, so PATH alone cannot establish that auditd is absent.
_SBIN_CANDIDATES = (
    "/usr/sbin/auditctl",
    "/sbin/auditctl",
    "/usr/local/sbin/auditctl",
)


@dataclass(frozen=True)
class AuditdCollection:
    installed: bool | None
    effective_rules: str | None
    status: str | None
    errors: tuple[CollectionError, ...]


def _locate_auditctl() -> tuple[str | None, bool]:
    """Return the auditctl path and whether a negative result is conclusive."""
    executable = shutil.which("auditctl")
    if executable is not None:
        return executable, True
    for candidate in _SBIN_CANDIDATES:
        if os.path.exists(candidate):
            return candidate, True
    directories = sorted({os.path.dirname(item) for item in _SBIN_CANDIDATES})
    conclusive = not any(
        os.path.isdir(directory) and not os.access(directory, os.X_OK)
        for directory in directories
    )
    return None, conclusive


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
            timeout=_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, CollectionError("auditd", str(exc), " ".join(command))
    if proc.returncode != 0:
        message = (
            proc.stderr.decode("utf-8", "surrogateescape").strip()
            or f"auditctl exited {proc.returncode}"
        )
        return None, CollectionError("auditd", message, " ".join(command))
    return proc.stdout.decode("utf-8", "surrogateescape"), None


def collect_auditd() -> AuditdCollection:
    executable, conclusive = _locate_auditctl()
    if executable is None:
        if conclusive:
            return AuditdCollection(False, None, None, ())
        return AuditdCollection(
            None,
            None,
            None,
            (
                CollectionError(
                    "auditd",
                    "auditctl is absent from PATH and the standard sbin "
                    "directories could not be searched",
                    "auditctl",
                ),
            ),
        )

    errors: list[CollectionError] = []
    rules, error = _auditctl(executable, "-l")
    if error is not None:
        errors.append(error)
    status, error = _auditctl(executable, "-s")
    if error is not None:
        errors.append(error)
    return AuditdCollection(True, rules, status, tuple(errors))
