from __future__ import annotations

from dataclasses import dataclass
import subprocess
import sys

from sigmascope.model import CollectionError
from sigmascope.model import ParseResult
from sigmascope.parse.auditpol_csv import parse_auditpol_csv


@dataclass(frozen=True)
class AuditpolCliCollection:
    parsed: ParseResult | None
    error: CollectionError | None = None


def collect_cli_policy() -> AuditpolCliCollection:
    if sys.platform != "win32":
        return AuditpolCliCollection(
            None,
            CollectionError(
                "windows.audit_policy",
                "auditpol is only available on Windows",
                "auditpol /get /category:* /r",
            ),
        )
    try:
        proc = subprocess.run(
            ("auditpol", "/get", "/category:*", "/r"),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        return AuditpolCliCollection(
            None,
            CollectionError(
                "windows.audit_policy",
                str(exc),
                "auditpol /get /category:* /r",
            ),
        )
    if proc.returncode != 0:
        return AuditpolCliCollection(
            None,
            CollectionError(
                "windows.audit_policy",
                proc.stderr.decode("oem", "replace").strip()
                or f"auditpol exited {proc.returncode}",
                "auditpol /get /category:* /r",
            ),
        )
    return AuditpolCliCollection(
        parse_auditpol_csv("auditpol /r", proc.stdout)
    )
