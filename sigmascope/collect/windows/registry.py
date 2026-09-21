from __future__ import annotations

import sys

from sigmascope.collect.base import CollectionError
from sigmascope.model import Diagnostic, Gate, Origin, ParseResult


PROCESS_COMMAND_LINE = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
    "ProcessCreationIncludeCmdLine_Enabled",
)
PROVIDERS_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers"


def collect_registry_gates() -> ParseResult:
    if sys.platform != "win32":
        return ParseResult("windows.registry", "unknown")

    import winreg

    path, value_name = PROCESS_COMMAND_LINE
    origin = Origin(
        "windows.registry",
        f"HKLM\\{path}\\{value_name}",
    )
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            0,
            winreg.KEY_READ,
        ) as key:
            value, _ = winreg.QueryValueEx(key, value_name)
    except FileNotFoundError:
        value = 0
    except OSError as exc:
        return ParseResult(
            "windows.registry",
            "unknown",
            diagnostics=(Diagnostic("warn", str(exc), origin, ""),),
        )

    return ParseResult(
        "windows.registry",
        "effective",
        gates=(
            Gate(
                "windows.process_creation.include_command_line",
                bool(value),
                "effective",
                origin,
            ),
        ),
    )


def provider_registered(guid: str) -> tuple[bool | None, CollectionError | None]:
    if sys.platform != "win32":
        return None, CollectionError(
            "windows.provider",
            "Windows registry is unavailable on this platform",
            f"{PROVIDERS_KEY}\\{guid}",
        )

    import winreg

    path = f"{PROVIDERS_KEY}\\{guid}"
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            0,
            winreg.KEY_READ,
        ):
            return True, None
    except FileNotFoundError:
        return False, None
    except OSError as exc:
        return None, CollectionError(
            "windows.provider",
            str(exc),
            f"HKLM\\{path}",
        )
