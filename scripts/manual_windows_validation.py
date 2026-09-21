from __future__ import annotations

import sys

from sigmascope.collect.windows.auditpol_cli import collect_cli_policy
from sigmascope.catalog import WINDOWS_MAPPINGS
from sigmascope.collect.windows.auditpol_native import collect_native_policy


def main() -> int:
    if sys.platform != "win32":
        print("Windows only", file=sys.stderr)
        return 2

    guids = tuple(
        sorted(
            {
                str(provider["subcategory_guid"])
                for requirement in WINDOWS_MAPPINGS
                for provider in requirement["providers"]
                if provider.get("kind") == "windows_audit"
            }
        )
    )
    native = collect_native_policy(guids)
    cli = collect_cli_policy()
    if native.error is not None:
        print(f"native collection failed: {native.error.message}", file=sys.stderr)
        return 1
    if cli.error is not None or cli.parsed is None:
        message = cli.error.message if cli.error else "CLI parse unavailable"
        print(f"CLI collection failed: {message}", file=sys.stderr)
        return 1

    cli_states = {
        gate.key.removeprefix("windows.audit.").upper(): str(gate.value)
        for gate in cli.parsed.gates
    }
    mismatches = []
    ambiguous = []
    matched = 0
    for guid, state in native.states.items():
        cli_state = cli_states.get(guid.upper())
        if cli_state == "unknown":
            ambiguous.append(guid)
            continue
        if cli_state != state:
            mismatches.append((guid, state, cli_state))
        else:
            matched += 1

    if mismatches:
        for guid, native_state, cli_state in mismatches:
            print(f"{guid}: native={native_state} cli={cli_state}")
        return 3

    print(
        f"native and auditpol agree for {matched} determinate mapped subcategories; "
        f"{len(ambiguous)} auditpol state(s) were ambiguous"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
