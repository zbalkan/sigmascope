from __future__ import annotations

import argparse
import pkgutil
import sys

from sigmascope import __version__, run
from sigmascope.catalog import CATALOG_VERSION
from sigmascope.report.json_out import render_json
from sigmascope.report.table_out import render_table


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sigmascope")
    parser.add_argument("--format", choices=("json", "table"), default="table")
    parser.add_argument(
        "--fail-on",
        choices=("none", "degraded", "not_covered", "indeterminate"),
        default="none",
    )
    parser.add_argument("--print-schema", action="store_true")
    parser.add_argument("--print-catalog-version", action="store_true")
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def _threshold_met(report: dict[str, object], threshold: str) -> bool:
    if threshold == "none":
        return False
    order = {"covered": 0, "degraded": 1, "not_covered": 2, "indeterminate": 3}
    limit = order[threshold]
    findings = report.get("findings", [])
    return any(
        isinstance(item, dict) and order.get(str(item.get("verdict")), 0) >= limit
        for item in findings
        if isinstance(findings, list)
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.print_schema:
        data = pkgutil.get_data("sigmascope.schema", "report-0.1.json")
        if data is None:
            print("sigmascope: embedded report schema is unavailable", file=sys.stderr)
            return 1
        text = data.decode("utf-8")
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")
        return 0
    if args.print_catalog_version:
        print(CATALOG_VERSION)
        return 0
    try:
        report = run(demo=args.demo)
    except (OSError, ValueError) as exc:
        print(f"sigmascope: {exc}", file=sys.stderr)
        return 1
    if args.format == "json":
        render_json(report, sys.stdout)
    else:
        render_table(report, sys.stdout)
    return 3 if _threshold_met(report, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
