from __future__ import annotations

import os
from pathlib import Path
import re
import sys


_VERSION = re.compile(
    r'^__version__\s*=\s*["\'](?P<version>[^"\']+)["\']',
    re.MULTILINE,
)


def read_source_version(root: Path | None = None) -> str:
    repository = root or Path(__file__).resolve().parents[1]
    text = (repository / "sigmascope" / "__init__.py").read_text(
        encoding="utf-8"
    )
    match = _VERSION.search(text)
    if match is None:
        raise ValueError("could not locate sigmascope.__version__")
    return match.group("version")


def validate_tag(tag: str, version: str) -> str:
    if not tag.startswith("v"):
        raise ValueError("release tag must start with 'v'")
    tagged_version = tag[1:]
    if tagged_version != version:
        raise ValueError(
            f"release tag {tag!r} does not match package version {version!r}"
        )
    return tagged_version


def main() -> int:
    tag = os.environ.get("SIGMASCOPE_RELEASE_TAG", "")
    try:
        version = read_source_version()
        validate_tag(tag, version)
    except (OSError, ValueError) as exc:
        print(f"sigmascope: {exc}", file=sys.stderr)
        return 1
    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
