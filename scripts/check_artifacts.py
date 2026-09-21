from __future__ import annotations

import argparse
from pathlib import Path
import tarfile
import zipfile


REQUIRED_PACKAGE_FILES = {"sigmascope/schema/report-0.1.json"}


def _one(paths: list[Path], kind: str) -> Path:
    if len(paths) != 1:
        raise SystemExit(f"expected exactly one {kind}, found {len(paths)}")
    return paths[0]


def _check_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
    missing = REQUIRED_PACKAGE_FILES - names
    if missing:
        raise SystemExit(f"wheel is missing package resources: {sorted(missing)}")
    if not any(name.endswith(".dist-info/licenses/LICENSE") for name in names):
        raise SystemExit("wheel is missing LICENSE")
    if not any(name.endswith(".dist-info/licenses/NOTICE") for name in names):
        raise SystemExit("wheel is missing NOTICE")


def _check_sdist(path: Path) -> None:
    with tarfile.open(path, "r:gz") as archive:
        names = archive.getnames()
    suffixes = {name.split("/", 1)[1] for name in names if "/" in name}
    required = REQUIRED_PACKAGE_FILES | {"LICENSE", "NOTICE"}
    missing = required - suffixes
    if missing:
        raise SystemExit(f"sdist is missing files: {sorted(missing)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    args = parser.parse_args()
    _check_wheel(_one(list(args.dist.glob("*.whl")), "wheel"))
    _check_sdist(_one(list(args.dist.glob("*.tar.gz")), "sdist"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
