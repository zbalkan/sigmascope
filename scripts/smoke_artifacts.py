from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import tempfile
import venv


def _one(paths: list[Path], kind: str) -> Path:
    if len(paths) != 1:
        raise SystemExit(f"expected exactly one {kind}, found {len(paths)}")
    return paths[0]


def _venv_python(root: Path) -> Path:
    return root / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    args = parser.parse_args()
    wheel = _one(list(args.dist.glob("*.whl")), "wheel")

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        venv.EnvBuilder(with_pip=True, clear=True).create(root)
        python = _venv_python(root)
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                str(wheel.resolve()),
            ],
            check=True,
        )
        for command in (
            ("--demo", "--format", "json"),
            ("--print-catalog-version",),
            ("--print-schema",),
        ):
            subprocess.run(
                [str(python), "-m", "sigmascope", *command],
                check=True,
                stdout=subprocess.DEVNULL,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
