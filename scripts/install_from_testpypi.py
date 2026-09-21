from __future__ import annotations

import os
import subprocess
import sys
import time


def main() -> int:
    tag = os.environ.get("SIGMASCOPE_RELEASE_TAG", "")
    version = tag.removeprefix("v")
    if not version:
        raise SystemExit("SIGMASCOPE_RELEASE_TAG is empty")

    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--no-deps",
        "--index-url",
        "https://test.pypi.org/simple",
        f"sigmascope=={version}",
    ]
    for attempt in range(6):
        result = subprocess.run(command, check=False)
        if result.returncode == 0:
            return 0
        if attempt != 5:
            time.sleep(10)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
