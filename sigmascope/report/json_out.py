from __future__ import annotations

import json
from typing import TextIO


def render_json(report: dict[str, object], stream: TextIO | None = None) -> str:
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if stream is not None:
        stream.write(text)
    return text
