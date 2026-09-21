from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CollectionError:
    source_id: str
    message: str
    resource: str = ""
