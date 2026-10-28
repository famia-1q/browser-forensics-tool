from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional

BROWSERS = ("chrome", "firefox")
ARTIFACT_TYPES = ("history", "search", "bookmark", "cookie", "download", "cache", "form", "deleted_history", "deleted_search", "private_history", "private_search")
TAGS = ("private", "deleted")


@dataclass
class Record:
    browser: str
    artifact_type: str
    url: str
    title: str
    timestamp_utc: Optional[str]
    raw_timestamp: Optional[int]
    timestamp_source: str
    source_file: str
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Profile:
    browser: str
    name: str
    path: str
    cache_path: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
