from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
FMT = "%Y-%m-%dT%H:%M:%SZ"
MAX_SECONDS = 253402300799


def _fmt(dt: datetime) -> str:
    return dt.strftime(FMT)


def chrome_to_utc(value) -> Optional[str]:
    try:
        us = int(value)
    except (TypeError, ValueError):
        return None
    if us <= 0:
        return None
    seconds = us / 1_000_000
    if seconds > MAX_SECONDS + 11644473600:
        return None
    return _fmt(CHROME_EPOCH + timedelta(microseconds=us))


def firefox_us_to_utc(value) -> Optional[str]:
    try:
        us = int(value)
    except (TypeError, ValueError):
        return None
    if us <= 0 or us / 1_000_000 > MAX_SECONDS:
        return None
    return _fmt(UNIX_EPOCH + timedelta(microseconds=us))


def unix_seconds_to_utc(value) -> Optional[str]:
    try:
        s = float(value)
    except (TypeError, ValueError):
        return None
    if s <= 0 or s > MAX_SECONDS:
        return None
    return _fmt(UNIX_EPOCH + timedelta(seconds=s))


def unix_ms_to_utc(value) -> Optional[str]:
    try:
        ms = int(value)
    except (TypeError, ValueError):
        return None
    if ms <= 0 or ms / 1000 > MAX_SECONDS:
        return None
    return _fmt(UNIX_EPOCH + timedelta(milliseconds=ms))


def now_utc() -> str:
    return _fmt(datetime.now(timezone.utc))
