from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List, Optional

from .models import Profile

CHROME_MARKER = "History"
FIREFOX_MARKER = "places.sqlite"


def _home() -> Path:
    return Path.home()


def _chrome_roots() -> List[tuple]:
    h = _home()
    if sys.platform == "darwin":
        return [
            (h / "Library/Application Support/Google/Chrome", h / "Library/Caches/Google/Chrome"),
            (h / "Library/Application Support/Chromium", h / "Library/Caches/Chromium"),
        ]
    if sys.platform.startswith("win"):
        local = Path(os.environ.get("LOCALAPPDATA", h / "AppData/Local"))
        return [
            (local / "Google/Chrome/User Data", None),
            (local / "Chromium/User Data", None),
        ]
    return [
        (h / ".config/google-chrome", h / ".cache/google-chrome"),
        (h / ".config/chromium", h / ".cache/chromium"),
    ]


def _firefox_roots() -> List[tuple]:
    h = _home()
    if sys.platform == "darwin":
        return [(h / "Library/Application Support/Firefox/Profiles", h / "Library/Caches/Firefox/Profiles")]
    if sys.platform.startswith("win"):
        roaming = Path(os.environ.get("APPDATA", h / "AppData/Roaming"))
        local = Path(os.environ.get("LOCALAPPDATA", h / "AppData/Local"))
        return [(roaming / "Mozilla/Firefox/Profiles", local / "Mozilla/Firefox/Profiles")]
    return [
        (h / ".mozilla/firefox", h / ".cache/mozilla/firefox"),
        (h / "snap/firefox/common/.mozilla/firefox", h / "snap/firefox/common/.cache/mozilla/firefox"),
    ]


def chrome_cache_dir(profile_dir: Path, cache_root: Optional[Path]) -> Optional[str]:
    candidates = [profile_dir / "Cache/Cache_Data", profile_dir / "Cache"]
    if cache_root is not None:
        candidates = [cache_root / profile_dir.name / "Cache/Cache_Data", cache_root / profile_dir.name / "Cache"] + candidates
    for c in candidates:
        if c.is_dir() and any(c.iterdir()):
            return str(c)
    return None


def firefox_cache_dir(profile_dir: Path, cache_root: Optional[Path]) -> Optional[str]:
    candidates = [profile_dir / "cache2"]
    if cache_root is not None:
        candidates = [cache_root / profile_dir.name / "cache2"] + candidates
    for c in candidates:
        if (c / "entries").is_dir():
            return str(c)
    return None


def find_profiles(browser: Optional[str] = None) -> List[Profile]:
    found: List[Profile] = []
    if browser in (None, "chrome"):
        for root, cache_root in _chrome_roots():
            if not root.is_dir():
                continue
            for d in sorted(root.iterdir()):
                if d.is_dir() and (d / CHROME_MARKER).is_file():
                    found.append(Profile("chrome", d.name, str(d), chrome_cache_dir(d, cache_root)))
    if browser in (None, "firefox"):
        for root, cache_root in _firefox_roots():
            if not root.is_dir():
                continue
            for d in sorted(root.iterdir()):
                if d.is_dir() and (d / FIREFOX_MARKER).is_file():
                    found.append(Profile("firefox", d.name, str(d), firefox_cache_dir(d, cache_root)))
    return found


def profile_from_path(browser: str, path: str, cache: Optional[str] = None) -> Profile:
    p = Path(path)
    if browser == "chrome":
        c = cache or chrome_cache_dir(p, None)
    else:
        c = cache or firefox_cache_dir(p, None)
    return Profile(browser, p.name, str(p), c)
