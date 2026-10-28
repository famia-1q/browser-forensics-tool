from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import shutil
import socket
from pathlib import Path
from typing import Dict, List, Optional

from .models import Profile
from .timestamps import now_utc

CHROME_FILES = [
    "History", "History-journal", "History-wal",
    "Bookmarks", "Bookmarks.bak",
    "Cookies", "Cookies-journal", "Cookies-wal",
    "Network/Cookies", "Network/Cookies-journal", "Network/Cookies-wal",
    "Web Data", "Web Data-journal",
    "Favicons", "Top Sites", "Visited Links", "Preferences",
]
FIREFOX_FILES = [
    "places.sqlite", "places.sqlite-wal", "places.sqlite-shm",
    "cookies.sqlite", "cookies.sqlite-wal", "cookies.sqlite-shm",
    "formhistory.sqlite", "formhistory.sqlite-wal",
    "downloads.sqlite", "favicons.sqlite", "sessionstore.jsonlz4", "prefs.js",
]
CUSTODY = "custody.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _copy_one(src: Path, dst: Path) -> Optional[str]:
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy2(src, dst)
    except PermissionError:
        return "locked"
    except OSError as e:
        return str(e)
    return None


def _rel(p: Path, base: Path) -> str:
    return p.relative_to(base).as_posix()


def manifest_sha256(files: Dict[str, str]) -> str:
    lines = "".join("%s  %s\n" % (files[k], k) for k in sorted(files))
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def _copy_cache(src: Path, dst: Path, max_mb: int) -> Dict:
    if dst.exists():
        shutil.rmtree(dst)
    total = 0
    skipped = 0
    hashes: Dict[str, str] = {}
    limit = max_mb * 1024 * 1024
    for p in sorted(src.rglob("*")):
        if not p.is_file():
            continue
        size = p.stat().st_size
        if total + size > limit:
            skipped += 1
            continue
        target = dst / p.relative_to(src)
        err = _copy_one(p, target)
        if err:
            skipped += 1
            continue
        total += size
        hashes[_rel(p, src)] = sha256_file(target)
    return {"files": hashes, "skipped": skipped, "bytes": total}


def acquire(profiles: List[Profile], out: Path, case: str, include_cache: bool = True, max_cache_mb: int = 300) -> Dict:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = now_utc()
    if (out / CUSTODY).is_file():
        custody = load_custody(out)
        custody["updated_at_utc"] = stamp
    else:
        custody = {
            "case": case,
            "acquired_at_utc": stamp,
            "host": socket.gethostname(),
            "user": getpass.getuser(),
            "os": platform.platform(),
            "python": platform.python_version(),
            "items": [],
            "errors": [],
        }
    for prof in profiles:
        names = CHROME_FILES if prof.browser == "chrome" else FIREFOX_FILES
        dest_root = out / prof.browser / prof.name
        src_root = Path(prof.path)
        for rel in names:
            src = src_root / rel
            if not src.is_file():
                continue
            dst = dest_root / rel
            err = _copy_one(src, dst)
            if err:
                custody["errors"].append({"source": str(src), "error": err})
                continue
            rel_path = str(Path(prof.browser) / prof.name / rel).replace("\\", "/")
            custody["items"] = [i for i in custody["items"] if i["relative_path"] != rel_path]
            custody["items"].append({
                "browser": prof.browser,
                "profile": prof.name,
                "relative_path": rel_path,
                "source_path": str(src),
                "sha256": sha256_file(dst),
                "size": dst.stat().st_size,
                "source_mtime_utc": _mtime(src),
                "acquired_at_utc": stamp,
            })
        if include_cache and prof.cache_path and Path(prof.cache_path).is_dir():
            cdst = dest_root / "_cache"
            stats = _copy_cache(Path(prof.cache_path), cdst, max_cache_mb)
            cache_rel = str(Path(prof.browser) / prof.name / "_cache").replace("\\", "/")
            custody["items"] = [i for i in custody["items"] if i["relative_path"] != cache_rel]
            custody["items"].append({
                "browser": prof.browser,
                "profile": prof.name,
                "relative_path": cache_rel,
                "source_path": prof.cache_path,
                "acquired_at_utc": stamp,
                "manifest_sha256": manifest_sha256(stats["files"]),
                "size": stats["bytes"],
                "cache_files": len(stats["files"]),
                "cache_skipped": stats["skipped"],
                "files": stats["files"],
            })
    with open(out / CUSTODY, "w", encoding="utf-8") as f:
        json.dump(custody, f, indent=2)
    return custody


def _mtime(p: Path) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _verify_folder(evidence: Path, item: Dict, result: Dict) -> None:
    base = evidence / item["relative_path"]
    files = item["files"]
    if manifest_sha256(files) != item.get("manifest_sha256"):
        result["mismatch"].append(item["relative_path"] + " (file list in custody.json changed)")
    for rel in sorted(files):
        name = item["relative_path"] + "/" + rel
        p = base / rel
        if not p.is_file():
            result["missing"].append(name)
        elif sha256_file(p) == files[rel]:
            result["ok"].append(name)
        else:
            result["mismatch"].append(name)
    if base.is_dir():
        for p in sorted(base.rglob("*")):
            if p.is_file() and _rel(p, base) not in files:
                result["added"].append(item["relative_path"] + "/" + _rel(p, base))


def load_custody(evidence: Path) -> Dict:
    with open(Path(evidence) / CUSTODY, encoding="utf-8") as f:
        return json.load(f)


def verify(evidence: Path) -> Dict:
    evidence = Path(evidence)
    custody = load_custody(evidence)
    result = {"checked_at_utc": now_utc(), "ok": [], "mismatch": [], "missing": [], "added": [], "unhashed": []}
    for item in custody["items"]:
        if "files" in item:
            _verify_folder(evidence, item, result)
            continue
        if not item.get("sha256"):
            result["unhashed"].append(item["relative_path"])
            continue
        p = evidence / item["relative_path"]
        if not p.is_file():
            result["missing"].append(item["relative_path"])
            continue
        if sha256_file(p) == item["sha256"]:
            result["ok"].append(item["relative_path"])
        else:
            result["mismatch"].append(item["relative_path"])
    result["passed"] = not result["mismatch"] and not result["missing"] and not result["added"]
    with open(evidence / "verify.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    return result
