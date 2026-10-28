from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Iterator, List, Optional

from .models import Record
from .sqlite_ro import open_copy, select_available, tables
from .timestamps import chrome_to_utc, unix_seconds_to_utc

SIMPLE_MAGIC = 0xFEDCBA9876543210
TRANSITIONS = {
    0: "link", 1: "typed", 2: "auto_bookmark", 3: "auto_subframe", 4: "manual_subframe",
    5: "generated", 6: "auto_toplevel", 7: "form_submit", 8: "reload", 9: "keyword", 10: "keyword_generated",
}
DOWNLOAD_STATES = {0: "in_progress", 1: "complete", 2: "cancelled", 3: "interrupted", 4: "interrupted"}


def _rel(path: Path, root: Optional[Path]) -> str:
    if root is None:
        return str(path)
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path)


def parse_history(db: Path, root: Optional[Path] = None) -> Iterator[Record]:
    src = _rel(db, root)
    with open_copy(db) as conn:
        names = tables(conn)
        if "urls" in names and "visits" in names:
            vcols = select_available(conn, "visits", ["id", "url", "visit_time", "from_visit", "transition", "visit_duration"])
            sql = "SELECT %s, u.url AS u_url, u.title AS u_title, u.visit_count, u.typed_count FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time" % ", ".join("v.%s AS v_%s" % (c, c) for c in vcols)
            for r in conn.execute(sql):
                core = r["v_transition"] & 0xFF if "v_transition" in r.keys() and r["v_transition"] is not None else None
                yield Record(
                    "chrome", "history", r["u_url"] or "", r["u_title"] or "",
                    chrome_to_utc(r["v_visit_time"]), r["v_visit_time"], "visits.visit_time (us since 1601)", src,
                    {
                        "visit_id": r["v_id"],
                        "from_visit": r["v_from_visit"] if "v_from_visit" in r.keys() else None,
                        "transition": TRANSITIONS.get(core, str(core)),
                        "visit_count": r["visit_count"],
                        "typed_count": r["typed_count"],
                        "duration_us": r["v_visit_duration"] if "v_visit_duration" in r.keys() else None,
                    },
                )
        if "keyword_search_terms" in names and "urls" in names:
            sql = "SELECT k.term, u.url, u.title, u.last_visit_time FROM keyword_search_terms k JOIN urls u ON u.id = k.url_id"
            for r in conn.execute(sql):
                yield Record(
                    "chrome", "search", r["url"] or "", r["term"] or "",
                    chrome_to_utc(r["last_visit_time"]), r["last_visit_time"], "urls.last_visit_time (us since 1601)", src,
                    {"page_title": r["title"]},
                )
        if "downloads" in names:
            cols = select_available(conn, "downloads", ["id", "current_path", "target_path", "start_time", "end_time", "received_bytes", "total_bytes", "state", "tab_url", "referrer", "mime_type", "danger_type", "opened"])
            chains = {}
            if "downloads_url_chains" in names:
                for r in conn.execute("SELECT id, chain_index, url FROM downloads_url_chains ORDER BY id, chain_index"):
                    chains.setdefault(r["id"], []).append(r["url"])
            for r in conn.execute("SELECT %s FROM downloads" % ", ".join(cols)):
                keys = r.keys()
                urls = chains.get(r["id"], [])
                yield Record(
                    "chrome", "download", urls[-1] if urls else (r["tab_url"] if "tab_url" in keys else ""),
                    r["target_path"] if "target_path" in keys else "",
                    chrome_to_utc(r["start_time"]), r["start_time"], "downloads.start_time (us since 1601)", src,
                    {
                        "download_id": r["id"],
                        "end_time_utc": chrome_to_utc(r["end_time"]) if "end_time" in keys else None,
                        "received_bytes": r["received_bytes"] if "received_bytes" in keys else None,
                        "total_bytes": r["total_bytes"] if "total_bytes" in keys else None,
                        "state": DOWNLOAD_STATES.get(r["state"], str(r["state"])) if "state" in keys else None,
                        "mime_type": r["mime_type"] if "mime_type" in keys else None,
                        "referrer": r["referrer"] if "referrer" in keys else None,
                        "url_chain": urls,
                    },
                )


def parse_bookmarks(path: Path, root: Optional[Path] = None) -> Iterator[Record]:
    src = _rel(path, root)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    roots = data.get("roots", {})

    def walk(node, folder):
        t = node.get("type")
        if t == "folder":
            name = node.get("name", "")
            for child in node.get("children", []):
                yield from walk(child, folder + "/" + name if name else folder)
        elif t == "url":
            yield Record(
                "chrome", "bookmark", node.get("url", ""), node.get("name", ""),
                chrome_to_utc(node.get("date_added")), _int(node.get("date_added")), "bookmarks.date_added (us since 1601)", src,
                {"folder": folder or "/", "guid": node.get("guid"), "last_used_utc": chrome_to_utc(node.get("date_last_used"))},
            )

    for key, node in roots.items():
        if isinstance(node, dict):
            yield from walk(node, "")


def parse_cookies(db: Path, root: Optional[Path] = None) -> Iterator[Record]:
    src = _rel(db, root)
    with open_copy(db) as conn:
        if "cookies" not in tables(conn):
            return
        cols = select_available(conn, "cookies", ["host_key", "name", "value", "encrypted_value", "path", "creation_utc", "expires_utc", "last_access_utc", "is_secure", "is_httponly", "has_expires", "is_persistent", "samesite"])
        for r in conn.execute("SELECT %s FROM cookies" % ", ".join(cols)):
            keys = r.keys()
            plain = r["value"] if "value" in keys else ""
            enc = r["encrypted_value"] if "encrypted_value" in keys else b""
            yield Record(
                "chrome", "cookie", r["host_key"] or "", r["name"] or "",
                chrome_to_utc(r["creation_utc"]), r["creation_utc"], "cookies.creation_utc (us since 1601)", src,
                {
                    "path": r["path"] if "path" in keys else None,
                    "expires_utc": chrome_to_utc(r["expires_utc"]) if "expires_utc" in keys else None,
                    "last_access_utc": chrome_to_utc(r["last_access_utc"]) if "last_access_utc" in keys else None,
                    "secure": bool(r["is_secure"]) if "is_secure" in keys else None,
                    "httponly": bool(r["is_httponly"]) if "is_httponly" in keys else None,
                    "persistent": bool(r["is_persistent"]) if "is_persistent" in keys else None,
                    "value": plain if plain else None,
                    "value_encrypted": bool(enc) and not plain,
                    "encrypted_bytes": len(enc) if enc else 0,
                },
            )


def parse_cache(cache_dir: Path, root: Optional[Path] = None) -> Iterator[Record]:
    cache_dir = Path(cache_dir)
    for p in sorted(cache_dir.rglob("*_0")):
        if not p.is_file():
            continue
        try:
            with open(p, "rb") as f:
                head = f.read(20)
                if len(head) < 20:
                    continue
                magic, version, key_len, key_hash = struct.unpack("<QIII", head)
                if magic != SIMPLE_MAGIC or key_len > 65536:
                    continue
                key = f.read(key_len).decode("utf-8", "replace")
        except OSError:
            continue
        st = p.stat()
        yield Record(
            "chrome", "cache", _strip_cache_key(key), "",
            unix_seconds_to_utc(st.st_mtime), int(st.st_mtime), "filesystem mtime of cache entry", _rel(p, root),
            {"entry_file": p.name, "size_bytes": st.st_size, "format": "simple_cache_v%d" % version, "raw_key": key},
        )


def _strip_cache_key(key: str) -> str:
    if key.startswith("_dk_"):
        parts = key.split(" ")
        return parts[-1] if parts else key
    return key


def _int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse_profile(profile_dir: Path, cache_dir: Optional[Path], root: Optional[Path] = None) -> List[Record]:
    out: List[Record] = []
    profile_dir = Path(profile_dir)
    hist = profile_dir / "History"
    if hist.is_file():
        out.extend(parse_history(hist, root))
    bm = profile_dir / "Bookmarks"
    if bm.is_file():
        out.extend(parse_bookmarks(bm, root))
    for rel in ("Network/Cookies", "Cookies"):
        ck = profile_dir / rel
        if ck.is_file() and ck.stat().st_size > 0:
            out.extend(parse_cookies(ck, root))
            break
    if cache_dir and Path(cache_dir).is_dir():
        out.extend(parse_cache(Path(cache_dir), root))
    return out
