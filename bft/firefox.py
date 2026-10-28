from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Iterator, List, Optional

from .models import Record
from .sqlite_ro import open_copy, select_available, tables
from .timestamps import firefox_us_to_utc, unix_ms_to_utc, unix_seconds_to_utc

VISIT_TYPES = {1: "link", 2: "typed", 3: "bookmark", 4: "embed", 5: "redirect_permanent", 6: "redirect_temporary", 7: "download", 8: "framed_link", 9: "reload"}
CHUNK = 256 * 1024
KEY_RE = re.compile(rb"(?:^|[,\x00])(?::|O\^[^,]*,:)?(https?://[^\x00]+)\x00")


def _rel(path: Path, root: Optional[Path]) -> str:
    if root is None:
        return str(path)
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path)


def parse_places(db: Path, root: Optional[Path] = None) -> Iterator[Record]:
    src = _rel(db, root)
    with open_copy(db) as conn:
        names = tables(conn)
        if "moz_historyvisits" in names and "moz_places" in names:
            sql = "SELECT v.id, v.visit_date, v.visit_type, v.from_visit, p.url, p.title, p.visit_count, p.typed, p.frecency FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id ORDER BY v.visit_date"
            for r in conn.execute(sql):
                yield Record(
                    "firefox", "history", r["url"] or "", r["title"] or "",
                    firefox_us_to_utc(r["visit_date"]), r["visit_date"], "moz_historyvisits.visit_date (us since 1970)", src,
                    {"visit_id": r["id"], "from_visit": r["from_visit"], "transition": VISIT_TYPES.get(r["visit_type"], str(r["visit_type"])), "visit_count": r["visit_count"], "typed": r["typed"], "frecency": r["frecency"]},
                )
        if "moz_bookmarks" in names and "moz_places" in names:
            sql = "SELECT b.id, b.title, b.dateAdded, b.lastModified, b.guid, p.url, parent.title AS folder FROM moz_bookmarks b JOIN moz_places p ON p.id = b.fk LEFT JOIN moz_bookmarks parent ON parent.id = b.parent WHERE b.type = 1"
            for r in conn.execute(sql):
                yield Record(
                    "firefox", "bookmark", r["url"] or "", r["title"] or "",
                    firefox_us_to_utc(r["dateAdded"]), r["dateAdded"], "moz_bookmarks.dateAdded (us since 1970)", src,
                    {"folder": r["folder"], "guid": r["guid"], "last_modified_utc": firefox_us_to_utc(r["lastModified"])},
                )
        if "moz_annos" in names and "moz_anno_attributes" in names:
            sql = "SELECT a.place_id, a.content, a.dateAdded, n.name, p.url, p.title FROM moz_annos a JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id JOIN moz_places p ON p.id = a.place_id WHERE n.name LIKE 'downloads/%'"
            by_place = {}
            for r in conn.execute(sql):
                d = by_place.setdefault(r["place_id"], {"url": r["url"], "title": r["title"], "dateAdded": r["dateAdded"]})
                d[r["name"]] = r["content"]
            for pid, d in by_place.items():
                meta = {}
                try:
                    meta = json.loads(d.get("downloads/metaData") or "{}")
                except ValueError:
                    meta = {}
                end_ms = meta.get("endTime")
                yield Record(
                    "firefox", "download", d["url"] or "", d.get("downloads/destinationFileURI") or d["title"] or "",
                    unix_ms_to_utc(end_ms) if end_ms else firefox_us_to_utc(d["dateAdded"]), end_ms or d["dateAdded"],
                    "downloads/metaData.endTime (ms since 1970)" if end_ms else "moz_annos.dateAdded (us since 1970)", src,
                    {"place_id": pid, "file_size": meta.get("fileSize"), "state": meta.get("state"), "destination": d.get("downloads/destinationFileURI")},
                )


def parse_cookies(db: Path, root: Optional[Path] = None) -> Iterator[Record]:
    src = _rel(db, root)
    with open_copy(db) as conn:
        if "moz_cookies" not in tables(conn):
            return
        cols = select_available(conn, "moz_cookies", ["id", "name", "value", "host", "path", "expiry", "lastAccessed", "creationTime", "isSecure", "isHttpOnly", "sameSite"])
        for r in conn.execute("SELECT %s FROM moz_cookies" % ", ".join(cols)):
            keys = r.keys()
            yield Record(
                "firefox", "cookie", r["host"] or "", r["name"] or "",
                firefox_us_to_utc(r["creationTime"]) if "creationTime" in keys else None, r["creationTime"] if "creationTime" in keys else None,
                "moz_cookies.creationTime (us since 1970)", src,
                {
                    "path": r["path"] if "path" in keys else None,
                    "expires_utc": unix_seconds_to_utc(r["expiry"]) if "expiry" in keys else None,
                    "last_access_utc": firefox_us_to_utc(r["lastAccessed"]) if "lastAccessed" in keys else None,
                    "secure": bool(r["isSecure"]) if "isSecure" in keys else None,
                    "httponly": bool(r["isHttpOnly"]) if "isHttpOnly" in keys else None,
                    "value": r["value"] if "value" in keys else None,
                    "value_encrypted": False,
                },
            )


def parse_formhistory(db: Path, root: Optional[Path] = None) -> Iterator[Record]:
    src = _rel(db, root)
    with open_copy(db) as conn:
        if "moz_formhistory" not in tables(conn):
            return
        for r in conn.execute("SELECT id, fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory"):
            yield Record(
                "firefox", "form", "", r["value"] or "",
                firefox_us_to_utc(r["lastUsed"]), r["lastUsed"], "moz_formhistory.lastUsed (us since 1970)", src,
                {"field": r["fieldname"], "times_used": r["timesUsed"], "first_used_utc": firefox_us_to_utc(r["firstUsed"])},
            )


def _parse_cache2_entry(data: bytes):
    if len(data) < 4:
        return None
    meta_off = struct.unpack(">I", data[-4:])[0]
    if meta_off >= len(data) - 4:
        return None
    meta = data[meta_off:-4]
    chunks = (meta_off + CHUNK - 1) // CHUNK
    info = {"key": None, "last_fetched": None, "last_modified": None, "fetch_count": None, "expiration": None, "elements": {}}
    for hdr_off in (4 + 2 * chunks, 2 * chunks):
        if hdr_off + 28 > len(meta):
            continue
        version, fetch_count, last_fetched, last_modified, frecency, expiration, key_size = struct.unpack(">7I", meta[hdr_off:hdr_off + 28])
        key_off = hdr_off + (32 if version >= 2 else 28)
        if version > 10 or key_size > 65536 or key_off + key_size > len(meta):
            continue
        key = meta[key_off:key_off + key_size]
        if b":http" not in key and not key.startswith(b"http"):
            continue
        info.update({"key": key.decode("utf-8", "replace"), "last_fetched": last_fetched, "last_modified": last_modified, "fetch_count": fetch_count, "expiration": expiration})
        tail = meta[key_off + key_size + 1:]
        parts = tail.split(b"\x00")
        for i in range(0, len(parts) - 1, 2):
            k = parts[i].decode("utf-8", "replace")
            if k:
                info["elements"][k] = parts[i + 1].decode("utf-8", "replace")
        break
    if info["key"] is None:
        m = KEY_RE.search(meta)
        if m:
            info["key"] = m.group(1).decode("utf-8", "replace")
    return info


def parse_cache(cache_dir: Path, root: Optional[Path] = None) -> Iterator[Record]:
    entries = Path(cache_dir) / "entries"
    if not entries.is_dir():
        return
    for p in sorted(entries.iterdir()):
        if not p.is_file():
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        info = _parse_cache2_entry(data)
        if not info or not info["key"]:
            continue
        url = info["key"]
        idx = url.find(":http")
        if idx >= 0:
            url = url[idx + 1:]
        st = p.stat()
        if info["last_modified"]:
            ts, raw, tsrc = unix_seconds_to_utc(info["last_modified"]), info["last_modified"], "cache2 header lastModified (s since 1970)"
        else:
            ts, raw, tsrc = unix_seconds_to_utc(st.st_mtime), int(st.st_mtime), "filesystem mtime of cache entry"
        head = info["elements"].get("response-head", "")
        yield Record(
            "firefox", "cache", url, head.split("\r\n")[0] if head else "",
            ts, raw, tsrc, _rel(p, root),
            {"entry_file": p.name, "size_bytes": st.st_size, "fetch_count": info["fetch_count"], "last_fetched_utc": unix_seconds_to_utc(info["last_fetched"]), "expires_utc": unix_seconds_to_utc(info["expiration"]), "request_method": info["elements"].get("request-method"), "raw_key": info["key"]},
        )


def parse_profile(profile_dir: Path, cache_dir: Optional[Path], root: Optional[Path] = None) -> List[Record]:
    out: List[Record] = []
    profile_dir = Path(profile_dir)
    for name, fn in (("places.sqlite", parse_places), ("cookies.sqlite", parse_cookies), ("formhistory.sqlite", parse_formhistory)):
        p = profile_dir / name
        if p.is_file():
            out.extend(fn(p, root))
    if cache_dir and Path(cache_dir).is_dir():
        out.extend(parse_cache(Path(cache_dir), root))
    return out
