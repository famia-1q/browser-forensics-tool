from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlsplit

from .models import Record
from .sqlite_ro import open_copy, tables
from .timestamps import chrome_to_utc, firefox_us_to_utc

SQLITE_MAGIC = b"SQLite format 3\x00"
WAL_MAGIC = (0x377F0682, 0x377F0683)
URL_START = re.compile(rb"https?://")
MAX_HEADER_BACK = 40
MIN_URL = 12

CHROME_MIN = 12591158400 * 1_000_000
CHROME_MAX = 15746918400 * 1_000_000
UNIX_US_MIN = 946684800 * 1_000_000
UNIX_US_MAX = 4102444800 * 1_000_000

TARGETS = {
    "chrome": {"db": "History", "table": "urls", "column": "url", "sidecars": ("History-wal", "History-journal")},
    "firefox": {"db": "places.sqlite", "table": "moz_places", "column": "url", "sidecars": ("places.sqlite-wal",)},
}

Region = Tuple[int, int, str]


def _varint(buf: bytes, i: int, end: int):
    v = 0
    for k in range(9):
        if i >= end:
            return None, i
        b = buf[i]
        i += 1
        if k == 8:
            return (v << 8) | b, i
        v = (v << 7) | (b & 0x7F)
        if b < 0x80:
            return v, i
    return v, i


def _size(t: int) -> Optional[int]:
    if t in (0, 8, 9):
        return 0
    if 1 <= t <= 4:
        return t
    if t == 5:
        return 6
    if t in (6, 7):
        return 8
    if t >= 12:
        return (t - 12) // 2 if t % 2 == 0 else (t - 13) // 2
    return None


def _value(buf: bytes, pos: int, t: int):
    n = _size(t)
    raw = buf[pos:pos + n]
    if t == 0:
        return None
    if t == 8:
        return 0
    if t == 9:
        return 1
    if 1 <= t <= 6:
        return int.from_bytes(raw, "big", signed=True)
    if t == 7:
        return struct.unpack(">d", raw)[0]
    if t % 2:
        return raw.decode("utf-8")
    return bytes(raw)


def _printable(buf: bytes, lo: int, hi: int) -> bool:
    return all(0x21 <= b <= 0x7E for b in buf[lo:hi])


def _host(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def classify(browser: str, values: list, intact: bool, truncated: bool) -> Optional[str]:
    url = values[0]
    host = _host(url)
    if not host or ("." not in host and host != "localhost"):
        return None
    if browser == "chrome":
        if intact and len(values) == 2 and _is_int(values[1]):
            return "index entry"
        if len(values) >= 5 and not truncated and (values[1] is None or isinstance(values[1], str)) \
                and _is_int(values[2]) and _is_int(values[3]) and _is_int(values[4]) \
                and (values[4] == 0 or CHROME_MIN <= values[4] <= CHROME_MAX):
            return "table row"
        return None
    if browser == "firefox":
        if len(values) >= 3 and (values[1] is None or isinstance(values[1], str)) \
                and values[2] == host.lower()[::-1] + ".":
            return "table row"
        return None
    return None


def _decode_at(buf: bytes, s: int, lo: int, hi: int, browser: str):
    best = None
    for back in range(1, MAX_HEADER_BACK + 1):
        hp = s - back
        if hp < lo:
            break
        types = []
        pos = hp
        ok = True
        while pos < s:
            t, pos = _varint(buf, pos, s)
            if t is None or _size(t) is None:
                ok = False
                break
            types.append(t)
        if not ok or pos != s or not types:
            continue
        intact = types[0] == s - hp and len(types) >= 2
        cols = types[1:] if intact else types
        idx = next((i for i, t in enumerate(cols) if _size(t) > 0), None)
        if idx is None or any(_size(t) != 0 for t in cols[:idx]):
            continue
        t_url = cols[idx]
        if t_url < 13 or t_url % 2 == 0:
            continue
        url_len = _size(t_url)
        if url_len < MIN_URL or s + url_len > hi or not _printable(buf, s, s + url_len):
            continue
        if len(cols) - idx < 2:
            continue
        values = []
        p = s
        truncated = False
        for t in cols[idx:]:
            n = _size(t)
            if p + n > hi:
                truncated = True
                break
            try:
                values.append(_value(buf, p, t))
            except UnicodeDecodeError:
                values = None
                break
            p += n
        if not values or len(values) < 2:
            continue
        kind = classify(browser, values, intact, truncated)
        if kind is None:
            continue
        score = (kind == "table row", intact, len(values))
        if best is None or score > best[0]:
            best = (score, {"values": values, "intact": intact, "columns": len(cols), "truncated": truncated, "kind": kind})
    return best[1] if best else None


def page_regions(data: bytes) -> List[Region]:
    if len(data) < 100 or data[:16] != SQLITE_MAGIC:
        return []
    ps = struct.unpack(">H", data[16:18])[0]
    ps = 65536 if ps == 1 else ps
    usable = ps - data[20]
    npages = len(data) // ps
    regions: List[Region] = []
    free: Set[int] = set()
    trunk = struct.unpack(">I", data[32:36])[0]
    while 0 < trunk <= npages and trunk not in free:
        free.add(trunk)
        off = (trunk - 1) * ps
        nxt, cnt = struct.unpack(">II", data[off:off + 8])
        cnt = min(cnt, (usable - 8) // 4)
        leaves = struct.unpack(">%dI" % cnt, data[off + 8:off + 8 + 4 * cnt])
        regions.append((off + 8 + 4 * cnt, off + usable, "freelist trunk page %d" % trunk))
        for leaf in leaves:
            if 0 < leaf <= npages and leaf not in free:
                free.add(leaf)
                regions.append(((leaf - 1) * ps, (leaf - 1) * ps + usable, "freelist page %d" % leaf))
        trunk = nxt
    for p in range(1, npages + 1):
        if p in free:
            continue
        base = (p - 1) * ps
        h = base + (100 if p == 1 else 0)
        kind = data[h]
        if kind not in (2, 5, 10, 13):
            continue
        hdr = 12 if kind in (2, 5) else 8
        ncell = struct.unpack(">H", data[h + 3:h + 5])[0]
        start = struct.unpack(">H", data[h + 5:h + 7])[0] or 65536
        lo, hi = h + hdr + 2 * ncell, base + start
        if lo < hi <= base + usable:
            regions.append((lo, hi, "unallocated space in page %d" % p))
        fb = struct.unpack(">H", data[h + 1:h + 3])[0]
        steps = 0
        while fb and fb + 4 <= usable and steps < 4096:
            nxt, size = struct.unpack(">HH", data[base + fb:base + fb + 4])
            regions.append((base + fb, base + min(fb + size, usable), "freeblock in page %d" % p))
            if nxt <= fb:
                break
            fb = nxt
            steps += 1
    return regions


def wal_regions(data: bytes) -> List[Region]:
    if len(data) < 32 or struct.unpack(">I", data[:4])[0] not in WAL_MAGIC:
        return []
    ps = struct.unpack(">I", data[8:12])[0]
    salts = data[16:24]
    regions: List[Region] = []
    i, n = 32, 0
    while ps and i + 24 + ps <= len(data):
        page = struct.unpack(">I", data[i:i + 4])[0]
        n += 1
        state = "current" if data[i + 8:i + 16] == salts else "stale"
        regions.append((i + 24, i + 24 + ps, "WAL frame %d (page %d, %s)" % (n, page, state)))
        i += 24 + ps
    return regions


def wal_pages(data: bytes) -> Set[int]:
    if len(data) < 32 or struct.unpack(">I", data[:4])[0] not in WAL_MAGIC:
        return set()
    ps = struct.unpack(">I", data[8:12])[0]
    pages: Set[int] = set()
    i = 32
    while ps and i + 24 + ps <= len(data):
        pages.add(struct.unpack(">I", data[i:i + 4])[0])
        i += 24 + ps
    return pages


def superseded_regions(data: bytes, pages: Set[int]) -> List[Region]:
    if len(data) < 100 or data[:16] != SQLITE_MAGIC:
        return []
    ps = struct.unpack(">H", data[16:18])[0]
    ps = 65536 if ps == 1 else ps
    npages = len(data) // ps
    return [((p - 1) * ps, p * ps, "page %d of main file, superseded by WAL" % p) for p in sorted(pages) if 0 < p <= npages]


def journal_regions(data: bytes) -> List[Region]:
    return [(0, len(data), "rollback journal")] if len(data) > 0 else []


def search_term(url: str) -> Optional[str]:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host, path = parts.netloc.lower(), parts.path.lower()
    qs = parse_qs(parts.query)
    for key in ("q", "search_query", "query", "p", "wd", "text"):
        if key not in qs or not qs[key][0].strip():
            continue
        if key == "p" and "yahoo" not in host:
            continue
        if key == "wd" and "baidu" not in host:
            continue
        if key == "text" and "yandex" not in host:
            continue
        if key == "query" and "search" not in host + path:
            continue
        return qs[key][0].strip()
    return None


def _timestamp(browser: str, ints: List[int]):
    for v in ints:
        if browser == "chrome" and CHROME_MIN <= v <= CHROME_MAX:
            return chrome_to_utc(v), v, "carved urls.last_visit_time (us since 1601)"
        if browser == "firefox" and UNIX_US_MIN <= v <= UNIX_US_MAX:
            return firefox_us_to_utc(v), v, "carved moz_places.last_visit_date (us since 1970)"
    return None, None, "no timestamp (index entry or partial row)"


def carve_bytes(data: bytes, regions: List[Region], browser: str) -> Iterator[Tuple[int, str, dict]]:
    for lo, hi, label in regions:
        for m in URL_START.finditer(data, lo, hi):
            rec = _decode_at(data, m.start(), lo, hi, browser)
            if rec:
                yield m.start(), label, rec


def live_urls(db: Path, table: str, column: str) -> Set[str]:
    try:
        with open_copy(db) as conn:
            if table not in tables(conn):
                return set()
            return {r[0] for r in conn.execute("SELECT %s FROM %s" % (column, table)) if r[0]}
    except Exception:
        return set()


def _rel(path: Path, root: Optional[Path]) -> str:
    if root is None:
        return str(path)
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path)


def carve_profile(browser: str, profile_dir: Path, root: Optional[Path] = None) -> List[Record]:
    spec = TARGETS[browser]
    profile_dir = Path(profile_dir)
    db = profile_dir / spec["db"]
    if not db.is_file():
        return []
    live = live_urls(db, spec["table"], spec["column"])
    wal_file = profile_dir / (spec["db"] + "-wal")
    replaced = wal_pages(wal_file.read_bytes()) if wal_file.is_file() else set()
    files = [(db, lambda d: page_regions(d) + superseded_regions(d, replaced))]
    for side in spec["sidecars"]:
        p = profile_dir / side
        if p.is_file() and p.stat().st_size:
            files.append((p, wal_regions if side.endswith("-wal") else journal_regions))
    found: Dict[Tuple[str, Optional[int]], dict] = {}
    for path, regions_fn in files:
        data = path.read_bytes()
        for offset, label, rec in carve_bytes(data, regions_fn(data), browser):
            values = rec["values"]
            url = values[0]
            if url in live:
                continue
            title = values[1] if len(values) > 1 and isinstance(values[1], str) else ""
            ints = [v for v in values[1:] if _is_int(v)]
            ts, raw, tsrc = _timestamp(browser, ints)
            key = (url, raw)
            if key in found:
                found[key]["hits"] += 1
                continue
            found[key] = {
                "url": url, "title": title, "ts": ts, "raw": raw, "tsrc": tsrc, "hits": 1,
                "source": _rel(path, root), "region": label, "offset": offset,
                "kind": rec["kind"],
                "header": "intact" if rec["intact"] else "partially overwritten",
                "truncated": rec["truncated"],
                "integers": [v for v in ints if v != raw],
            }
    timed = {u for (u, r) in found if r is not None}
    out: List[Record] = []
    for (url, raw), f in sorted(found.items(), key=lambda kv: (kv[1]["ts"] or "", kv[0][0])):
        if raw is None and url in timed:
            continue
        extra = {
            "tag": "deleted",
            "tag_source": "Recovered from %s, %s, offset %d" % (f["source"], f["region"], f["offset"]),
            "recovered_from": f["region"],
            "file_offset": f["offset"],
            "record_kind": f["kind"],
            "record_header": f["header"],
            "truncated": f["truncated"],
            "copies_found": f["hits"],
            "other_integer_fields": f["integers"],
        }
        out.append(Record(browser, "deleted_history", url, f["title"], f["ts"], f["raw"], f["tsrc"], f["source"], extra))
        term = search_term(url)
        if term:
            out.append(Record(browser, "deleted_search", url, term, f["ts"], f["raw"], f["tsrc"], f["source"], dict(extra)))
    return out
