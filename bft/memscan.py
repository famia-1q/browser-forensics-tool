from __future__ import annotations

import json
import mmap
import re
import struct
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from . import carve
from .acquire import CUSTODY, sha256_file
from .models import Record
from .timestamps import now_utc

URL_CHARS = rb"A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%"
URL_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=%")
ASCII_URL = re.compile(rb"https?://[" + URL_CHARS + rb"]{4,2048}")
UTF16_URL = re.compile(rb"h\x00t\x00t\x00p\x00(?:s\x00)?:\x00/\x00/\x00(?:[" + URL_CHARS + rb"]\x00){4,2048}")
ORIGIN = re.compile(r"https?://[a-z0-9.\-]+(?::\d{1,5})?")
TRAILING = ".,;:!?)]'\"("
HOSTNAME = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}")
MAX_TAIL = 8
TAIL_RATIO = 10
STRUCTURAL = "/?#&="
PRIVATE_STAMP = b"^privateBrowsingId=1"
SUFFIX_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=&%(),.-_+^")
FIELD_GAP = 24
NOISE_SUFFIXES = (
    "w3.org", "schemas.microsoft.com", "schemas.openxmlformats.org", "schemas.xmlsoap.org", "schemas.android.com",
    "ns.adobe.com", "purl.org", "xmlns.com", "digicert.com", "verisign.com", "globalsign.com", "globalsign.net",
    "sectigo.com", "comodoca.com", "usertrust.com", "entrust.net", "letsencrypt.org", "lencr.org", "pki.goog",
    "amazontrust.com", "identrust.com", "godaddy.com", "starfieldtech.com", "microsoft.com/pki", "apple.com/appleca",
    "localhost",
)
NOISE_PREFIXES = ("ocsp.", "crl.", "crl3.", "crl4.", "cacerts.", "certificates.")
MEMORY_DIR = "memory"
LIVE_TYPES = ("history", "search")


def clean_url(raw: str) -> Optional[str]:
    url = raw.rstrip(TRAILING)
    host = carve._host(url).lower()
    if len(host) > 253 or not HOSTNAME.fullmatch(host):
        return None
    return url


def is_noise(url: str) -> bool:
    host = carve._host(url).lower()
    full = host + carve.urlsplit(url).path.lower()
    if host.startswith(NOISE_PREFIXES):
        return True
    return any(host == s or host.endswith("." + s) or full.startswith(s) for s in NOISE_SUFFIXES)


def _fold_tails(found: Dict[str, dict]) -> None:
    for url in sorted(found, key=len, reverse=True):
        info = found[url]
        for k in range(len(url) - 1, max(len(url) - MAX_TAIL, 0) - 1, -1):
            parent = found.get(url[:k])
            if parent is None:
                continue
            if url[k] not in STRUCTURAL and url[k - 1] not in STRUCTURAL and parent["hits"] >= TAIL_RATIO * info["hits"]:
                parent["hits"] += info["hits"]
                parent["encodings"] |= info["encodings"]
                parent["first_offset"] = min(parent["first_offset"], info["first_offset"])
                parent["variants"] += [url] + info["variants"]
                del found[url]
            break


def _prefixed(mm, start: int, limit: int):
    s = mm.find(b"http", start, min(len(mm), start + limit))
    if s < 4:
        return None, None
    n = struct.unpack("<I", mm[s - 4:s])[0]
    if not 10 <= n <= 4096 or s + n > len(mm):
        return None, None
    raw = mm[s:s + n]
    if not all(b in URL_BYTES for b in raw):
        return None, None
    return s, raw.decode("ascii")


def private_pages(mm) -> Dict[str, dict]:
    pages: Dict[str, dict] = {}
    i = mm.find(PRIVATE_STAMP)
    while i != -1:
        j = i + len(PRIVATE_STAMP)
        end = min(len(mm), j + 300)
        while j < end and mm[j] in SUFFIX_BYTES:
            j += 1
        os_, origin = _prefixed(mm, j, FIELD_GAP)
        if origin and ORIGIN.fullmatch(origin):
            us, url = _prefixed(mm, os_ + len(origin), FIELD_GAP)
            if url and url.startswith(origin) and len(url) > len(origin) and url[len(origin)] in "/?#" and clean_url(url) == url:
                info = pages.setdefault(url, {"copies": 0, "first_offset": us})
                info["copies"] += 1
        i = mm.find(PRIVATE_STAMP, i + 1)
    return pages


def _cached_row(mm, s: int):
    lo, hi = max(0, s - 64), min(len(mm), s + 16384)
    for browser in ("firefox", "chrome"):
        rec = carve._decode_at(mm, s, lo, hi, browser)
        if rec and rec["kind"] == "table row":
            return browser, rec
    return None, None


def scan_image(path: Path, keep_noise: bool = False) -> Dict[str, dict]:
    strings: Dict[str, dict] = {}
    rows: Dict[str, dict] = {}

    def note(url: str, offset: int, encoding: str):
        info = strings.get(url)
        if info is None:
            info = strings[url] = {"hits": 0, "encodings": set(), "first_offset": offset, "variants": []}
        info["hits"] += 1
        info["encodings"].add(encoding)

    with open(path, "rb") as f:
        if f.seek(0, 2) == 0:
            return {"strings": strings, "rows": rows, "private": {}}
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            for m in ASCII_URL.finditer(mm):
                browser, rec = _cached_row(mm, m.start())
                if rec and isinstance(rec["values"][0], str) and rec["values"][0].startswith("http"):
                    url = rec["values"][0]
                    row = rows.get(url)
                    if row is None:
                        values = rec["values"]
                        ints = [v for v in values[1:] if carve._is_int(v)]
                        ts, raw, tsrc = carve._timestamp(browser, ints)
                        row = rows[url] = {"browser": browser, "title": values[1] if len(values) > 1 and isinstance(values[1], str) else "",
                                           "ts": ts, "raw": raw, "copies": 0, "first_offset": m.start()}
                    row["copies"] += 1
                url = clean_url(m.group().decode("ascii"))
                if url and (keep_noise or not is_noise(url)):
                    note(url, m.start(), "ascii")
            for m in UTF16_URL.finditer(mm):
                url = clean_url(m.group().decode("utf-16-le"))
                if url and (keep_noise or not is_noise(url)):
                    note(url, m.start(), "utf-16le")
            private = private_pages(mm)
        finally:
            mm.close()
    _fold_tails(strings)
    return {"strings": strings, "rows": rows, "private": private}


def live_urls(records: Iterable[dict]) -> Dict[str, set]:
    out: Dict[str, set] = {"live": set(), "deleted": set(), "browsers": set()}
    for r in records:
        t = r["artifact_type"]
        b = r["browser"]
        if t in LIVE_TYPES:
            out["live"].add((b, r["url"]))
            out["browsers"].add(b)
            for u in (r.get("extra") or {}).get("url_chain") or []:
                out["live"].add((b, u))
        elif t in ("deleted_history", "deleted_search") and r.get("extra", {}).get("recovered_from"):
            out["deleted"].add((b, r["url"]))
    return out


def build_records(meta: dict, disk: Dict[str, set]) -> List[Record]:
    image = meta["image"]
    out: List[Record] = []
    for url, p in sorted(meta["private_pages"].items()):
        extra = {
            "tag": "private",
            "tag_source": "Firefox private-window page record (privateBrowsingId=1) in memory capture %s at offset %d, %d copies"
                          % (image, p["first_offset"], p["copies"]),
            "memory_offset": p["first_offset"],
            "copies_in_memory": p["copies"],
        }
        tsrc = "no timestamp (private pages are never written to history)"
        out.append(Record("firefox", "private_history", url, "", None, None, tsrc, image, extra))
        term = carve.search_term(url)
        if term:
            out.append(Record("firefox", "private_search", url, term, None, None, tsrc, image, dict(extra)))
    for url, r in sorted(meta["history_rows"].items()):
        key = (r["browser"], url)
        if r["browser"] not in disk["browsers"] or key in disk["live"] or key in disk["deleted"]:
            continue
        extra = {
            "tag": "deleted",
            "tag_source": "%s history row in memory capture %s at offset %d, not in the acquired live history"
                          % (r["browser"].capitalize(), image, r["first_offset"]),
            "memory_offset": r["first_offset"],
            "copies_in_memory": r["copies"],
        }
        tsrc = "history row in memory capture" if r["raw"] is not None else "no timestamp in history row"
        out.append(Record(r["browser"], "deleted_history", url, r["title"], r["ts"], r["raw"], tsrc, image, extra))
        term = carve.search_term(url)
        if term:
            out.append(Record(r["browser"], "deleted_search", url, term, r["ts"], r["raw"], tsrc, image, dict(extra)))
    return out


def memscan(image: Path, evidence: Path, case: Optional[str] = None, keep_noise: bool = False) -> Dict:
    from .pipeline import merge_memory
    image = Path(image)
    evidence = Path(evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    custody_path = evidence / CUSTODY
    if custody_path.is_file():
        with open(custody_path, encoding="utf-8") as f:
            custody = json.load(f)
    else:
        custody = {"case": case or evidence.name, "acquired_at_utc": now_utc(), "items": [], "errors": []}
    digest = sha256_file(image)
    found = scan_image(image, keep_noise)
    meta = {
        "image": image.name,
        "source_path": str(image),
        "sha256": digest,
        "size": image.stat().st_size,
        "scanned_at_utc": now_utc(),
        "noise_filtered": not keep_noise,
        "private_pages": found["private"],
        "history_rows": found["rows"],
        "audit_url_strings": {u: {"copies": i["hits"], "encodings": sorted(i["encodings"]), "first_offset": i["first_offset"],
                                  "slack_variants": sorted(i["variants"])} for u, i in sorted(found["strings"].items())},
    }
    (evidence / MEMORY_DIR).mkdir(exist_ok=True)
    with open(evidence / MEMORY_DIR / (image.name + ".json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    images = [m for m in custody.get("memory_images", []) if m.get("source_path") != str(image)]
    images.append({k: meta[k] for k in ("image", "source_path", "sha256", "size", "scanned_at_utc")})
    custody["memory_images"] = images
    with open(custody_path, "w", encoding="utf-8") as f:
        json.dump(custody, f, indent=2)
    result = merge_memory(evidence)
    mine = [r for r in result["records"] if r["source_file"] == image.name]
    return {
        "image": image.name,
        "sha256": digest,
        "private_pages": sum(1 for r in mine if r["artifact_type"] == "private_history"),
        "private_searches": sum(1 for r in mine if r["artifact_type"] == "private_search"),
        "deleted_pages": sum(1 for r in mine if r["artifact_type"] == "deleted_history"),
        "deleted_searches": sum(1 for r in mine if r["artifact_type"] == "deleted_search"),
        "history_rows": len(found["rows"]),
        "url_strings": len(found["strings"]),
        "profile_acquired": bool(live_urls(r for r in result["records"] if r["source_file"] != image.name)["browsers"]),
        "audit_file": str(evidence / MEMORY_DIR / (image.name + ".json")),
    }
