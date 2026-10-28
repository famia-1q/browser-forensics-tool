from __future__ import annotations

import json
import os
import random
import shutil
import sqlite3
import struct
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "demo-profiles")
BASE = datetime(2026, 10, 20, 8, 30, tzinfo=timezone.utc)
CHROME_OFFSET = 11644473600
rng = random.Random(2026)

SITES = [
    ("https://mail.example.com/inbox", "Inbox - Example Mail"),
    ("https://news.example.org/", "Example News"),
    ("https://intranet.example-corp.test/home", "Example Corp Intranet"),
    ("https://intranet.example-corp.test/hr/policies", "HR Policies - Example Corp"),
    ("https://www.wikipedia.org/", "Wikipedia"),
    ("https://weather.example.net/lahore", "Weather Lahore"),
    ("https://shop.example.com/cart", "Your Cart - Example Shop"),
    ("https://video.example.org/watch?v=abc123", "Cooking basics - Example Video"),
    ("https://maps.example.com/?q=office", "Example Maps"),
    ("https://docs.example.com/document/d/1", "Project plan - Example Docs"),
]
SCENARIO = [
    (1, 9, 5, "search", "how to copy files to usb without admin rights"),
    (1, 9, 7, "visit", "https://answers.example.net/questions/usb-copy", "Copying files to USB without admin - Example Answers"),
    (1, 14, 20, "visit", "https://intranet.example-corp.test/finance/reports", "Finance Reports - Example Corp"),
    (1, 14, 26, "download", "https://intranet.example-corp.test/finance/reports/Q3_client_list.xlsx", "Q3_client_list.xlsx", 184320),
    (2, 10, 2, "search", "free cloud storage no registration"),
    (2, 10, 4, "visit", "https://transfer.example.io/", "Example Transfer - send files"),
    (2, 10, 11, "visit", "https://transfer.example.io/upload/complete?id=7f3a", "Upload complete - Example Transfer"),
    (2, 10, 12, "bookmark", "https://transfer.example.io/", "Example Transfer"),
    (2, 17, 45, "search", "permanently delete files windows"),
    (2, 17, 47, "visit", "https://tools.example.org/secure-erase", "Secure erase tools - Example Tools"),
    (2, 17, 50, "download", "https://tools.example.org/dl/secure-erase-setup.exe", "secure-erase-setup.exe", 5242880),
    (3, 8, 40, "search", "how to clear browser history"),
    (3, 8, 41, "visit", "https://help.example.com/browser/clear-history", "Clear browsing data - Example Help"),
    (3, 9, 15, "visit", "https://mail.example.com/compose", "New message - Example Mail"),
]


PRIVATE_SESSION = [
    "https://search.example.com/?q=anonymous+email+with+attachment",
    "https://anonmail.example.net/",
    "https://anonmail.example.net/compose",
    "https://anonmail.example.net/sent?id=4471",
    "https://search.example.com/?q=does+private+browsing+leave+traces",
]
PRIVATE_RESOURCES = [
    "https://anonmail.example.net/static/app.js",
    "https://anonmail.example.net/static/logo.svg",
    "https://cdn.example.com/fonts/inter.woff2",
]
PRECLEAR = {}
MEMORY_NOISE = [
    "http://www.w3.org/2000/svg",
    "http://www.w3.org/1999/xhtml",
    "http://ocsp.digicert.com/MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ",
    "http://crl.globalsign.com/root.crl",
    "http://schemas.microsoft.com/SMI/2005/WindowsSettings",
]


def cleaned_urls():
    out = []
    for s in SCENARIO:
        if s[3] == "search":
            out.append("https://search.example.com/?q=" + s[4].replace(" ", "+"))
        elif s[3] == "visit" and "mail.example.com" not in s[4]:
            out.append(s[4])
    return out


def _in(n):
    return ",".join("?" * n)


def at(day, hour, minute):
    return BASE + timedelta(days=day - 1, hours=hour - 8, minutes=minute - 30)


def chrome_us(dt):
    return int((dt.timestamp() + CHROME_OFFSET) * 1_000_000)


def ff_us(dt):
    return int(dt.timestamp() * 1_000_000)


def events():
    out = []
    for day in (1, 2, 3):
        for _ in range(rng.randint(12, 18)):
            url, title = rng.choice(SITES)
            t = at(day, rng.randint(8, 22), rng.randint(0, 59))
            out.append((t, "visit", url, title, None))
    for s in SCENARIO:
        t = at(s[0], s[1], s[2])
        if s[3] == "search":
            out.append((t, "search", "https://search.example.com/?q=" + s[4].replace(" ", "+"), s[4] + " - Example Search", s[4]))
        elif s[3] == "visit":
            out.append((t, "visit", s[4], s[5], None))
        elif s[3] == "bookmark":
            out.append((t, "bookmark", s[4], s[5], None))
        elif s[3] == "download":
            out.append((t, "download", s[4], s[5], s[6]))
    out.sort(key=lambda e: e[0])
    return out


def build_chrome(root: Path, evs):
    p = root / "Default"
    (p / "Network").mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(p / "History")
    conn.execute("PRAGMA secure_delete=ON")
    conn.executescript("""
    CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
    CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);
    CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER, term TEXT, normalized_term TEXT);
    CREATE TABLE downloads(id INTEGER PRIMARY KEY, current_path TEXT, target_path TEXT, start_time INTEGER, end_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state INTEGER, tab_url TEXT, referrer TEXT, mime_type TEXT);
    CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url TEXT);
    """)
    url_ids = {}
    vid = 0
    did = 0
    for t, kind, url, title, data in evs:
        if kind in ("visit", "search"):
            if url not in url_ids:
                url_ids[url] = len(url_ids) + 1
                conn.execute("INSERT INTO urls VALUES (?,?,?,0,0,0,0)", (url_ids[url], url, title))
            uid = url_ids[url]
            vid += 1
            trans = 5 if kind == "search" else rng.choice([0, 0, 1, 0, 8])
            conn.execute("INSERT INTO visits VALUES (?,?,?,0,?,?)", (vid, uid, chrome_us(t), trans | 0x30000000, rng.randint(2000, 90000) * 1000))
            conn.execute("UPDATE urls SET visit_count = visit_count + 1, typed_count = typed_count + ?, last_visit_time = MAX(last_visit_time, ?) WHERE id = ?", (1 if trans == 1 else 0, chrome_us(t), uid))
            if kind == "search":
                conn.execute("INSERT INTO keyword_search_terms VALUES (1,?,?,?)", (uid, data, data.lower()))
        elif kind == "download":
            did += 1
            end = t + timedelta(seconds=rng.randint(3, 40))
            conn.execute("INSERT INTO downloads VALUES (?,?,?,?,?,?,?,1,?,?,?)", (did, "C:\\Users\\jdoe\\Downloads\\" + title, "C:\\Users\\jdoe\\Downloads\\" + title, chrome_us(t), chrome_us(end), data, data, url.rsplit("/", 1)[0] + "/", url.rsplit("/", 1)[0] + "/", "application/octet-stream"))
            conn.execute("INSERT INTO downloads_url_chains VALUES (?,0,?)", (did, url))
    conn.commit()
    PRECLEAR["chrome"] = (p / "History").read_bytes()
    ids = [url_ids[u] for u in cleaned_urls() if u in url_ids]
    conn.execute("DELETE FROM visits WHERE url IN (%s)" % _in(len(ids)), ids)
    conn.execute("DELETE FROM keyword_search_terms WHERE url_id IN (%s)" % _in(len(ids)), ids)
    conn.execute("DELETE FROM urls WHERE id IN (%s)" % _in(len(ids)), ids)
    conn.commit()
    conn.close()
    bm_children = [{"type": "url", "name": t, "url": u, "date_added": str(chrome_us(ts)), "guid": "bm%d" % i} for i, (ts, k, u, t, d) in enumerate(evs) if k == "bookmark"]
    bm_children += [{"type": "url", "name": "Example News", "url": "https://news.example.org/", "date_added": str(chrome_us(at(1, 8, 31))), "guid": "bm90"},
                    {"type": "folder", "name": "Work", "children": [{"type": "url", "name": "Intranet", "url": "https://intranet.example-corp.test/home", "date_added": str(chrome_us(at(1, 8, 32))), "guid": "bm91"}]}]
    (p / "Bookmarks").write_text(json.dumps({"roots": {"bookmark_bar": {"type": "folder", "name": "Bookmarks bar", "children": bm_children}, "other": {"type": "folder", "name": "Other bookmarks", "children": []}}}, indent=1), encoding="utf-8")
    conn = sqlite3.connect(p / "Network/Cookies")
    conn.executescript("CREATE TABLE cookies(creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER, last_access_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, has_expires INTEGER, is_persistent INTEGER, samesite INTEGER);")
    hosts = sorted({"." + u.split("/")[2] for _, k, u, _, _ in evs if k in ("visit", "search")})
    for h in hosts:
        t = at(1, rng.randint(8, 12), rng.randint(0, 59))
        conn.execute("INSERT INTO cookies VALUES (?,?,'session_id','',X'763130ab12cd34ef','/',?,?,1,1,1,1,0)", (chrome_us(t), h, chrome_us(t + timedelta(days=30)), chrome_us(t + timedelta(days=2))))
        conn.execute("INSERT INTO cookies VALUES (?,?,'consent','',X'763130ff00ff00','/',?,?,1,0,1,1,1)", (chrome_us(t), h, chrome_us(t + timedelta(days=365)), chrome_us(t + timedelta(days=2))))
    conn.commit()
    conn.close()
    cache = p / "Cache/Cache_Data"
    cache.mkdir(parents=True, exist_ok=True)
    for i, (ts, k, u, t, d) in enumerate(e for e in evs if e[1] == "visit"):
        key = ("1/0/" + u).encode()
        f = cache / ("%016x_0" % rng.getrandbits(64))
        f.write_bytes(struct.pack("<QIII", 0xFEDCBA9876543210, 5, len(key), 0) + key + rng.randbytes(rng.randint(200, 4000)))
        os.utime(f, (ts.timestamp(), ts.timestamp()))
    return p


def build_firefox(root: Path, evs):
    p = root / "demo.default-release"
    (p / "cache2/entries").mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="bft-demo-")) / "places.sqlite"
    conn = sqlite3.connect(work)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("PRAGMA secure_delete=ON")
    conn.executescript("""
    CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, rev_host TEXT, visit_count INTEGER, hidden INTEGER, typed INTEGER, frecency INTEGER, last_visit_date INTEGER, guid TEXT);
    CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER, session INTEGER);
    CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, parent INTEGER, position INTEGER, title TEXT, dateAdded INTEGER, lastModified INTEGER, guid TEXT);
    CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name TEXT);
    CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content TEXT, flags INTEGER, expiration INTEGER, type INTEGER, dateAdded INTEGER, lastModified INTEGER);
    INSERT INTO moz_anno_attributes VALUES (1,'downloads/destinationFileURI');
    INSERT INTO moz_anno_attributes VALUES (2,'downloads/metaData');
    INSERT INTO moz_bookmarks VALUES (1,2,NULL,0,0,'toolbar',0,0,'toolbar_____');
    """)
    place_ids = {}
    vid = 0
    bid = 1
    aid = 0
    subset = [e for e in evs if rng.random() < 0.55 or e[1] != "visit"]
    for t, kind, url, title, data in subset:
        if url not in place_ids:
            place_ids[url] = len(place_ids) + 1
            conn.execute("INSERT INTO moz_places VALUES (?,?,?,?,0,0,0,?,0,?)", (place_ids[url], url, title, url.split("/")[2][::-1] + ".", rng.randint(10, 2000), "p%d" % place_ids[url]))
        pid = place_ids[url]
        if kind in ("visit", "search", "download"):
            vid += 1
            vt = 7 if kind == "download" else rng.choice([1, 1, 2, 1])
            conn.execute("INSERT INTO moz_historyvisits VALUES (?,0,?,?,?,1)", (vid, pid, ff_us(t), vt))
            conn.execute("UPDATE moz_places SET visit_count = visit_count + 1, typed = typed + ?, last_visit_date = MAX(last_visit_date, ?) WHERE id = ?", (1 if vt == 2 else 0, ff_us(t), pid))
        if kind == "bookmark":
            bid += 1
            conn.execute("INSERT INTO moz_bookmarks VALUES (?,1,?,1,?,?,?,?,?)", (bid, pid, bid, title, ff_us(t), ff_us(t), "b%d" % bid))
        if kind == "download":
            end = t + timedelta(seconds=rng.randint(3, 40))
            aid += 1
            conn.execute("INSERT INTO moz_annos VALUES (?,?,1,?,0,4,3,?,?)", (aid, pid, "file:///home/jdoe/Downloads/" + title, ff_us(t), ff_us(t)))
            aid += 1
            conn.execute("INSERT INTO moz_annos VALUES (?,?,2,?,0,4,3,?,?)", (aid, pid, json.dumps({"state": 1, "endTime": int(end.timestamp() * 1000), "fileSize": data}), ff_us(t), ff_us(t)))
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    gone = [place_ids[u] for u in cleaned_urls() if u in place_ids]
    conn.execute("DELETE FROM moz_historyvisits WHERE place_id IN (%s)" % _in(len(gone)), gone)
    conn.execute("DELETE FROM moz_places WHERE id IN (%s) AND id NOT IN (SELECT fk FROM moz_bookmarks WHERE fk IS NOT NULL)" % _in(len(gone)), gone)
    conn.commit()
    shutil.copy2(work, p / "places.sqlite")
    shutil.copy2(work.with_name("places.sqlite-wal"), p / "places.sqlite-wal")
    conn.close()
    shutil.rmtree(work.parent, ignore_errors=True)
    conn = sqlite3.connect(p / "cookies.sqlite")
    conn.executescript("CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY, originAttributes TEXT, name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER);")
    cid = 0
    for h in sorted({"." + u.split("/")[2] for _, k, u, _, _ in subset if k in ("visit", "search")}):
        t = at(1, rng.randint(8, 12), rng.randint(0, 59))
        cid += 1
        conn.execute("INSERT INTO moz_cookies VALUES (?,'','sid',?,?,'/',?,?,?,1,1,0)", (cid, "%032x" % rng.getrandbits(128), h, int((t + timedelta(days=30)).timestamp()), ff_us(t + timedelta(days=2)), ff_us(t)))
    conn.commit()
    conn.close()
    conn = sqlite3.connect(p / "formhistory.sqlite")
    conn.executescript("CREATE TABLE moz_formhistory(id INTEGER PRIMARY KEY, fieldname TEXT, value TEXT, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER, guid TEXT);")
    fid = 0
    for t, kind, url, title, data in subset:
        if kind == "search":
            fid += 1
            conn.execute("INSERT INTO moz_formhistory VALUES (?,'q',?,1,?,?,?)", (fid, data, ff_us(t), ff_us(t), "f%d" % fid))
    fid += 1
    conn.execute("INSERT INTO moz_formhistory VALUES (?,'email','jdoe@example.com',6,?,?,'f99')", (fid, ff_us(at(1, 8, 35)), ff_us(at(3, 9, 16))))
    conn.commit()
    conn.close()
    for t, kind, url, title, data in subset:
        if kind != "visit":
            continue
        body = rng.randbytes(rng.randint(300, 5000))
        key = ("a,:" + url).encode()
        header = struct.pack(">8I", 3, rng.randint(1, 4), int(t.timestamp()), int(t.timestamp()), 100, int(t.timestamp()) + 86400, len(key), 0)
        elements = b"request-method\x00GET\x00response-head\x00HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\x00"
        chunks = (len(body) + 262143) // 262144
        meta = b"\x00\x00\x00\x00" + b"\x00\x00" * chunks + header + key + b"\x00" + elements
        (p / "cache2/entries" / ("%040x" % rng.getrandbits(160))).write_bytes(body + meta + struct.pack(">I", len(body)))
    return p


def _prefixed(text: str) -> bytes:
    return struct.pack("<I", len(text)) + text.encode()


def private_page_record(url: str) -> bytes:
    origin = "/".join(url.split("/")[:3])
    return (b"O^privateBrowsingId=1\x00\x00\x00\x00\x00" + _prefixed(origin) + b"\xbf\xbf\x00\x00\x00" + _prefixed(url)
            + rng.choice([b"", b"refox-", b"w.ex"]) + b"\xd2\x40\x2b\x99")


def build_memory(root: Path, ff_profile: Path, evs):
    root.mkdir(parents=True, exist_ok=True)
    blocks = []
    for u in PRIVATE_SESSION:
        for _ in range(rng.randint(2, 5)):
            blocks.append(private_page_record(u))
        blocks.append(u.encode("utf-16-le") + b"\x00\x00")
        blocks.append(b"GET " + u.split("/", 3)[-1].encode() + b" HTTP/1.1\r\nHost: " + u.split("/")[2].encode() + b"\r\n")
        blocks.append(u.encode() + b"\x00")
    for u in PRIVATE_RESOURCES:
        blocks.append(b"^privateBrowsingId=1&partitionKey=%28https%2Canonmail.example.net%29\x00\x00\x00" + u.encode() + b"\x00")
    pre = PRECLEAR["chrome"]
    cps = struct.unpack(">H", pre[16:18])[0]
    for p in range(2, len(pre) // cps + 1):
        blocks.append(pre[(p - 1) * cps:p * cps])
    for _, kind, url, _, _ in evs:
        if kind == "visit" and rng.random() < 0.4:
            blocks.append(url.encode() + b"\x00")
    for u in MEMORY_NOISE:
        blocks.append(u.encode() + b"\x00")
    places = (ff_profile / "places.sqlite").read_bytes()
    ps = struct.unpack(">H", places[16:18])[0]
    for p in range(2, len(places) // ps + 1):
        blocks.append(places[(p - 1) * ps:p * ps])
    rng.shuffle(blocks)
    path = root / "suspect-ram.raw"
    with open(path, "wb") as f:
        for b in blocks:
            f.write(rng.randbytes(rng.randint(40_000, 400_000)))
            f.write(b)
        f.write(rng.randbytes(1_000_000))
    return path


if __name__ == "__main__":
    evs = events()
    OUT.mkdir(parents=True, exist_ok=True)
    c = build_chrome(OUT / "chrome", evs)
    f = build_firefox(OUT / "firefox", evs)
    m = build_memory(OUT / "memory", f, evs)
    print("chrome profile:", c)
    print("firefox profile:", f)
    print("memory image:", m, "(%.1f MB)" % (m.stat().st_size / 1048576))
    print("events:", len(evs))
