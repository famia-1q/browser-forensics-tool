from __future__ import annotations

import json
import sqlite3
import struct
from pathlib import Path

CHROME_T = 13300000000000000
FF_T = 1700000000000000


def chrome_profile(root: Path) -> Path:
    p = root / "Default"
    p.mkdir(parents=True)
    conn = sqlite3.connect(p / "History")
    conn.executescript("""
    CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
    CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);
    CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER, term TEXT, normalized_term TEXT);
    CREATE TABLE downloads(id INTEGER PRIMARY KEY, current_path TEXT, target_path TEXT, start_time INTEGER, end_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state INTEGER, tab_url TEXT, referrer TEXT, mime_type TEXT);
    CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url TEXT);
    """)
    conn.execute("INSERT INTO urls VALUES (1,'https://example.com/','Example',2,1,?,0)", (CHROME_T + 60_000_000,))
    conn.execute("INSERT INTO urls VALUES (2,'https://www.google.com/search?q=forensics','forensics - Google Search',1,0,?,0)", (CHROME_T + 120_000_000,))
    conn.execute("INSERT INTO visits VALUES (1,1,?,0,0x30000001,5000)", (CHROME_T,))
    conn.execute("INSERT INTO visits VALUES (2,1,?,1,0,0)", (CHROME_T + 60_000_000,))
    conn.execute("INSERT INTO visits VALUES (3,2,?,0,5,0)", (CHROME_T + 120_000_000,))
    conn.execute("INSERT INTO keyword_search_terms VALUES (2,2,'forensics','forensics')")
    conn.execute("INSERT INTO downloads VALUES (1,'/tmp/a.pdf','/Users/x/Downloads/a.pdf',?,?,1000,1000,1,'https://example.com/','https://example.com/','application/pdf')", (CHROME_T + 200_000_000, CHROME_T + 205_000_000))
    conn.execute("INSERT INTO downloads_url_chains VALUES (1,0,'https://example.com/a.pdf')")
    conn.commit()
    conn.close()
    bookmarks = {"roots": {"bookmark_bar": {"type": "folder", "name": "Bookmarks bar", "children": [
        {"type": "folder", "name": "Study", "children": [{"type": "url", "name": "Kali", "url": "https://www.kali.org/", "date_added": str(CHROME_T + 300_000_000), "guid": "g1"}]},
        {"type": "url", "name": "Example", "url": "https://example.com/", "date_added": str(CHROME_T), "guid": "g2"},
    ]}, "other": {"type": "folder", "name": "Other", "children": []}}}
    (p / "Bookmarks").write_text(json.dumps(bookmarks), encoding="utf-8")
    (p / "Network").mkdir()
    conn = sqlite3.connect(p / "Network/Cookies")
    conn.executescript("CREATE TABLE cookies(creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER, last_access_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, has_expires INTEGER, is_persistent INTEGER, samesite INTEGER);")
    conn.execute("INSERT INTO cookies VALUES (?,'.example.com','session','',X'7631300102',' /',?,?,1,1,1,1,0)", (CHROME_T, CHROME_T + 10**9, CHROME_T))
    conn.execute("INSERT INTO cookies VALUES (?,'.plain.test','pref','dark',X'','/',?,?,0,0,1,1,0)", (CHROME_T, CHROME_T + 10**9, CHROME_T))
    conn.commit()
    conn.close()
    cache = p / "Cache/Cache_Data"
    cache.mkdir(parents=True)
    key = b"1/0/https://example.com/style.css"
    (cache / "0123456789abcdef_0").write_bytes(struct.pack("<QIII", 0xFEDCBA9876543210, 5, len(key), 0) + key + b"\x00" * 40)
    (cache / "index").write_bytes(b"\x00" * 16)
    return p


def firefox_profile(root: Path) -> Path:
    p = root / "abc123.default-release"
    p.mkdir(parents=True)
    conn = sqlite3.connect(p / "places.sqlite")
    conn.executescript("""
    CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, rev_host TEXT, visit_count INTEGER, hidden INTEGER, typed INTEGER, frecency INTEGER, last_visit_date INTEGER, guid TEXT);
    CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER, session INTEGER);
    CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, parent INTEGER, position INTEGER, title TEXT, dateAdded INTEGER, lastModified INTEGER, guid TEXT);
    CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name TEXT);
    CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content TEXT, flags INTEGER, expiration INTEGER, type INTEGER, dateAdded INTEGER, lastModified INTEGER);
    """)
    conn.execute("INSERT INTO moz_places VALUES (1,'https://mozilla.org/','Mozilla','gro.allizom.',1,0,1,100,?, 'p1')", (FF_T,))
    conn.execute("INSERT INTO moz_places VALUES (2,'https://example.com/file.zip','file.zip','moc.elpmaxe.',1,0,0,50,?, 'p2')", (FF_T + 5_000_000,))
    conn.execute("INSERT INTO moz_historyvisits VALUES (1,0,1,?,2,1)", (FF_T,))
    conn.execute("INSERT INTO moz_historyvisits VALUES (2,1,2,?,7,1)", (FF_T + 5_000_000,))
    conn.execute("INSERT INTO moz_bookmarks VALUES (1,2,NULL,0,0,'toolbar',?,?,'root')", (FF_T, FF_T))
    conn.execute("INSERT INTO moz_bookmarks VALUES (2,1,1,1,0,'Mozilla home',?,?,'b1')", (FF_T + 1_000_000, FF_T + 1_000_000))
    conn.execute("INSERT INTO moz_anno_attributes VALUES (1,'downloads/destinationFileURI')")
    conn.execute("INSERT INTO moz_anno_attributes VALUES (2,'downloads/metaData')")
    conn.execute("INSERT INTO moz_annos VALUES (1,2,1,'file:///home/x/Downloads/file.zip',0,4,3,?,?)", (FF_T + 5_000_000, FF_T + 5_000_000))
    conn.execute("INSERT INTO moz_annos VALUES (2,2,2,'{\"state\":1,\"endTime\":1700000010000,\"fileSize\":2048}',0,4,3,?,?)", (FF_T + 5_000_000, FF_T + 5_000_000))
    conn.commit()
    conn.close()
    conn = sqlite3.connect(p / "cookies.sqlite")
    conn.executescript("CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY, originAttributes TEXT, name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER);")
    conn.execute("INSERT INTO moz_cookies VALUES (1,'','sid','abc','.mozilla.org','/',1800000000,?,?,1,1,0)", (FF_T, FF_T))
    conn.commit()
    conn.close()
    conn = sqlite3.connect(p / "formhistory.sqlite")
    conn.executescript("CREATE TABLE moz_formhistory(id INTEGER PRIMARY KEY, fieldname TEXT, value TEXT, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER, guid TEXT);")
    conn.execute("INSERT INTO moz_formhistory VALUES (1,'q','browser forensics',3,?,?,'f1')", (FF_T, FF_T + 2_000_000))
    conn.commit()
    conn.close()
    entries = p / "cache2/entries"
    entries.mkdir(parents=True)
    body = b"hello world"
    key = b"a,:https://mozilla.org/logo.png"
    header = struct.pack(">8I", 3, 2, 1700000000, 1700000001, 10, 1800000000, len(key), 0)
    elements = b"request-method\x00GET\x00response-head\x00HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\x00"
    meta = b"\x00\x00\x00\x00" + b"\x00\x00" + header + key + b"\x00" + elements
    (entries / ("0" * 40)).write_bytes(body + meta + struct.pack(">I", len(body)))
    return p
