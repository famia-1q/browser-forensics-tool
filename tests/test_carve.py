from __future__ import annotations

import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from bft import carve
from bft.acquire import acquire
from bft.locate import profile_from_path
from bft.pipeline import parse_evidence
from bft.timestamps import chrome_to_utc, firefox_us_to_utc

CHROME_T = 13400000000000000
FF_T = 1760000000000000
SEARCH = "https://www.google.com/search?q=how+to+wipe+a+laptop&oq=how"
DELETED = [7, 33, 64, 98, 500]


def chrome_history(folder: Path, secure_delete: bool = False) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(folder / "History")
    conn.execute("PRAGMA secure_delete=%s" % ("ON" if secure_delete else "OFF"))
    conn.executescript("""
    CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER DEFAULT 0 NOT NULL,
      typed_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);
    CREATE INDEX urls_url_index ON urls (url);
    CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);
    """)
    for i in range(1, 121):
        conn.execute("INSERT INTO urls VALUES (?,?,?,?,?,?,0)", (i, url_for(i), "Page number %d" % i, i % 5 + 1, i % 2, CHROME_T + i * 1_000_000))
        conn.execute("INSERT INTO visits VALUES (?,?,?,0,1,0)", (i, i, CHROME_T + i * 1_000_000))
    conn.execute("INSERT INTO urls VALUES (500,?,'how to wipe a laptop - Google Search',1,0,?,0)", (SEARCH, CHROME_T + 999_000_000))
    conn.commit()
    conn.execute("DELETE FROM urls WHERE id IN (%s)" % ",".join(map(str, DELETED)))
    conn.commit()
    conn.close()
    return folder


def url_for(i: int) -> str:
    return SEARCH if i == 500 else "https://site%d.example.com/page/%d" % (i % 9, i)


class SearchTerms(unittest.TestCase):
    def test_engines(self):
        self.assertEqual(carve.search_term("https://www.google.com/search?q=usb+copy&oq=usb"), "usb copy")
        self.assertEqual(carve.search_term("https://www.bing.com/search?q=delete%20files"), "delete files")
        self.assertEqual(carve.search_term("https://duckduckgo.com/?q=cloud+storage"), "cloud storage")
        self.assertEqual(carve.search_term("https://www.youtube.com/results?search_query=wipe+disk"), "wipe disk")
        self.assertEqual(carve.search_term("https://search.yahoo.com/search?p=shred"), "shred")
        self.assertIsNone(carve.search_term("https://example.com/page?p=2"))
        self.assertIsNone(carve.search_term("https://example.com/"))


class ChromeCarving(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_recovers_every_deleted_url_and_no_live_url(self):
        prof = chrome_history(self.root / "Default")
        recs = carve.carve_profile("chrome", prof)
        hist = [r for r in recs if r.artifact_type == "deleted_history"]
        self.assertEqual({r.url for r in hist}, {url_for(i) for i in DELETED})
        for r in hist:
            self.assertEqual(r.extra["tag"], "deleted")
            self.assertRegex(r.extra["tag_source"], r"^Recovered from .*History, .+, offset \d+$")
            if r.raw_timestamp is not None:
                i = 500 if r.url == SEARCH else int(r.url.rsplit("/", 1)[1])
                expected = CHROME_T + (999_000_000 if i == 500 else i * 1_000_000)
                self.assertEqual(r.raw_timestamp, expected)
                self.assertEqual(r.timestamp_utc, chrome_to_utc(expected))
                self.assertEqual(r.extra["record_kind"], "table row")
            else:
                self.assertEqual(r.extra["record_kind"], "index entry")
        self.assertGreaterEqual(sum(1 for r in hist if r.raw_timestamp is not None), 3)
        searches = [r for r in recs if r.artifact_type == "deleted_search"]
        self.assertEqual([(s.title, s.url) for s in searches], [("how to wipe a laptop", SEARCH)])

    def test_secure_delete_wipes_freed_space(self):
        prof = chrome_history(self.root / "Default", secure_delete=True)
        recs = carve.carve_profile("chrome", prof)
        regions = [r.extra["recovered_from"] for r in recs]
        self.assertFalse([g for g in regions if g.startswith(("freelist", "freeblock"))])

    def test_evidence_file_untouched(self):
        from bft.acquire import sha256_file
        prof = chrome_history(self.root / "Default")
        before = sha256_file(prof / "History")
        carve.carve_profile("chrome", prof)
        self.assertEqual(before, sha256_file(prof / "History"))

    def test_pipeline_includes_recovered_records(self):
        prof = chrome_history(self.root / "Default")
        out = self.root / "evidence"
        acquire([profile_from_path("chrome", str(prof))], out, "carve-case")
        result = parse_evidence(out)
        self.assertGreaterEqual(result["counts"].get("chrome:deleted_history", 0), 5)
        self.assertEqual(result["counts"].get("chrome:deleted_search"), 1)
        self.assertTrue(result["verify"]["passed"])


class FirefoxWalCarving(unittest.TestCase):
    def test_recovers_deleted_rows_from_wal_frames(self):
        with tempfile.TemporaryDirectory() as tmp:
            live_dir = Path(tmp) / "live"
            live_dir.mkdir()
            db = live_dir / "places.sqlite"
            conn = sqlite3.connect(db)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA wal_autocheckpoint=0")
            conn.execute("PRAGMA secure_delete=ON")
            conn.execute("CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR, visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL, frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER, guid TEXT)")
            for i in range(1, 41):
                host = "news%d.example.org" % i
                conn.execute("INSERT INTO moz_places VALUES (?,?,?,?,1,0,0,100,?,?)", (i, "https://%s/story/%d" % (host, i), "Story %d" % i, host[::-1] + ".", FF_T + i * 1_000_000, "g%d" % i))
            conn.commit()
            conn.execute("DELETE FROM moz_places WHERE id IN (5, 17, 30)")
            conn.commit()
            prof = Path(tmp) / "copy"
            prof.mkdir()
            shutil.copy2(db, prof / "places.sqlite")
            shutil.copy2(live_dir / "places.sqlite-wal", prof / "places.sqlite-wal")
            conn.close()
            recs = carve.carve_profile("firefox", prof)
            got = {r.url: r for r in recs if r.artifact_type == "deleted_history"}
            self.assertEqual(set(got), {"https://news%d.example.org/story/%d" % (i, i) for i in (5, 17, 30)})
            for i in (5, 17, 30):
                r = got["https://news%d.example.org/story/%d" % (i, i)]
                self.assertEqual(r.title, "Story %d" % i)
                self.assertEqual(r.timestamp_utc, firefox_us_to_utc(FF_T + i * 1_000_000))
                self.assertTrue(r.extra["recovered_from"].startswith("WAL frame"))
                self.assertEqual(r.source_file, str(prof / "places.sqlite-wal"))


    def test_recovers_rows_from_main_file_pages_superseded_by_wal(self):
        with tempfile.TemporaryDirectory() as tmp:
            live_dir = Path(tmp) / "live"
            live_dir.mkdir()
            db = live_dir / "places.sqlite"
            conn = sqlite3.connect(db)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA wal_autocheckpoint=0")
            conn.execute("PRAGMA secure_delete=ON")
            conn.execute("CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR, visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL, frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER, guid TEXT)")
            for i in range(1, 41):
                host = "news%d.example.org" % i
                conn.execute("INSERT INTO moz_places VALUES (?,?,?,?,1,0,0,100,?,?)", (i, "https://%s/story/%d" % (host, i), "Story %d" % i, host[::-1] + ".", FF_T + i * 1_000_000, "g%d" % i))
            conn.commit()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.execute("DELETE FROM moz_places WHERE id IN (9, 22)")
            conn.commit()
            prof = Path(tmp) / "copy"
            prof.mkdir()
            shutil.copy2(db, prof / "places.sqlite")
            shutil.copy2(live_dir / "places.sqlite-wal", prof / "places.sqlite-wal")
            conn.close()
            recs = [r for r in carve.carve_profile("firefox", prof) if r.artifact_type == "deleted_history"]
            self.assertEqual({r.url for r in recs}, {"https://news9.example.org/story/9", "https://news22.example.org/story/22"})
            self.assertTrue(all("superseded by WAL" in r.extra["recovered_from"] for r in recs))
            self.assertTrue(all(r.raw_timestamp is not None for r in recs))


if __name__ == "__main__":
    unittest.main()
