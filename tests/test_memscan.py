from __future__ import annotations

import json
import random
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path

from bft.acquire import acquire, sha256_file
from bft.locate import profile_from_path
from bft.memscan import build_records, clean_url, live_urls, memscan, scan_image
from bft.pipeline import parse_evidence
from bft.timestamps import firefox_us_to_utc
from tests.fixtures import firefox_profile

FF_T = 1761000000000000
PRIVATE = "https://anonmail.example.net/compose?to=buyer"
PRIVATE_SEARCH = "https://search.example.com/?q=how+to+avoid+dlp"
SUBRESOURCE = "https://anonmail.example.net/static/app.js"
PLAIN = "https://trail.example.com/report"
LIVE_ROW = "https://mozilla.org/"
MARKER = "https://example.org/?bft=private-test-4471"


def private_record(url: str, slack: bytes = b"refox-") -> bytes:
    origin = "/".join(url.split("/")[:3])
    return (b"O^privateBrowsingId=1\x00\x00\x00\x00\x00" + struct.pack("<I", len(origin)) + origin.encode()
            + b"\xbf\xbf\x00\x00\x00" + struct.pack("<I", len(url)) + url.encode() + slack + b"\xd2\x40")


def prefixed(text: str) -> bytes:
    return struct.pack("<I", len(text)) + text.encode()


def firefox_page_bytes(tmp: Path, urls) -> bytes:
    db = tmp / ("cached%d.sqlite" % len(list(tmp.glob("cached*.sqlite"))))
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR, visit_count INTEGER, hidden INTEGER, typed INTEGER, frecency INTEGER, last_visit_date INTEGER, guid TEXT)")
    for i, url in enumerate(urls, 1):
        host = url.split("/")[2]
        conn.execute("INSERT INTO moz_places VALUES (?,?,?,?,1,0,0,50,?,?)", (i, url, "Cached page %d" % i, host[::-1] + ".", FF_T + i * 1_000_000, "c%d" % i))
    conn.commit()
    conn.close()
    data = db.read_bytes()
    ps = struct.unpack(">H", data[16:18])[0]
    return data[ps:2 * ps]


CLEARED = ["https://cleared%d.example.org/page/%d" % (i, i) for i in range(1, 4)]


def build_image(path: Path, tmp: Path) -> None:
    rng = random.Random(7)
    parts = [rng.randbytes(300_000)]
    for _ in range(3):
        parts += [private_record(PRIVATE), rng.randbytes(20_000)]
    parts += [private_record(PRIVATE_SEARCH, b"\x00"), rng.randbytes(20_000)]
    parts.append(b"^privateBrowsingId=1&partitionKey=%28https%2Canonmail.example.net%29\x00\x00\x00" + SUBRESOURCE.encode() + b"\x00")
    parts.append(PRIVATE.encode() + b"\x00" + PRIVATE.encode("utf-16-le") + b"\x00\x00")
    parts.append(rng.randbytes(50_000))
    parts.append(b"http://www.w3.org/2000/svg\x00http://ocsp.digicert.com/MFEw\x00")
    parts.append(("see " + PLAIN + ").\x00").encode())
    parts.append(rng.randbytes(40_000))
    parts.append(firefox_page_bytes(tmp, CLEARED + [LIVE_ROW]))
    parts.append(rng.randbytes(100_000))
    path.write_bytes(b"".join(parts))


class MemoryScan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.image = self.root / "capture.raw"
        build_image(self.image, self.root)
        self.prof = firefox_profile(self.root / "ff")
        self.evidence = self.root / "evidence"
        acquire([profile_from_path("firefox", str(self.prof))], self.evidence, "mem-case")
        parse_evidence(self.evidence)

    def tearDown(self):
        self.tmp.cleanup()

    def records(self, evidence=None):
        with open((evidence or self.evidence) / "records.json", encoding="utf-8") as f:
            return [r for r in json.load(f)["records"] if r["source_file"] == self.image.name]

    def test_private_pages_come_only_from_firefox_page_records(self):
        memscan(self.image, self.evidence)
        private = {r["url"]: r for r in self.records() if r["artifact_type"] == "private_history"}
        self.assertEqual(set(private), {PRIVATE, PRIVATE_SEARCH})
        self.assertEqual(private[PRIVATE]["extra"]["tag"], "private")
        self.assertEqual(private[PRIVATE]["extra"]["copies_in_memory"], 3)
        self.assertIn("privateBrowsingId=1", private[PRIVATE]["extra"]["tag_source"])
        self.assertEqual(private[PRIVATE]["browser"], "firefox")
        searches = [r for r in self.records() if r["artifact_type"] == "private_search"]
        self.assertEqual([s["title"] for s in searches], ["how to avoid dlp"])

    def test_resources_and_plain_strings_stay_out_of_the_records(self):
        memscan(self.image, self.evidence)
        urls = {r["url"] for r in self.records()}
        self.assertNotIn(SUBRESOURCE, urls)
        self.assertNotIn(PLAIN, urls)
        self.assertNotIn(LIVE_ROW, urls)
        self.assertFalse([r for r in self.records() if r["artifact_type"].startswith("memory_")])

    def test_audit_file_keeps_every_url_string(self):
        memscan(self.image, self.evidence)
        with open(self.evidence / "memory" / "capture.raw.json", encoding="utf-8") as f:
            audit = json.load(f)["audit_url_strings"]
        self.assertIn(PLAIN, audit)
        self.assertIn(SUBRESOURCE, audit)
        self.assertEqual(sorted(audit[PRIVATE]["encodings"]), ["ascii", "utf-16le"])
        self.assertFalse([u for u in audit if "w3.org" in u or "ocsp." in u])

    def test_history_rows_missing_from_live_history_are_deleted(self):
        memscan(self.image, self.evidence)
        deleted = {r["url"]: r for r in self.records() if r["artifact_type"] == "deleted_history"}
        self.assertEqual(set(deleted), set(CLEARED))
        r = deleted[CLEARED[0]]
        self.assertEqual(r["extra"]["tag"], "deleted")
        self.assertIn("not in the acquired live history", r["extra"]["tag_source"])
        self.assertEqual(r["title"], "Cached page 1")
        self.assertEqual(r["timestamp_utc"], firefox_us_to_utc(FF_T + 1_000_000))

    def test_no_deleted_tag_without_an_acquired_profile(self):
        out = self.root / "memonly"
        r = memscan(self.image, out, case="memory only case")
        self.assertFalse(r["profile_acquired"])
        types = {x["artifact_type"] for x in self.records(out)}
        self.assertEqual(types, {"private_history", "private_search"})

    def test_acquiring_after_the_scan_gives_the_same_tags(self):
        late = self.root / "late"
        memscan(self.image, late, case="late")
        acquire([profile_from_path("firefox", str(self.prof))], late, "late")
        parse_evidence(late)
        first = sorted((r["artifact_type"], r["url"]) for r in self.records(late))
        memscan(self.image, self.evidence)
        self.assertEqual(first, sorted((r["artifact_type"], r["url"]) for r in self.records()))

    def test_custody_integrity_and_reparse(self):
        before = sha256_file(self.image)
        memscan(self.image, self.evidence)
        memscan(self.image, self.evidence)
        self.assertEqual(before, sha256_file(self.image))
        with open(self.evidence / "custody.json", encoding="utf-8") as f:
            custody = json.load(f)
        self.assertEqual([m["sha256"] for m in custody["memory_images"]], [before])
        result = parse_evidence(self.evidence)
        self.assertTrue(result["verify"]["passed"])
        self.assertEqual(result["counts"].get("firefox:private_history"), 2)
        self.assertEqual(result["counts"].get("firefox:deleted_history"), 3)


class DeletedPerBrowser(unittest.TestCase):
    def test_live_or_carved_in_one_browser_does_not_hide_deletion_in_another(self):
        url = "https://shared.example.com/page"
        disk = [
            {"browser": "chrome", "artifact_type": "history", "url": "https://other.example.com/", "extra": {}},
            {"browser": "chrome", "artifact_type": "bookmark", "url": "https://kept.example.com/", "extra": {}},
            {"browser": "firefox", "artifact_type": "history", "url": url, "extra": {}},
            {"browser": "firefox", "artifact_type": "deleted_history", "url": "https://gone.example.com/", "extra": {"recovered_from": "freelist page 2"}},
        ]
        row = {"title": "t", "ts": None, "raw": None, "copies": 1, "first_offset": 10}
        meta = {"image": "ram.raw", "private_pages": {},
                "history_rows": {url: dict(row, browser="chrome"), "https://gone.example.com/": dict(row, browser="chrome"),
                                 "https://other.example.com/": dict(row, browser="chrome"), "https://kept.example.com/": dict(row, browser="chrome")}}
        got = sorted(r.url for r in build_records(meta, live_urls(disk)))
        self.assertEqual(got, ["https://gone.example.com/", "https://kept.example.com/", url])


class UrlBoundaries(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.image = Path(self.tmp.name) / "slack.raw"

    def tearDown(self):
        self.tmp.cleanup()

    def test_rejects_hosts_with_empty_or_malformed_labels(self):
        for bad in ("http://.css", "https://a..b.com/x", "https://-bad.com/", "https://bad-.com/", "https://example./"):
            self.assertIsNone(clean_url(bad), bad)
        for good in ("https://ok.example.org:8080/p", "https://xn--bcher-kva.example/", "https://a-b.c-d.org/"):
            self.assertEqual(clean_url(good), good)

    def test_folds_slack_tails_into_the_real_url(self):
        parts = [(MARKER + "\x00").encode()] * 20
        parts += [MARKER.encode() + b"refox-\x89", MARKER.encode() + b"w.kali\xd2", MARKER.encode() + b"+\xff"]
        parts += [b"https://www.kali.org/docs/\x00"] * 20 + [b"https://www.kali.org/docs/arm/\x00", b"https://www.kali.org/docs/#top\x00"]
        parts += [b"https://search.example.com/?q=wh\x00", b"https://search.example.com/?q=wha\x00", b"https://search.example.com/?q=what\x00"]
        self.image.write_bytes(b"\x01" * 64 + b"".join(parts))
        found = scan_image(self.image)["strings"]
        self.assertEqual([u for u in found if u.startswith(MARKER)], [MARKER])
        self.assertEqual(found[MARKER]["hits"], 23)
        self.assertEqual(sorted(found[MARKER]["variants"]), sorted([MARKER + "refox-", MARKER + "w.kali", MARKER + "+"]))
        for kept in ("https://www.kali.org/docs/arm/", "https://www.kali.org/docs/#top", "https://search.example.com/?q=wh",
                     "https://search.example.com/?q=wha", "https://search.example.com/?q=what"):
            self.assertIn(kept, found)

    def test_private_record_needs_matching_origin_and_adjacent_fields(self):
        stamp = b"O^privateBrowsingId=1\x00\x00\x00\x00\x00"
        third_party = stamp + prefixed("https://aaa.example.net") + b"\xbf\xbf\x00\x00\x00" + prefixed("https://cdn.example.net/lib.js")
        far_away = stamp + b"\x00" * 100 + prefixed("https://far.example.com") + b"\x00" * 5 + prefixed("https://far.example.com/page")
        lookalike = stamp + prefixed("https://example.org") + b"\xbf\xbf\x00\x00\x00" + prefixed("https://example.org.evil.com/x")
        self.image.write_bytes(b"\x01" * 64 + third_party + b"\x00" * 64 + far_away + b"\x00" * 64 + lookalike + b"\x00" * 64)
        self.assertEqual(scan_image(self.image)["private"], {})

    def test_private_record_length_ignores_slack(self):
        self.image.write_bytes(b"\x01" * 64 + private_record(MARKER, b"w.kali") + b"\x00" * 64)
        self.assertEqual(list(scan_image(self.image)["private"]), [MARKER])


if __name__ == "__main__":
    unittest.main()
