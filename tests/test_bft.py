from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from bft import chrome, firefox
from bft.acquire import acquire, sha256_file, verify
from bft.locate import profile_from_path
from bft.pipeline import parse_evidence
from bft.timestamps import chrome_to_utc, firefox_us_to_utc, unix_ms_to_utc, unix_seconds_to_utc
from tests.fixtures import CHROME_T, FF_T, chrome_profile, firefox_profile


class Timestamps(unittest.TestCase):
    def test_chrome_epoch(self):
        self.assertEqual(chrome_to_utc(11644473600 * 10**6), "1970-01-01T00:00:00Z")
        self.assertEqual(chrome_to_utc(13300000000000000), "2022-06-18T04:26:40Z")
        self.assertIsNone(chrome_to_utc(0))
        self.assertIsNone(chrome_to_utc(None))
        self.assertIsNone(chrome_to_utc("x"))

    def test_firefox_epoch(self):
        self.assertEqual(firefox_us_to_utc(1700000000000000), "2023-11-14T22:13:20Z")
        self.assertEqual(unix_seconds_to_utc(1700000000), "2023-11-14T22:13:20Z")
        self.assertEqual(unix_ms_to_utc(1700000000000), "2023-11-14T22:13:20Z")
        self.assertIsNone(firefox_us_to_utc(-5))


class ChromeParser(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.prof = chrome_profile(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_profile(self):
        recs = chrome.parse_profile(self.prof, self.prof / "Cache/Cache_Data")
        by = {}
        for r in recs:
            by.setdefault(r.artifact_type, []).append(r)
        self.assertEqual(len(by["history"]), 3)
        self.assertEqual(by["history"][0].timestamp_utc, chrome_to_utc(CHROME_T))
        self.assertEqual(by["history"][0].extra["transition"], "typed")
        self.assertEqual(len(by["search"]), 1)
        self.assertEqual(by["search"][0].title, "forensics")
        self.assertEqual(len(by["download"]), 1)
        self.assertEqual(by["download"][0].url, "https://example.com/a.pdf")
        self.assertEqual(by["download"][0].extra["state"], "complete")
        self.assertEqual(len(by["bookmark"]), 2)
        folders = sorted(b.extra["folder"] for b in by["bookmark"])
        self.assertEqual(folders, ["/Bookmarks bar", "/Bookmarks bar/Study"])
        self.assertEqual(len(by["cookie"]), 2)
        enc = [c for c in by["cookie"] if c.title == "session"][0]
        self.assertTrue(enc.extra["value_encrypted"])
        self.assertIsNone(enc.extra["value"])
        plain = [c for c in by["cookie"] if c.title == "pref"][0]
        self.assertFalse(plain.extra["value_encrypted"])
        self.assertEqual(plain.extra["value"], "dark")
        self.assertEqual(len(by["cache"]), 1)
        self.assertEqual(by["cache"][0].url, "1/0/https://example.com/style.css")

    def test_original_untouched(self):
        before = sha256_file(self.prof / "History")
        list(chrome.parse_history(self.prof / "History"))
        self.assertEqual(before, sha256_file(self.prof / "History"))


class FirefoxParser(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.prof = firefox_profile(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_profile(self):
        recs = firefox.parse_profile(self.prof, self.prof / "cache2")
        by = {}
        for r in recs:
            by.setdefault(r.artifact_type, []).append(r)
        self.assertEqual(len(by["history"]), 2)
        self.assertEqual(by["history"][0].timestamp_utc, firefox_us_to_utc(FF_T))
        self.assertEqual(by["history"][1].extra["transition"], "download")
        self.assertEqual(len(by["bookmark"]), 1)
        self.assertEqual(by["bookmark"][0].extra["folder"], "toolbar")
        self.assertEqual(len(by["download"]), 1)
        self.assertEqual(by["download"][0].timestamp_utc, "2023-11-14T22:13:30Z")
        self.assertEqual(by["download"][0].extra["file_size"], 2048)
        self.assertEqual(len(by["cookie"]), 1)
        self.assertEqual(by["cookie"][0].extra["value"], "abc")
        self.assertEqual(by["cookie"][0].extra["expires_utc"], "2027-01-15T08:00:00Z")
        self.assertEqual(len(by["form"]), 1)
        self.assertEqual(by["form"][0].title, "browser forensics")
        self.assertEqual(len(by["cache"]), 1)
        c = by["cache"][0]
        self.assertEqual(c.url, "https://mozilla.org/logo.png")
        self.assertEqual(c.timestamp_utc, "2023-11-14T22:13:21Z")
        self.assertEqual(c.title, "HTTP/1.1 200 OK")
        self.assertEqual(c.extra["request_method"], "GET")
        self.assertEqual(c.extra["fetch_count"], 2)


class Pipeline(unittest.TestCase):
    def test_acquire_parse_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cp = chrome_profile(root / "c")
            fp = firefox_profile(root / "f")
            out = root / "evidence"
            custody = acquire([profile_from_path("chrome", str(cp)), profile_from_path("firefox", str(fp))], out, "case1")
            self.assertEqual(custody["errors"], [])
            rels = {i["relative_path"] for i in custody["items"]}
            self.assertIn("chrome/Default/History", rels)
            self.assertIn("firefox/abc123.default-release/places.sqlite", rels)
            self.assertIn("chrome/Default/_cache", rels)
            result = parse_evidence(out)
            self.assertEqual(result["total"], 17)
            self.assertTrue(result["verify"]["passed"])
            self.assertTrue((out / "records.json").is_file())
            with open(out / "chrome/Default/History", "ab") as f:
                f.write(b"tamper")
            v = verify(out)
            self.assertFalse(v["passed"])
            self.assertEqual(v["mismatch"], ["chrome/Default/History"])

    def test_second_acquire_merges_custody(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cp = chrome_profile(root / "c")
            fp = firefox_profile(root / "f")
            out = root / "evidence"
            acquire([profile_from_path("chrome", str(cp))], out, "case1")
            custody = acquire([profile_from_path("firefox", str(fp))], out, "case1")
            rels = sorted(i["relative_path"] for i in custody["items"])
            self.assertIn("chrome/Default/History", rels)
            self.assertIn("firefox/abc123.default-release/places.sqlite", rels)
            self.assertEqual(custody["case"], "case1")
            self.assertIn("updated_at_utc", custody)
            self.assertTrue(verify(out)["passed"])
            self.assertEqual(len([r for r in verify(out)["ok"] if "/_cache/" not in r]), 6)


class CacheIntegrity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.cp = chrome_profile(root / "c")
        self.out = root / "evidence"
        self.custody = acquire([profile_from_path("chrome", str(self.cp))], self.out, "case1")
        self.cache = self.out / "chrome/Default/_cache"

    def tearDown(self):
        self.tmp.cleanup()

    def test_every_cache_file_is_hashed(self):
        item = [i for i in self.custody["items"] if i["relative_path"] == "chrome/Default/_cache"][0]
        self.assertEqual(sorted(item["files"]), ["0123456789abcdef_0", "index"])
        self.assertEqual(item["files"]["index"], sha256_file(self.cache / "index"))
        lines = "".join("%s  %s\n" % (item["files"][k], k) for k in sorted(item["files"]))
        self.assertEqual(item["manifest_sha256"], hashlib.sha256(lines.encode()).hexdigest())
        v = verify(self.out)
        self.assertTrue(v["passed"])
        self.assertIn("chrome/Default/_cache/index", v["ok"])
        self.assertEqual(v["unhashed"], [])

    def test_changed_deleted_and_added_cache_files_fail(self):
        with open(self.cache / "0123456789abcdef_0", "ab") as f:
            f.write(b"x")
        (self.cache / "index").unlink()
        (self.cache / "planted_0").write_bytes(b"planted")
        v = verify(self.out)
        self.assertFalse(v["passed"])
        self.assertEqual(v["mismatch"], ["chrome/Default/_cache/0123456789abcdef_0"])
        self.assertEqual(v["missing"], ["chrome/Default/_cache/index"])
        self.assertEqual(v["added"], ["chrome/Default/_cache/planted_0"])

    def test_rewritten_hash_list_in_custody_is_caught(self):
        with open(self.cache / "index", "ab") as f:
            f.write(b"x")
        with open(self.out / "custody.json", encoding="utf-8") as f:
            custody = json.load(f)
        item = [i for i in custody["items"] if i["relative_path"] == "chrome/Default/_cache"][0]
        item["files"]["index"] = sha256_file(self.cache / "index")
        with open(self.out / "custody.json", "w", encoding="utf-8") as f:
            json.dump(custody, f)
        v = verify(self.out)
        self.assertFalse(v["passed"])
        self.assertEqual(v["mismatch"], ["chrome/Default/_cache (file list in custody.json changed)"])

    def test_second_acquire_replaces_the_cache_copy(self):
        (self.cache / "leftover_0").write_bytes(b"old copy")
        acquire([profile_from_path("chrome", str(self.cp))], self.out, "case1")
        self.assertFalse((self.cache / "leftover_0").exists())
        self.assertTrue(verify(self.out)["passed"])

    def test_cache_from_an_older_version_is_reported_unhashed(self):
        with open(self.out / "custody.json", encoding="utf-8") as f:
            custody = json.load(f)
        for i in custody["items"]:
            if i["relative_path"].endswith("_cache"):
                i.pop("files"); i.pop("manifest_sha256"); i["sha256"] = None
        with open(self.out / "custody.json", "w", encoding="utf-8") as f:
            json.dump(custody, f)
        v = verify(self.out)
        self.assertTrue(v["passed"])
        self.assertEqual(v["unhashed"], ["chrome/Default/_cache"])


if __name__ == "__main__":
    unittest.main()
