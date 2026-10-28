from __future__ import annotations

import http.client
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from bft.locate import profile_from_path
from bft.web.server import App, start_server
from tests.fixtures import chrome_profile
from tests.test_memscan import PRIVATE, PRIVATE_SEARCH, build_image


class AppServer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.prof = chrome_profile(t / "Default")
        self.vms = t / "vms"
        (self.vms / "Kali.vmwarevm").mkdir(parents=True)
        self.vmem = self.vms / "Kali.vmwarevm" / "Kali-Snapshot1.vmem"
        build_image(self.vmem, t)
        self.downloads = t / "Downloads"
        self.downloads.mkdir()
        (self.downloads / "dump.raw").write_bytes(self.vmem.read_bytes())
        self.app = App(t / "evidence", find_profiles=lambda: [profile_from_path("chrome", str(self.prof))],
                       snapshot_dirs=lambda: [self.vms], drop_dirs=lambda: [self.vms, self.downloads])
        self.server, url = start_server(self.app.root, None, 8800, self.app)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def call(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"Host": "127.0.0.1:%d" % self.port}
        if method == "POST":
            h.update({"Content-Type": "application/json", "X-BFT": "1"})
        h.update(headers or {})
        c.request(method, path, json.dumps(body).encode() if body is not None else None, h)
        r = c.getresponse()
        data = json.loads(r.read() or b"{}")
        c.close()
        return r.status, data

    def wait(self):
        for _ in range(600):
            status, d = self.call("GET", "/api/job")
            if d["job"] and d["job"]["state"] != "running":
                return d["job"]
            time.sleep(0.05)
        self.fail("job did not finish")

    def test_rejects_other_hosts_sites_and_bare_posts(self):
        self.assertEqual(self.call("GET", "/api/state", headers={"Host": "evil.example:%d" % self.port})[0], 403)
        self.assertEqual(self.call("POST", "/api/demo", {}, {"X-BFT": "0"})[0], 403)
        self.assertEqual(self.call("POST", "/api/demo", {}, {"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.call("POST", "/api/demo", {}, {"Content-Type": "text/plain"})[0], 403)
        self.assertEqual(self.call("GET", "/api/records?case=../secret")[0], 400)

    def test_capture_copies_only_listed_profiles_and_parses(self):
        self.assertEqual(self.call("POST", "/api/capture", {"profiles": ["/etc"]})[0], 400)
        status, d = self.call("POST", "/api/capture", {"profiles": [str(self.prof)]})
        self.assertEqual(status, 200)
        job = self.wait()
        self.assertEqual(job["state"], "done", job)
        self.assertTrue(job["case"].startswith("capture-"))
        self.assertTrue(job["result"]["passed"])
        status, rec = self.call("GET", "/api/records?case=" + job["case"])
        self.assertEqual(rec["total"], job["result"]["total"])
        self.assertGreater(rec["total"], 0)
        names = [c["name"] for c in self.call("GET", "/api/state")[1]["cases"]]
        self.assertIn(job["case"], names)

    def test_finds_and_scans_a_snapshot_in_place(self):
        snaps = self.call("GET", "/api/snapshots")[1]["snapshots"]
        self.assertEqual([s["path"] for s in snaps], [str(self.vmem)])
        self.assertEqual(self.call("POST", "/api/scan", {"path": str(self.downloads / "dump.raw")})[0], 400)
        self.call("POST", "/api/scan", {"path": str(self.vmem), "case": "kali"})
        job = self.wait()
        self.assertEqual(job["state"], "done", job)
        self.assertEqual(job["result"]["private_pages"], 2)
        urls = {r["url"] for r in self.call("GET", "/api/records?case=kali")[1]["records"]}
        self.assertEqual(urls, {PRIVATE, PRIVATE_SEARCH})
        self.assertEqual(sorted(p.name for p in self.vmem.parent.iterdir()), ["Kali-Snapshot1.vmem"])

    def test_dropped_file_is_matched_by_name_and_size(self):
        size = self.vmem.stat().st_size
        self.assertIsNone(self.call("POST", "/api/match", {"name": "dump.raw", "size": size + 1})[1]["path"])
        path = self.call("POST", "/api/match", {"name": "dump.raw", "size": size})[1]["path"]
        self.assertEqual(path, str(self.downloads / "dump.raw"))
        self.call("POST", "/api/scan", {"path": path})
        job = self.wait()
        self.assertEqual(job["state"], "done", job)
        self.assertTrue(job["case"].startswith("snapshot-"))

    def test_demo_builds_inside_the_process(self):
        self.call("POST", "/api/demo", {})
        job = self.wait()
        self.assertEqual(job["state"], "done", job)
        counts = self.call("GET", "/api/records?case=demo")[1]["counts"]
        self.assertEqual(counts["firefox:private_history"], 5)
        self.assertEqual(counts["chrome:deleted_history"], 10)


if __name__ == "__main__":
    unittest.main()
