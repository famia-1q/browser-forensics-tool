from __future__ import annotations

import json
import os
import re
import runpy
import shutil
import sys
import threading
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from .. import locate
from ..acquire import CUSTODY, acquire, load_custody, verify
from ..memscan import memscan
from ..pipeline import RECORDS, load_records, parse_evidence

HERE = Path(__file__).parent
CASE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
MEMORY_SUFFIXES = (".vmem",)
DEMO_CASE = "demo"


def bundle_dir() -> Path:
    return Path(getattr(sys, "_MEIPASS", HERE.parent.parent))


def default_root() -> Path:
    if getattr(sys, "frozen", False):
        docs = Path.home() / "Documents"
        return (docs if docs.is_dir() else Path.home()) / "Browser Forensics" / "evidence"
    return HERE.parent.parent / "evidence"


def snapshot_dirs() -> List[Path]:
    h = Path.home()
    names = ["Virtual Machines.localized", "Virtual Machines", "vmware"]
    bases = [h, h / "Documents", h / "OneDrive" / "Documents"]
    if os.environ.get("USERPROFILE"):
        up = Path(os.environ["USERPROFILE"])
        bases += [up / "Documents", up / "OneDrive" / "Documents"]
    seen, out = set(), []
    for b in bases:
        for n in names:
            p = b / n
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


def drop_dirs() -> List[Path]:
    h = Path.home()
    return snapshot_dirs() + [h / "Desktop", h / "Downloads", h / "Documents"]


def _walk(base: Path, depth: int):
    if depth < 0 or not base.is_dir():
        return
    try:
        entries = list(os.scandir(base))
    except OSError:
        return
    for e in entries:
        try:
            if e.is_file(follow_symlinks=False):
                yield Path(e.path)
            elif e.is_dir(follow_symlinks=False):
                yield from _walk(Path(e.path), depth - 1)
        except OSError:
            continue


def _tilde(p: Path) -> str:
    home = str(Path.home())
    s = str(p)
    return "~" + s[len(home):] if s == home or s.startswith(home + os.sep) else s


def _file_info(p: Path) -> dict:
    st = p.stat()
    return {"path": str(p), "name": p.name, "folder": p.parent.name, "size": st.st_size,
            "modified": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"), "mtime": st.st_mtime}


class App:
    def __init__(self, root: Path, find_profiles: Callable = locate.find_profiles,
                 snapshot_dirs: Callable = snapshot_dirs, drop_dirs: Callable = drop_dirs):
        self.root = Path(root)
        self.find_profiles = find_profiles
        self.snapshot_dirs = snapshot_dirs
        self.drop_dirs = drop_dirs
        self.job: Optional[dict] = None
        self.lock = threading.Lock()
        self.dropped: set = set()

    def case_dir(self, name: str) -> Path:
        if not name or not CASE_NAME.match(name):
            raise ValueError("invalid case name")
        return self.root / name

    def cases(self) -> List[dict]:
        out = []
        if self.root.is_dir():
            for d in sorted(self.root.iterdir()):
                if not d.is_dir() or not CASE_NAME.match(d.name):
                    continue
                rec = d / RECORDS
                if not rec.is_file() and not (d / CUSTODY).is_file():
                    continue
                info = {"name": d.name, "total": None, "generated_at_utc": None, "case": d.name}
                if rec.is_file():
                    try:
                        data = load_records(d)
                        info.update(total=data.get("total"), generated_at_utc=data.get("generated_at_utc"), case=data.get("case", d.name))
                    except (OSError, ValueError):
                        pass
                out.append(info)
        return out

    def profiles(self) -> List[dict]:
        return [p.to_dict() for p in self.find_profiles()]

    def snapshots(self) -> List[dict]:
        found = {}
        for base in self.snapshot_dirs():
            for p in _walk(base, 3):
                if p.suffix.lower() in MEMORY_SUFFIXES:
                    try:
                        found[str(p)] = _file_info(p)
                    except OSError:
                        continue
        return sorted(found.values(), key=lambda x: -x["mtime"])

    def match_drop(self, name: str, size: int) -> Optional[str]:
        for base in self.drop_dirs():
            for p in _walk(base, 3):
                try:
                    if p.name == name and p.stat().st_size == size:
                        return str(p)
                except OSError:
                    continue
        return None

    def start(self, kind: str, case: str, fn: Callable[[Callable[[str], None]], dict]) -> dict:
        with self.lock:
            if self.job and self.job["state"] == "running":
                raise RuntimeError("another task is still running")
            job = {"kind": kind, "case": case, "state": "running", "steps": [], "result": None, "error": None, "started": time.time()}
            self.job = job

        def step(text: str) -> None:
            job["steps"].append(text)

        def run():
            try:
                job["result"] = fn(step)
                job["state"] = "done"
            except Exception as e:
                job["error"] = str(e) or e.__class__.__name__
                job["state"] = "error"
        threading.Thread(target=run, daemon=True).start()
        return job

    def capture(self, paths: List[str]) -> dict:
        chosen = [p for p in self.find_profiles() if p.path in set(paths)]
        if not chosen:
            raise ValueError("no browser profile selected")
        case = "capture-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        out = self.case_dir(case)

        def work(step):
            step("Copying and hashing %d profile(s)" % len(chosen))
            custody = acquire(chosen, out, case)
            step("Copied %d files" % len(custody["items"]))
            step("Parsing and checking hashes")
            result = parse_evidence(out)
            step("Done")
            return {"total": result["total"], "passed": result["verify"]["passed"],
                    "skipped": [{"source": e["source"], "error": e["error"]} for e in custody["errors"]]}
        return self.start("capture", case, work)

    def scan(self, path: str, case: Optional[str]) -> dict:
        allowed = {s["path"] for s in self.snapshots()}
        if path not in allowed and path not in self.dropped:
            raise ValueError("unknown memory file")
        if not case:
            case = "snapshot-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        out = self.case_dir(case)

        def work(step):
            n = Path(path).stat().st_size
            step("Hashing and scanning %s (%s)" % (Path(path).name, "%.1f GB" % (n / 1e9) if n >= 1e9 else "%d MB" % max(1, round(n / 1e6))))
            r = memscan(Path(path), out, case)
            step("Done")
            return r
        return self.start("scan", case, work)

    def demo(self) -> dict:
        out = self.case_dir(DEMO_CASE)
        if (out / RECORDS).is_file():
            return {"kind": "demo", "case": DEMO_CASE, "state": "done", "steps": ["Demo case already built"], "result": None, "error": None}
        profiles = self.root.parent / "demo-profiles"

        def work(step):
            step("Building the fictional demo profiles")
            if profiles.exists():
                shutil.rmtree(profiles)
            saved = sys.argv
            try:
                sys.argv = ["make_demo_evidence.py", str(profiles)]
                runpy.run_path(str(bundle_dir() / "tools" / "make_demo_evidence.py"), run_name="__main__")
            finally:
                sys.argv = saved
            step("Copying and hashing the demo profiles")
            acquire([locate.profile_from_path("chrome", str(profiles / "chrome" / "Default"))], out, "Demo case")
            acquire([locate.profile_from_path("firefox", str(profiles / "firefox" / "demo.default-release"))], out, "Demo case")
            step("Parsing and carving deleted history")
            parse_evidence(out)
            step("Scanning the demo memory capture")
            memscan(profiles / "memory" / "suspect-ram.raw", out, "Demo case")
            return {}
        return self.start("demo", DEMO_CASE, work)


def make_handler(app: App, initial: Optional[str]):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _json(self, obj, status=200):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _local(self) -> bool:
            port = self.server.server_address[1]
            hosts = {"127.0.0.1:%d" % port, "localhost:%d" % port}
            if self.headers.get("Host") not in hosts:
                return False
            origin = self.headers.get("Origin")
            return origin is None or origin in {"http://" + h for h in hosts}

        def _case(self, q) -> Path:
            name = (q.get("case") or [initial or ""])[0]
            return app.case_dir(name)

        def do_GET(self):
            if not self._local():
                return self._json({"error": "forbidden"}, 403)
            u = urlparse(self.path)
            q = parse_qs(u.query)
            path = u.path
            try:
                if path in ("/", "/index.html"):
                    body = (HERE / "index.html").read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(body)
                elif path == "/api/state":
                    self._json({"root": _tilde(app.root), "initial": initial, "cases": app.cases(), "job": app.job, "platform": sys.platform})
                elif path == "/api/records":
                    self._json(load_records(self._case(q)))
                elif path == "/api/custody":
                    self._json(load_custody(self._case(q)))
                elif path == "/api/verify":
                    self._json(verify(self._case(q)))
                elif path == "/api/profiles":
                    self._json({"profiles": app.profiles()})
                elif path == "/api/snapshots":
                    self._json({"snapshots": app.snapshots(), "searched": [str(d) for d in app.snapshot_dirs() if d.is_dir()]})
                elif path == "/api/job":
                    self._json({"job": app.job})
                else:
                    self._json({"error": "not found"}, 404)
            except ValueError as e:
                self._json({"error": str(e)}, 400)
            except FileNotFoundError:
                self._json({"error": "this case has no records yet"}, 404)

        def do_POST(self):
            if not self._local() or self.headers.get("X-BFT") != "1" or not (self.headers.get("Content-Type") or "").startswith("application/json"):
                return self._json({"error": "forbidden"}, 403)
            try:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(min(n, 65536)) or b"{}")
                path = urlparse(self.path).path
                if path == "/api/capture":
                    self._json({"job": app.capture(list(body.get("profiles") or []))})
                elif path == "/api/match":
                    found = app.match_drop(str(body.get("name") or ""), int(body.get("size") or -1))
                    if found:
                        app.dropped.add(found)
                    self._json({"path": found})
                elif path == "/api/scan":
                    case = body.get("case") or None
                    if case:
                        app.case_dir(case)
                    self._json({"job": app.scan(str(body.get("path") or ""), case)})
                elif path == "/api/demo":
                    self._json({"job": app.demo()})
                else:
                    self._json({"error": "not found"}, 404)
            except RuntimeError as e:
                self._json({"error": str(e)}, 409)
            except (ValueError, TypeError) as e:
                self._json({"error": str(e)}, 400)

    return Handler


def start_server(root: Path, initial: Optional[str] = None, port: int = 8765, app: Optional[App] = None):
    app = app or App(root)
    server = None
    for candidate in range(port, port + 20):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", candidate), make_handler(app, initial))
            break
        except OSError:
            continue
    if server is None:
        raise SystemExit("no free port between %d and %d" % (port, port + 19))
    return server, "http://127.0.0.1:%d/" % server.server_address[1]


def serve(evidence: Path, port: int = 8765, open_browser: bool = True) -> None:
    evidence = Path(evidence).resolve()
    server, url = start_server(evidence.parent, evidence.name, port)
    _run(server, url + "#case=" + evidence.name, open_browser, "serving %s" % evidence)


def _run(server, url: str, open_browser: bool, label: str) -> None:
    print("%s at %s (Ctrl+C to stop)" % (label, url), flush=True)
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def run_app(root: Optional[Path] = None, port: int = 8765, window: bool = True, open_browser: bool = True) -> None:
    root = Path(root) if root else default_root()
    root.mkdir(parents=True, exist_ok=True)
    server, url = start_server(root, None, port)
    if window:
        try:
            import webview
        except ImportError:
            webview = None
        if webview is not None:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                webview.settings["ALLOW_DOWNLOADS"] = True
                webview.create_window("Browser Forensics", url, width=1280, height=840, min_size=(900, 600))
                webview.start()
            except Exception as e:
                print("app window unavailable (%s); opening the default browser instead" % e, flush=True)
                webbrowser.open(url)
                threading.Event().wait()
            server.shutdown()
            server.server_close()
            return
    _run(server, url, open_browser, "Browser Forensics")
