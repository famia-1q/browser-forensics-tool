from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .acquire import acquire, verify
from .export import filter_records, write_csv, write_json
from .locate import find_profiles, profile_from_path
from .models import ARTIFACT_TYPES
from .pipeline import load_records, parse_evidence


def cmd_detect(args):
    profiles = find_profiles(args.browser)
    if not profiles:
        print("no browser profiles found for this user")
        return 1
    for p in profiles:
        print("%-8s %-28s %s" % (p.browser, p.name, p.path))
        print("%-8s %-28s cache: %s" % ("", "", p.cache_path or "none"))
    return 0


def _profiles_from_args(args):
    if args.profile:
        if not args.browser:
            print("--profile requires --browser", file=sys.stderr)
            sys.exit(2)
        return [profile_from_path(args.browser, args.profile, args.cache)]
    profiles = find_profiles(args.browser)
    if not profiles:
        print("no browser profiles found; pass --browser and --profile", file=sys.stderr)
        sys.exit(1)
    return profiles


def cmd_acquire(args):
    profiles = _profiles_from_args(args)
    custody = acquire(profiles, Path(args.out), args.case or Path(args.out).name, not args.no_cache, args.max_cache_mb)
    print("acquired %d files into %s" % (len(custody["items"]), args.out))
    for e in custody["errors"]:
        print("  SKIPPED %s (%s)" % (e["source"], e["error"]))
    if custody["errors"]:
        print("close the browser and run again, or acquire from a copied profile folder")
    return 0


def integrity_line(v) -> str:
    parts = ["%d ok" % len(v["ok"]), "%d mismatch" % len(v["mismatch"]), "%d missing" % len(v["missing"])]
    if v.get("added"):
        parts.append("%d added" % len(v["added"]))
    if v.get("unhashed"):
        parts.append("%d not hashed by an older version" % len(v["unhashed"]))
    return "integrity: %s (%s)" % ("PASSED" if v["passed"] else "FAILED", ", ".join(parts))


def cmd_parse(args):
    result = parse_evidence(Path(args.evidence))
    print("parsed %d records" % result["total"])
    for k, v in result["counts"].items():
        print("  %-20s %d" % (k, v))
    v = result["verify"]
    print(integrity_line(v))
    return 0 if v["passed"] else 1


def cmd_verify(args):
    v = verify(Path(args.evidence))
    print(integrity_line(v))
    for m in v["mismatch"]:
        print("  MISMATCH " + m)
    for m in v["missing"]:
        print("  MISSING  " + m)
    for m in v.get("added", []):
        print("  ADDED    " + m)
    for m in v.get("unhashed", []):
        print("  NOT HASHED " + m)
    return 0 if v["passed"] else 1


def cmd_export(args):
    data = load_records(Path(args.evidence))
    rows = filter_records(data["records"], args.browser, args.type, args.search)
    if args.csv:
        print("wrote %d rows to %s" % (write_csv(rows, Path(args.csv)), args.csv))
    if args.json:
        print("wrote %d rows to %s" % (write_json(rows, Path(args.json)), args.json))
    if not args.csv and not args.json:
        json.dump(rows, sys.stdout, indent=2, ensure_ascii=False)
    return 0


def cmd_memscan(args):
    from .memscan import memscan
    image = Path(args.image)
    if not image.is_file():
        print("memory image not found: %s" % image, file=sys.stderr)
        return 1
    print("hashing and scanning %s (%.1f MB)" % (image.name, image.stat().st_size / 1048576))
    r = memscan(image, Path(args.evidence), args.case, args.keep_noise)
    print("sha256: %s" % r["sha256"])
    print("private pages: %d (searches: %d)" % (r["private_pages"], r["private_searches"]))
    if r["profile_acquired"]:
        print("deleted pages from memory: %d (searches: %d)" % (r["deleted_pages"], r["deleted_searches"]))
    else:
        print("deleted pages from memory: not checked, no browser profile acquired in this evidence folder")
    print("audit file: %s (%d URL strings, %d history rows)" % (r["audit_file"], r["url_strings"], r["history_rows"]))
    print("records merged into %s" % (Path(args.evidence) / "records.json"))
    return 0


def cmd_serve(args):
    from .web.server import serve
    serve(Path(args.evidence), args.port, not args.no_open)
    return 0


def cmd_app(args):
    from .web.server import run_app
    run_app(Path(args.root) if args.root else None, args.port, not args.no_window, not args.no_open)
    return 0


def cmd_quick(args):
    profiles = _profiles_from_args(args)
    out = Path(args.out)
    custody = acquire(profiles, out, args.case or out.name, not args.no_cache, args.max_cache_mb)
    print("acquired %d files" % len(custody["items"]))
    for e in custody["errors"]:
        print("  SKIPPED %s (%s)" % (e["source"], e["error"]))
    result = parse_evidence(out)
    print("parsed %d records, integrity %s" % (result["total"], "PASSED" if result["verify"]["passed"] else "FAILED"))
    from .web.server import serve
    serve(out, args.port, not args.no_open)
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="bft", description="Browser forensics tool: acquire, parse, search and export Chrome and Firefox artifacts")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("detect", help="list browser profiles on this machine")
    d.add_argument("--browser", choices=["chrome", "firefox"])
    d.set_defaults(fn=cmd_detect)

    def acq_args(sp):
        sp.add_argument("--out", required=True, help="evidence folder to create")
        sp.add_argument("--case", help="case label stored in custody.json")
        sp.add_argument("--browser", choices=["chrome", "firefox"])
        sp.add_argument("--profile", help="path to a profile folder (live or copied)")
        sp.add_argument("--cache", help="path to the cache folder when it is not inside the profile")
        sp.add_argument("--no-cache", action="store_true")
        sp.add_argument("--max-cache-mb", type=int, default=300)

    a = sub.add_parser("acquire", help="copy and hash browser files into an evidence folder")
    acq_args(a)
    a.set_defaults(fn=cmd_acquire)

    pa = sub.add_parser("parse", help="parse an evidence folder into records.json and verify hashes")
    pa.add_argument("evidence")
    pa.set_defaults(fn=cmd_parse)

    v = sub.add_parser("verify", help="recompute hashes of an evidence folder against custody.json")
    v.add_argument("evidence")
    v.set_defaults(fn=cmd_verify)

    e = sub.add_parser("export", help="export records to CSV or JSON")
    e.add_argument("evidence")
    e.add_argument("--csv")
    e.add_argument("--json")
    e.add_argument("--browser", choices=["chrome", "firefox"])
    e.add_argument("--type", choices=list(ARTIFACT_TYPES))
    e.add_argument("--search")
    e.set_defaults(fn=cmd_export)

    mm = sub.add_parser("memscan", help="scan a memory capture for pages visited in private windows and for deleted history rows")
    mm.add_argument("image", help="raw memory image, VMware .vmem, LiME, or process dump")
    mm.add_argument("--evidence", required=True, help="evidence folder to compare with and add results to")
    mm.add_argument("--case", help="case label if the evidence folder is new")
    mm.add_argument("--keep-noise", action="store_true", help="keep certificate, schema and other system URLs")
    mm.set_defaults(fn=cmd_memscan)

    s = sub.add_parser("serve", help="open the web UI for an evidence folder")
    s.add_argument("evidence")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--no-open", action="store_true")
    s.set_defaults(fn=cmd_serve)

    ap = sub.add_parser("app", help="open the tool with its home screen: capture the browser, scan a memory snapshot, open a case")
    ap.add_argument("--root", help="folder that holds the cases (default: evidence next to the tool)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-window", action="store_true", help="use the default browser instead of an app window")
    ap.add_argument("--no-open", action="store_true", help="with --no-window, do not open a browser")
    ap.set_defaults(fn=cmd_app)

    q = sub.add_parser("quick", help="detect, acquire, parse and open the UI in one step")
    acq_args(q)
    q.add_argument("--port", type=int, default=8765)
    q.add_argument("--no-open", action="store_true")
    q.set_defaults(fn=cmd_quick)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
