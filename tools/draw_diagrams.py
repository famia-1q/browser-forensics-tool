from __future__ import annotations

import sys
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/diagrams")
FONT = "font-family='Helvetica, Arial, sans-serif'"


class Svg:
    def __init__(self, w, h, title):
        self.w, self.h = w, h
        self.parts = [
            "<svg xmlns='http://www.w3.org/2000/svg' width='%d' height='%d' viewBox='0 0 %d %d'>" % (w, h, w, h),
            "<defs><marker id='a' markerWidth='10' markerHeight='8' refX='9' refY='4' orient='auto'><path d='M0,0 L10,4 L0,8 z' fill='#333'/></marker></defs>",
            "<rect width='100%' height='100%' fill='white'/>",
            "<text x='%d' y='30' %s font-size='20' font-weight='bold' fill='#111' text-anchor='middle'>%s</text>" % (w // 2, FONT, title),
        ]

    def box(self, x, y, w, h, lines, fill="#f4f6f9", stroke="#334", bold_first=True, size=13):
        self.parts.append("<rect x='%d' y='%d' width='%d' height='%d' rx='3' fill='%s' stroke='%s' stroke-width='1.2'/>" % (x, y, w, h, fill, stroke))
        lh = size + 5
        total = lh * len(lines)
        ty = y + (h - total) / 2 + size
        for i, line in enumerate(lines):
            weight = "bold" if (i == 0 and bold_first) else "normal"
            self.parts.append("<text x='%d' y='%.1f' %s font-size='%d' font-weight='%s' fill='#111' text-anchor='middle'>%s</text>" % (x + w / 2, ty + i * lh, FONT, size, weight, esc(line)))

    def circle(self, cx, cy, r, lines, fill="#eef5ee"):
        self.parts.append("<circle cx='%d' cy='%d' r='%d' fill='%s' stroke='#334' stroke-width='1.2'/>" % (cx, cy, r, fill))
        lh = 17
        ty = cy - lh * (len(lines) - 1) / 2 + 5
        for i, line in enumerate(lines):
            self.parts.append("<text x='%d' y='%.1f' %s font-size='13' font-weight='%s' fill='#111' text-anchor='middle'>%s</text>" % (cx, ty + i * lh, FONT, "bold" if i == 0 else "normal", esc(line)))

    def store(self, x, y, w, h, label):
        self.parts.append("<path d='M%d,%d h%d M%d,%d h%d M%d,%d v%d' fill='none' stroke='#334' stroke-width='1.2'/>" % (x, y, w, x, y + h, w, x, y, h))
        self.parts.append("<text x='%d' y='%d' %s font-size='13' fill='#111' text-anchor='middle'>%s</text>" % (x + w / 2, y + h / 2 + 5, FONT, esc(label)))

    def arrow(self, x1, y1, x2, y2, label=None, dashed=False):
        dash = " stroke-dasharray='6,4'" if dashed else ""
        self.parts.append("<line x1='%d' y1='%d' x2='%d' y2='%d' stroke='#333' stroke-width='1.3' marker-end='url(#a)'%s/>" % (x1, y1, x2, y2, dash))
        if label:
            self.parts.append("<text x='%d' y='%d' %s font-size='11' fill='#444' text-anchor='middle'>%s</text>" % ((x1 + x2) / 2, (y1 + y2) / 2 - 6, FONT, esc(label)))

    def path_arrow(self, pts, label=None, label_at=None):
        d = "M" + " L".join("%d,%d" % p for p in pts)
        self.parts.append("<path d='%s' fill='none' stroke='#333' stroke-width='1.3' marker-end='url(#a)'/>" % d)
        if label:
            lx, ly = label_at or pts[len(pts) // 2]
            self.parts.append("<text x='%d' y='%d' %s font-size='11' fill='#444' text-anchor='middle'>%s</text>" % (lx, ly - 6, FONT, esc(label)))

    def text(self, x, y, s, size=12, anchor="start", color="#444", bold=False):
        self.parts.append("<text x='%d' y='%d' %s font-size='%d' fill='%s' text-anchor='%s' font-weight='%s'>%s</text>" % (x, y, FONT, size, color, anchor, "bold" if bold else "normal", esc(s)))

    def vline(self, x, y1, y2):
        self.parts.append("<line x1='%d' y1='%d' x2='%d' y2='%d' stroke='#999' stroke-width='1' stroke-dasharray='4,4'/>" % (x, y1, x, y2))

    def group(self, x, y, w, h, label):
        self.parts.append("<rect x='%d' y='%d' width='%d' height='%d' rx='4' fill='none' stroke='#889' stroke-width='1' stroke-dasharray='5,4'/>" % (x, y, w, h))
        self.parts.append("<text x='%d' y='%d' %s font-size='12' fill='#556' font-weight='bold'>%s</text>" % (x + 8, y + 16, FONT, esc(label)))

    def save(self, name):
        self.parts.append("</svg>")
        (OUT / name).write_text("\n".join(self.parts), encoding="utf-8")


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def architecture():
    s = Svg(1240, 600, "Figure 1. System architecture of the browser forensics tool")
    cols = [40, 290, 540, 790, 1020]
    s.group(cols[0] - 10, 50, 230, 520, "Sources (read only)")
    s.box(cols[0], 90, 210, 120, ["Chrome profile", "History (SQLite)", "Bookmarks (JSON)", "Cookies (SQLite)", "Cache/Cache_Data"], fill="#fff7e6")
    s.box(cols[0], 240, 210, 130, ["Firefox profile", "places.sqlite", "cookies.sqlite", "formhistory.sqlite", "cache2/entries"], fill="#fff7e6")
    s.box(cols[0], 395, 210, 60, ["Copied profile folder", "(zip from another machine)"], fill="#fff7e6")
    s.box(cols[0], 475, 210, 70, ["Memory capture", "VM .vmem, WinPmem, AVML,", "LiME, process dump"], fill="#fff1e0")
    s.group(cols[1] - 10, 50, 230, 520, "Acquisition")
    s.box(cols[1], 90, 210, 70, ["locate.py", "default profile paths", "for Windows, macOS, Linux"])
    s.box(cols[1], 200, 210, 90, ["acquire.py", "copy artifact files", "SHA-256 each file", "write custody.json"])
    s.box(cols[1], 330, 210, 60, ["Evidence folder", "chrome/, firefox/, custody.json"], fill="#e8f0fe")
    s.box(cols[1], 430, 210, 60, ["acquire.verify()", "re-hash, write verify.json"])
    s.group(cols[2] - 10, 50, 230, 520, "Parsing")
    s.box(cols[2], 70, 210, 44, ["sqlite_ro.py", "temporary working copy"], size=12)
    s.box(cols[2], 126, 210, 56, ["chrome.py", "history, search, bookmark,", "cookie, download, cache"], size=12)
    s.box(cols[2], 194, 210, 56, ["firefox.py", "history, bookmark, download,", "cookie, form, cache2"], size=12)
    s.box(cols[2], 262, 210, 70, ["carve.py", "free pages, freeblocks, slack,", "WAL frames, journal", "deleted history + searches"], fill="#fdecea", size=12)
    s.box(cols[2], 344, 210, 70, ["memscan.py", "private page records,", "history rows in memory,", "tagged private or deleted"], fill="#fff1e0", size=12)
    s.box(cols[2], 426, 210, 44, ["timestamps.py", "1601/1970 epochs to UTC"], size=12)
    s.box(cols[2], 482, 210, 50, ["models.Record", "one shape for every artifact"], fill="#e8f0fe", size=12)
    s.group(cols[3] - 10, 50, 220, 520, "Storage")
    s.box(cols[3], 90, 200, 70, ["pipeline.py", "walk evidence folder", "run parsers, sort, count"])
    s.box(cols[3], 200, 200, 60, ["records.json", "all records + counts"], fill="#e8f0fe")
    s.box(cols[3], 300, 200, 60, ["verify.json", "integrity result"], fill="#e8f0fe")
    s.group(cols[4] - 10, 50, 220, 520, "Presentation")
    s.box(cols[4], 90, 200, 70, ["__main__.py (CLI)", "detect, acquire, parse,", "verify, export, serve, quick"])
    s.box(cols[4], 200, 200, 60, ["export.py", "CSV and JSON files"])
    s.box(cols[4], 300, 200, 80, ["web/server.py", "http.server on 127.0.0.1", "/api/records, /api/verify"])
    s.box(cols[4], 420, 200, 90, ["web/index.html", "search, filters, sort,", "timeline, detail, export"], fill="#eef5ee")
    s.arrow(250, 150, 290, 125)
    s.arrow(250, 305, 290, 240)
    s.arrow(250, 435, 290, 245)
    s.arrow(395, 160, 395, 200)
    s.arrow(395, 290, 395, 330)
    s.arrow(395, 390, 395, 430)
    s.arrow(500, 355, 540, 160)
    s.arrow(500, 360, 540, 225)
    s.arrow(500, 365, 540, 297)
    s.arrow(250, 515, 540, 385)
    s.arrow(645, 114, 645, 126)
    s.arrow(645, 182, 645, 194)
    s.arrow(645, 250, 645, 262)
    s.arrow(645, 332, 645, 344)
    s.arrow(645, 414, 645, 426)
    s.arrow(645, 470, 645, 482)
    s.arrow(750, 507, 790, 160)
    s.arrow(890, 160, 890, 200)
    s.arrow(890, 260, 890, 300)
    s.arrow(990, 230, 1020, 230)
    s.arrow(990, 235, 1020, 340)
    s.arrow(1120, 380, 1120, 420)
    s.arrow(1120, 160, 1120, 200)
    s.save("fig1-architecture.svg")


def dataflow():
    s = Svg(1240, 720, "Figure 2. Data flow diagram (level 1)")
    s.box(40, 270, 150, 60, ["Investigator"], fill="#fff")
    s.box(1050, 420, 150, 60, ["Web browser", "(127.0.0.1)"], fill="#fff")
    s.circle(330, 120, 52, ["1.0", "Locate", "profiles"])
    s.circle(330, 300, 52, ["2.0", "Acquire", "and hash"])
    s.circle(600, 300, 52, ["3.0", "Parse and", "carve"])
    s.circle(600, 480, 52, ["4.0", "Verify", "hashes"])
    s.circle(860, 180, 52, ["5.0", "Export"])
    s.circle(860, 420, 52, ["6.0", "Serve UI"])
    s.circle(1110, 580, 52, ["7.0", "Scan", "memory"], fill="#fff1e0")
    s.store(1010, 668, 200, 36, "D6  Memory capture")
    s.store(260, 500, 180, 36, "D1  Browser profile")
    s.store(470, 150, 200, 36, "D2  Evidence folder")
    s.store(470, 70, 200, 36, "D3  custody.json")
    s.store(720, 560, 200, 36, "D4  records.json")
    s.store(960, 70, 200, 36, "D5  CSV / JSON files")
    s.arrow(190, 290, 278, 140, "command")
    s.arrow(190, 300, 278, 300, "profile path, case name")
    s.arrow(330, 172, 330, 248, "profile list")
    s.arrow(350, 480, 340, 352, "artifact files")
    s.arrow(370, 270, 490, 190, "file copies")
    s.arrow(355, 258, 480, 108, "hashes")
    s.arrow(560, 170, 580, 248, "copies")
    s.arrow(652, 300, 808, 210, "records")
    s.arrow(630, 348, 720, 570, "records")
    s.arrow(600, 352, 600, 428)
    s.arrow(610, 110, 585, 430, "expected hashes")
    s.arrow(652, 490, 808, 430, "pass / fail")
    s.arrow(830, 560, 850, 472, "records")
    s.arrow(890, 140, 960, 100, "rows")
    s.arrow(912, 420, 1050, 440, "HTML + JSON")
    s.arrow(1110, 668, 1110, 634)
    s.arrow(1058, 566, 922, 572, "tagged records")
    s.arrow(922, 592, 1060, 600, "disk URLs to compare")
    s.arrow(1050, 460, 912, 440, "search, filter")
    s.save("fig2-dataflow.svg")


def sequence():
    s = Svg(1240, 640, "Figure 3. Sequence of one case run (python -m bft quick)")
    actors = [("Investigator", 90), ("CLI", 270), ("locate", 420), ("acquire", 570), ("pipeline", 720), ("parsers", 870), ("server", 1020), ("Browser UI", 1160)]
    for name, x in actors:
        s.box(x - 60, 50, 120, 36, [name], fill="#eef")
        s.vline(x, 86, 610)
    steps = [
        (90, 270, 120, "quick --out evidence/case1"),
        (270, 420, 150, "find_profiles()"),
        (420, 270, 180, "Chrome, Firefox profiles", True),
        (270, 570, 215, "acquire(profiles, out)"),
        (570, 570, 245, "copy files, sha256, custody.json", None),
        (570, 270, 280, "custody", True),
        (270, 720, 315, "parse_evidence(out)"),
        (720, 870, 345, "parse_profile() per browser"),
        (870, 870, 375, "SQL on working copy, carve free space, UTC", None),
        (870, 720, 410, "Record list", True),
        (720, 720, 440, "records.json, verify()", None),
        (720, 270, 475, "total, integrity", True),
        (270, 1020, 510, "serve(out, port)"),
        (1020, 1160, 540, "open http://127.0.0.1:8765"),
        (1160, 1020, 570, "GET /api/records", True),
        (1020, 1160, 600, "JSON records", True),
    ]
    for st in steps:
        x1, x2, y, label = st[0], st[1], st[2], st[3]
        kind = st[4] if len(st) > 4 else False
        if kind is None:
            s.path_arrow([(x1, y), (x1 + 40, y), (x1 + 40, y + 18), (x1 + 2, y + 18)], label, (x1 + 150, y + 12))
        else:
            s.arrow(x1, y, x2, y, label, dashed=bool(kind))
    s.save("fig3-sequence.svg")


def schema():
    s = Svg(1240, 690, "Figure 4. Artifact sources mapped to the common record schema")
    left = [
        ("Chrome History", ["visits + urls", "keyword_search_terms", "downloads + url_chains"], "#fff7e6"),
        ("Chrome Bookmarks", ["roots.*.children (JSON)"], "#fff7e6"),
        ("Chrome Cookies", ["cookies (value encrypted)"], "#fff7e6"),
        ("Chrome Cache", ["Simple Cache *_0 headers"], "#fff7e6"),
        ("Firefox places.sqlite", ["moz_historyvisits + moz_places", "moz_bookmarks", "moz_annos downloads/*"], "#fff0f0"),
        ("Firefox cookies.sqlite", ["moz_cookies (plaintext)"], "#fff0f0"),
        ("Firefox formhistory.sqlite", ["moz_formhistory"], "#fff0f0"),
        ("Firefox cache2", ["entries/* metadata"], "#fff0f0"),
        ("Free space of History / places.sqlite", ["freelist, freeblocks, slack, WAL, journal"], "#fdecea"),
        ("Memory capture", ["private page records, cached history pages"], "#fff1e0"),
    ]
    y = 60
    for title, lines, fill in left:
        h = 22 + 16 * len(lines)
        s.box(40, y, 300, h, [title] + lines, fill=fill, size=12)
        s.arrow(340, y + h / 2, 470, 300)
        y += h + 10
    s.box(470, 170, 300, 340, [
        "Record", "",
        "browser: chrome | firefox",
        "artifact_type: history | search | bookmark |",
        "  cookie | download | form | cache |",
        "  deleted_history | deleted_search |",
        "  private_history | private_search",
        "url: str", "title: str",
        "timestamp_utc: YYYY-MM-DDTHH:MM:SSZ",
        "raw_timestamp: int (as stored)",
        "timestamp_source: column and unit",
        "source_file: path inside evidence",
        "extra: dict (tag, tag_source, flags...)",
    ], fill="#e8f0fe", size=12)
    s.box(880, 90, 300, 60, ["records.json", "sorted by time, with counts"], fill="#eef5ee")
    s.box(880, 200, 300, 60, ["Web UI", "search, filter, timeline, detail"], fill="#eef5ee")
    s.box(880, 310, 300, 60, ["CSV / JSON export", "extra flattened as JSON text"], fill="#eef5ee")
    s.box(880, 420, 300, 60, ["Unit tests", "synthetic profiles, expected records"], fill="#eef5ee")
    for yy in (120, 230, 340, 450):
        s.arrow(770, 300, 880, yy)
    s.text(620, 650, "Timestamps: Chrome = microseconds since 1601-01-01; Firefox = microseconds since 1970-01-01;", 12, "middle")
    s.text(620, 668, "cookie expiry in seconds, download end in milliseconds, cache2 header in seconds. All converted to UTC.", 12, "middle")
    s.save("fig4-schema.svg")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    architecture()
    dataflow()
    sequence()
    schema()
    print("wrote 4 diagrams to", OUT)
