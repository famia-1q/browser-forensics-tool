# Browser Forensics Tool (bft)

Extracts, hashes, parses and displays forensic artifacts from Google Chrome and Mozilla Firefox profiles: history, searches, bookmarks, cookies, downloads, form history and cache entries. It carves the history databases' free space, WAL and journal to recover deleted history entries and search terms, and scans memory captures (such as a VMware snapshot) for pages opened in Firefox private windows and for deleted history still in RAM. The tool itself uses only the Python standard library and runs on macOS, Windows and Linux with Python 3.9 or newer.

## Open the tool

- **Windows, no Python needed:** `BrowserForensics.exe`, built by GitHub Actions (see [WINDOWS.md](WINDOWS.md)).
- **Setting it up on Windows with an AI assistant:** paste the prompt in [WINDOWS-AI-PROMPT.md](WINDOWS-AI-PROMPT.md) into Claude or ChatGPT.
- **From this folder:** double-click `start.command` (macOS, or `./start.command` on Kali) or `start.bat` (Windows).
- **VS Code:** open the folder and press F5 (Python extension) or Ctrl+Shift+B.

The tool opens on a home screen with three buttons: **Capture the browser** (copy, hash and parse the Chrome and Firefox profiles on this computer, with a reminder not to close the browser first), **Memory snapshot** (steps for taking a VMware snapshot, the snapshots found on this computer with a Scan button, and a drop area for a memory file), and **Open demo case** (a fictional case, no real browsing). It opens in its own window when `pywebview` is installed, as it is inside the `.exe`, and in the default browser otherwise. Cases are saved in `evidence/` next to the tool, or in `Documents/Browser Forensics/evidence` for the `.exe`.

## Run

    python3 -m bft app
    python3 -m bft detect
    python3 -m bft quick --out evidence/case1

On Windows use `py -m bft ...` or `python -m bft ...`. The `quick` command detects local profiles, copies the files into `evidence/case1`, hashes them, parses them and opens the web UI at http://127.0.0.1:8765/.

Step by step:

    python3 -m bft acquire --out evidence/case1 --case "Case 1"
    python3 -m bft parse evidence/case1
    python3 -m bft verify evidence/case1
    python3 -m bft export evidence/case1 --csv case1.csv --type history
    python3 -m bft serve evidence/case1

Scan a memory capture (a VMware `.vmem`, a WinPmem, AVML or LiME image, or a process dump) and compare it with the disk evidence:

    python3 -m bft memscan /path/to/capture.raw --evidence evidence/case1

Pages opened in a Firefox private window are tagged `private`, from the page record Firefox keeps in RAM. History rows in RAM whose URL is missing from the acquired live history are tagged `deleted`, like rows the carver recovers from disk. Hovering over a tag shows where the evidence came from. Other URL strings in the capture are not shown; they are kept in `memory/<image>.json` as an audit list. The tool analyses captures; it does not take them.

Acquire from a copied profile folder (the normal forensic workflow, and the way to demo without exposing your own browsing):

    python3 -m bft acquire --out evidence/demo --browser chrome --profile /path/to/Default --cache /path/to/Cache_Data
    python3 -m bft acquire --out evidence/demo --browser firefox --profile /path/to/xxxx.default-release

Close the browser before acquiring a live profile on Windows, otherwise Chrome holds `History` locked and the file is reported as skipped.

Tests:

    python3 -m unittest -v

## How it works

1. `acquire` copies the artifact files from the profile into an evidence folder and writes `custody.json`: SHA-256, size, source path and modification time of every file, plus host, user, OS and acquisition time.
2. `parse` copies each evidence file to a temporary working copy, opens that copy with SQLite, converts every timestamp to UTC, normalises everything into one record shape and writes `records.json`. It then recomputes the hashes of the evidence files and writes `verify.json`. The evidence files are never opened for writing.
3. `serve` runs a local HTTP server bound to 127.0.0.1 and shows the records with full-text search, browser and type filters, date range, sortable columns, a per-day timeline, a per-record detail panel, CSV/JSON export of the filtered set and a hash re-verification button.

Record shape: `browser, artifact_type, url, title, timestamp_utc, raw_timestamp, timestamp_source, source_file, extra`.

## Artifact sources

| Artifact | Chrome | Firefox |
|---|---|---|
| history | `History`: `visits` joined to `urls` | `places.sqlite`: `moz_historyvisits` joined to `moz_places` |
| search | `History`: `keyword_search_terms` | (searches appear as history URLs; `formhistory.sqlite` holds typed form values) |
| bookmark | `Bookmarks` JSON, folder path kept | `places.sqlite`: `moz_bookmarks` type 1 |
| cookie | `Network/Cookies` or `Cookies`; values are OS-encrypted, metadata only | `cookies.sqlite`: `moz_cookies`, values in plaintext |
| download | `History`: `downloads` + `downloads_url_chains` | `places.sqlite`: `moz_annos` `downloads/*` annotations |
| form | not collected | `formhistory.sqlite` |
| cache | Simple Cache `*_0` entry headers (URL key, size, mtime) | `cache2/entries` metadata (URL key, last modified, fetch count, response status) |

Timestamps: Chrome stores microseconds since 1601-01-01 UTC. Firefox stores microseconds since 1970-01-01 UTC, except cookie expiry (seconds), download end time (milliseconds) and cache2 headers (seconds). Every record carries the raw value and a `timestamp_source` naming the column and unit.

Default profile locations:

| | Chrome | Firefox |
|---|---|---|
| macOS | `~/Library/Application Support/Google/Chrome/Default` (cache under `~/Library/Caches/Google/Chrome/Default/Cache/Cache_Data`) | `~/Library/Application Support/Firefox/Profiles/<id>` (cache under `~/Library/Caches/Firefox/Profiles/<id>/cache2`) |
| Windows | `%LOCALAPPDATA%\Google\Chrome\User Data\Default` | `%APPDATA%\Mozilla\Firefox\Profiles\<id>` (cache under `%LOCALAPPDATA%\Mozilla\Firefox\Profiles\<id>\cache2`) |
| Linux / Kali | `~/.config/google-chrome/Default` or `~/.config/chromium/Default` | `~/.mozilla/firefox/<id>` (cache under `~/.cache/mozilla/firefox/<id>/cache2`) |

## Limitations

- Chrome cookie values are encrypted with the OS keystore (DPAPI on Windows, Keychain on macOS). The tool reports host, name, path, flags and timestamps and marks the value as encrypted. It does not decrypt.
- Cache parsing reads entry headers and metadata, not the cached content. Chrome's older blockfile cache format (`data_0` to `data_3`) is not parsed.
- Deleted-record recovery is opportunistic. Chrome on macOS zeroes freed database space (secure delete), so recovery there is rare; Firefox's WAL often still holds deleted rows. Rows lost to page rebalancing or WAL checkpoints cannot be recovered. Index entries give the URL but no time.
- Private and incognito sessions are kept in memory and never written to the profile. They can only be found in a memory capture taken while the machine is still on. The `private` tag relies on a Firefox page record identified from one real capture (Firefox on Kali ARM); Chrome incognito pages are never tagged. Private pages have no timestamp. `deleted` from memory needs the browser profile acquired into the same evidence folder.
- Session restore files, saved logins and autofill are copied for completeness but not parsed.
- Acquisition from a running browser depends on the OS allowing the copy. On Windows, close Chrome first.

## Documents

- `docs/01-planning.md`: problem statement, objectives, requirements, work split, timeline, risks
- `docs/02-architecture.md`: design principles, diagrams, record schema, module ownership
- `docs/03-report.md` and `docs/report.docx`: the project report with code, output and interface screenshots
- `tools/draw_diagrams.py` regenerates the SVG diagrams in `docs/diagrams/`
- `tools/make_demo_evidence.py` builds the fictional demo profiles used in the report

## Layout

    bft/
      __main__.py    command line interface
      models.py      Record and Profile dataclasses
      timestamps.py  epoch converters
      locate.py      default profile paths per OS
      acquire.py     copy, hash, custody log, verify
      sqlite_ro.py   temporary working copy of a SQLite file
      chrome.py      Chrome parsers
      firefox.py     Firefox parsers
      carve.py       deleted-record recovery from free space, WAL and journal
      memscan.py     browser artifacts in memory captures
      pipeline.py    evidence folder to records.json
      export.py      CSV and JSON writers
      web/           HTTP server and the single-page UI
    tests/           synthetic profiles and unit tests
    tools/           diagram generator, demo evidence generator
    start.command    one-click start (macOS, Linux); start.bat for Windows
    .vscode/         Run and Debug configuration and tasks
    packaging/       PyInstaller entry point and build script for the app and the .exe
    .github/         workflow that runs the tests on Windows and builds BrowserForensics.exe
    docs/            planning, architecture, report, diagrams, screenshots
