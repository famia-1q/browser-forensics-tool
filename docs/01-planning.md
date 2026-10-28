# Web Browser Forensics Tool: Project Plan

Course: Digital Forensics (midterm project)
Team: Ayesha Zulfiqar, [teammate name]
Date: 28 October 2026

## 1. Problem statement

Web browsers keep a detailed record of what a user did online: pages visited, searches typed, bookmarks saved, cookies set, files downloaded and content cached. Investigators need this data in a readable form, but the browsers store it in internal SQLite databases, JSON files and binary cache formats with their own timestamp conventions. The task is to build a tool that extracts these artifacts from Google Chrome and Mozilla Firefox and presents them in a structured, searchable interface without altering the original evidence.

## 2. Objectives

1. Identify where Chrome and Firefox store history, bookmarks, cookies, downloads and cache on Windows, macOS and Linux.
2. Copy those files into an evidence folder and record SHA-256 hashes so integrity can be proven later.
3. Parse each artifact type into one common record format with timestamps converted to UTC.
4. Display the records in a user interface with search, filtering by browser, type and date, sorting and a timeline view.
5. Export the results to CSV and JSON for use in a report.
6. Run on both team members' machines (macOS and Windows) and on Kali Linux without installing extra packages.

## 3. Scope

In scope: Chrome and Firefox desktop profiles; history, search terms, bookmarks, cookies, downloads, form history (Firefox), cache entry metadata; acquisition from a live profile folder or from a copied profile folder; local web interface; CSV and JSON export; unit tests with synthetic data.

Out of scope: decrypting Chrome cookie values; parsing cached file contents; acquiring RAM itself (done with a capture tool or a VM snapshot); mobile browsers; Safari and Edge (Edge uses the same format as Chrome and could be added later).

## 4. Requirements

Functional:

| ID | Requirement |
|---|---|
| FR1 | Detect installed Chrome and Firefox profiles for the current user on Windows, macOS and Linux. |
| FR2 | Accept a profile folder path so the tool can run against an acquired copy. |
| FR3 | Copy artifact files to an evidence folder and write a custody log with SHA-256, size, source path and acquisition time. |
| FR4 | Parse history, searches, bookmarks, cookies, downloads, form history and cache entries. |
| FR5 | Convert every timestamp to UTC and keep the raw value and its source column. |
| FR6 | Re-verify evidence hashes after parsing and report pass or fail. |
| FR7 | Show records in a table with free-text search, browser filter, type filter, date range and sortable columns. |
| FR8 | Show a chronological timeline grouped by day. |
| FR9 | Show the full detail of a selected record. |
| FR10 | Export the current filtered set to CSV and JSON. |
| FR11 | Recover deleted history entries and search terms from SQLite free space, WAL frames and rollback journals, and label each with where it was found. (Added in the scope change below.) |
| FR12 | Scan a memory capture for pages opened in Firefox private windows and for deleted history rows still in RAM. Tag the first `private` and the second `deleted`, keep only visited pages, and show the evidence behind each tag. (Added in the second scope change and narrowed in the third.) |

Non-functional:

| ID | Requirement |
|---|---|
| NFR1 | Never open an evidence file for writing. Parsing works on a temporary copy. |
| NFR2 | Python 3.9 or newer, standard library only, so the tool runs on any machine with Python. |
| NFR3 | The web interface binds to 127.0.0.1 only. |
| NFR4 | A profile with 50,000 records loads in the interface in under five seconds. |
| NFR5 | All parsers are covered by unit tests that run with `python -m unittest`. |

## 5. Approach

Incremental build, one layer at a time, each layer tested before the next starts:

1. Planning: this document, requirements, work split.
2. Design: architecture, data flow, record schema, sequence of a run (see `02-architecture.md`).
3. Core: record model, timestamp converters, profile locator, acquisition with hashing, SQLite working copy.
4. Parsers: Chrome, then Firefox, each against a synthetic test profile.
5. Pipeline and CLI: evidence folder to `records.json`, export, verify.
6. Interface: local HTTP server and single-page UI.
7. Testing: unit tests, run on a real profile, cross-platform check on both laptops and Kali.
8. Report: screenshots, results, limitations.

## 6. Work breakdown and ownership

| # | Task | Owner | Depends on |
|---|---|---|---|
| 1 | Planning document and requirements | both | |
| 2 | Architecture and data flow diagrams | Ayesha | 1 |
| 3 | Record schema and timestamp converters | Ayesha | 2 |
| 4 | Profile locator (three OSes) | Ayesha | 2 |
| 5 | Acquisition and custody log | Ayesha | 3 |
| 6 | Chrome parsers (history, bookmarks, cookies, downloads, cache) | Ayesha | 3, 5 |
| 7 | Firefox parsers (places, cookies, form history, downloads, cache2) | teammate | 3, 5 |
| 8 | Pipeline, CLI, export, verify | Ayesha | 5, 6, 7 |
| 9 | Web interface | teammate | 8 |
| 10 | Synthetic test profiles and unit tests | both | 6, 7 |
| 11 | Demo evidence set (fictional scenario) | teammate | 10 |
| 12 | Windows and Kali test run | teammate | 8, 9 |
| 13 | macOS test run, validation against Hindsight and dumpzilla | Ayesha | 8, 9 |
| 14 | Report and presentation | both | 12, 13 |

## 7. Timeline

| Day | Milestone |
|---|---|
| 1 | Plan agreed, diagrams drawn, repository created, schema fixed in code |
| 2 | Core and acquisition working, hashes verified on a real profile |
| 3 | Chrome and Firefox parsers passing unit tests |
| 4 | CLI, export and web interface showing real records |
| 5 | Cache parsing, timeline, demo evidence set |
| 6 | Cross-platform runs, validation against existing tools, bug fixes |
| 7 | Report, screenshots, dry run of the demo on both laptops |

## 8. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Browser locks its database while running (Windows) | Acquisition fails | Close the browser, or acquire from a copied profile folder; the tool reports locked files instead of crashing |
| Cache formats are binary and undocumented | Time sink | Parse entry headers only (URL, size, time); accept partial coverage |
| Chrome cookie values are encrypted | Incomplete data | Show metadata, document the limitation |
| Different Python versions on the two laptops | Code breaks on one | Target Python 3.9 syntax, no third-party packages |
| Demo uses personal browsing data | Privacy, unpredictable | Demo from a synthetic evidence set generated by a script |
| Two people editing the same file | Lost work | Separate modules per owner, Git branches, merge through pull requests |

## 9. Tools

Python 3 (standard library: sqlite3, hashlib, json, struct, http.server), Git and GitHub, VMware with Kali Linux for Linux testing and for validation tools (Hindsight, dumpzilla), draw.io for diagrams, Microsoft Word for the report.

## 10. Scope change

After the first working version, review of the requirements against the course material showed that a forensics tool which reads only live records misses the most important case: a user who has deleted their history. Deleted-record recovery was moved into scope as FR11. Plan impact:

| Task | Owner | Depends on |
|---|---|---|
| Measure what a real Chrome profile leaves in free space | Ayesha | 8 |
| SQLite carver (free pages, freeblocks, unallocated space, WAL, journal) | Ayesha | 3 |
| Carving tests (deleted rows, secure delete, WAL, superseded pages) | both | carver |
| Demo scenario extended: suspect clears history | teammate | carver |
| Report sections on deleted-record recovery | both | all above |

Private and incognito browsing stayed out of scope at this point, because browsers keep those sessions in memory only.

### Second scope change: memory as a browser artifact source

Private sessions, and recently deleted history while the browser is still running, exist only in RAM. A memory scanner limited to browser artifacts (URLs, search terms, cached history pages) keeps the project a browser forensics tool while covering that gap. It was added as FR12. Acquiring RAM is not part of the tool: in the lab a VMware snapshot of the suspect VM provides the image, and in the field a capture tool such as WinPmem, AVML or LiME would.

| Task | Owner | Depends on |
|---|---|---|
| Memory scanner: ASCII and UTF-16 URLs, noise filter, cached history rows, comparison with disk evidence | Ayesha | carver |
| Memory scanner tests on synthetic captures | both | scanner |
| Demo: private session captured in a memory image | teammate | scanner |
| Real capture from the Kali VM with a private window open; compare against bulk_extractor | both | scanner |
| Report: memory states, order of volatility, results, limits | both | all above |

### Third scope change: tags instead of memory labels

The first version of FR12 labelled every URL found in memory (in disk history, in deleted history, in disk cache only, memory only). The real capture from the Kali VM showed three problems. It produced 11,868 URLs, most of them links, scripts, images and settings that were never visited. "Memory only" was written even when no profile had been acquired, so it claimed a disk check that never happened. And a bare URL in memory cannot show whether it came from a private window. The labels were replaced with two tags that are added only on positive evidence:

| Tag | Added when | Evidence shown on hover |
|---|---|---|
| `private` | Firefox's private-window page record (origin attribute `privateBrowsingId=1`, then the site, then the full page address, each with its length) holds the URL | the memory capture and byte offset, and the number of copies |
| `deleted` | the carver recovers the row from the history database's free space, WAL or journal, or a history row in RAM holds a URL missing from the acquired live history of the same browser | the file, region and offset, or the memory capture and offset |

Every other record carries no tag and no mention of memory. Plain URL strings stay out of the records and are kept only in the scan's audit file, so another examiner can rerun the scan and check nothing was hidden.

| Task | Owner | Depends on |
|---|---|---|
| Find a private-window marker in the real capture and test that it separates pages from the resources they load | Ayesha | Kali capture |
| Rewrite the scanner around the page record and history rows; audit file for all URL strings | Ayesha | marker |
| Tag and tooltip in the interface; tag filter | teammate | scanner |
| Validate on a second capture with a written list of pages opened | both | scanner |

### Fourth change: a tool that opens without the command line

Preparing the teammate's Windows run showed that the command line was the main obstacle: every step needed a typed command, and memory captures could only be scanned from a terminal. The interface gained a home screen with three actions (capture the browser, scan a memory snapshot, open the demo case), the capture panel shows what not to do before capturing, and the snapshot page explains the VMware steps and finds the snapshots itself. The tool opens in its own window and is packaged as `BrowserForensics.exe` for Windows, built automatically by GitHub Actions, so the teammate does not need Python. The tool itself still uses only the standard library; the window package is bundled into the `.exe` only.

| Task | Owner | Depends on |
|---|---|---|
| Server: cases, background tasks, capture, snapshot discovery, request guard | Ayesha | interface |
| Interface: home, capture panel, snapshot page, drop matching | teammate | server |
| App window, packaging script, Windows build and test workflow | Ayesha | server |
| First run of the `.exe` on the teammate's Windows machine | teammate | workflow |

## 11. Deliverables

Source code with tests, planning and design documents, demo evidence set, report with screenshots, live demonstration.
