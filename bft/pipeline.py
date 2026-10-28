from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

from . import carve, chrome, firefox
from .acquire import load_custody, verify
from .models import Record
from .timestamps import now_utc

RECORDS = "records.json"


def parse_evidence(evidence: Path) -> Dict:
    evidence = Path(evidence)
    custody = load_custody(evidence)
    records: List[Record] = []
    for browser, mod in (("chrome", chrome), ("firefox", firefox)):
        broot = evidence / browser
        if not broot.is_dir():
            continue
        for prof in sorted(broot.iterdir()):
            if not prof.is_dir():
                continue
            cache = prof / "_cache"
            records.extend(mod.parse_profile(prof, cache if cache.is_dir() else None, evidence))
            records.extend(carve.carve_profile(browser, prof, evidence))
    disk = [r.to_dict() for r in records]
    result = _bundle(disk + memory_rows(evidence, disk), custody.get("case", evidence.name), str(evidence))
    result["verify"] = verify(evidence)
    with open(evidence / RECORDS, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    return result


def parse_live_profile(browser: str, profile_dir: Path, cache_dir: Optional[Path]) -> Dict:
    mod = chrome if browser == "chrome" else firefox
    records = mod.parse_profile(Path(profile_dir), Path(cache_dir) if cache_dir else None, None)
    records.extend(carve.carve_profile(browser, Path(profile_dir), None))
    return _bundle(records, profile_dir.name, str(profile_dir))


def memory_rows(evidence: Path, disk: List[Dict]) -> List[Dict]:
    from .memscan import MEMORY_DIR, build_records, live_urls
    rows: List[Dict] = []
    mdir = Path(evidence) / MEMORY_DIR
    if mdir.is_dir():
        known = live_urls(disk)
        for p in sorted(mdir.glob("*.json")):
            with open(p, encoding="utf-8") as f:
                rows.extend(r.to_dict() for r in build_records(json.load(f), known))
    return rows


def _from_memory(r: Dict) -> bool:
    return r["artifact_type"].startswith("memory_") or "memory_offset" in (r.get("extra") or {})


def merge_memory(evidence: Path) -> Dict:
    evidence = Path(evidence)
    if (evidence / RECORDS).is_file():
        current = load_records(evidence)
        disk = [r for r in current["records"] if not _from_memory(r)]
        case, verify_result = current.get("case", evidence.name), current.get("verify")
    else:
        disk, verify_result = [], None
        case = load_custody(evidence).get("case", evidence.name) if (evidence / "custody.json").is_file() else evidence.name
    result = _bundle(disk + memory_rows(evidence, disk), case, str(evidence))
    if verify_result is not None:
        result["verify"] = verify_result
    with open(evidence / RECORDS, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    return result


def _bundle(records: list, case: str, source: str) -> Dict:
    rows = [r.to_dict() if isinstance(r, Record) else r for r in records]
    rows.sort(key=lambda r: (r["timestamp_utc"] or "", r["browser"], r["artifact_type"]))
    counts = Counter()
    for r in rows:
        counts[r["browser"] + ":" + r["artifact_type"]] += 1
    return {
        "case": case,
        "source": source,
        "generated_at_utc": now_utc(),
        "total": len(rows),
        "counts": dict(sorted(counts.items())),
        "records": rows,
    }


def load_records(evidence: Path) -> Dict:
    with open(Path(evidence) / RECORDS, encoding="utf-8") as f:
        return json.load(f)
