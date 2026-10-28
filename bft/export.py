from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, Iterable, List

COLUMNS = ["timestamp_utc", "browser", "artifact_type", "title", "url", "raw_timestamp", "timestamp_source", "source_file", "extra"]


def write_csv(records: Iterable[Dict], path: Path) -> int:
    n = 0
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        for r in records:
            row = {k: r.get(k) for k in COLUMNS}
            row["extra"] = json.dumps(r.get("extra", {}), ensure_ascii=False, sort_keys=True)
            w.writerow(row)
            n += 1
    return n


def write_json(records: List[Dict], path: Path) -> int:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)
    return len(records)


def filter_records(records: Iterable[Dict], browser=None, artifact_type=None, text=None) -> List[Dict]:
    out = []
    needle = text.lower() if text else None
    for r in records:
        if browser and r["browser"] != browser:
            continue
        if artifact_type and r["artifact_type"] != artifact_type:
            continue
        if needle and needle not in (r.get("url", "") + " " + r.get("title", "")).lower():
            continue
        out.append(r)
    return out
