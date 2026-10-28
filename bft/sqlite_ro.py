from __future__ import annotations

import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import List

SIDECARS = ("-wal", "-journal", "-shm")


class WorkingCopy:
    def __init__(self, source: Path):
        self.source = Path(source)
        self.tmp = Path(tempfile.mkdtemp(prefix="bft-"))
        self.path = self.tmp / self.source.name
        shutil.copy2(self.source, self.path)
        for s in SIDECARS:
            side = self.source.with_name(self.source.name + s)
            if side.is_file():
                shutil.copy2(side, self.path.with_name(self.path.name + s))
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row

    def __enter__(self) -> sqlite3.Connection:
        return self.conn

    def __exit__(self, *exc) -> None:
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


def open_copy(source) -> WorkingCopy:
    return WorkingCopy(Path(source))


def tables(conn: sqlite3.Connection) -> List[str]:
    return [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]


def columns(conn: sqlite3.Connection, table: str) -> List[str]:
    return [r[1] for r in conn.execute("PRAGMA table_info(%s)" % _q(table))]


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def select_available(conn: sqlite3.Connection, table: str, wanted: List[str]):
    have = set(columns(conn, table))
    picked = [c for c in wanted if c in have]
    return picked
