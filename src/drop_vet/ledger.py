"""The ledger is the single log: one metadata row per file, never content."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

SCHEMA = (
    "create table if not exists items (id integer primary key, batch text, name text, sha256 text,"
    " size integer, mime text, verdict text, tier text, category text, reasons text, secrets text,"
    " pii text, dest text, received_at text, decided_at text, sigs_at text)"
)
COLS = (
    "id",
    "batch",
    "name",
    "size",
    "mime",
    "verdict",
    "tier",
    "category",
    "reasons",
    "secrets",
    "pii",
    "received_at",
    "decided_at",
    "sigs_at",
)


def connect(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.execute(SCHEMA)
    return con


def read_only(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def insert(con: sqlite3.Connection, row: dict) -> None:
    con.execute(
        "insert into items (batch, name, sha256, size, mime, verdict, tier, category, reasons, secrets, pii,"
        " dest, received_at, decided_at, sigs_at) values (:batch, :name, :sha256, :size, :mime, :verdict,"
        " :tier, :category, :reasons, :secrets, :pii, :dest, :received_at, :decided_at, :sigs_at)",
        {**row, **{k: json.dumps(row.get(k) or []) for k in ("reasons", "secrets", "pii")}},
    )
    con.commit()


def recent(con: sqlite3.Connection, limit: int = 2000) -> list[dict]:
    rows = []
    for r in con.execute(f"select {', '.join(COLS)}, dest from items order by id desc limit ?", (limit,)):
        row = dict(zip(COLS, r[:-1], strict=True))
        row["dest"] = r[-1]
        for k in ("reasons", "secrets", "pii"):
            row[k] = json.loads(row[k] or "[]")
        rows.append(row)
    return rows


def get(con: sqlite3.Connection, item_id: int) -> dict | None:
    r = con.execute("select name, sha256, verdict, tier, dest from items where id = ?", (item_id,)).fetchone()
    return dict(zip(("name", "sha256", "verdict", "tier", "dest"), r, strict=True)) if r else None
