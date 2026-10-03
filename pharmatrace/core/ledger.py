"""Append-only, hash-chained audit ledger.

Each event stores sha256(prev_hash || canonical_json(event)). Any edit, deletion
or reordering of a past row breaks the chain and is detected by `verify()`.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass

GENESIS = "0" * 64


def _canonical(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checked: int
    broken_at: int | None = None
    reason: str | None = None


class Ledger:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS ledger (
                   seq INTEGER PRIMARY KEY AUTOINCREMENT,
                   ts REAL NOT NULL,
                   actor TEXT NOT NULL,
                   action TEXT NOT NULL,
                   subject TEXT NOT NULL,
                   payload TEXT NOT NULL,
                   prev_hash TEXT NOT NULL,
                   hash TEXT NOT NULL UNIQUE)"""
        )

    def _last_hash(self) -> str:
        row = self.conn.execute("SELECT hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    @staticmethod
    def _digest(prev_hash: str, ts: float, actor: str, action: str, subject: str, payload: str) -> str:
        material = _canonical({"prev": prev_hash, "ts": repr(ts), "actor": actor,
                               "action": action, "subject": subject, "payload": payload})
        return hashlib.sha256(material.encode()).hexdigest()

    def append(self, actor: str, action: str, subject: str, payload: dict | None = None,
               ts: float | None = None) -> str:
        ts = time.time() if ts is None else ts
        body = _canonical(payload or {})
        prev = self._last_hash()
        h = self._digest(prev, ts, actor, action, subject, body)
        self.conn.execute(
            "INSERT INTO ledger (ts, actor, action, subject, payload, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
            (ts, actor, action, subject, body, prev, h),
        )
        return h

    def history(self, subject: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT seq, ts, actor, action, payload, hash FROM ledger WHERE subject = ? ORDER BY seq",
            (subject,),
        ).fetchall()
        return [{"seq": s, "ts": ts, "actor": a, "action": act, "payload": json.loads(p), "hash": h}
                for s, ts, a, act, p, h in rows]

    def verify(self) -> VerifyResult:
        prev = GENESIS
        n = 0
        for seq, ts, actor, action, subject, payload, prev_hash, h in self.conn.execute(
            "SELECT seq, ts, actor, action, subject, payload, prev_hash, hash FROM ledger ORDER BY seq"
        ):
            n += 1
            if prev_hash != prev:
                return VerifyResult(False, n, seq, "prev_hash mismatch (row deleted or reordered)")
            if self._digest(prev_hash, ts, actor, action, subject, payload) != h:
                return VerifyResult(False, n, seq, "content hash mismatch (row modified)")
            prev = h
        return VerifyResult(True, n)
