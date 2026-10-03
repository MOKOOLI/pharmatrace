"""Domain service: drugs, units, custody transfers, public verification."""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass

from .identifiers import is_valid_gtin, new_serial, unit_uid
from .ledger import Ledger
from .security import AuthError, require

SCHEMA = """
CREATE TABLE IF NOT EXISTS drugs (
    gtin TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    manufacturer_org TEXT NOT NULL,
    approved INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS units (
    uid TEXT PRIMARY KEY,
    gtin TEXT NOT NULL REFERENCES drugs(gtin),
    lot TEXT NOT NULL,
    expiry TEXT NOT NULL,
    owner_org TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT NOT NULL,
    ts REAL NOT NULL,
    lat REAL, lon REAL,
    source TEXT NOT NULL
);
"""


class DomainError(Exception):
    pass


@dataclass
class VerificationResult:
    uid: str
    authentic: bool
    status: str
    drug_name: str | None = None
    expiry: str | None = None
    warning: str | None = None


class TraceService:
    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self.ledger = Ledger(self.conn)

    # ---- drugs ---------------------------------------------------------
    def register_drug(self, claims: dict, gtin: str, name: str) -> None:
        require(claims, "drug:register")
        if not is_valid_gtin(gtin):
            raise DomainError("invalid GTIN check digit")
        try:
            self.conn.execute("INSERT INTO drugs (gtin, name, manufacturer_org) VALUES (?,?,?)",
                              (gtin, name, claims["org"]))
        except sqlite3.IntegrityError:
            raise DomainError("GTIN already registered")
        self.ledger.append(claims["sub"], "drug.register", gtin, {"name": name, "org": claims["org"]})

    def approve_drug(self, claims: dict, gtin: str) -> None:
        require(claims, "drug:approve")
        cur = self.conn.execute("UPDATE drugs SET approved = 1 WHERE gtin = ?", (gtin,))
        if cur.rowcount == 0:
            raise DomainError("unknown GTIN")
        self.ledger.append(claims["sub"], "drug.approve", gtin, {})

    # ---- units ---------------------------------------------------------
    def create_units(self, claims: dict, gtin: str, lot: str, expiry: str, count: int) -> list[str]:
        require(claims, "unit:create")
        row = self.conn.execute("SELECT manufacturer_org, approved FROM drugs WHERE gtin = ?", (gtin,)).fetchone()
        if not row:
            raise DomainError("unknown GTIN")
        if row[0] != claims["org"]:
            raise AuthError("only the owning manufacturer can create units")
        if not row[1]:
            raise DomainError("drug not approved by regulator")
        if not 1 <= count <= 10_000:
            raise DomainError("count must be between 1 and 10000")
        uids = []
        for _ in range(count):
            uid = unit_uid(gtin, new_serial())
            self.conn.execute("INSERT INTO units (uid, gtin, lot, expiry, owner_org) VALUES (?,?,?,?,?)",
                              (uid, gtin, lot, expiry, claims["org"]))
            self.ledger.append(claims["sub"], "unit.create", uid, {"lot": lot, "expiry": expiry, "org": claims["org"]})
            uids.append(uid)
        return uids

    def transfer(self, claims: dict, uid: str, to_org: str) -> None:
        require(claims, "unit:transfer")
        row = self.conn.execute("SELECT owner_org, status FROM units WHERE uid = ?", (uid,)).fetchone()
        if not row:
            raise DomainError("unknown unit")
        owner, status = row
        if owner != claims["org"]:  # IDOR protection: you can only move what you hold
            raise AuthError("caller does not hold custody of this unit")
        if status != "active":
            raise DomainError(f"unit is {status}")
        if to_org == owner:
            raise DomainError("cannot transfer to self")
        self.conn.execute("UPDATE units SET owner_org = ? WHERE uid = ?", (to_org, uid))
        self.ledger.append(claims["sub"], "unit.transfer", uid, {"from": owner, "to": to_org})

    def dispense(self, claims: dict, uid: str) -> None:
        require(claims, "unit:dispense")
        row = self.conn.execute("SELECT owner_org, status FROM units WHERE uid = ?", (uid,)).fetchone()
        if not row or row[0] != claims["org"]:
            raise AuthError("caller does not hold custody of this unit")
        if row[1] != "active":
            raise DomainError(f"unit is {row[1]}")
        self.conn.execute("UPDATE units SET status = 'dispensed' WHERE uid = ?", (uid,))
        self.ledger.append(claims["sub"], "unit.dispense", uid, {"org": claims["org"]})

    # ---- public --------------------------------------------------------
    def verify_unit(self, uid: str, lat: float | None = None, lon: float | None = None,
                    ts: float | None = None) -> VerificationResult:
        self.conn.execute("INSERT INTO scans (uid, ts, lat, lon, source) VALUES (?,?,?,?, 'public')",
                          (uid, ts or time.time(), lat, lon))
        row = self.conn.execute(
            "SELECT u.status, u.expiry, d.name FROM units u JOIN drugs d ON d.gtin = u.gtin WHERE u.uid = ?",
            (uid,),
        ).fetchone()
        if not row:
            return VerificationResult(uid, False, "unknown", warning="Serial not found: possible counterfeit")
        status, expiry, name = row
        warning = None
        if status == "dispensed":
            warning = "Unit already dispensed: if you just bought it, report to regulator"
        elif expiry < time.strftime("%Y-%m-%d"):
            warning = "Unit is expired"
        return VerificationResult(uid, True, status, name, expiry, warning)

    def history(self, claims: dict, uid: str) -> list[dict]:
        require(claims, "audit:read")
        return self.ledger.history(uid)

    def scans(self) -> list[tuple]:
        return self.conn.execute("SELECT uid, ts, lat, lon FROM scans ORDER BY ts").fetchall()
