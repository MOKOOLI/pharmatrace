"""Security regression suite: each test maps to an OWASP API Top 10 risk."""
import unittest
from typing import ClassVar

from pharmatrace.core.security import AuthError, Role, TokenSigner
from tests.helpers import GTIN, claims, seeded, signer


class TestBrokenObjectLevelAuth(unittest.TestCase):  # API1:2023 BOLA / IDOR
    def test_cannot_transfer_unit_you_do_not_hold(self):
        svc, _, _, uids = seeded()
        attacker = claims(Role.DISTRIBUTOR, "EVIL")
        with self.assertRaises(AuthError):
            svc.transfer(attacker, uids[0], "EVIL")

    def test_competitor_cannot_mint_units_for_foreign_gtin(self):
        svc, *_ = seeded()
        rival = claims(Role.MANUFACTURER, "RIVAL")
        with self.assertRaises(AuthError):
            svc.create_units(rival, GTIN, "X", "2099-01-01", 1)


class TestBrokenFunctionLevelAuth(unittest.TestCase):  # API5:2023
    def test_pharmacy_cannot_approve_drugs(self):
        svc, *_ = seeded()
        with self.assertRaises(AuthError):
            svc.approve_drug(claims(Role.PHARMACY, "P"), GTIN)

    def test_manufacturer_cannot_read_audit(self):
        svc, _, mfr, uids = seeded()
        with self.assertRaises(AuthError):
            svc.history(mfr, uids[0])


class TestBrokenAuthentication(unittest.TestCase):  # API2:2023
    def test_tampered_token_rejected(self):
        tok = signer.issue("u", Role.PHARMACY, "P")
        body, sig = tok.split(".")
        import base64
        import json
        payload = json.loads(base64.urlsafe_b64decode(body + "=="))
        payload["role"] = "regulator"  # privilege escalation attempt
        forged = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        with self.assertRaises(AuthError):
            signer.verify(f"{forged}.{sig}")

    def test_wrong_key_rejected(self):
        tok = TokenSigner("other-key").issue("u", Role.REGULATOR, "X")
        with self.assertRaises(AuthError):
            signer.verify(tok)

    def test_expired_token_rejected(self):
        tok = TokenSigner("test-secret", ttl_seconds=-1).issue("u", Role.REGULATOR, "X")
        with self.assertRaises(AuthError):
            signer.verify(tok)

    def test_garbage_token(self):
        for t in ["", "a", "a.b.c", None]:
            with self.assertRaises(AuthError):
                signer.verify(t)


class TestInjection(unittest.TestCase):  # SQL injection via public endpoint
    PAYLOADS: ClassVar[list[str]] = ["' OR '1'='1", "x'; DROP TABLE units;--", "\" OR 1=1 --", "%' UNION SELECT * FROM ledger--"]

    def test_sqli_payloads_are_inert(self):
        svc, _, _, uids = seeded()
        for p in self.PAYLOADS:
            self.assertFalse(svc.verify_unit(p).authentic)
        self.assertTrue(svc.verify_unit(uids[0]).authentic)  # tables intact
        self.assertTrue(svc.ledger.verify().ok)


class TestLedgerTamperEvidence(unittest.TestCase):  # integrity / repudiation
    def test_modified_row_detected(self):
        svc, *_ = seeded()
        svc.conn.execute("UPDATE ledger SET payload = '{\"lot\":\"FORGED\"}' WHERE seq = 3")
        r = svc.ledger.verify()
        self.assertFalse(r.ok)
        self.assertEqual(r.broken_at, 3)

    def test_deleted_row_detected(self):
        svc, *_ = seeded()
        svc.conn.execute("DELETE FROM ledger WHERE seq = 2")
        self.assertFalse(svc.ledger.verify().ok)

    def test_untouched_ledger_ok(self):
        svc, *_ = seeded()
        self.assertTrue(svc.ledger.verify().ok)


if __name__ == "__main__":
    unittest.main()
