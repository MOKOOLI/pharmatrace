import unittest

from pharmatrace.core.identifiers import gtin_check_digit, is_valid_gtin
from pharmatrace.core.security import Role, hash_password, verify_password
from pharmatrace.core.service import DomainError
from tests.helpers import GTIN, claims, seeded


class TestIdentifiers(unittest.TestCase):
    def test_gtin(self):
        self.assertTrue(is_valid_gtin(GTIN))
        self.assertFalse(is_valid_gtin("05012345678901"))
        self.assertEqual(gtin_check_digit("501234567890"), 0)


class TestPasswords(unittest.TestCase):
    def test_roundtrip(self):
        h = hash_password("correct horse battery", iterations=1000)
        self.assertTrue(verify_password("correct horse battery", h))
        self.assertFalse(verify_password("wrong password!", h))

    def test_min_length(self):
        with self.assertRaises(ValueError):
            hash_password("short")


class TestLifecycle(unittest.TestCase):
    def test_full_chain_of_custody(self):
        svc, reg, mfr, uids = seeded()
        dist = claims(Role.DISTRIBUTOR, "DIST", "d")
        pharm = claims(Role.PHARMACY, "PHARM", "p")
        uid = uids[0]
        svc.transfer(mfr, uid, "DIST")
        svc.transfer(dist, uid, "PHARM")
        svc.dispense(pharm, uid)
        actions = [e["action"] for e in svc.history(reg, uid)]
        self.assertEqual(actions, ["unit.create", "unit.transfer", "unit.transfer", "unit.dispense"])
        self.assertTrue(svc.ledger.verify().ok)

    def test_public_verify(self):
        svc, *_ , uids = seeded()
        self.assertTrue(svc.verify_unit(uids[0]).authentic)
        fake = svc.verify_unit("01" + GTIN + "21FAKESERIAL")
        self.assertFalse(fake.authentic)
        self.assertIn("counterfeit", fake.warning)

    def test_double_dispense_warns(self):
        svc, _, mfr, uids = seeded()
        svc.transfer(mfr, uids[0], "PHARM")
        pharm = claims(Role.PHARMACY, "PHARM")
        svc.dispense(pharm, uids[0])
        with self.assertRaises(DomainError):
            svc.dispense(pharm, uids[0])
        self.assertIn("already dispensed", svc.verify_unit(uids[0]).warning)

    def test_unapproved_drug_blocks_units(self):
        svc, _, mfr, _ = seeded()
        svc.register_drug(mfr, "96385074", "Test")
        with self.assertRaises(DomainError):
            svc.create_units(mfr, "96385074", "L", "2099-01-01", 1)


if __name__ == "__main__":
    unittest.main()
