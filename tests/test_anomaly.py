import unittest

import pandas as pd

from pharmatrace.analytics.anomaly import model_scores, rule_flags, unknown_clusters
from scripts.generate_synthetic_data import generate


class TestRules(unittest.TestCase):
    def test_impossible_travel(self):
        df = pd.DataFrame([("A", 0, 35.69, 51.39), ("A", 1800, 36.30, 59.60)], columns=["uid", "ts", "lat", "lon"])
        self.assertIn("impossible_travel", set(rule_flags(df).rule))

    def test_normal_travel_not_flagged(self):
        df = pd.DataFrame([("A", 0, 35.69, 51.39), ("A", 86400, 32.65, 51.67)], columns=["uid", "ts", "lat", "lon"])
        self.assertTrue(rule_flags(df).empty)

    def test_burst(self):
        df = pd.DataFrame([("B", i * 60, 35.7, 51.4) for i in range(10)], columns=["uid", "ts", "lat", "lon"])
        self.assertIn("scan_burst", set(rule_flags(df).rule))


class TestOnSynthetic(unittest.TestCase):
    def test_recall_on_injected_fraud(self):
        scans, labels = generate(800, seed=1)
        known = set(labels.uid)
        k = scans[scans.uid.isin(known)]
        flagged = set(rule_flags(k).uid) | set(model_scores(k).query("is_anomaly").index)
        truth = set(labels[labels.label != "normal"].uid)
        self.assertGreaterEqual(len(flagged & truth) / len(truth), 0.8)

    def test_counterfeit_cluster_found(self):
        scans, labels = generate(300, seed=2)
        c = unknown_clusters(scans, set(labels.uid))
        self.assertFalse(c.empty)


if __name__ == "__main__":
    unittest.main()
