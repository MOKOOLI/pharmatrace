"""Run rule + model detection on a scans CSV and print an evaluation report."""
from __future__ import annotations

import argparse
import json
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pharmatrace.analytics.anomaly import model_scores, rule_flags, unknown_clusters


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scans", default="data/scans.csv")
    ap.add_argument("--labels", default="data/scans_labels.csv")
    ap.add_argument("--json", action="store_true", help="emit JSON (for n8n)")
    a = ap.parse_args()

    scans = pd.read_csv(a.scans, dtype={"uid": str})
    labels = pd.read_csv(a.labels, dtype={"uid": str}).set_index("uid")["label"]
    known = set(labels.index)

    flags = rule_flags(scans[scans.uid.isin(known)])
    scores = model_scores(scans[scans.uid.isin(known)])
    clusters = unknown_clusters(scans, known)

    flagged = set(flags.uid) | set(scores[scores.is_anomaly].index)
    truth = set(labels[labels != "normal"].index)
    tp = len(flagged & truth)
    precision = tp / max(len(flagged), 1)
    recall = tp / max(len(truth), 1)
    report = {
        "units": len(known), "scans": len(scans),
        "rule_flags": flags.rule.value_counts().to_dict(),
        "model_anomalies": int(scores.is_anomaly.sum()),
        "unknown_clusters": clusters.to_dict(orient="records"),
        "precision": round(precision, 3), "recall": round(recall, 3),
        "top_suspects": scores.head(5).reset_index()[["uid", "anomaly_score"]].round(3).to_dict(orient="records"),
    }
    if a.json:
        print(json.dumps(report))
    else:
        for k, v in report.items():
            print(f"{k:>18}: {v}")


if __name__ == "__main__":
    main()
