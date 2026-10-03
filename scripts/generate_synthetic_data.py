"""Generate a realistic synthetic scan dataset with injected counterfeit patterns.

Usage: python scripts/generate_synthetic_data.py --out data/scans.csv
"""
from __future__ import annotations

import argparse
import os

import numpy as np
import pandas as pd

CITIES = {  # lat, lon
    "Tehran": (35.69, 51.39), "Isfahan": (32.65, 51.67), "Mashhad": (36.30, 59.60),
    "Shiraz": (29.59, 52.58), "Tabriz": (38.08, 46.29), "Dubai": (25.20, 55.27),
}


def generate(n_units: int = 2000, seed: int = 7):
    rng = np.random.default_rng(seed)
    t0 = 1_780_000_000.0
    rows, labels = [], {}
    names = list(CITIES)
    for i in range(n_units):
        uid = f"0106260000000017{i:010d}"
        city = names[rng.integers(len(names))]
        lat, lon = CITIES[city]
        n = rng.poisson(1.5) + 1
        ts = t0 + np.sort(rng.uniform(0, 30 * 86400, n))
        for t in ts:
            rows.append((uid, t, lat + rng.normal(0, 0.03), lon + rng.normal(0, 0.03)))
        labels[uid] = "normal"

    # cloned serials: same uid scanned in two distant cities within an hour
    for uid in rng.choice(list(labels), 25, replace=False):
        t = t0 + rng.uniform(0, 30 * 86400)
        a, b = rng.choice(names, 2, replace=False)
        rows.append((uid, t, *CITIES[a]))
        rows.append((uid, t + rng.uniform(600, 3000), *CITIES[b]))
        labels[uid] = "cloned"

    # bursts: a reseller repeatedly scanning one genuine code on many fakes
    for uid in rng.choice([u for u, lbl in labels.items() if lbl == "normal"], 15, replace=False):
        t = t0 + rng.uniform(0, 30 * 86400)
        lat, lon = CITIES[names[rng.integers(len(names))]]
        for k in range(int(rng.integers(8, 20))):
            rows.append((uid, t + k * 120, lat, lon))
        labels[uid] = "burst"

    # unknown serials from a counterfeit batch near Dubai
    for k in range(40):
        rows.append((f"FAKE{k:06d}", t0 + rng.uniform(0, 30 * 86400),
                     25.20 + rng.normal(0, 0.02), 55.27 + rng.normal(0, 0.02)))

    scans = pd.DataFrame(rows, columns=["uid", "ts", "lat", "lon"])
    lab = pd.Series(labels, name="label").rename_axis("uid").reset_index()
    return scans, lab


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/scans.csv")
    ap.add_argument("--units", type=int, default=2000)
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    s, lbl = generate(a.units)
    s.to_csv(a.out, index=False)
    lbl.to_csv(a.out.replace(".csv", "_labels.csv"), index=False)
    print(f"wrote {len(s)} scans for {len(lbl)} units -> {a.out}")
