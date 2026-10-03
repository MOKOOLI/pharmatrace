"""Counterfeit / diversion detection on public verification scans.

Two layers:
1. Deterministic rules (explainable, regulator-friendly):
   - impossible_travel: same serial scanned in two places faster than `max_kmh`
   - scan_burst: a serial scanned more than `burst_n` times inside `burst_window` seconds
   - unknown_cluster: many unknown serials scanned in the same ~11 km grid cell (fake batch in the wild)
2. Unsupervised model (IsolationForest) over per-serial behavioural features.
"""
from __future__ import annotations


import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1, p2 = np.radians(lat1), np.radians(lat2)
    dphi = p2 - p1
    dl = np.radians(lon2) - np.radians(lon1)
    a = np.sin(dphi / 2) ** 2 + np.cos(p1) * np.cos(p2) * np.sin(dl / 2) ** 2
    return 2 * r * np.arcsin(np.sqrt(a))


def rule_flags(scans: pd.DataFrame, *, max_kmh: float = 900.0, burst_n: int = 5,
               burst_window: float = 3600.0) -> pd.DataFrame:
    """scans columns: uid, ts (epoch s), lat, lon. Returns one row per flag."""
    df = scans.dropna(subset=["lat", "lon"]).sort_values(["uid", "ts"]).copy()
    flags = []

    g = df.groupby("uid")
    df["prev_lat"], df["prev_lon"], df["prev_ts"] = g["lat"].shift(), g["lon"].shift(), g["ts"].shift()
    moved = df.dropna(subset=["prev_lat"])
    if not moved.empty:
        km = haversine_km(moved["prev_lat"], moved["prev_lon"], moved["lat"], moved["lon"])
        hours = np.maximum((moved["ts"] - moved["prev_ts"]) / 3600.0, 1e-6)
        speed = km / hours
        bad = moved[(speed > max_kmh) & (km > 50)]
        for idx, row in bad.iterrows():
            flags.append({"uid": row.uid, "rule": "impossible_travel",
                          "detail": f"{km[idx]:.0f} km in {hours[idx]*60:.0f} min"})

    for uid, grp in df.groupby("uid"):
        ts = grp["ts"].to_numpy()
        j = 0
        for i in range(len(ts)):
            while ts[i] - ts[j] > burst_window:
                j += 1
            if i - j + 1 > burst_n:
                flags.append({"uid": uid, "rule": "scan_burst", "detail": f">{burst_n} scans/{int(burst_window)}s"})
                break

    return pd.DataFrame(flags, columns=["uid", "rule", "detail"]).drop_duplicates()


def unknown_clusters(scans: pd.DataFrame, known_uids: set[str], min_count: int = 5) -> pd.DataFrame:
    unk = scans[~scans["uid"].isin(known_uids)].dropna(subset=["lat", "lon"]).copy()
    if unk.empty:
        return pd.DataFrame(columns=["cell", "unknown_scans"])
    unk["cell"] = unk["lat"].round(1).astype(str) + "," + unk["lon"].round(1).astype(str)
    out = unk.groupby("cell").size().rename("unknown_scans").reset_index()
    return out[out["unknown_scans"] >= min_count].sort_values("unknown_scans", ascending=False)


def features(scans: pd.DataFrame) -> pd.DataFrame:
    df = scans.dropna(subset=["lat", "lon"]).sort_values(["uid", "ts"])
    rows = []
    for uid, g in df.groupby("uid"):
        lat, lon, ts = g["lat"].to_numpy(), g["lon"].to_numpy(), g["ts"].to_numpy()
        dist = haversine_km(lat[:-1], lon[:-1], lat[1:], lon[1:]) if len(g) > 1 else np.array([0.0])
        rows.append({
            "uid": uid,
            "n_scans": len(g),
            "span_h": (ts.max() - ts.min()) / 3600.0,
            "total_km": float(dist.sum()),
            "max_hop_km": float(dist.max()),
            "geo_spread": float(np.std(lat) + np.std(lon)),
        })
    return pd.DataFrame(rows).set_index("uid")


def model_scores(scans: pd.DataFrame, contamination: float = 0.03, seed: int = 42) -> pd.DataFrame:
    X = features(scans)
    if len(X) < 10:
        X["anomaly_score"] = 0.0
        X["is_anomaly"] = False
        return X
    model = IsolationForest(n_estimators=300, contamination=contamination, random_state=seed)
    Xl = np.log1p(X)
    model.fit(Xl)
    X["anomaly_score"] = -model.score_samples(Xl)
    X["is_anomaly"] = model.predict(Xl) == -1
    return X.sort_values("anomaly_score", ascending=False)
