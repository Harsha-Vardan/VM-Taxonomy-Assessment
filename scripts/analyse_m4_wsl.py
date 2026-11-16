#!/usr/bin/env python3
"""Analyse a limited M4 run (WSL2 host vs KVM guest inside WSL2):  python scripts/analyse_m4_wsl.py <run-dir>
Unit of analysis = one (environment, session, workload) run: the median over its windows (windows are not independent).
Per signal and workload: medians per environment, Cliff's delta and the equivalent single-signal AUROC over sessions,
Mann-Whitney U p-value (Holm-corrected across signals within a workload), within-environment spread (IQR/median).
Combined signals: logistic regression on standardised log medians, leave-one-session-out (both environments of a
session held out together), per workload and pooled. EXPLORATORY: 5 sessions per environment, one machine.
Writes results/real/m4_wsl/m4_wsl.json and m4_wsl.md."""
import json
import math
import sys
from pathlib import Path

import numpy as np
from scipy.stats import mannwhitneyu
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

SIGNALS = ["cpuid_tsc", "rdtsc_tsc", "syscall_ns", "pagefault_ns", "seq_ns", "stride_ns", "rand_ns", "sleep_jitter_us",
           "ipc", "dtlb_miss"]
GROUP = {"cpuid_tsc": "timing", "rdtsc_tsc": "timing", "syscall_ns": "timing", "pagefault_ns": "memory",
         "seq_ns": "memory", "stride_ns": "memory", "rand_ns": "memory", "sleep_jitter_us": "scheduler",
         "ipc": "perf", "dtlb_miss": "perf"}
ENVS = ("wsl2-host", "kvm-in-wsl2")
OUT = Path(__file__).resolve().parent.parent / "results" / "real" / "m4_wsl"


def load(run):
    units = []
    for f in sorted(run.glob("*.csv")):
        lines = f.read_text().splitlines()
        meta = [l for l in lines if l.startswith("#")]
        hdr = next(l for l in lines if l.startswith("window,")).split(",")
        rows = [l.split(",") for l in lines if l and l[0].isdigit()]
        env, s, w = f.stem.rsplit("_", 2)
        a = np.array([[float(x) for x in r[2:]] for r in rows]) if rows else np.zeros((0, len(hdr) - 2))
        col = {h: a[:, i] for i, h in enumerate(hdr[2:])}
        med = {k: (float(np.nanmedian(v)) if np.isfinite(v).sum() >= 0.8 * len(v) and len(v) else math.nan)
               for k, v in col.items() if k in SIGNALS}
        units.append({"env": env, "session": int(s[1:]), "workload": w, "n": len(rows), "median": med,
                      "elapsed_ms": float(np.median(col["elapsed_ms"])) if len(rows) else math.nan,
                      "exit": next((l.split("=")[1] for l in meta if l.startswith("# exit=")), None),
                      "meta": [l for l in meta if "cpu_model" in l][:1]})
    return units


def holm(ps):
    order = sorted(range(len(ps)), key=lambda i: ps[i])
    adj, run = [math.nan] * len(ps), 0.0
    for k, i in enumerate(order):
        run = max(run, min(1.0, (len(ps) - k) * ps[i]))
        adj[i] = run
    return adj


def cliff(a, b):
    return float(np.mean([(x > y) - (x < y) for x in a for y in b]))


def loso(units, feats):
    """Leave-one-session-out logistic regression; returns AUROC over held-out units, or None."""
    X = np.array([[math.log(max(u["median"][f], 1e-12)) for f in feats] for u in units])
    y = np.array([ENVS.index(u["env"]) for u in units])
    g = np.array([u["session"] for u in units])
    if np.isnan(X).any() or len(set(y)) < 2:
        return None
    score = np.zeros(len(y))
    for s in sorted(set(g)):
        tr, te = g != s, g == s
        sc = StandardScaler().fit(X[tr])
        m = LogisticRegression(C=1.0, max_iter=1000).fit(sc.transform(X[tr]), y[tr])
        score[te] = m.predict_proba(sc.transform(X[te]))[:, 1]
    return {"auroc": float(roc_auc_score(y, score)), "accuracy": float(np.mean((score > 0.5) == y)), "n_units": int(len(y))}


def main(run):
    run = Path(run)
    units = [u for u in load(run) if u["n"] > 0 and u["exit"] == "0"]
    workloads = sorted({u["workload"] for u in units})
    res = {"run": run.name, "units_used": len(units), "per_workload": {}, "combined": {}, "availability": {}}
    for sig in SIGNALS:
        res["availability"][sig] = {e: sum(1 for u in units if u["env"] == e and math.isfinite(u["median"][sig]))
                                    for e in ENVS}
    for w in workloads:
        us = [u for u in units if u["workload"] == w]
        rows, ps = [], []
        for sig in SIGNALS:
            a = [u["median"][sig] for u in us if u["env"] == ENVS[0] and math.isfinite(u["median"][sig])]
            b = [u["median"][sig] for u in us if u["env"] == ENVS[1] and math.isfinite(u["median"][sig])]
            if len(a) < 3 or len(b) < 3:
                rows.append({"signal": sig, "group": GROUP[sig], "status": "NA (not measurable in both)",
                             "n_host": len(a), "n_guest": len(b)})
                ps.append(1.0)
                continue
            d = cliff(b, a)
            p = float(mannwhitneyu(b, a, alternative="two-sided").pvalue)
            ps.append(p)
            spread = lambda v: float((np.percentile(v, 75) - np.percentile(v, 25)) / np.median(v)) if np.median(v) else math.nan
            rows.append({"signal": sig, "group": GROUP[sig], "host_median": float(np.median(a)),
                         "guest_median": float(np.median(b)), "ratio_guest_host": float(np.median(b) / np.median(a)) if np.median(a) else math.nan,
                         "cliffs_delta": d, "single_auroc": (d + 1) / 2 if d >= 0 else (1 - d) / 2,
                         "p_mwu": p, "host_iqr_rel": spread(a), "guest_iqr_rel": spread(b), "n_host": len(a), "n_guest": len(b)})
        for r, q in zip(rows, holm(ps)):
            if "p_mwu" in r:
                r["p_holm"] = q
        res["per_workload"][w] = rows
        feats = [r["signal"] for r in rows if "p_mwu" in r]
        res["combined"][w] = {"features": feats, **(loso(us, feats) or {"auroc": None})}
    common = [s for s in SIGNALS if all(math.isfinite(u["median"][s]) for u in units)]
    res["combined"]["pooled_all_workloads"] = {"features": common, **(loso(units, common) or {"auroc": None})}
    res["host_meta"] = next((u["meta"] for u in units if u["env"] == ENVS[0] and u["meta"]), [])
    res["guest_meta"] = next((u["meta"] for u in units if u["env"] == ENVS[1] and u["meta"]), [])
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "m4_wsl.json").write_text(json.dumps(res, indent=1))
    md = [f"# Limited M4 run {run.name}: WSL2 host vs KVM guest inside WSL2 (EXPLORATORY, not native vs VM)", "",
          f"Units used: {len(units)} (environment x session x workload runs, exit 0). Values = medians of per-run medians.",
          "Note: with 5 vs 5 sessions the smallest two-sided Mann-Whitney p is 2/252 = 0.0079, so after Holm over 10 signals "
          "no single signal can reach p < 0.05. Read Cliff's delta (effect size) and AUROC; the p-values only show the limit.", ""]
    for w, rows in res["per_workload"].items():
        md += [f"## Workload {w}", "", "| signal | group | host | guest | guest/host | Cliff d | single AUROC | p (Holm) |", "|---|---|---|---|---|---|---|---|"]
        for r in rows:
            if "p_mwu" not in r:
                md.append(f"| {r['signal']} | {r['group']} | {r['status']} |  |  |  |  |  |")
            else:
                md.append(f"| {r['signal']} | {r['group']} | {r['host_median']:.4g} | {r['guest_median']:.4g} | {r['ratio_guest_host']:.3g} | "
                          f"{r['cliffs_delta']:+.2f} | {r['single_auroc']:.2f} | {r['p_holm']:.3g} |")
        c = res["combined"][w]
        md += ["", f"Combined (logistic regression, leave-one-session-out): AUROC {c.get('auroc')}, accuracy {c.get('accuracy')}", ""]
    c = res["combined"]["pooled_all_workloads"]
    md += [f"Pooled over workloads: AUROC {c.get('auroc')}, accuracy {c.get('accuracy')}, features {c['features']}", ""]
    (OUT / "m4_wsl.md").write_text("\n".join(md))
    print("\n".join(md))


if __name__ == "__main__":
    main(sys.argv[1])
