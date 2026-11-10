#!/usr/bin/env python3
"""Reproducible experiments that can run WITHOUT KVM hardware (paper Section 7.7).

    python scripts/run_experiments.py [--quick]

Writes results/experiments.json, docs/paper/results_experiments.md and docs/paper/figures/fig6..fig8.

HONEST LABELS (repeated in every output):
  E1, E2  M1 auditor on CONSTRUCTED case folders with known seeded faults (fault injection). This measures whether
          the checker reports exactly the faults that were seeded, including when many faults interact in one
          folder. It is NOT accuracy on real hosts (same team wrote checker and fixtures).
  E3      M2 secret scanner on SYNTHETIC memory dumps with planted secrets (ground truth by construction).
  E4-E6   The Attack Lab MODEL (vsec/attacks.yaml + fleet.yaml): what the survey's attack logic implies, not a
          measurement of real attacks.
Nothing here uses or replaces the pending real-hardware results (M3, M4, Sections 7.1-7.6).
"""
import argparse
import importlib.util
import json
import random
import statistics
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from vsec import m1_audit, m2_snapshot, sim  # noqa: E402
from vsec.score import wilson  # noqa: E402

_spec = importlib.util.spec_from_file_location("make_fixtures", ROOT / "tests" / "make_fixtures.py")
mf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mf)

SEED = 20261109
NA_BY_DESIGN = {"C23", "C24"}  # CVE checks: the shipped CVE list is unverified, so they are NA (never PASS)
TESTABLE = [c for c in sorted(mf.FAULTS) if c not in NA_BY_DESIGN]


def keys_of(fault):
    return set(fault)


def write_case(folder, settings):
    folder.mkdir(parents=True, exist_ok=True)
    for fn, text in mf.files_for(settings, e0=False).items():
        (folder / fn).write_text(text, encoding="utf-8", newline="")


def audit_status(folder):
    return {f["id"]: f["status"] for f in m1_audit.audit(folder, env="E1")}


def pick_faults(rng, p):
    """Random fault set with prob p per control; faults that write the same setting are not combined
    (ground truth would be ambiguous), except C11+C12 which have a defined joint form."""
    chosen, used = {}, set()
    for c in TESTABLE:
        if rng.random() >= p:
            continue
        f = rng.choice(mf.FAULTS[c])
        if keys_of(f) & used:
            continue
        chosen[c] = f
        used |= keys_of(f)
    return chosen


# ------------------------------------------------------------------ E1 single-fault, E2 multi-fault injection
def e1_single(tmp):
    """Every control x every seeded variant, alone in an otherwise hardened folder (28 x 3 = 84 cases, minus NA)."""
    rows, wrong = {}, []
    base = audit_status(write_and(tmp / "base", {}))
    for c in TESTABLE:
        ok_target = ok_others = 0
        for i, f in enumerate(mf.FAULTS[c]):
            st = audit_status(write_and(tmp / f"s-{c}-{i}", f))
            ok_target += st[c] == "FAIL"
            others = [k for k in TESTABLE if k != c and st[k] != base[k]]
            ok_others += not others
            if st[c] != "FAIL" or others:
                wrong.append({"control": c, "variant": i, "target": st[c], "side_effects": others})
        rows[c] = {"variants": len(mf.FAULTS[c]), "detected": ok_target, "no_side_effect": ok_others}
    n = sum(r["variants"] for r in rows.values())
    d = sum(r["detected"] for r in rows.values())
    clean = sum(r["no_side_effect"] for r in rows.values())
    return {"baseline_all_pass": all(base[c] == "PASS" for c in TESTABLE), "cases": n, "detected": d,
            "detection_ci": wilson(d, n), "isolated": clean, "isolation_ci": wilson(clean, n),
            "per_control": rows, "errors": wrong}


def write_and(folder, settings):
    write_case(folder, settings)
    return folder


def e2_multi(tmp, n_cases, rng):
    """Random folders with many faults at once (p in 0.1..0.7): per-control confusion vs the seeded truth."""
    tp = fp = fn = tn = 0
    per = defaultdict(lambda: [0, 0, 0, 0])
    by_p = {}
    times = []
    for p in (0.1, 0.3, 0.5, 0.7):
        exact = 0
        for i in range(n_cases):
            faults = pick_faults(rng, p)
            settings = {}
            for f in faults.values():
                settings.update(f)
            if "C11" in faults and "C12" in faults:
                settings["x.graphics"] = "vnc|0.0.0.0|"
            folder = write_and(tmp / f"m-{p}-{i}", settings)
            t0 = time.perf_counter()
            st = audit_status(folder)
            times.append(time.perf_counter() - t0)
            all_ok = True
            for c in TESTABLE:
                truth, pred = c in faults, st[c] == "FAIL"
                k = 0 if truth and pred else 1 if pred else 2 if truth else 3
                per[c][k] += 1
                all_ok &= k in (0, 3)
            exact += all_ok
        by_p[p] = {"cases": n_cases, "exact_match": exact, "ci": wilson(exact, n_cases)}
    for v in per.values():
        tp, fp, fn, tn = tp + v[0], fp + v[1], fn + v[2], tn + v[3]
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    return {"cases": 4 * n_cases, "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": prec, "recall": rec,
            "f1": 2 * prec * rec / (prec + rec) if prec and rec else None,
            "fpr": fp / (fp + tn) if fp + tn else None,
            "precision_ci": wilson(tp, tp + fp), "recall_ci": wilson(tp, tp + fn),
            "by_fault_rate": by_p, "per_control": {c: dict(zip(("tp", "fp", "fn", "tn"), v)) for c, v in sorted(per.items())},
            "audit_ms": {"median": 1000 * statistics.median(times), "p95": 1000 * sorted(times)[int(.95 * len(times))],
                         "n": len(times)}}


# ------------------------------------------------------------------ E3 M2 scanner
def e3_m2(n, decode=False):
    """decode=False: scanner v1 (the original design). decode=True: v2 with UTF-16 and base64 passes, added after
    v1's result. The dumps are regenerated with a DIFFERENT seed for v2, so v2 is not scored on the dumps that
    revealed the gap."""
    dumps = list(m2_snapshot.synthetic_dumps(n=n, seed=SEED + (1 if decode else 0)))
    res = m2_snapshot.evaluate(dumps, synthetic=True, decode=decode)
    red_ok = sum(1 for data, man in dumps if man["needles"]
                 and not m2_snapshot.scan(m2_snapshot.redact(bytes(data), decode), decode))
    red_n = sum(1 for _, man in dumps if man["needles"])
    res["redaction_clean"] = red_ok
    res["redaction_n"] = red_n
    res["throughput_mb_s"] = res["total_bytes"] / 2**20 / res["scan_seconds"] if res["scan_seconds"] else None
    return res


# ------------------------------------------------------------------ E4-E6 Attack Lab model
def example_states():
    spec = importlib.util.spec_from_file_location("bs", ROOT / "scripts" / "build_simulator.py")
    bs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bs)
    data = bs.fleet_states(sim.load_fleet())
    return {h["id"]: h["state"] for h in data["hosts"]}, {v["id"]: v["state"] for v in data["vms"]}


def e4_leverage(A, F, hs, vs):
    """Which single control, fixed everywhere it fails, blocks the most open (VM, attack) pairs in the example fleet."""
    def open_pairs(h, v):
        return {(x["id"], a["id"]) for x in F["vms"] for a in A
                if not sim.evaluate(a, sim.merged_state(F, h, v, x["id"]))["blocked"]}
    base = open_pairs(hs, vs)
    vml = set(F["vm_level"])
    rows = []
    for c in sim.gate_controls(A):
        h2 = {k: dict(s) for k, s in hs.items()}
        v2 = {k: dict(s) for k, s in vs.items()}
        for s in (v2 if c in vml else h2).values():
            if s.get(c) == "FAIL":
                s[c] = "PASS"
        rows.append({"control": c, "level": "vm" if c in vml else "host", "blocked_pairs": len(base - open_pairs(h2, v2))})
    rows.sort(key=lambda r: -r["blocked_pairs"])
    out = sim.campaign(A, F, hs, vs, None)
    steps, h2, v2, curve = [], hs, vs, [sim.blast(F, out)[1]]
    while True:
        adv = sim.containment_advice(A, F, h2, v2, None, 1)
        if not adv:
            break
        steps.append(adv[0]["fixes"])
        h2, v2 = sim.apply_fixes(h2, v2, adv[0]["fixes"])
        curve.append(sim.blast(F, sim.campaign(A, F, h2, v2, None))[1])
    per_vm = {}
    for x in F["vms"]:
        st = sim.merged_state(F, hs, vs, x["id"])
        mfs = sim.minimal_fix_set(A, st)
        results, n_blocked = sim.posture(A, st)
        per_vm[x["id"]] = {"risk": sim.risk(A, st), "open": len(A) - n_blocked,
                           "min_fix": len(mfs) if mfs is not None else None}
    return {"open_pairs": len(base), "total_pairs": len(F["vms"]) * len(A), "leverage": rows,
            "outsider_curve": curve, "outsider_plan": steps, "per_vm": per_vm}


def random_states(rng, F, p, hardened_host=None, force_pass=(), harden_vms_on_host=False):
    vml = set(F["vm_level"])
    hostc = [c for c in TESTABLE if c not in vml]
    hs = {h["id"]: {**{c: ("PASS" if h["id"] == hardened_host or rng.random() >= p else "FAIL") for c in hostc},
                    "C23": "NA", "C24": "NA"} for h in F["hosts"]}
    vs = {v["id"]: {c: ("PASS" if (harden_vms_on_host and v["host"] == hardened_host) or rng.random() >= p else "FAIL")
                    for c in sorted(vml)} for v in F["vms"]}
    for c in force_pass:
        for s in (vs if c in vml else hs).values():
            s[c] = "PASS"
    return hs, vs


E5_CONFIGS = (("host_only", "host-c hardened; its VMs random", False, ()),
              ("host_and_vms", "host-c and its VMs hardened", True, ()),
              ("host_vms_isolated", "as before + every network isolated (C15, C16)", True, ("C15", "C16")))


def e5_montecarlo(A, F, n, rng):
    """Random fleets on the example topology. kvm-host-c is fully hardened; every other control fails with prob p.
    Question: how often does an outsider still reach a VM on the hardened host, and what closes the gap?"""
    hard = "host-c"
    on_hard = {v["id"] for v in F["vms"] if v["host"] == hard}
    res = {}
    for p in (0.1, 0.2, 0.3, 0.5):
        row = {}
        for name, _, hv, force in E5_CONFIGS:
            hit = comp = 0
            for _ in range(n):
                hs, vs = random_states(rng, F, p, hard, force, hv)
                out = sim.campaign(A, F, hs, vs, None)
                hit += bool(on_hard & set(out["compromised"]))
                comp += len(out["compromised"])
            row[name] = {"hardened_host_breached": hit, "n": n, "ci": wilson(hit, n), "mean_compromised": comp / n}
        res[str(p)] = row
    return res


def e6_depth(A, F, n, rng):
    """Defence in depth: in random VM states, share of blocked attacks that hold by exactly one control."""
    single = blocked = 0
    for _ in range(n):
        hs, vs = random_states(rng, F, 0.3)
        for v in F["vms"]:
            st = sim.merged_state(F, hs, vs, v["id"])
            for a in A:
                r = sim.evaluate(a, st)
                if r["blocked"]:
                    blocked += 1
                    single += r.get("layers", 0) == 1
    return {"blocked": blocked, "single_layer": single, "ci": wilson(single, blocked)}


# ------------------------------------------------------------------ outputs
def pct(x):
    return "n/a" if x is None else f"{100 * x:.1f}%"


def ci(c):
    return f"[{100 * c[0]:.1f}, {100 * c[1]:.1f}]" if c else ""


def figures(R, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    out.mkdir(parents=True, exist_ok=True)
    lev = R["E4"]["leverage"][:12]
    fig, ax = plt.subplots(figsize=(7, 3.6))
    ax.barh([f"{r['control']} ({r['level']})" for r in lev][::-1], [r["blocked_pairs"] for r in lev][::-1], color="#1d4ed8")
    ax.set_xlabel("open (VM, attack) pairs blocked by fixing this control")
    ax.set_title("Control leverage in the example fleet (model)")
    fig.tight_layout(); fig.savefig(out / "fig6_leverage.png", dpi=160); plt.close(fig)
    c = R["E4"]["outsider_curve"]
    fig, ax = plt.subplots(figsize=(6, 3.4))
    ax.step(range(len(c)), c, where="post", color="#b91c1c", marker="o")
    ax.set_xlabel("containment steps applied (greedy)"); ax.set_ylabel("VMs compromised by an outsider")
    ax.set_title("Greedy containment from the outside (model)")
    fig.tight_layout(); fig.savefig(out / "fig7_containment.png", dpi=160); plt.close(fig)
    ps = list(R["E5"])
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    for (name, label, _, _), col in zip(E5_CONFIGS, ("#b91c1c", "#92600a", "#15803d")):
        y = [100 * R["E5"][p][name]["hardened_host_breached"] / R["E5"][p][name]["n"] for p in ps]
        lo = [100 * R["E5"][p][name]["ci"][0] for p in ps]
        hi = [100 * R["E5"][p][name]["ci"][1] for p in ps]
        ax.plot([float(p) for p in ps], y, marker="o", color=col, label=label)
        ax.fill_between([float(p) for p in ps], lo, hi, color=col, alpha=.15)
    ax.set_xlabel("fault probability on the other hosts and VMs"); ax.set_ylabel("% fleets where a VM on the\nhardened host is breached")
    ax.set_title("A hardened host is not enough (model, 95% Wilson CI)"); ax.legend(fontsize=8)
    fig.tight_layout(); fig.savefig(out / "fig8_hardened_host.png", dpi=160); plt.close(fig)


def markdown(R):
    e1, e2, e3, e4, e5, e6 = (R[k] for k in ("E1", "E2", "E3", "E4", "E5", "E6"))
    L = ["<!-- generated by scripts/run_experiments.py; do not edit by hand -->",
         f"Seed {R['seed']}; {R['generated']}. All six experiments run on this repository without KVM hardware. "
         "E1 to E3 use constructed inputs with known ground truth; E4 to E6 evaluate the Attack Lab model. None of them is a measurement of a real host.", "",
         "**E1. Single-fault injection (M1).** Each of the "
         f"{len(e1['per_control'])} testable configuration controls was broken in each of its seeded variants, one at a time, in an otherwise hardened folder "
         f"({e1['cases']} cases; C23 and C24 are NA by design because the shipped CVE list is unverified). "
         f"The hardened baseline audits all-PASS: {e1['baseline_all_pass']}. The seeded fault was reported as FAIL in {e1['detected']}/{e1['cases']} cases "
         f"(95% Wilson CI {ci(e1['detection_ci'])}), and in {e1['isolated']}/{e1['cases']} cases no other control changed state ({ci(e1['isolation_ci'])}).", ""]
    if e1["errors"]:
        L += ["Cases that did not behave as seeded:", "", "| Control | Variant | Status of seeded control | Other controls that changed |", "|---|---|---|---|"]
        L += [f"| {w['control']} | {w['variant']} | {w['target']} | {', '.join(w['side_effects']) or '-'} |" for w in e1["errors"]]
        L += [""]
    L += [f"**E2. Multi-fault injection (M1).** {e2['cases']} random folders, each control broken independently with probability p in {{0.1, 0.3, 0.5, 0.7}} "
          "(faults that write the same setting are not combined). Every testable control in every folder is one decision.", "",
          "| Metric | Value | 95% CI |", "|---|---|---|",
          f"| Decisions | {e2['tp'] + e2['fp'] + e2['fn'] + e2['tn']} | |",
          f"| Precision | {pct(e2['precision'])} | {ci(e2['precision_ci'])} |",
          f"| Recall | {pct(e2['recall'])} | {ci(e2['recall_ci'])} |",
          f"| F1 | {pct(e2['f1'])} | |", f"| False-positive rate | {pct(e2['fpr'])} | |",
          f"| Audit time per folder (median / p95) | {e2['audit_ms']['median']:.1f} ms / {e2['audit_ms']['p95']:.1f} ms | n = {e2['audit_ms']['n']} |", "",
          "| Fault probability p | Folders | Folders with every control correct | 95% CI |", "|---|---|---|---|"]
    L += [f"| {p} | {v['cases']} | {v['exact_match']} | {ci(v['ci'])} |" for p, v in e2["by_fault_rate"].items()]
    bad = {c: v for c, v in e2["per_control"].items() if v["fp"] or v["fn"]}
    L += ["", "Controls with any error: " + (", ".join(f"{c} (FP {v['fp']}, FN {v['fn']})" for c, v in bad.items()) if bad else "none") + ".", "",
          f"**E3. Snapshot secret scanner (M2) on synthetic dumps.** {e3['dumps']} dumps of {e3['total_bytes'] // e3['dumps'] // 1024} KiB "
          f"({e3['gb_scanned'] * 1024:.0f} MiB in total) with secrets planted by the generator, plus negative dumps.", "",
          "| Group | Detected / present | Recall | 95% CI |", "|---|---|---|---|"]
    for g in ("plain", "held_out", "real_programs"):
        s = e3.get(g)
        if s and s["present"]:
            L.append(f"| {g.replace('_', ' ')} | {s['detected']} / {s['present']} | {pct(s['recall'])} | {ci(s['ci'])} |")
    L += ["", "| Cell | Detected / present | Recall |", "|---|---|---|"]
    L += [f"| {c} | {s['detected']} / {s['present']} | {pct(s['recall'])} |" for c, s in e3["cells"].items()]
    L += ["", f"False positives: {e3['false_positives']} ({e3['fp_per_gb']:.1f} per GiB). Scan throughput {e3['throughput_mb_s']:.1f} MiB/s on this laptop. "
          f"After redaction, {e3['redaction_clean']}/{e3['redaction_n']} planted dumps rescanned with zero hits; redaction adds 0 bytes.", "",
          f"**E3b. Scanner v2: fixing the gap.** After E3, we added two decoding passes (UTF-16LE text and base64 runs are decoded and the same rules run on the result; hits are reported as the encoded byte span). "
          f"v2 is scored on freshly generated dumps (seed + 1), not on the dumps that revealed the gap.", "",
          "| Group | v1 detected / present | v2 detected / present | v2 recall | v2 95% CI |", "|---|---|---|---|---|"]
    v2 = R["E3v2"]
    for g in ("plain", "held_out"):
        L.append(f"| {g.replace('_', ' ')} | {e3[g]['detected']} / {e3[g]['present']} | {v2[g]['detected']} / {v2[g]['present']} | {pct(v2[g]['recall'])} | {ci(v2[g]['ci'])} |")
    L += ["", "| Encoding | v1 | v2 |", "|---|---|---|"]
    for var in ("utf16", "base64", "split"):
        d1 = sum(s["detected"] for c, s in e3["cells"].items() if c.endswith("/" + var)); p1 = sum(s["present"] for c, s in e3["cells"].items() if c.endswith("/" + var))
        d2 = sum(s["detected"] for c, s in v2["cells"].items() if c.endswith("/" + var)); p2 = sum(s["present"] for c, s in v2["cells"].items() if c.endswith("/" + var))
        L.append(f"| {var} | {d1} / {p1} | {d2} / {p2} |")
    L += ["", f"v2 false positives: {v2['false_positives']} ({v2['fp_per_gb']:.1f} per GiB); throughput {v2['throughput_mb_s']:.1f} MiB/s; "
          f"after v2 redaction {v2['redaction_clean']}/{v2['redaction_n']} dumps rescan clean. Secrets split across pages remain undetected: a pattern needs the whole secret in one place.", "",
          f"**E4. Attack Lab: control leverage and containment (model, example fleet).** {e4['open_pairs']} of {e4['total_pairs']} (VM, attack) pairs are open. "
          "Fixing a single control everywhere it fails blocks this many open pairs:", "",
          "| Rank | Control | Level | Open pairs blocked |", "|---|---|---|---|"]
    L += [f"| {i + 1} | {r['control']} {sim.control_index()[r['control']]['control'].replace('_', ' ')} | {r['level']} | {r['blocked_pairs']} |"
          for i, r in enumerate(e4["leverage"][:10])]
    L += ["", f"Outsider campaign, VMs compromised after each greedy containment step: {' -> '.join(map(str, e4['outsider_curve']))} "
          f"({len(e4['outsider_plan'])} steps).", "",
          "| VM | Risk score | Open attacks | Smallest fix set that blocks every modelled attack |", "|---|---|---|---|"]
    L += [f"| {k} | {v['risk']} | {v['open']} of {len(sim.load_attacks())} | {v['min_fix']} |" for k, v in e4["per_vm"].items()]
    L += ["", f"**E5. Is a hardened host enough? (model, Monte Carlo).** {e5[next(iter(e5))]['host_only']['n']} random fleets per cell on the example topology. "
          "`kvm-host-c` is fully hardened; every other host and VM control fails independently with probability p. Cell = share of fleets in which an outsider compromises at least one VM on the hardened host (95% Wilson CI), and the mean number of VMs compromised in the fleet.", "",
          "| p | " + " | ".join(c[1] for c in E5_CONFIGS) + " |", "|---|---|---|---|"]
    for p, row in e5.items():
        L.append("| " + p + " | " + " | ".join(f"{pct(row[k]['hardened_host_breached'] / row[k]['n'])} {ci(row[k]['ci'])}, mean {row[k]['mean_compromised']:.2f} VMs"
                                                 for k in (c[0] for c in E5_CONFIGS)) + " |")
    L += ["", f"**E6. Defence in depth (model).** Over random VM states (p = 0.3), {e6['single_layer']} of {e6['blocked']} blocked (VM, attack) pairs "
          f"({pct(e6['single_layer'] / e6['blocked'])}, CI {ci(e6['ci'])}) are held by exactly one control: one more misconfiguration would open them.", "",
          "![Figure 6. Control leverage in the example fleet (model).](figures/fig6_leverage.png)", "",
          "![Figure 7. Greedy containment from the outside (model).](figures/fig7_containment.png)", "",
          "![Figure 8. Share of random fleets in which a VM on the fully hardened host is breached, with 95% Wilson intervals (model).](figures/fig8_hardened_host.png)", ""]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="small sample sizes (for tests)")
    a = ap.parse_args()
    rng = random.Random(SEED)
    n_multi, n_m2, n_mc, n_depth = (5, 2, 40, 20) if a.quick else (100, 10, 2000, 500)
    A, F = sim.load_attacks(), sim.load_fleet()
    t0 = time.time()
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        R = {"seed": SEED, "generated": time.strftime("%Y-%m-%d"), "quick": a.quick,
             "labels": __doc__.split("HONEST LABELS")[1].strip()}
        R["E1"] = e1_single(tmp)
        R["E2"] = e2_multi(tmp, n_multi, rng)
    R["E3"] = e3_m2(n_m2)
    R["E3v2"] = e3_m2(n_m2, decode=True)
    hs, vs = example_states()
    R["E4"] = e4_leverage(A, F, hs, vs)
    R["E5"] = e5_montecarlo(A, F, n_mc, rng)
    R["E6"] = e6_depth(A, F, n_depth, rng)
    R["runtime_s"] = round(time.time() - t0, 1)
    if a.quick:
        print(json.dumps({"E1": R["E1"]}, default=list))
        return
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "experiments.json").write_text(json.dumps(R, indent=1, default=list), encoding="utf-8")
    (ROOT / "docs" / "paper" / "results_experiments.md").write_text(markdown(R), encoding="utf-8", newline="\n")
    figures(R, ROOT / "docs" / "paper" / "figures")
    print(f"done in {R['runtime_s']} s -> results/experiments.json, docs/paper/results_experiments.md, figures fig6-fig8")


if __name__ == "__main__":
    main()
