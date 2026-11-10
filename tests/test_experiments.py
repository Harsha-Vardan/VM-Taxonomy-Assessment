"""scripts/run_experiments.py runs end to end (quick mode) and the committed results agree with the paper."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_quick_run_reports_exact_single_fault_detection():
    r = subprocess.run([sys.executable, "scripts/run_experiments.py", "--quick"], cwd=ROOT, capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stderr
    e1 = json.loads(r.stdout.strip())["E1"]
    assert e1["baseline_all_pass"] and e1["detected"] == e1["cases"] == 78


def test_committed_results_match_the_paper():
    res = json.loads((ROOT / "results" / "experiments.json").read_text(encoding="utf-8"))
    paper = (ROOT / "docs" / "paper" / "paper.md").read_text(encoding="utf-8")
    gen = (ROOT / "docs" / "paper" / "results_experiments.md").read_text(encoding="utf-8").split("\n", 1)[1].strip()
    assert gen in paper, "paper Section 7.7 is stale: rerun scripts/run_experiments.py and paste results_experiments.md"
    assert res["E2"]["fp"] == 0 and res["E2"]["fn"] == 0
    assert res["E3"]["plain"]["detected"] == res["E3"]["plain"]["present"]


def test_scanner_v2_finds_utf16_and_base64_but_v1_does_not():
    from vsec import m2_snapshot as m
    dumps = list(m.synthetic_dumps(n=2, seed=99))
    v1, v2 = m.evaluate(dumps, synthetic=True), m.evaluate(dumps, synthetic=True, decode=True)
    enc = lambda r, var: sum(s["detected"] for c, s in r["cells"].items() if c.endswith("/" + var))
    assert enc(v1, "utf16") == enc(v1, "base64") == 0
    assert enc(v2, "utf16") == enc(v2, "base64") == 8 and v2["false_positives"] == 0
    assert v2["plain"]["detected"] == v1["plain"]["detected"]
    for data, man in dumps:  # v2 redaction leaves nothing v2 can find
        assert not m.scan(m.redact(data, True), True)


def test_real_host_results_are_consistent_with_the_paper():
    import re
    real = ROOT / "results" / "real"
    h = json.loads((real / "hardening.json").read_text())
    for tag, key in (("1-default", "default"), ("2-weakened", "weakened"), ("3-hardened", "hardened")):
        audit = dict(re.findall(r"^(C\d\d)\s+(PASS|FAIL|NA)", (real / f"vsec-target.{tag}.audit.txt").read_text(), re.M))
        assert audit == h[key], tag
    fails = {k: list(h[k].values()).count("FAIL") for k in ("default", "weakened", "hardened")}
    paper = (ROOT / "docs" / "paper" / "paper.md").read_text(encoding="utf-8")
    assert "### 7.8 Real-Host Measurements" in paper
    assert f"| Default | {fails['default']} |" in paper and f"| Hardened | {fails['hardened']} |" in paper
    for c in ("C12", "C14", "C22"):  # every seeded weakness detected, then fixed
        assert h["default"][c] == "PASS" and h["weakened"][c] == "FAIL" and h["hardened"][c] == "PASS"
    m = json.loads((real / "m2_real.json").read_text())
    assert all(v["detected"] == v["present"] for v in m["v2"]["by_encoding"].values())
    assert m["after_v2_redaction"]["secrets_still_present"] == 0


def test_ieee_paper_numbers_match_results():
    tex = (ROOT / "docs" / "paper" / "ieee" / "paper_ieee.tex").read_text(encoding="utf-8")
    R = json.loads((ROOT / "results" / "experiments.json").read_text(encoding="utf-8"))
    e2 = R["E2"]
    assert f"{e2['tp'] + e2['fp'] + e2['fn'] + e2['tn']:,}" in tex and f"{e2['tp']:,}" in tex and f"{e2['tn']:,}" in tex
    assert f"{e2['audit_ms']['median']:.1f}" in tex and f"{e2['audit_ms']['p95']:.1f}" in tex
    assert f"{R['E6']['single_layer']:,} of {R['E6']['blocked']:,}" in tex
    for p, row in R["E5"].items():
        x = 100 * row["host_only"]["hardened_host_breached"] / row["host_only"]["n"]
        assert f"{x:.1f}" in tex or f"{x - 0.05:.1f}" in tex, (p, x)
        assert row["host_and_vms"]["hardened_host_breached"] == 0
    v2 = R["E3v2"]
    assert v2["held_out"]["detected"] == 80 and "80/120" in tex and v2["false_positives"] == 0
    H = json.loads((ROOT / "results" / "real" / "hardening.json").read_text())
    for k in ("default", "weakened", "hardened"):
        v = list(H[k].values())
        assert f"{v.count('FAIL')} & {v.count('PASS')} & {v.count('NA')}" in tex, k
    M = json.loads((ROOT / "results" / "real" / "m2_real.json").read_text())
    assert f"{M['v1']['mib_per_s']}" in tex and f"{M['v2']['mib_per_s']}" in tex and f"{M['dump_bytes'] // 2**20}" in tex
    assert "Sahith Akash Manikanta" in tex and "23BDS031" in tex
