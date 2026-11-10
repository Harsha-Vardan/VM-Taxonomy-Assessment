"""The what-if attack simulator: data is valid, results come from the real audit, the HTML is current, JS == Python."""
import importlib.util
import json
import random
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from vsec import load_taxonomy, m1_audit, sim

ROOT = Path(__file__).resolve().parent.parent


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


build_sim = _load("build_simulator", "scripts/build_simulator.py")
demo = _load("make_demo_cases", "scripts/make_demo_cases.py")
ATTACKS, FLEET = sim.load_attacks(), sim.load_fleet()
VM_LEVEL = set(FLEET["vm_level"])
M1 = [c["id"] for c in load_taxonomy()["controls"] if c["module"] == "M1"]


@pytest.fixture(scope="module")
def states(tmp_path_factory):
    """Host and VM control states from a fresh REAL audit of the generated fleet folders."""
    d = tmp_path_factory.mktemp("fleet")
    demo.build_fleet(d, FLEET)
    hs = {h["id"]: {f["id"]: f["status"] for f in m1_audit.audit(d / f"host-{h['id']}", env="E1") if f["id"] not in VM_LEVEL}
          for h in FLEET["hosts"]}
    vs = {v["id"]: {f["id"]: f["status"] for f in m1_audit.audit(d / f"vm-{v['id']}", env="E1") if f["id"] in VM_LEVEL}
          for v in FLEET["vms"]}
    return hs, vs


# ---------------------------------------------------------------- data
def test_attack_and_fleet_data_are_valid():
    assert sim.validate() == [] and sim.validate_fleet() == []
    ids = [a["id"] for a in ATTACKS]
    assert len(ids) == len(set(ids)) >= 10


def test_every_gate_is_a_real_m1_control_with_a_fix():
    idx = {c["id"]: c for c in load_taxonomy()["controls"]}
    for c in sim.gate_controls(ATTACKS):
        assert idx[c]["module"] == "M1" and idx[c]["fix"]


def test_validate_rejects_bad_data():
    bad = [{"id": "X", "severity": 9, "origin": "moon", "scope": "all", "steps": [{"lane": "guest", "gates": ["C99"], "why": "w"}]},
           {"id": "Y", "severity": 1, "origin": "guest", "scope": "vm", "steps": [{"lane": "moon", "gates": []}]}]
    problems = " ".join(sim.validate(bad))
    for needle in ("unknown control C99", "bad lane", "no stage can be blocked", "severity must be 1-4", "bad origin", "bad scope"):
        assert needle in problems


def test_validate_fleet_rejects_bad_data():
    bad = {"vm_level": ["C11"], "hosts": [{"id": "h", "faults": ["C11"]}],
           "vms": [{"id": "v", "host": "nope", "criticality": 7, "faults": ["C01"]}]}
    problems = " ".join(sim.validate_fleet(bad))
    assert "not a host-level" in problems and "unknown host" in problems and "criticality" in problems and "not a VM-level" in problems


def test_na_is_never_protection():
    a = ATTACKS[0]
    assert not sim.evaluate(a, {c: "NA" for c in sim.gate_controls([a])})["blocked"]


# ---------------------------------------------------------------- fleet from the real audit
def test_embedded_fleet_equals_a_real_audit(states):
    data = build_sim.build_data()["fleet"]
    hs, vs = states
    assert {h["id"]: h["state"] for h in data["hosts"]} == hs
    assert {v["id"]: v["state"] for v in data["vms"]} == vs


def test_host_and_vm_controls_do_not_mix(states):
    hs, vs = states
    assert all(VM_LEVEL.isdisjoint(s) for s in hs.values())
    assert all(set(s) <= VM_LEVEL for s in vs.values())
    for v in FLEET["vms"]:
        assert set(sim.merged_state(FLEET, hs, vs, v["id"])) == set(M1)


def test_risk_scores_tell_the_expected_story(states):
    hs, vs = states
    risk = {v["id"]: sim.risk(ATTACKS, sim.merged_state(FLEET, hs, vs, v["id"])) for v in FLEET["vms"]}
    assert risk["monitoring"] == 0  # hardened host, hardened VM
    assert risk["payments-db"] < 15  # hardened host, but a VM on a shared network
    assert risk["dev-sandbox"] == max(risk.values())
    assert all(0 <= r <= 100 for r in risk.values())


def test_shared_fate_one_host_control_protects_every_vm_on_the_host(states):
    hs, vs = states
    a03 = next(a for a in ATTACKS if a["id"] == "A03")
    on_a = [v["id"] for v in FLEET["vms"] if v["host"] == "host-a"]
    assert len(on_a) >= 2
    assert all(not sim.evaluate(a03, sim.merged_state(FLEET, hs, vs, i))["blocked"] for i in on_a)
    fixed = {**hs, "host-a": {**hs["host-a"], "C20": "PASS"}}
    assert all(sim.evaluate(a03, sim.merged_state(FLEET, fixed, vs, i))["blocked"] for i in on_a)


# ---------------------------------------------------------------- campaigns
def test_outsider_campaign_chains_across_hosts(states):
    hs, vs = states
    r = sim.campaign(ATTACKS, FLEET, hs, vs, None)
    assert set(r["compromised"]) == {"web-frontend", "ci-runner", "dev-sandbox", "legacy-erp", "payments-db"}
    assert "monitoring" not in r["compromised"]
    assert ("legacy-erp", "payments-db", "A10", "compromised") in r["edges"]  # a hardened host does not save a VM on a shared network


def test_foothold_campaigns(states):
    hs, vs = states
    assert set(sim.campaign(ATTACKS, FLEET, hs, vs, "web-frontend")["compromised"]) == {"web-frontend", "ci-runner"}
    assert sim.campaign(ATTACKS, FLEET, hs, vs, "monitoring")["compromised"] == ["monitoring"]
    assert "payments-db" in sim.campaign(ATTACKS, FLEET, hs, vs, "legacy-erp")["compromised"]


def test_isolating_the_network_cuts_the_lateral_path(states):
    hs, vs = states
    base = sim.campaign(ATTACKS, FLEET, hs, vs, "legacy-erp")
    fixed = {**vs, "payments-db": {**vs["payments-db"], "C15": "PASS"}}
    after = sim.campaign(ATTACKS, FLEET, hs, fixed, "legacy-erp")
    assert "payments-db" in base["compromised"] and "payments-db" not in after["compromised"]


def test_blast_weights_by_criticality(states):
    hs, vs = states
    r = sim.campaign(ATTACKS, FLEET, hs, vs, "web-frontend")
    total = sum(v["criticality"] for v in FLEET["vms"])
    w = sum(v["criticality"] for v in FLEET["vms"] if v["id"] in r["compromised"])
    assert sim.blast(FLEET, r) == (round(100 * w / total), 2, 0)


def test_greedy_containment_plan_reaches_zero(states):
    hs, vs = states
    steps = 0
    while steps < 8:
        adv = sim.containment_advice(ATTACKS, FLEET, hs, vs, None, 1)
        if not adv:
            break
        hs, vs = sim.apply_fixes(hs, vs, adv[0]["fixes"])
        steps += 1
    assert sim.blast(FLEET, sim.campaign(ATTACKS, FLEET, hs, vs, None))[1] == 0
    assert 1 <= steps <= 4


def test_pair_fallback_when_no_single_fix_helps(states):
    hs, vs = states
    adv = sim.containment_advice(ATTACKS, FLEET, hs, vs, "legacy-erp", 5)  # two host-escape paths open on host-b
    assert adv and all(len(x["fixes"]) in (1, 2) for x in adv)
    # inside host-b alone no single fix removes the host escape: pairs of host fixes must appear after the network fixes are gone
    hs2, vs2 = hs, {**vs, "legacy-erp": {**vs["legacy-erp"], "C15": "PASS"}, "payments-db": {**vs["payments-db"], "C15": "PASS"}}
    adv2 = sim.containment_advice(ATTACKS, FLEET, hs2, vs2, "legacy-erp", 5)
    assert adv2 and all(len(x["fixes"]) == 2 for x in adv2)


def test_minimal_fix_set_blocks_everything_and_is_minimal(states):
    hs, vs = states
    st = sim.merged_state(FLEET, hs, vs, "dev-sandbox")
    best = sim.minimal_fix_set(ATTACKS, st)
    assert sim.posture(ATTACKS, {**st, **{c: "PASS" for c in best}})[1] == len(ATTACKS)
    for c in best:
        assert sim.posture(ATTACKS, {**st, **{x: "PASS" for x in best if x != c}})[1] < len(ATTACKS)


# ---------------------------------------------------------------- the page
def test_committed_html_is_up_to_date():
    assert (ROOT / "simulator.html").read_text(encoding="utf-8") == build_sim.render(), "run: python scripts/build_simulator.py"


def test_html_has_the_honesty_statement_and_no_injection_sinks():
    html = (ROOT / "simulator.html").read_text(encoding="utf-8")
    assert "not a measurement" in html and "no exploit code" in html
    assert "innerHTML" not in html and "document.write" not in html and "eval(" not in html


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_javascript_engine_matches_python_engine(tmp_path):
    html = (ROOT / "simulator.html").read_text(encoding="utf-8")
    script = re.search(r"<script>(.*)</script>", html, re.S).group(1)
    head = script[script.index("const D ="):script.index("/*ENGINE-END*/")]
    rng = random.Random(11)
    host_controls = [c for c in M1 if c not in VM_LEVEL and c not in ("C23", "C24")]
    trials = []
    for _ in range(25):
        hs = {h["id"]: {**{c: rng.choice(["PASS", "FAIL"]) for c in host_controls}, "C23": "NA", "C24": "NA"} for h in FLEET["hosts"]}
        vs = {v["id"]: {c: rng.choice(["PASS", "FAIL", "NA"]) for c in sorted(VM_LEVEL)} for v in FLEET["vms"]}
        trials.append([hs, vs])
    starts = [None] + [v["id"] for v in FLEET["vms"]]
    driver = f"""
const T = {json.dumps(trials)}; const STARTS = {json.dumps(starts)}; const FL = D.fleet;
const out = T.map(([hs, vs]) => ({{
  vms: FL.vms.map(v => {{ const st = mergedOf(FL, hs, vs, v.id), p = posture(st);
    return [v.id, p.n, p.depth, riskOf(st), (minimalFix(st) || []).length, Object.values(p.r).map(x => x.by)]; }}),
  camp: STARTS.map(s => {{ const r = campaignOf(FL, hs, vs, s); return [r.compromised, r.exposed, r.persistent, r.edges, blastOf(FL, r)]; }}),
  adv: [null, 'legacy-erp'].map(s => containmentOf(FL, hs, vs, s, 3).map(x => [x.fixes, x.before, x.after, x.gain]))
}}));
console.log(JSON.stringify(out));
"""
    f = tmp_path / "t.js"
    f.write_text(head + "/*ENGINE-END*/\n" + driver, encoding="utf-8")
    js = json.loads(subprocess.run(["node", str(f)], capture_output=True, text=True, check=True, timeout=180).stdout)
    norm = lambda o: json.loads(json.dumps(o))  # noqa: E731  tuples -> lists
    for (hs, vs), got in zip(trials, js):
        for (vid, n, depth, rk, par, bys) in got["vms"]:
            st = sim.merged_state(FLEET, hs, vs, vid)
            res, k = sim.posture(ATTACKS, st)
            assert (n, rk) == (k, sim.risk(ATTACKS, st))
            assert depth == sum(r["blocked"] and r["layers"] >= 2 for r in res.values())
            assert bys == [r["by"] for r in res.values()]
            fix = sim.minimal_fix_set(ATTACKS, st)
            assert par == (len(fix) if fix is not None else 0)
        for s, g in zip(starts, got["camp"]):
            r = sim.campaign(ATTACKS, FLEET, hs, vs, s)
            assert norm([r["compromised"], r["exposed"], r["persistent"], r["edges"], sim.blast(FLEET, r)]) == g
        for s, g in zip([None, "legacy-erp"], got["adv"]):
            py = sim.containment_advice(ATTACKS, FLEET, hs, vs, s, 3)
            assert norm([[x["fixes"], x["before"], x["after"], x["gain"]] for x in py]) == g
