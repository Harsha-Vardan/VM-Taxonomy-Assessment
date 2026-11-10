"""Engine of the what-if attack simulator (simulator.html). See the header of attacks.yaml for what the model claims.

Single-VM rules: a stage is stopped when any of its gate controls is PASS. Fleet rules: hosts share their host-level
controls, VMs own their VM-level controls, and a campaign spreads by the explicit scope rules in `campaign`.
The same rules run in simulator.html (JavaScript); tests/test_simulator.py keeps both in step.
"""
from pathlib import Path

import yaml

from . import control_index

ATTACKS_FILE = Path(__file__).parent / "attacks.yaml"
FLEET_FILE = Path(__file__).parent / "fleet.yaml"
LANES = ("guest", "device", "host", "network")
ORIGINS = ("network", "guest", "local")
SCOPES = ("vm", "host", "neighbour", "leak")


def load_attacks():
    return yaml.safe_load(ATTACKS_FILE.read_text(encoding="utf-8"))["attacks"]


def load_fleet():
    return yaml.safe_load(FLEET_FILE.read_text(encoding="utf-8"))


def validate(attacks=None):
    """Return a list of problems (empty = fine): unknown controls, bad lanes/origin/scope, attacks nothing can stop."""
    attacks = attacks if attacks is not None else load_attacks()
    idx, problems, seen = control_index(), [], set()
    for a in attacks:
        if a["id"] in seen:
            problems.append(f"{a['id']}: duplicate id")
        seen.add(a["id"])
        if a.get("severity") not in (1, 2, 3, 4):
            problems.append(f"{a['id']}: severity must be 1-4")
        if a.get("origin") not in ORIGINS:
            problems.append(f"{a['id']}: bad origin {a.get('origin')!r}")
        if a.get("scope") not in SCOPES:
            problems.append(f"{a['id']}: bad scope {a.get('scope')!r}")
        if not any(s["gates"] for s in a["steps"]):
            problems.append(f"{a['id']}: no stage can be blocked")
        for i, s in enumerate(a["steps"]):
            if s["lane"] not in LANES:
                problems.append(f"{a['id']} stage {i + 1}: bad lane {s['lane']!r}")
            if s["gates"] and not s.get("why"):
                problems.append(f"{a['id']} stage {i + 1}: a gated stage needs a 'why'")
            for g in s["gates"]:
                if g not in idx:
                    problems.append(f"{a['id']} stage {i + 1}: unknown control {g}")
                elif idx[g]["module"] != "M1":
                    problems.append(f"{a['id']} stage {i + 1}: {g} is not an M1 control")
    return problems


def validate_fleet(fleet=None):
    fleet = fleet if fleet is not None else load_fleet()
    idx, problems = control_index(), []
    m1 = {c for c, v in idx.items() if v["module"] == "M1"}
    for c in fleet["vm_level"]:
        if c not in m1:
            problems.append(f"vm_level: {c} is not an M1 control")
    hosts = {h["id"] for h in fleet["hosts"]}
    if len(hosts) != len(fleet["hosts"]):
        problems.append("duplicate host id")
    ids = [v["id"] for v in fleet["vms"]]
    if len(set(ids)) != len(ids):
        problems.append("duplicate vm id")
    for h in fleet["hosts"]:
        for c in h["faults"]:
            if c not in m1 or c in fleet["vm_level"]:
                problems.append(f"host {h['id']}: {c} is not a host-level M1 control")
    for v in fleet["vms"]:
        if v["host"] not in hosts:
            problems.append(f"vm {v['id']}: unknown host {v['host']}")
        if v["criticality"] not in (1, 2, 3):
            problems.append(f"vm {v['id']}: criticality must be 1-3")
        for c in v["faults"]:
            if c not in fleet["vm_level"]:
                problems.append(f"vm {v['id']}: {c} is not a VM-level control")
    return problems


# ---------------------------------------------------------------- single VM
def evaluate(attack, state):
    """state: control id -> 'PASS' | 'FAIL' | 'NA'. Only PASS stops a stage; FAIL and NA do not.

    Returns {'blocked': bool, 'stage': index of the stage that stopped it (or None), 'by': control id (or None),
    'layers': how many distinct controls on this attack's path currently hold (defence in depth)}.
    """
    layers = len({g for s in attack["steps"] for g in s["gates"] if state.get(g) == "PASS"})
    for i, s in enumerate(attack["steps"]):
        for g in s["gates"]:
            if state.get(g) == "PASS":
                return {"blocked": True, "stage": i, "by": g, "layers": layers}
    return {"blocked": False, "stage": None, "by": None, "layers": 0}


def posture(attacks, state):
    results = {a["id"]: evaluate(a, state) for a in attacks}
    return results, sum(r["blocked"] for r in results.values())


def risk(attacks, state):
    """0-100: severity-weighted share of attacks that are open against this VM (its own host + VM controls)."""
    total = sum(a["severity"] for a in attacks)
    open_ = sum(a["severity"] for a in attacks if not evaluate(a, state)["blocked"])
    return round(100 * open_ / total)


def gate_controls(attacks):
    return sorted({g for a in attacks for s in a["steps"] for g in s["gates"]})


def minimal_fix_set(attacks, state):
    """Smallest set of FAIL controls that, once fixed, blocks every attack (minimum hitting set, branch and bound).

    Each attack needs at least one of its gate controls to PASS. Pick an attack that is still open, try each control
    that could stop it, and keep the smallest result. Returns None if some attack has no fixable gate (only NA).
    """
    needs = []
    for a in attacks:
        gates = sorted({g for s in a["steps"] for g in s["gates"]})
        if any(state.get(g) == "PASS" for g in gates):
            continue
        needs.append([g for g in gates if state.get(g) != "NA"])
    best = [None]

    def solve(chosen, open_needs):
        if best[0] is not None and len(chosen) >= len(best[0]):
            return
        if not open_needs:
            best[0] = list(chosen)
            return
        first = min(open_needs, key=len)
        for g in first:
            solve(chosen + [g], [n for n in open_needs if g not in n])

    solve([], needs)
    return sorted(best[0]) if best[0] is not None else None


# ---------------------------------------------------------------- fleet
def merged_state(fleet, host_states, vm_states, vm_id):
    """A VM's full control state: its host's host-level controls plus its own VM-level controls."""
    v = next(x for x in fleet["vms"] if x["id"] == vm_id)
    return {**host_states[v["host"]], **vm_states[vm_id]}


def campaign(attacks, fleet, host_states, vm_states, start=None):
    """Spread of an attacker through the fleet. start=None: an outsider; start=<vm id>: root inside that VM.

    Rules (each scope is explained in attacks.yaml; local-origin attacks need a host account and are not modelled here):
      network origin  an outsider tries it against every VM; evaluated on the target VM's state (once, at the start)
      guest origin    from every compromised VM x:
        host       open on x -> every VM on x's host is compromised
        vm         open on x -> persistence in x (recorded, does not spread)
        neighbour  for each other VM y on x's segment: open on BOTH x and y -> y compromised
        leak       for each other VM y on x's host: open on BOTH x and y -> y exposed (data), not compromised
    Returns {'compromised': [...], 'exposed': [...], 'persistent': [...], 'edges': [(from, to, attack, kind), ...]}.
    """
    vms = {v["id"]: v for v in fleet["vms"]}
    states = {i: merged_state(fleet, host_states, vm_states, i) for i in vms}

    def open_(a, i):
        return not evaluate(a, states[i])["blocked"]

    comp, exposed, persist, edges = [], [], [], []
    seen_edges = set()

    def add_edge(frm, to, a, kind):
        key = (frm, to, a["id"], kind)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append(key)

    def compromise(i, frm, a):
        if i not in comp:
            comp.append(i)
        add_edge(frm, i, a, "compromised")

    guest = [a for a in attacks if a["origin"] == "guest"]
    if start is None:
        for a in (x for x in attacks if x["origin"] == "network"):
            for t in vms:
                if open_(a, t):
                    if a["scope"] == "host":
                        for y in vms:
                            if vms[y]["host"] == vms[t]["host"]:
                                compromise(y, "outside", a)
                    else:
                        compromise(t, "outside", a)
    else:
        comp.append(start)
    done = 0
    while done < len(comp):  # breadth-first; VMs compromised later are processed too
        x = comp[done]
        done += 1
        for a in guest:
            if not open_(a, x):
                continue
            if a["scope"] == "host":
                for y in vms:
                    if vms[y]["host"] == vms[x]["host"] and y != x:
                        compromise(y, x, a)
            elif a["scope"] == "vm":
                if x not in persist:
                    persist.append(x)
            elif a["scope"] == "neighbour":
                for y in vms:
                    if y != x and vms[y]["segment"] == vms[x]["segment"] and open_(a, y):
                        compromise(y, x, a)
            elif a["scope"] == "leak":
                for y in vms:
                    if y != x and vms[y]["host"] == vms[x]["host"] and open_(a, y):
                        if y not in exposed:
                            exposed.append(y)
                        add_edge(x, y, a, "exposed")
    exposed = [i for i in exposed if i not in comp]
    return {"compromised": comp, "exposed": exposed, "persistent": persist, "edges": edges}


def blast(fleet, result):
    """(criticality-weighted share of compromised VMs in %, number compromised, number exposed)."""
    total = sum(v["criticality"] for v in fleet["vms"])
    w = sum(v["criticality"] for v in fleet["vms"] if v["id"] in result["compromised"])
    return round(100 * w / total), len(result["compromised"]), len(result["exposed"])


def _candidates(attacks, fleet, host_states, vm_states):
    """Every (kind, entity, control) that could be fixed: a failing host-level control on a host, or a failing VM-level one on a VM."""
    gates = gate_controls(attacks)
    vm_level = set(fleet["vm_level"])
    out = []
    for h in fleet["hosts"]:
        out += [("host", h["id"], c) for c in gates if c not in vm_level and host_states[h["id"]].get(c) not in ("PASS", "NA")]
    for v in fleet["vms"]:
        out += [("vm", v["id"], c) for c in gates if c in vm_level and vm_states[v["id"]].get(c) not in ("PASS", "NA")]
    return out


def apply_fixes(host_states, vm_states, fixes):
    hs = {k: dict(v) for k, v in host_states.items()}
    vs = {k: dict(v) for k, v in vm_states.items()}
    for kind, ent, c in fixes:
        (hs if kind == "host" else vs)[ent][c] = "PASS"
    return hs, vs


def containment_advice(attacks, fleet, host_states, vm_states, start=None, limit=5):
    """Fixes ranked by how much they shrink the campaign's reach.

    Single fixes first. If no single fix helps (two independent paths are open), fix PAIRS are ranked instead.
    Each entry: {'fixes': [(kind, entity, control), ...], 'before': blast, 'after': blast, 'gain': (dw, dn, de)}.
    """
    base = blast(fleet, campaign(attacks, fleet, host_states, vm_states, start))
    cands = _candidates(attacks, fleet, host_states, vm_states)

    def rank(groups):
        out = []
        for fixes in groups:
            hs, vs = apply_fixes(host_states, vm_states, fixes)
            b = blast(fleet, campaign(attacks, fleet, hs, vs, start))
            gain = (base[0] - b[0], base[1] - b[1], base[2] - b[2])
            if any(g > 0 for g in gain):
                out.append({"fixes": list(fixes), "before": base, "after": b, "gain": gain})
        out.sort(key=lambda r: (-r["gain"][0], -r["gain"][1], -r["gain"][2], r["fixes"]))
        return out[:limit]

    ranked = rank([[c] for c in cands])
    if not ranked:
        ranked = rank([[cands[i], cands[j]] for i in range(len(cands)) for j in range(i + 1, len(cands))])
    return ranked
