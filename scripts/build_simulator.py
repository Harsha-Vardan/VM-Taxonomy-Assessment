"""Build simulator.html: the what-if Attack Lab, one self-contained file.

    python scripts/build_simulator.py [out_file]       (default: simulator.html in the project root)

Everything on the page comes from the project itself:
  controls  vsec/taxonomy.yaml (M1 controls only: the ones that can gate an attack)
  attacks   vsec/attacks.yaml  (validated by vsec.sim.validate; the build refuses to run on problems)
  fleet     vsec/fleet.yaml: hosts, VMs and their control states, produced by a REAL `vsec audit` of generated case
            folders (scripts/make_demo_cases.py build_fleet); host-level controls come from the host, VM-level from the VM
tests/test_simulator.py fails when the committed simulator.html is out of date.
"""
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vsec import load_taxonomy, m1_audit, sim  # noqa: E402

TEMPLATE = ROOT / "scripts" / "simulator_template.html"
MARK = "null/*__DATA__*/"


def _demo_builder():
    spec = importlib.util.spec_from_file_location("make_demo_cases", ROOT / "scripts" / "make_demo_cases.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def fleet_states(fleet):
    """Audit one generated case folder per host and per VM with the REAL M1 auditor; keep each entity's own controls."""
    vm_level = set(fleet["vm_level"])
    with tempfile.TemporaryDirectory() as tmp:
        demo = _demo_builder()
        demo.build_fleet(tmp, fleet)
        hosts = [{**{k: h[k] for k in ("id", "name", "note")},
                  "state": {f["id"]: f["status"] for f in m1_audit.audit(Path(tmp) / f"host-{h['id']}", env="E1")
                            if f["id"] not in vm_level}} for h in fleet["hosts"]]
        vms = [{**{k: v[k] for k in ("id", "name", "role", "host", "segment", "criticality")},
                "state": {f["id"]: f["status"] for f in m1_audit.audit(Path(tmp) / f"vm-{v['id']}", env="E1")
                          if f["id"] in vm_level}} for v in fleet["vms"]]
    return {"vm_level": list(fleet["vm_level"]), "hosts": hosts, "vms": vms}


def build_data():
    problems = sim.validate() + sim.validate_fleet()
    if problems:
        raise SystemExit("attacks.yaml / fleet.yaml have problems: " + "; ".join(problems))
    tax = load_taxonomy()
    controls = {c["id"]: {k: c[k] for k in ("id", "control", "threat", "severity", "expected", "fix", "survey")}
                for c in tax["controls"] if c["module"] == "M1"}
    return {"controls": controls, "order": list(controls), "attacks": sim.load_attacks(),
            "fleet": fleet_states(sim.load_fleet())}


def render():
    blob = json.dumps(build_data(), ensure_ascii=True, separators=(",", ":"))
    blob = blob.replace("</", "<\\/")
    html = TEMPLATE.read_text(encoding="utf-8")
    assert html.count(MARK) == 1, "template placeholder missing"
    return html.replace(MARK, blob)


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "simulator.html"
    out.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {out} ({out.stat().st_size // 1024} KB)")
