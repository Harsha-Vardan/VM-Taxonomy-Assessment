"""Build the case folders of the Attack Lab's EXAMPLE FLEET (vsec/fleet.yaml) so the real M1 auditor can give their
control states. MODEL INPUT: the fleet is an invented scenario and these folders are constructed, not captured
from a machine. Used by scripts/build_simulator.py and tests/test_simulator.py.
"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("make_fixtures", ROOT / "tests" / "make_fixtures.py")
mf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mf)


def settings_for(faults):
    """make_fixtures settings that break exactly these controls (the first seeded fault of each)."""
    s = {}
    for cid in faults:
        fault = mf.FAULTS[cid][2] if cid == "C16" else mf.FAULTS[cid][0]
        s.update(fault)
    if "C11" in faults and "C12" in faults:
        s["x.graphics"] = "vnc|0.0.0.0|"  # open to the network AND no password
    return s


def build_fleet(out, fleet):
    """One case folder per host (host-level faults) and per VM (VM-level faults), audited separately by the build."""
    out = Path(out)
    for kind, items in (("host", fleet["hosts"]), ("vm", fleet["vms"])):
        for it in items:
            folder = out / f"{kind}-{it['id']}"
            folder.mkdir(parents=True, exist_ok=True)
            for fn, text in mf.files_for(settings_for(it["faults"]), e0=False).items():
                with open(folder / fn, "w", encoding="utf-8", newline="") as fh:
                    fh.write(text)
            (folder / "PROVENANCE").write_text(PROVENANCE_NOTE, encoding="utf-8", newline="")
    return out


PROVENANCE_NOTE = "constructed: Attack Lab example-fleet input (model). Not evidence about a real system.\n"
