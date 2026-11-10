"""The hand-built demo targets must keep telling the before/after story the demo relies on."""
import importlib.util
from pathlib import Path

from vsec import m1_audit

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("make_demo_cases", ROOT / "scripts" / "make_demo_cases.py")
mdc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mdc)


def statuses(folder):
    return {f["id"]: f["status"] for f in m1_audit.audit(folder, env="E1")}


def test_weak_hardened_and_fixed_tell_the_before_after_story(tmp_path):
    mdc.build(tmp_path)
    weak, hard, fixed = (statuses(tmp_path / n) for n in ("weak", "hardened", "weak-fixed"))
    assert sum(v == "FAIL" for v in weak.values()) >= 20
    assert "FAIL" not in hard.values()
    assert [c for c, v in fixed.items() if v == "FAIL"] == ["C25"]  # a CPU vulnerability needs a microcode update
    assert {c for c, v in weak.items() if v == "NA"} == {"C23", "C24"}  # unverified CVE list: NA, never PASS


def test_no_control_flips_from_pass_to_fail_after_fixing(tmp_path):
    mdc.build(tmp_path)
    weak, fixed = statuses(tmp_path / "weak"), statuses(tmp_path / "weak-fixed")
    assert not [c for c in weak if weak[c] == "PASS" and fixed[c] == "FAIL"]
