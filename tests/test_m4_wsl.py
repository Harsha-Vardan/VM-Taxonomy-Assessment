"""Limited M4 run (WSL2 vs KVM inside WSL2): helpers and the committed raw data agree with the stated findings."""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "results/real/m4_wsl/raw/20261116T053926Z"
spec = importlib.util.spec_from_file_location("a", ROOT / "scripts/analyse_m4_wsl.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def test_cliff_and_holm():
    assert a.cliff([3, 4], [1, 2]) == 1.0 and a.cliff([1, 2], [3, 4]) == -1.0
    assert a.holm([0.01, 0.04, 0.03]) == pytest.approx([0.03, 0.06, 0.06])


@pytest.mark.skipif(not RAW.exists(), reason="raw data not present")
def test_raw_run_matches_reported_findings():
    units = a.load(RAW)
    assert len(units) == 40 and all(u["n"] == 30 and u["exit"] == "0" for u in units)
    for w in a.load.__globals__["np"].unique([u["workload"] for u in units]):
        host = [u["median"]["cpuid_tsc"] for u in units if u["workload"] == w and u["env"] == "wsl2-host"]
        guest = [u["median"]["cpuid_tsc"] for u in units if u["workload"] == w and u["env"] == "kvm-in-wsl2"]
        assert min(guest) > 5 * max(host)  # complete separation, every session
    guest_ipc = [u["median"]["ipc"] for u in units if u["env"] == "kvm-in-wsl2"]
    assert all(x != x for x in guest_ipc)  # NaN: no vPMU in the guest
    meta = json.loads((RAW / "run.json").read_text())
    assert "Not native" in meta["note"]
