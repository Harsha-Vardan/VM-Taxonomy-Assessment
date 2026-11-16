"""Provenance tags and the pure runtime-validation observers / comparison."""
import json
from pathlib import Path

from vsec import m1_audit, provenance as pv, runtime_check as rc

ROOT = Path(__file__).resolve().parent.parent


def test_constructed_folders_are_tagged(tmp_path):
    import importlib.util
    from vsec import sim
    spec = importlib.util.spec_from_file_location("mfc", ROOT / "scripts/make_fleet_cases.py")
    mfc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mfc)
    mfc.build_fleet(tmp_path, sim.load_fleet())
    for folder in [p for p in tmp_path.iterdir() if p.is_dir()][:3]:
        assert pv.case_kind(folder) == "constructed"
        assert {f["provenance"] for f in m1_audit.audit(str(folder), env="E1")} == {"constructed"}


def test_recorded_real_cases_are_live():
    case = ROOT / "results/real/runtime_validation/raw/20261116T063834Z/arm-A/assess/case"
    if case.exists():
        assert pv.case_kind(case) == "live"


def test_live_case_tags(tmp_path):
    (tmp_path / pv.MANIFEST).write_text("{}")
    assert pv.case_kind(tmp_path) == "live"
    assert pv.control_source("C04", tmp_path) == "live-runtime"
    assert pv.control_source("C12", tmp_path) == "live-config"
    assert pv.control_source("C14", tmp_path) == "live-config"
    (tmp_path / "qemu_devices").write_text("isa-fdc\n")
    assert pv.control_source("C14", tmp_path) == "live-runtime"
    (tmp_path / "PROVENANCE").write_text("constructed: copy of a fixture")
    assert pv.case_kind(tmp_path) == "constructed"


def test_observers():
    assert rc.obs_c04("Seccomp:\t2\nSeccomp_filters:\t1\n")["status"] == "PASS"
    assert rc.obs_c04("Seccomp:\t0\n")["status"] == "FAIL"
    assert rc.obs_c04(None)["status"] == "NA"
    assert rc.obs_c06("unconfined\n", {"apparmor": "N\n", "selinux_enforce": None})["status"] == "FAIL"
    assert rc.obs_c06("libvirt-1234 (enforce)", {"apparmor": "Y", "selinux_enforce": None})["status"] == "PASS"
    assert rc.obs_c06("libvirt-1234 (enforce)", {"apparmor": "N", "selinux_enforce": None})["status"] == "FAIL"
    open_rfb = {"connected": True, "version": "RFB 003.008", "none_offered": True}
    assert rc.obs_c11(open_rfb)["status"] == "FAIL" and rc.obs_c12(open_rfb)["status"] == "FAIL"
    closed = {"connected": False, "version": "", "none_offered": False}
    assert rc.obs_c11(closed)["status"] == "NA" and rc.obs_c12(closed)["status"] == "PASS"
    assert rc.obs_c14(0xFF, {"isa_fdc": False, "floppy_drives": 0})["status"] == "PASS"
    assert rc.obs_c14(0x80, {"isa_fdc": True, "floppy_drives": 0})["status"] == "FAIL"
    assert rc.obs_c14(None, {"isa_fdc": True, "floppy_drives": 0})["status"] == "NA"
    assert rc.obs_c16(True)["status"] == "FAIL" and rc.obs_c16(False)["status"] == "PASS" and rc.obs_c16(None)["status"] == "NA"


def test_compare_and_report():
    findings = [{"id": "C16", "status": "PASS", "evidence": "host-verified", "provenance": "live-config"},
                {"id": "C04", "status": "PASS", "evidence": "Seccomp: 2", "provenance": "live-runtime"}]
    obs = {"C16": rc.obs_c16(True), "C04": rc.obs_c04("Seccomp:\t2\n")}
    rows = rc.compare(findings, obs)
    by = {r["id"]: r for r in rows}
    assert by["C16"]["agree"] is False and by["C04"]["agree"] is True and by["C11"]["agree"] is None
    assert rc.summary(rows) == {"agree": 1, "disagree": 1, "unobserved": 4}
    md = rc.markdown({"run_id": "t", "meta": {"env": "E0"}, "arms": [{"arm": "X", "vm": "v", "config": {}, "rows": rows}]})
    assert "**NO**" in md and "arm X, C16" in md
    json.dumps(rows)


def test_c16_peer_paths():
    from vsec.m1_audit import peer_paths
    assert peer_paths("no-interfaces")[0] == "PASS"
    assert peer_paths("own vnet0 bridge=br0 isolated=0")[0] == "PASS"  # alone on its bridge
    assert peer_paths("own vnet0 bridge=br0 isolated=0\npeer vnet1 bridge=br0 isolated=0")[0] == "FAIL"
    assert peer_paths("own vnet0 bridge=br0 isolated=1\npeer vnet1 bridge=br0 isolated=0")[0] == "FAIL"  # one side only
    assert peer_paths("own vnet0 bridge=br0 isolated=1\npeer vnet1 bridge=br0 isolated=1")[0] == "PASS"
    assert peer_paths("own vnet0 bridge=br0 isolated=1\npeer vnet1 bridge=br0 isolated=?")[0] == "NA"
    assert peer_paths("unknown: vnet0 is not a bridge port")[0] == "NA"


def test_net_peers_reads_fake_sysfs(tmp_path):
    import os
    from vsec.collect import net_peers
    if not hasattr(os, "symlink"):
        return
    br = tmp_path / "virbr9"
    (br / "brif").mkdir(parents=True)
    for dev, iso in (("vnet0", "1"), ("vnet1", "0")):
        (tmp_path / dev / "brport").mkdir(parents=True)
        (tmp_path / dev / "brport" / "isolated").write_text(iso + "\n")
        try:
            os.symlink(br, tmp_path / dev / "brport" / "bridge")
        except OSError:
            return  # no symlink privilege on this Windows account
        (br / "brif" / dev).write_text("")
    xml = "<domain><devices><interface type='network'><target dev='vnet0'/></interface></devices></domain>"
    out = net_peers(xml, sys_net=str(tmp_path))
    assert out.splitlines() == ["own vnet0 bridge=virbr9 isolated=1", "peer vnet1 bridge=virbr9 isolated=0"]
    assert net_peers("<domain><devices/></domain>", sys_net=str(tmp_path)) == "no-interfaces"


RV = ROOT / "results/real/runtime_validation/raw"


def test_recorded_runs_are_consistent():
    import pytest
    first, ten = RV / "20261116T060915Z/run.json", RV / "20261116T063834Z/run.json"
    if not ten.exists():
        pytest.skip("runtime-validation data not present")
    a = json.loads(first.read_text())
    assert a["summary"] == {"agree": 16, "disagree": 2, "unobserved": 0}  # historical run, old C16 rule
    b = json.loads(ten.read_text())
    assert b["summary"] == {"agree": 60, "disagree": 0, "unobserved": 0} and b["meta"]["protected_state_unchanged"]
    for arm in b["arms"]:
        tags = {f["id"]: f["provenance"] for f in arm["findings"]}
        assert set(tags.values()) <= {"live-runtime", "live-config"}
        assert tags["C16"] == tags["C14"] == tags["C04"] == "live-runtime"
        assert tags["C11"] == tags["C12"] == "live-config"
    c16 = {arm["arm"]: next(r["observed"] for r in arm["rows"] if r["id"] == "C16") for arm in b["arms"]}
    assert {k for k, v in c16.items() if v == "PASS"} == {"D", "F", "G", "J"}  # blocked paths
    for p in RV.rglob("*.xml"):
        assert "passwd='REDACTED'" in p.read_text() or "passwd=" not in p.read_text()
