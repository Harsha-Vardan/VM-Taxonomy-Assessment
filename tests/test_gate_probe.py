"""Offline tests for the Attack Lab gate-validation probes (vsec/gate_probe.py). No VM, no virsh."""
import json
import socket
import threading
from pathlib import Path

import pytest

from vsec import gate_probe as gp
from vsec import sim
from vsec.score import wilson

REAL = Path(__file__).resolve().parent.parent / "results" / "real"
RUNS = [REAL / "gate_validation" / "gate_validation.json",            # original run: XML-only C14 (paper 7.8 R4)
        REAL / "gate_validation_postfix" / "gate_validation.json"]    # after the C14 runtime fix


def test_probed_stages_are_gated_by_exactly_that_control():
    attacks = sim.load_attacks()
    for cid, aid, idx in gp.PROBED:
        assert cid in gp.stage(attacks, aid, idx)["gates"]


def test_prediction_is_the_simulator_rule():
    attacks = sim.load_attacks()
    for cid, aid, idx in gp.PROBED:
        for st in ("PASS", "FAIL", "NA"):
            state = {g: "FAIL" for a in attacks for s in a["steps"] for g in s["gates"]}
            state[cid] = st
            assert gp.predict_blocked(attacks, aid, idx, state) is (st == "PASS")
            a = next(x for x in attacks if x["id"] == aid)
            if st == "PASS":  # the simulator then stops the chain at this very stage (earlier gates are FAIL)
                assert sim.evaluate(a, state)["stage"] == idx


def test_ungated_stage_cannot_be_validated():
    attacks = sim.load_attacks()
    with pytest.raises(ValueError):
        gp.predict_blocked(attacks, "A02", 2, {})


def test_coverage_counts_gated_stages():
    assert gp.coverage(sim.load_attacks()) == (4, 18)


def test_parse_rfb():
    assert gp.parse_rfb(b"RFB 003.008\n", b"\x01\x01")["none_offered"] is True
    r = gp.parse_rfb(b"RFB 003.008\n", b"\x01\x02")
    assert r["types"] == [2] and not r["none_offered"]
    assert "refused" in gp.parse_rfb(b"RFB 003.008\n", b"\x00\x00\x00\x00\x03bad")["reason"]
    assert gp.parse_rfb(b"HTTP/1.1 200", b"")["reason"] == "no RFB banner"


def _fake_rfb(types):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        c, _ = srv.accept()
        c.sendall(b"RFB 003.008\n")
        c.recv(12)
        c.sendall(bytes([len(types), *types]))
        c.close()
        srv.close()
    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1]


def test_rfb_probe_against_a_fake_server():
    open_ = gp.rfb_probe("127.0.0.1", _fake_rfb([1]))
    assert open_["connected"] and open_["none_offered"]
    assert gp.observe_c11(open_)["blocked"] is False and gp.observe_c12(open_)["blocked"] is False
    locked = gp.rfb_probe("127.0.0.1", _fake_rfb([2]))
    assert gp.observe_c11(locked)["blocked"] is True


def test_refused_connection_blocks_c12_and_gives_no_c11_observation():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens there now
    p = gp.rfb_probe("127.0.0.1", port, timeout=1)
    assert not p["connected"] and p["error"]
    assert gp.observe_c12(p)["blocked"] is True
    assert gp.observe_c11(p)["blocked"] is None


def test_qtree_and_port_byte():
    q = "  dev: isa-fdc, id \"\"\n    iobase = 1008 (0x3f0)\n      dev: floppy, id \"\"\n"
    assert gp.parse_qtree(q) == {"isa_fdc": True, "floppy_drives": 1}
    assert gp.parse_qtree("dev: i8042, id \"\"") == {"isa_fdc": False, "floppy_drives": 0}
    assert gp.parse_port_byte(" 80") == 0x80 and gp.parse_port_byte("ff\r") == 0xFF and gp.parse_port_byte("") is None


def test_c14_observation_uses_the_guest_port_and_flags_qtree_disagreement():
    yes, no = {"isa_fdc": True, "floppy_drives": 0}, {"isa_fdc": False, "floppy_drives": 0}
    assert gp.observe_c14(0x80, yes) == {"blocked": False, "evidence": {"msr": "0x80", "qtree": yes}, "note": ""}
    assert gp.observe_c14(0xFF, no)["blocked"] is True
    assert gp.observe_c14(0xFF, yes)["note"]
    assert gp.observe_c14(None, yes)["blocked"] is None


def test_c17_needs_the_qcow2_magic():
    assert gp.observe_c17(gp.QCOW2_MAGIC + b"\0" * 12, 0)["blocked"] is False
    assert gp.observe_c17(b"", 1, "Permission denied")["blocked"] is True
    assert gp.observe_c17(b"garbage", 0)["blocked"] is True


def test_summarise_counts_disagreements_by_direction():
    rows = [{"control": "C14", "predicted_blocked": True, "observed_blocked": False},
            {"control": "C14", "predicted_blocked": True, "observed_blocked": True},
            {"control": "C17", "predicted_blocked": False, "observed_blocked": True},
            {"control": "C17", "predicted_blocked": False, "observed_blocked": None}]
    s = gp.summarise(rows, wilson)
    assert s["overall"] == {"n": 3, "agree": 1, "ci": list(wilson(1, 3)), "unsafe_disagreements": 1,
                            "conservative_disagreements": 1, "no_observation": 1}
    assert s["per_control"]["C14"]["unsafe_disagreements"] == 1


@pytest.mark.parametrize("path", RUNS, ids=["original", "postfix"])
def test_committed_real_results_are_internally_consistent(path):
    if not path.exists():
        pytest.skip("no real gate-validation run committed")
    res = json.loads(path.read_text(encoding="utf-8"))
    assert res["protected_unchanged"] is True
    assert res["summary"] == gp.summarise(res["rows"], wilson)
    for r in res["rows"]:
        assert r["predicted_blocked"] is (r["m1"] == "PASS")  # each probed stage has a single gate
        assert r["agree"] == (None if r["observed_blocked"] is None else r["predicted_blocked"] == r["observed_blocked"])
    assert all(rec["legit_access"]["ok"] for rec in res["records"] if int(rec["arm"]["mode"]) == 0o600)


def test_recorded_numbers_match_the_paper():
    """Paper 7.8 R4 quotes these counts; they must come from the committed runs."""
    orig, post = (json.loads(p.read_text(encoding="utf-8")) for p in RUNS)
    o = orig["summary"]
    assert (o["overall"]["agree"], o["overall"]["n"], o["overall"]["unsafe_disagreements"]) == (54, 60, 6)
    assert {c: v["agree"] for c, v in o["per_control"].items()} == {"C11": 15, "C12": 15, "C14": 9, "C17": 15}
    assert (post["summary"]["overall"]["agree"], post["summary"]["overall"]["n"]) == (20, 20)
    paper = (REAL.parent.parent / "docs" / "paper" / "paper.md").read_text(encoding="utf-8")
    assert "| All | 60 | 54 (Wilson 95% CI 0.80-0.95) | 6 | 0 |" in paper and "20 of 20" in paper
