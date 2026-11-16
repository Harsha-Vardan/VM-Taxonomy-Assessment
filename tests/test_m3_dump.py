"""Offline tests for vsec/m3_dump.py (real-M3 helpers). A synthetic ELF core stands in for a `virsh dump`."""
import ast
import io
import json
import lzma
import struct
from pathlib import Path

import pytest

from vsec import m3_dump as md

T_OFF = 0x30          # task_struct.tasks offset in the fake layout
KBASE = 0xFFFF888000000000  # direct map: VA = KBASE + PA


def elf_core(segments):
    """segments: [(paddr, bytes)] -> a minimal ELF64 LE core with one PT_LOAD per segment."""
    phoff, phent = 64, 56
    data_off = phoff + phent * len(segments)
    hdr = bytearray(64)
    hdr[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HHIQQQIHHHHHH", hdr, 0x10, 4, 62, 1, 0, phoff, 0, 0, 64, phent, len(segments), 0, 0, 0)
    phdrs, blobs, off = b"", b"", data_off
    for pa, blob in segments:
        phdrs += struct.pack("<IIQQQQQQ", 1, 7, off, KBASE + pa, pa, len(blob), len(blob), 0x1000)
        blobs += blob
        off += len(blob)
    return bytes(hdr) + phdrs + blobs


def task_ring(pas):
    """Physical memory (one segment from 0) holding tasks at the given PAs, linked in a circular list."""
    mem = bytearray(0x4000)
    for i, pa in enumerate(pas):
        nxt, prv = pas[(i + 1) % len(pas)], pas[i - 1]
        struct.pack_into("<QQ", mem, pa + T_OFF, KBASE + nxt + T_OFF, KBASE + prv + T_OFF)
    return bytes(mem)


def walk(f, loads, start_pa):
    """PIDs reachable by following tasks.next from start_pa (like pslist walking init_task.tasks)."""
    seen, pa = [], start_pa
    while True:
        seen.append(pa)
        f.seek(md.phys_to_file(loads, pa + T_OFF))
        pa = struct.unpack("<Q", f.read(8))[0] - T_OFF - KBASE
        if pa == start_pa:
            return seen


def test_elf_loads_and_translation():
    raw = elf_core([(0x0, b"A" * 0x100), (0x100000, b"B" * 0x100)])
    f = io.BytesIO(raw)
    loads = md.elf_loads(f)
    assert [(pa, n) for pa, _, n in loads] == [(0, 0x100), (0x100000, 0x100)]
    f.seek(md.phys_to_file(loads, 0x100010))
    assert f.read(1) == b"B"
    with pytest.raises(ValueError):
        md.phys_to_file(loads, 0x200000)
    with pytest.raises(ValueError):
        md.phys_to_file(loads, 0xFC)  # an 8-byte read would run past the segment
    with pytest.raises(ValueError):
        md.elf_loads(io.BytesIO(b"not an elf" * 10))


def test_unlink_removes_exactly_one_task_from_the_list():
    pas = [0x100, 0x800, 0x1000, 0x2000]  # pid 1..4
    f = io.BytesIO(elf_core([(0, task_ring(pas))]))
    loads = md.elf_loads(f)
    pa_by_pid = {i + 1: pa for i, pa in enumerate(pas)}
    va_to_pid = {KBASE + pa: pid for pid, pa in pa_by_pid.items()}
    assert walk(f, loads, pas[0]) == pas
    prev_pid, next_pid = md.unlink_task(f, loads, T_OFF, pa_by_pid[3], va_to_pid, pa_by_pid)
    assert (prev_pid, next_pid) == (2, 4)
    assert walk(f, loads, pas[0]) == [0x100, 0x800, 0x2000]  # pid 3 is gone from the list ...
    f.seek(md.phys_to_file(loads, pas[2] + T_OFF))
    assert struct.unpack("<Q", f.read(8))[0] == KBASE + pas[3] + T_OFF  # ... but its own struct is untouched


def test_unlink_refuses_unknown_neighbours():
    pas = [0x100, 0x800, 0x1000]
    f = io.BytesIO(elf_core([(0, task_ring(pas))]))
    with pytest.raises(ValueError):
        md.unlink_task(f, md.elf_loads(f), T_OFF, pas[1], {}, {1: pas[0], 2: pas[1], 3: pas[2]})


@pytest.mark.parametrize("xz", [False, True])
def test_tasks_offset_from_isf(tmp_path, xz):
    isf = json.dumps({"user_types": {"task_struct": {"fields": {"tasks": {"offset": 2280}}}}}).encode()
    (tmp_path / ("k.json.xz" if xz else "k.json")).write_bytes(lzma.compress(isf) if xz else isf)
    assert md.tasks_offset(tmp_path) == 2280


def test_compare_against_guest_ground_truth():
    gt = {"procs": {1: "init", 476: "vsgt1", 478: "vsgt2", 900: "cat"}, "modules": ["virtio_net", "e1000"],
          "exited_pid": 482, "marker_pids": {"vsgt1": [476], "vsgt2": [478]}}
    raw = {"pslist": [{"PID": 1, "COMM": "init"}, {"PID": 476, "COMM": "vsgt1\n"}, {"PID": 478, "COMM": "sleep"}],
           "psscan": [{"PID": p, "EXIT_STATE": "TASK_RUNNING"} for p in (1, 476, 478)]
           + [{"PID": 482, "EXIT_STATE": "EXIT_DEAD"}, {"PID": 777, "EXIT_STATE": "TASK_RUNNING"}],
           "lsmod": [{"Module Name": "virtio_net"}, {"Name": "e1000"}], "hidden_modules": []}
    c = md.compare(gt, raw, {"hidden_pids": [482, 777], "hidden_modules": []})
    assert c["guest_not_in_pslist"] == [900] and c["pslist_not_in_guest"] == []
    assert c["markers_in_pslist"] == {"vsgt1": True, "vsgt2": True} and c["name_mismatches"] == [478]
    assert c["exited_in_psscan"] and not c["exited_in_pslist"]
    assert c["psscan_only"] == c["false_hidden"] == [482, 777] and c["psscan_only_exited"] == [482]
    assert c["false_hidden_after_exit_filter"] == [777] and c["psscan_only_live_in_guest"] == []
    assert c["modules_only_guest"] == c["modules_only_lsmod"] == []


def test_experiment_script_parses_and_uses_the_shared_helpers():
    src = (Path(__file__).resolve().parent.parent / "scripts" / "real_m3_test.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    called = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and getattr(n.value, "id", "") == "md"}
    assert {"compare", "elf_loads", "unlink_task", "tasks_offset"} <= called


def test_summarise_counts_boots():
    ok = {"name_mismatches": [], "guest_not_in_pslist": [], "pslist_not_in_guest": [], "markers_in_pslist": {"a": True},
          "markers_in_psscan": {"a": True}, "exited_in_psscan": True, "exited_in_pslist": False, "false_hidden": [],
          "false_hidden_after_exit_filter": [], "psscan_only_live_in_guest": [],
          "modules_only_guest": [], "modules_only_lsmod": [], "hidden_modules": []}
    bad = {**ok, "guest_not_in_pslist": [9], "false_hidden": [7, 8], "false_hidden_after_exit_filter": [8],
           "hidden_modules": ["x"], "exited_in_psscan": False}
    s = md.summarise([{"comparison": ok}, {"comparison": bad}])
    assert s["boots"] == 2 and s["pslist_equals_guest"] == 1 and s["dumps_with_false_hidden_raw"] == 1
    assert s["false_hidden_raw_per_dump"] == [0, 2] and s["dumps_with_false_hidden_after_exit_filter"] == 1
    assert s["dumps_with_hidden_modules"] == 1 and s["exited_in_psscan"] == 1 and s["dumps_with_live_hidden"] == 0


def test_module_name_handles_both_volatility_formats():
    from vsec.m3_forensics import _names, module_name
    assert module_name({"Module Name": "ahci", "Offset": 1}) == "ahci" and module_name({"Name": "e1000"}) == "e1000"
    assert _names([{"Module Name": "b"}, {"Name": "a"}]) == ["a", "b"]


def test_kworker_names_differ_only_by_the_workqueue_suffix():
    assert md.same_name("kworker/0:0H-events_highpri", "kworker/0:0H")
    assert md.same_name("vsgt1", "vsgt1\n") and not md.same_name("sshd", "sh")
    assert not md.same_name("evil-events", "evil")  # the suffix rule applies to kworker threads only


def test_unlink_accepts_volatility_48_bit_virtual_addresses():
    kb = 0xFFFF8D3680000000  # canonical direct-map base, as stored in memory
    pas = [0x100, 0x800, 0x1000]
    mem = bytearray(0x4000)
    for i, pa in enumerate(pas):
        struct.pack_into("<QQ", mem, pa + T_OFF, kb + pas[(i + 1) % 3] + T_OFF, kb + pas[i - 1] + T_OFF)
    f = io.BytesIO(elf_core([(0, bytes(mem))]))
    pa_by_pid = {i + 1: pa for i, pa in enumerate(pas)}
    va_volatility = {(kb + pa) & md.VA_MASK: pid for pid, pa in pa_by_pid.items()}  # 0x8d36... as vol prints it
    assert md.unlink_task(f, md.elf_loads(f), T_OFF, pas[1], va_volatility, pa_by_pid) == (1, 3)
    f.seek(md.phys_to_file(md.elf_loads(f), pas[0] + T_OFF))
    assert struct.unpack("<Q", f.read(8))[0] == kb + pas[2] + T_OFF  # full canonical pointer written back


REAL_M3 = Path(__file__).resolve().parent.parent / "results" / "real" / "m3"


@pytest.mark.skipif(not (REAL_M3 / "m3_real_20261115T154525Z.analysed.json").exists(), reason="no real M3 run")
def test_committed_real_m3_results_recompute_from_raw_evidence():
    run = "20261115T154525Z"
    res = json.loads((REAL_M3 / f"m3_real_{run}.analysed.json").read_text(encoding="utf-8"))
    assert res["protected_unchanged"] is True and res["reps"] == 3
    for rec in res["records"]:
        d = REAL_M3 / "raw" / run / f"r{rec['rep']}"
        raw = {n: json.loads((d / f"{n}.json").read_text(encoding="utf-8"))
               for n in ("pslist", "psscan", "lsmod", "hidden_modules")}
        gt = {**rec["ground_truth"], "procs": {int(k): v for k, v in rec["ground_truth"]["procs"].items()}}
        assert md.compare(gt, raw, rec["detect"]) == rec["comparison"]
    s = res["summary"]
    assert s == md.summarise(res["records"])
    assert (s["pslist_equals_guest"], s["lsmod_equals_guest"], s["names_equal_guest"]) == (3, 3, 3)
    assert s["dumps_with_false_hidden_after_exit_filter"] == 0 and s["false_hidden_raw_per_dump"] == [8, 8, 8]
    t = json.loads((REAL_M3 / "raw" / run / "tamper.json").read_text(encoding="utf-8"))
    assert t["detected_hidden_exit_filtered"] == t["truth_hidden"] == [475]
    assert t["victim_pid"] in t["detected_hidden_raw"] and t["eval_raw"]["false_items"] == 8
    v = json.loads((REAL_M3 / "isf_verification.json").read_text(encoding="utf-8"))
    assert v["ok"] and v["banner_match"] and v["sha256_ok"]
