#!/usr/bin/env python3
"""M3 on REAL guest memory: acquire a disposable CirrOS VM's memory with `virsh dump` and check Volatility 3's
process and module views against ground truth recorded inside the guest at the same moment.

    sudo .venv/bin/python scripts/real_m3_test.py setup                      # disposable VM vsec-m3 (no NIC)
    sudo .venv/bin/python scripts/real_m3_test.py kernel                     # boot it, print `uname -r`
    sudo VOL=/opt/vol3/bin/vol .venv/bin/python scripts/real_m3_test.py run --symbols <dir> --sha <isf sha256> [--reps 3]
    (symbols: scripts/m3_build_dwarf2json.sh, then scripts/m3_fetch_symbols.sh -> .local/m3/symbols)
    sudo .venv/bin/python scripts/real_m3_test.py tamper --symbols <dir> --sha <sha>   # positive control, see below
    sudo .venv/bin/python scripts/real_m3_test.py cleanup --i-really-mean-it # never automatic

run, per repetition (fresh boot each time):
  1. guest (serial console, root): start 3 marker processes (comm vsgt1..3), let 1 marker process exit (vsgtx),
     then record GROUND TRUTH with shell builtins only (no fork): every /proc/<pid>/comm, /proc/modules.
  2. host: `virsh dump --memory-only` (guest paused while dumping) into .local/m3/dumps/ (gitignored; kept until
     `cleanup` so every result can be re-checked; mode 0400).
  3. Volatility 3 via vsec.m3_forensics: pslist, psscan, lsmod, hidden_modules (raw JSON kept) and detect().
  4. compare: pslist vs guest PIDs, markers in pslist/psscan, hidden PIDs (truth: none), lsmod vs /proc/modules,
     hidden_modules (truth: none), where the exited marker shows up.
tamper (POSITIVE CONTROL, constructed): copies one real dump and unlinks one marker task from the kernel task list
  IN THE COPY ONLY (prev->next and next->prev rewritten, DKOM-style), then runs detect() on the copy. Ground truth:
  exactly that PID is hidden. No code runs in the guest; nothing is loaded into a kernel.
Touches only: domain vsec-m3 (marked), /var/lib/libvirt/images/vsec-m3.qcow2, files under .local/m3/. Hashes
vsec-target, every other domain/network and qemu.conf/libvirtd.conf before and after (via real_gate_validation).
Outputs: results/real/m3/ (m3_real.json, m3_real.md, raw/<run-id>/...).
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import real_gate_validation as gv  # noqa: E402  (Console, virsh wrapper, protected_state)
from vsec import m3_dump as md  # noqa: E402
from vsec import m3_forensics as m3  # noqa: E402

VM = "vsec-m3"
IMG = gv.IMG_DIR / f"{VM}.qcow2"
MARK = "vsec M3 disposable VM: safe to delete with real_m3_test.py cleanup"
OUT = ROOT / "results" / "real" / "m3"
WORK = ROOT / ".local" / "m3"
DUMPS = WORK / "dumps"  # kept until `cleanup` (analysis must be verifiable); symbols/ and build/ are never removed
MARKERS = ("vsgt1", "vsgt2", "vsgt3")
EXITED = "vsgtx"
gv.VMS = gv.VMS + (VM,)  # protected_state() then ignores only our VM besides the (deleted) gate VMs


def own(name):
    if name != VM:
        raise SystemExit(f"refusing to act on {name!r}")
    return name


def is_ours():
    r = gv.virsh("dumpxml", "--inactive", VM, check=False)
    return r.returncode == 0 and MARK in r.stdout


def exists():
    return gv.virsh("domstate", VM, check=False).returncode == 0


XML = f"""<domain type='kvm'>
  <name>{VM}</name>
  <description>{MARK}</description>
  <memory unit='MiB'>256</memory><vcpu>1</vcpu>
  <os><type arch='x86_64' machine='q35'>hvm</type><boot dev='hd'/></os>
  <features><acpi/><apic/></features>
  <devices>
    <disk type='file' device='disk'><driver name='qemu' type='qcow2' cache='none'/>
      <source file='{IMG}'/><target dev='vda' bus='virtio'/></disk>
    <serial type='pty'><target port='0'/></serial>
    <console type='pty'><target type='serial' port='0'/></console>
    <memballoon model='none'/>
  </devices>
</domain>"""  # no NIC, no graphics: no way in or out except the serial console


def setup():
    before = gv.protected_state()
    if exists() and not is_ours():
        raise SystemExit(f"{VM} exists and is not ours")
    if not IMG.exists():
        shutil.copyfile(gv.SOURCE_IMG, IMG)
    os.chmod(IMG, 0o600)
    if not exists():
        p = WORK / "domain.xml"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(XML)
        gv.virsh("define", str(p))
    if gv.protected_state() != before:
        raise SystemExit("PROTECTED STATE CHANGED during setup")
    print(f"ready: {VM}, image {IMG}")


def cleanup(confirm):
    if not confirm:
        raise SystemExit(f"cleanup deletes {VM} and {IMG}; re-run with --i-really-mean-it")
    before = gv.protected_state()
    if exists():
        if not is_ours():
            raise SystemExit(f"{VM} is not marked as ours: refusing")
        gv.virsh("destroy", VM, check=False)
        gv.virsh("undefine", VM)
    if IMG.exists() and not [n for n in gv.virsh("list", "--all", "--name").stdout.split()
                             if str(IMG) in gv.virsh("dumpxml", "--inactive", n, check=False).stdout]:
        IMG.unlink()
    shutil.rmtree(DUMPS, ignore_errors=True)
    if gv.protected_state() != before:
        raise SystemExit("PROTECTED STATE CHANGED during cleanup")
    print(f"removed {VM}, its image and the dumps in {DUMPS}; protected state unchanged")


# ---- guest -----------------------------------------------------------------------------------
def boot():
    if not is_ours():
        raise SystemExit("run setup first")
    gv.virsh("destroy", VM, check=False)
    gv.wait_stopped(VM)
    gv.virsh("start", VM)
    con = gv.Console(own(VM))
    if not con.expect(rb"login:", 300, poke=b"\r"):
        con.close()
        raise SystemExit("no login prompt")
    con.send("cirros", 1.0)
    con.send("gocubsgo", 3.0)
    con.send("sudo -s", 1.5)
    con.send("unset HISTFILE", 0.5)
    return con


def kernel():
    con = boot()
    m = con.run("echo KREL\"=$(uname -r)\"", rb"KREL=(\S+)", 15)
    con.close()
    gv.virsh("destroy", VM, check=False)
    print(m.group(1).decode() if m else "no answer")


def ground_truth(con):
    """Plant markers, let one exit, then read /proc and /proc/modules with shell builtins (no new processes)."""
    for name in MARKERS:  # a shell that renames itself (comm) and stays alive; its child is a `sleep`
        con.send(f"sh -c 'echo {name} > /proc/$$/comm; while :; do sleep 60; done' &", 0.5)
    m = con.run(f"sh -c 'echo {EXITED} > /proc/$$/comm; echo XPID=$$'", rb"XPID=(\d+)", 10)
    exited_pid = int(m.group(1)) if m else None
    time.sleep(1)
    m = con.run('for p in /proc/[0-9]*; do read c < $p/comm; echo "GT ${p#/proc/} $c"; done; echo GT""END',
                rb"GTEND", 30)
    text = con.buf.decode("utf-8", "replace")
    procs = {int(a): b for a, b in re.findall(r"^GT (\d+) (\S+)\r?$", text, re.M)}
    con.run('while read n rest; do echo "MOD $n"; done < /proc/modules; echo MOD""END', rb"MODEND", 15)
    mods = sorted(set(re.findall(r"^MOD (\S+)\r?$", con.buf.decode("utf-8", "replace"), re.M)))
    return {"procs": procs, "modules": mods, "exited_pid": exited_pid,
            "marker_pids": {n: [p for p, c in procs.items() if c == n] for n in MARKERS}}


# ---- analysis (pure parts in vsec/m3_dump.py) ----------------------------------------------
def vol_all(dump, symbols, sha):
    """Raw JSON of the four plugins (for the evidence folder) + m3.detect() on the same dump."""
    staged = m3.stage_verified_symbols(symbols, sha)
    try:
        raw = {name: m3.run_plugin(dump, name, staged) for name in ("pslist", "psscan", "lsmod", "hidden_modules")}
    finally:
        shutil.rmtree(staged, ignore_errors=True)
    det = m3.detect(dump, symbols, expected_sha256=sha)
    return raw, det


def dump_vm(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    t0 = time.time()
    gv.virsh("dump", "--memory-only", VM, str(path), timeout=600)
    os.chmod(path, 0o400)
    return round(time.time() - t0, 1), path.stat().st_size, sha256(path)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def now():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def run(reps, symbols, sha):
    before = gv.protected_state()
    run_id = now()
    raw_dir = OUT / "raw" / run_id
    raw_dir.mkdir(parents=True)
    records = []
    for rep in range(1, reps + 1):
        print(f"[{now()}] rep {rep}: boot", flush=True)
        con = boot()
        try:
            gt = ground_truth(con)
            dump = DUMPS / f"{run_id}-r{rep}.elf"
            secs, size, digest = dump_vm(dump)  # guest is paused while dumping; the console stays attached
        finally:
            con.close()
            gv.virsh("destroy", VM, check=False)
        print(f"   dump {size >> 20} MiB in {secs}s; volatility...", flush=True)
        t0 = time.time()
        raw, det = vol_all(dump, symbols, sha)
        rec = {"rep": rep, "dump_path": str(dump.relative_to(ROOT)), "dump_bytes": size, "dump_seconds": secs, "dump_sha256": digest,
               "vol_seconds": round(time.time() - t0, 1), "ground_truth": gt, "detect": det,
               "comparison": md.compare(gt, raw, det)}
        d = raw_dir / f"r{rep}"
        d.mkdir()
        for name, rows in raw.items():
            (d / f"{name}.json").write_text(json.dumps(rows, indent=1, default=str))
        (d / "record.json").write_text(json.dumps(rec, indent=1, default=str))
        (d / "console.txt").write_text(con.buf[-6000:].decode("utf-8", "replace"))
        records.append(rec)
        print("   ", json.dumps({k: rec["comparison"][k] for k in ("guest_not_in_pslist", "pslist_not_in_guest",
                                  "hidden_pids", "exited_in_psscan", "modules_only_guest", "modules_only_lsmod",
                                  "hidden_modules")}), flush=True)
    after = gv.protected_state()
    res = {"run_id": run_id, "vm": VM, "reps": reps, "vol_version": records[0]["detect"]["vol_version"],
           "symbols_sha256": sha, "env": gv.versions(), "records": records,
           "summary": md.summarise(records), "protected_unchanged": before == after,
           "label": "REAL acquisition of a disposable CirrOS VM (E0 = WSL2). Clean dumps: no hidden object exists."}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"m3_real_{run_id}.json").write_text(json.dumps(res, indent=1, default=str))
    print(json.dumps({"run_id": run_id, "summary": res["summary"], "protected_unchanged": res["protected_unchanged"]}))
    if before != after:
        raise SystemExit("PROTECTED STATE CHANGED")


# ---- positive control: DKOM-style unlink in a COPY of a real dump ----------------------------
def tamper(symbols, sha, src=None):
    """Unlink one marker task in a COPY of a dump; ground truth: that PID is hidden, nothing else."""
    rec_files = sorted(OUT.glob("raw/*/r*/record.json"))
    if not rec_files:
        raise SystemExit("run `run` first")
    rec_path = rec_files[-1]
    rec = json.loads(rec_path.read_text())
    src = Path(src) if src else ROOT / rec["dump_path"]
    if sha256(src) != rec["dump_sha256"]:
        raise SystemExit(f"{src} does not match the sha256 in {rec_path}")
    raw_dir = rec_path.parent
    pslist = json.loads((raw_dir / "pslist.json").read_text())
    psscan = json.loads((raw_dir / "psscan.json").read_text())
    victim = rec["ground_truth"]["marker_pids"][MARKERS[0]][0]
    vrow = next(r for r in pslist if r.get("PID") == victim)
    off_v_key = next(k for k in vrow if "OFFSET" in k.upper() and "V" in k.upper())
    off_p_key = next(k for k in psscan[0] if "OFFSET" in k.upper() and "P" in k.upper())
    t_off = md.tasks_offset(symbols)
    va_to_pid = {r[off_v_key]: r["PID"] for r in pslist if isinstance(r.get("PID"), int)}  # task VA -> pid
    pa = {r["PID"]: r[off_p_key] for r in psscan if isinstance(r.get("PID"), int)}       # task PA by pid
    copy = DUMPS / f"tampered-{src.name}"
    shutil.copyfile(src, copy)
    os.chmod(copy, 0o600)
    with open(copy, "r+b") as f:
        p_pid, n_pid = md.unlink_task(f, md.elf_loads(f), t_off, pa[victim], va_to_pid, pa)
    det = m3.detect(copy, symbols, expected_sha256=sha, exclude_exited=True)
    raw_hidden = sorted(set(det["hidden_pids"]) | {e["pid"] for e in det["excluded_exited"]})
    res = {"source_dump_sha256": rec["dump_sha256"], "source_record": str(rec_path.relative_to(ROOT)),
           "victim_pid": victim, "victim_comm": MARKERS[0], "neighbours": {"prev": p_pid, "next": n_pid},
           "tasks_offset": t_off, "truth_hidden": [victim],
           "detected_hidden_raw": raw_hidden, "detected_hidden_exit_filtered": det["hidden_pids"],
           "excluded_exited": det["excluded_exited"],
           "eval_raw": m3.evaluate([{"name": "tampered", "truth_hidden": [victim], "detected": raw_hidden}]),
           "eval_exit_filtered": m3.evaluate([{"name": "tampered", "truth_hidden": [victim],
                                               "detected": det["hidden_pids"]}]),
           "lsmod_modules": len(det["lsmod_modules"]), "hidden_modules": det["hidden_modules"],
           "label": "CONSTRUCTED positive control: a real dump with one task unlinked in a copy (DKOM-style)."}
    (raw_dir.parent / "tamper.json").write_text(json.dumps(res, indent=1, default=str))
    copy.unlink()
    print(json.dumps({k: res[k] for k in ("victim_pid", "neighbours", "detected_hidden_raw",
                                          "detected_hidden_exit_filtered", "hidden_modules")}))


def analyse(run_id):
    """Recompute every comparison of a run from its saved raw JSON (no VM, no dump needed) with the current
    vsec.m3_dump.compare; writes m3_real_<run>.analysed.json next to the original run file (kept as recorded)."""
    run_file = OUT / f"m3_real_{run_id}.json"
    res = json.loads(run_file.read_text())
    for rec in res["records"]:
        d = OUT / "raw" / run_id / f"r{rec['rep']}"
        raw = {n: json.loads((d / f"{n}.json").read_text()) for n in ("pslist", "psscan", "lsmod", "hidden_modules")}
        gt = {**rec["ground_truth"], "procs": {int(k): v for k, v in rec["ground_truth"]["procs"].items()}}
        rec["comparison"] = md.compare(gt, raw, rec["detect"])
    res["summary"] = md.summarise(res["records"])
    res["vol_version"] = res.get("vol_version") or m3.vol_version(m3._vol())  # the run predates the vol_version fix
    res["analysis"] = "recomputed from raw JSON by `real_m3_test.py analyse` (module names: 'Module Name' key)"
    out = OUT / f"m3_real_{run_id}.analysed.json"
    out.write_text(json.dumps(res, indent=1, default=str))
    print(json.dumps(res["summary"], indent=1))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup")
    sub.add_parser("kernel")
    for name in ("run", "tamper"):
        s = sub.add_parser(name)
        s.add_argument("--symbols", required=True, help="folder holding the verified ISF")
        s.add_argument("--sha", required=True, help="sha256 of the ISF")
        if name == "run":
            s.add_argument("--reps", type=int, default=3)
    an = sub.add_parser("analyse")
    an.add_argument("run_id")
    c = sub.add_parser("cleanup")
    c.add_argument("--i-really-mean-it", action="store_true")
    a = ap.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run as root on the KVM host")
    if a.cmd == "setup":
        setup()
    elif a.cmd == "kernel":
        kernel()
    elif a.cmd == "run":
        run(a.reps, a.symbols, a.sha)
    elif a.cmd == "analyse":
        analyse(a.run_id)
    elif a.cmd == "tamper":
        tamper(a.symbols, a.sha)
    else:
        cleanup(a.i_really_mean_it)


if __name__ == "__main__":
    main()
