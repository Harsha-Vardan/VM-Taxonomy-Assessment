#!/usr/bin/env python3
"""LIMITED M4 experiment: WSL2 host vs a KVM guest running INSIDE WSL2 (one extra virtualization layer).
This is NOT native-vs-VM: the WSL2 "host" is itself a Hyper-V guest. No native baseline exists here.

    sudo .venv/bin/python scripts/real_m4_wsl_test.py run [--sessions 5] [--windows 30]
Per session: the same static bench binary (vsec/m4_detect/bench.c, BUF_SIZE 32 MiB so it fits the 256 MiB guest)
runs the four workloads idle, cpu, mem, mixed (window_ms 100) on
  * wsl2-host: in WSL2, one fresh process per workload;
  * kvm-in-wsl2: in the disposable VM vsec-m3 (fresh boot per session; binary copied over the serial console,
    sha256 checked in the guest).
Touches only vsec-m3 (marked, from real_m3_test.py) and files under .local/m4wsl/. Output: results/real/m4_wsl/raw/<run>/.
"""
import argparse
import base64
import gzip
import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import real_m3_test as m3t  # noqa: E402  (boot(), VM marker checks, Console via real_gate_validation)

WORK = ROOT / ".local" / "m4wsl"
OUT = ROOT / "results" / "real" / "m4_wsl" / "raw"
WORKLOADS = ("idle", "cpu", "mem", "mixed")
BUF = "(32*MB)"
WIN_MS = 100
CSV_HEADER = ("window,workload,elapsed_ms,cpuid_tsc,rdtsc_tsc,syscall_ns,pagefault_ns,seq_ns,stride_ns,rand_ns,"
              "sleep_jitter_us,ipc,dtlb_miss")


def build():
    WORK.mkdir(parents=True, exist_ok=True)
    out = WORK / "bench32"
    subprocess.run(["gcc", "-O2", "-static", f"-DBUF_SIZE={BUF}", "-o", str(out),
                    str(ROOT / "vsec/m4_detect/bench.c"), "-lm"], check=True)
    return out


def parse(text, env, session, workload):
    """Keep CSV rows of this workload and '#' metadata; drop console noise."""
    rows, meta = [], []
    for ln in text.replace("\r", "").split("\n"):
        ln = ln.strip()
        if ln.startswith("# "):
            meta.append(ln)
        elif re.match(rf"^\d+,{workload},", ln):
            rows.append(ln)
    return {"env": env, "session": session, "workload": workload, "rows": rows, "meta": meta}


def host_session(binary, session, n):
    res = []
    for w in WORKLOADS:
        r = subprocess.run([str(binary), w, str(WIN_MS), str(n)], capture_output=True, text=True, timeout=600)
        d = parse(r.stdout + "\n" + r.stderr, "wsl2-host", session, w)
        d["exit"] = r.returncode
        res.append(d)
    return res


def push_binary(con, binary):
    data = binary.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    b64 = base64.b64encode(gzip.compress(data, 9)).decode()
    con.send("cd /tmp; rm -f b.gz.b64 b.gz bench; stty -echo", 1.0)
    step = 900
    for i in range(0, len(b64), step):
        con.send(f"echo {b64[i:i + step]}>>b.gz.b64", 0.02)
        if (i // step) % 40 == 39:
            con.run(f"echo SYNC{i}", rf"SYNC{i}".encode(), 60)
    con.send("stty echo", 0.5)
    m = con.run("base64 -d b.gz.b64 > b.gz && gunzip b.gz && mv b bench && chmod +x bench; sha256sum bench",
                rb"([0-9a-f]{64})\s+bench", 120)
    got = m.group(1).decode() if m else None
    if got != sha:
        raise SystemExit(f"binary transfer failed: {got} != {sha}")
    return sha


def guest_session(binary, session, n):
    con = m3t.boot()
    try:
        sha = push_binary(con, binary)
        res = []
        for w in WORKLOADS:
            m = con.run(f"./bench {w} {WIN_MS} {n} 2>&1; echo RC=$?", rb"RC=(\d+)", 900)
            text = con.buf.decode("utf-8", "replace")
            seg = text[text.rfind(f"./bench {w} "):]
            d = parse(seg, "kvm-in-wsl2", session, w)
            d["exit"] = int(m.group(1)) if m else None
            res.append(d)
        return res, sha
    finally:
        con.close()
        m3t.gv.virsh("destroy", m3t.VM, check=False)


def env_info():
    def sh(c):
        return subprocess.run(c, shell=True, capture_output=True, text=True).stdout.strip()
    return {"kernel": sh("uname -r"), "cpu": sh("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2"),
            "nproc": sh("nproc"), "clocksource": sh("cat /sys/devices/system/clocksource/clocksource0/current_clocksource"),
            "perf_event_paranoid": sh("cat /proc/sys/kernel/perf_event_paranoid"),
            "qemu": sh("qemu-system-x86_64 --version | head -1"), "guest_xml_cpu": sh(f"virsh dumpxml {m3t.VM} | grep -E '<cpu|vcpu|memory unit'")}


def run(sessions, n):
    if not m3t.is_ours():
        raise SystemExit("vsec-m3 missing or not ours (create it with real_m3_test.py setup)")
    binary = build()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    d = OUT / run_id
    d.mkdir(parents=True)
    all_res, shas = [], set()
    for s in range(sessions):  # interleave environments so slow drift hits both
        for env in (("host", "guest") if s % 2 == 0 else ("guest", "host")):
            t0 = time.time()
            if env == "host":
                r = host_session(binary, s, n)
            else:
                r, sha = guest_session(binary, s, n)
                shas.add(sha)
            all_res += r
            print(f"session {s} {env}: {[len(x['rows']) for x in r]} rows, exits {[x['exit'] for x in r]}, {time.time() - t0:.0f}s", flush=True)
    for x in all_res:
        (d / f"{x['env']}_s{x['session']}_{x['workload']}.csv").write_text(
            "\n".join(x["meta"] + [CSV_HEADER] + x["rows"]) + f"\n# exit={x['exit']}\n")
    meta = {"run_id": run_id, "sessions": sessions, "windows": n, "window_ms": WIN_MS, "buf": BUF, "workloads": WORKLOADS,
            "binary_sha256": sorted(shas), "host": env_info(),
            "note": "wsl2-host vs kvm-in-wsl2 (nested). Not native vs VM."}
    (d / "run.json").write_text(json.dumps(meta, indent=1))
    print("saved", d)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["run"])
    ap.add_argument("--sessions", type=int, default=5)
    ap.add_argument("--windows", type=int, default=30)
    a = ap.parse_args()
    run(a.sessions, a.windows)
