#!/usr/bin/env python3
"""Real snapshot-privacy test (survey S6.1, module M2) on a real KVM VM. Run as root on the host, in the venv.

    sudo .venv/bin/python scripts/real_snapshot_test.py <vm-name>

1. Generates FAKE secrets on the host (AWS key pair, JWT, 64-hex token, OpenSSH-style key; random, never valid).
2. Logs in to the VM over its serial console (CirrOS test image) and plants each secret in guest memory in three
   encodings: plain text, base64, UTF-16LE. Each copy sits in a tmpfs/page-cache file AND in a live process.
3. Takes a real memory snapshot: `virsh dump --memory-only` (what a hypervisor snapshot or migration image holds).
4. Scans the dump with scanner v1 (plain rules) and v2 (adds decoding), counts every hit that is NOT a planted
   secret as a false positive, redacts the dump in place with v2 and rescans it.
Writes results/real/m2_real.json. The secrets are fake and the dump never leaves the host; the dump is deleted.
Ground truth: a secret counts as PRESENT only if its exact bytes are found in the dump (as in vsec.m2_snapshot).
"""
import base64
import json
import os
import pty
import random
import select
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from vsec import m2_snapshot as m2  # noqa: E402
from vsec.score import wilson  # noqa: E402
from vsec.secrets_gen import make_secret, plant_text  # noqa: E402

VIRSH = ["virsh", "-c", "qemu:///system"]
KINDS = ("aws", "jwt", "hex32", "ssh_key")


class Console:
    def __init__(self, vm):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execvp("virsh", [*VIRSH, "console", vm, "--force"])
        self.buf = b""

    def read(self, t=0.5):
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if r:
                try:
                    self.buf += os.read(self.fd, 65536)
                except OSError:
                    break
        return self.buf

    def expect(self, token, timeout, poke=None):
        end = time.time() + timeout
        while time.time() < end:
            if token in self.read(1.0)[-4000:]:
                return True
            if poke:
                os.write(self.fd, poke)
        return False

    def send(self, line, wait=0.4):
        os.write(self.fd, line.encode() + b"\r")
        self.read(wait)

    def close(self):
        os.write(self.fd, b"\x1d")  # ctrl-] leaves virsh console
        time.sleep(0.3)


def printf_arg(b):
    """bytes -> printf format string with octal escapes for everything non-trivial (busybox printf)."""
    return "".join(chr(c) if (48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122 or c in b"=+/._-:")
                   else f"\\{c:03o}" for c in b)


def main():
    vm = sys.argv[1] if len(sys.argv) > 1 else "vsec-target"
    out = ROOT / "results" / "real"
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(int.from_bytes(os.urandom(8), "big"))
    plants = []
    for kind in KINDS:
        for enc in ("plain", "base64", "utf16"):
            secret = make_secret(kind, rng)
            text = plant_text(kind, secret).encode()
            data = text if enc == "plain" else base64.b64encode(text) if enc == "base64" else text.decode().encode("utf-16-le")
            needle = secret.encode() if enc == "plain" else data
            plants.append({"kind": kind, "enc": enc, "bytes": data, "needle": needle, "text": text})

    state = subprocess.run([*VIRSH, "domstate", vm], capture_output=True, text=True).stdout.strip()
    if state != "running":
        for net, br in (("default", "virbr0"), ("isolated", "virbr-iso")):  # WSL may have stopped; bridges can go stale
            if subprocess.run([*VIRSH, "net-start", net], capture_output=True, text=True).returncode:
                subprocess.run(["ip", "link", "delete", br], capture_output=True)
                subprocess.run([*VIRSH, "net-start", net], capture_output=True)
        subprocess.run([*VIRSH, "start", vm], check=True)

    def login():
        con = Console(vm)
        if not con.expect(b"login:", 240, poke=b"\r"):
            raise SystemExit("no login prompt on the serial console (is this the CirrOS image?)")
        con.send("cirros", 1.0)
        con.send("gocubsgo", 3.0)
        con.send("unset HISTFILE; sudo -s", 1.0)
        con.send("unset HISTFILE", 0.5)
        return con

    # Clean boot: an earlier run's secrets survive on disk in shell history (~/.ash_history) and /tmp, and the
    # login shell loads that history into memory. Wipe both, power off, boot again, plant with history disabled.
    con = login()
    con.send("rm -f /tmp/s* /root/.ash_history ~cirros/.ash_history; sync; echo WIPED-OK", 2.0)
    con.expect(b"WIPED-OK", 10)
    con.close()
    subprocess.run([*VIRSH, "destroy", vm], capture_output=True)
    time.sleep(1)
    subprocess.run([*VIRSH, "start", vm], check=True, capture_output=True)
    con = login()
    for i, p in enumerate(plants):
        arg = printf_arg(p["bytes"])
        con.send(f"printf '{arg}' > /tmp/s{i}; (V=\"$(cat /tmp/s{i})\" sleep 3600 &)", 1.2)
    con.send("sync; echo PLANTED-$(ls /tmp/s* | wc -l)-OK", 2.0)
    ok = con.expect(b"-OK", 10)
    con.close()
    if not ok:
        raise SystemExit("planting did not finish on the console")
    time.sleep(1)

    dump = ROOT / ".local" / "real_snapshot.elf"
    dump.parent.mkdir(exist_ok=True)
    dump.unlink(missing_ok=True)
    t0 = time.time()
    subprocess.run([*VIRSH, "dump", vm, str(dump), "--memory-only"], check=True, capture_output=True)
    dump_s = time.time() - t0
    data = dump.read_bytes()
    res = {"vm": vm, "dump_bytes": len(data), "dump_seconds": round(dump_s, 1), "plants": len(plants)}
    # the guest shell decodes what it reads (V="$(cat file)" strips NULs), so a decoded copy of a planted secret
    # is a real leak of that secret, not a false positive
    planted_bytes = [p["bytes"] for p in plants] + [p["text"] for p in plants]
    for ver, dec in (("v1", False), ("v2", True)):
        t0 = time.time()
        hits = m2.scan(data, dec)
        secs = time.time() - t0
        rows = []
        for p in plants:
            present = data.find(p["needle"]) != -1
            found = present and any(p["needle"] in h[3] or ("@" in h[0] and len(h[3]) >= 16 and h[3] in p["needle"]) for h in hits)
            rows.append({"kind": p["kind"], "enc": p["enc"], "present": present, "detected": found})
        fps = [h for h in hits if not any(h[3] in b or b in h[3] for b in planted_bytes)]
        by = {}
        for enc in ("plain", "base64", "utf16"):
            pr = [r for r in rows if r["enc"] == enc and r["present"]]
            d = sum(r["detected"] for r in pr)
            by[enc] = {"present": len(pr), "detected": d, "ci": wilson(d, len(pr)) if pr else None}
        res[ver] = {"by_encoding": by, "rows": rows, "hits": len(hits), "false_positives": len(fps),
                    "fp_rules": sorted({h[0] for h in fps}), "fp_examples": [h[3][:24].hex() for h in fps[:5]],
                    "scan_seconds": round(secs, 2), "mib_per_s": round(len(data) / 2**20 / secs, 1)}
    red = m2.redact(data, True)
    left = [p for p in plants if red.find(p["needle"]) != -1]
    res["after_v2_redaction"] = {"secrets_still_present": len(left), "v2_hits_left": len(m2.scan(red, True)),
                                 "size_unchanged": len(red) == len(data)}
    dump.unlink()
    (out / "m2_real.json").write_text(json.dumps(res, indent=1, default=list))
    for ver in ("v1", "v2"):
        print(ver, {k: f"{v['detected']}/{v['present']}" for k, v in res[ver]["by_encoding"].items()},
              "FP", res[ver]["false_positives"], res[ver]["fp_rules"], f"{res[ver]['mib_per_s']} MiB/s")
    print("dump", res["dump_bytes"] // 2**20, "MiB in", res["dump_seconds"], "s; after v2 redaction:", res["after_v2_redaction"])


if __name__ == "__main__":
    main()
