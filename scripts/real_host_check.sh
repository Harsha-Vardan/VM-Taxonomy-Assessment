#!/usr/bin/env bash
# Real-host evidence for the paper: run on ANY Linux machine with KVM + libvirt and at least one VM defined.
#
#   sudo bash scripts/real_host_check.sh <vm-name>
#
# What it does (read-only on the host; it changes no setting):
#   1. vsec collect  -> cases/real-<host>-<vm>/      (passwords and secrets are REDACTED before writing)
#   2. vsec audit    -> results/real/<host>-<vm>.audit.txt   (this is what you import into simulator.html)
#   3. Lynis         -> results/real/<host>.lynis.txt        (independent tool, if installed: sudo apt install lynis)
#   4. A side-by-side table of the controls both tools touch -> results/real/<host>.compare.md
#
# Paste results/real/*.audit.txt into the simulator ("Import real audit") and report the host in the paper
# as a REAL measurement (hardware, OS, QEMU and libvirt versions are written to results/real/<host>.env.txt).
# Do not commit the cases/ folder: it holds host configuration.
set -euo pipefail
VM="${1:?usage: sudo bash scripts/real_host_check.sh <vm-name>}"
cd "$(dirname "$0")/.."
HOST="$(hostname -s)"
CASE="cases/real-${HOST}-${VM}"
OUT="results/real"
mkdir -p "$OUT"

command -v virsh >/dev/null || { echo "virsh not found: install libvirt (this script needs a real KVM host)"; exit 2; }
[ -e /dev/kvm ] || echo "WARNING: /dev/kvm missing: this is not a KVM host, several controls will be NA"

{
  echo "date: $(date -Iseconds)"; echo "kernel: $(uname -r)"; echo "os: $(. /etc/os-release; echo "$PRETTY_NAME")"
  echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2-)"
  echo "qemu: $(qemu-system-x86_64 --version 2>/dev/null | head -1 || echo unknown)"
  echo "libvirt: $(virsh --version 2>/dev/null || echo unknown)"
} > "$OUT/${HOST}.env.txt"

echo "[1/4] collecting host files for VM '$VM'"
python3 -m vsec.collect "$VM" "$CASE"

echo "[2/4] auditing"
ENV=E1; grep -qi microsoft /proc/version && ENV=E0   # WSL2 = E0 (paper Section 4.4)
python3 -m vsec audit "$CASE" --env "$ENV" | tee "$OUT/${HOST}-${VM}.audit.txt" || true   # exit 1 just means FAILs exist

echo "[3/4] Lynis (independent comparison)"
if command -v lynis >/dev/null; then
  lynis audit system --quick --no-colors > "$OUT/${HOST}.lynis.txt" 2>&1 || true
else
  echo "lynis not installed (sudo apt install lynis); skipping the comparison" | tee "$OUT/${HOST}.lynis.txt"
fi

echo "[4/4] comparison table"
python3 - "$OUT/${HOST}-${VM}.audit.txt" "$OUT/${HOST}.lynis.txt" > "$OUT/${HOST}.compare.md" <<'PY'
import re, sys
audit = dict(re.findall(r"^(C\d\d)\s+(PASS|FAIL|NA)", open(sys.argv[1]).read(), re.M))
lynis = open(sys.argv[2], errors="replace").read()
# Lynis tests that cover the same ground as our controls (by Lynis test id / keyword). Only overlapping topics are listed.
pairs = [("C17", "file permissions on VM images", r"FILE-7524|permissions"),
         ("C20", "libvirt/remote management exposure", r"NETW-|listening"),
         ("C25", "CPU vulnerabilities / microcode", r"KRNL-|vulnerab|microcode"),
         ("C26", "SMT state", r"smt|hyperthread"),
         ("C24", "kernel version / updates", r"KRNL-5830|reboot|kernel")]
print("| Control | Topic | vsec | Lynis mentions topic? |\n|---|---|---|---|")
for c, topic, rx in pairs:
    print(f"| {c} | {topic} | {audit.get(c, 'missing')} | {'yes' if re.search(rx, lynis, re.I) else 'no'} |")
print(f"\nvsec controls: {len(audit)}; FAIL {sum(v == 'FAIL' for v in audit.values())}, "
      f"PASS {sum(v == 'PASS' for v in audit.values())}, NA {sum(v == 'NA' for v in audit.values())}")
print("Lynis is a general Linux hardening tool: most vsec controls (QEMU seccomp, sVirt, KSM, nested, VM devices,"
      " graphics, network mode) have no Lynis counterpart, which is the gap this project addresses.")
PY
echo "done: $OUT/${HOST}-${VM}.audit.txt (import it in simulator.html), $OUT/${HOST}.compare.md"
