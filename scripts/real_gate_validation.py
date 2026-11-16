#!/usr/bin/env python3
"""Attack Lab gate validation on a REAL KVM host (run as root on the host, inside the repo's venv).

    sudo .venv/bin/python scripts/real_gate_validation.py setup              # create the disposable resources
    sudo .venv/bin/python scripts/real_gate_validation.py run [--reps 3]     # the experiment
    sudo .venv/bin/python scripts/real_gate_validation.py cleanup --i-really-mean-it   # ONLY when asked; never automatic

What it does: for each ARM (a VM configuration) and repetition, boot a disposable CirrOS VM, then
  1. PREDICT: `vsec.collect` + `m1_audit.audit` on the running VM -> control states -> the Attack Lab's stage rule
     (vsec.gate_probe.predict_blocked, the same rule as vsec.sim.evaluate).
  2. OBSERVE: probes that never read M1's verdict (vsec.gate_probe): RFB on a non-loopback address (C12), RFB
     security types (C11), guest read of the floppy controller's status port + `info qtree` (C14), `nobody` reading
     the image (C17). Plus a legitimate-access check: the VM boots from its image and a guest command runs.
  3. Record prediction, observation, raw evidence and disagreements.
It touches ONLY: domains vsec-gate-a / vsec-gate-b (marked in their <description>), network vsec-gate-iso (bridge
virbr-gate), and the image copies /var/lib/libvirt/images/vsec-gate-{a,b}.qcow2. Every run hashes vsec-target, the
other networks and qemu.conf/libvirtd.conf before and after, and fails loudly if anything else changed.
No exploit: the probes connect, read a handshake, read one I/O port, and read 16 bytes of a file.
Outputs: results/real/gate_validation/ (gate_validation.json, gate_validation.md, raw/<run-id>/...).
"""
import argparse
import hashlib
import json
import os
import pty
import re
import secrets
import select
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from vsec import gate_probe as gp  # noqa: E402
from vsec import m1_audit, sim  # noqa: E402
from vsec.collect import collect  # noqa: E402
from vsec.guards import virsh as _virsh  # noqa: E402
from vsec.score import wilson  # noqa: E402

VMS = ("vsec-gate-a", "vsec-gate-b")
NET, BRIDGE = "vsec-gate-iso", "virbr-gate"
IMG_DIR = Path("/var/lib/libvirt/images")
SOURCE_IMG = IMG_DIR / "cirros.qcow2"  # read only (copied once); belongs to vsec-target
MARK = "vsec gate-validation disposable VM: safe to delete with the cleanup command"
OUT = ROOT / "results" / "real" / "gate_validation"
QEMU_DEVICES = True  # C14 runtime evidence via info qtree (the 2026-11-15 R4 run predates this: XML-only C14)
ENV = "E0" if "microsoft" in Path("/proc/version").read_text().lower() else "E1"
PROTECTED_VMS = ("vsec-target",)
PROTECTED_FILES = ("/etc/libvirt/qemu.conf", "/etc/libvirt/libvirtd.conf")

# Each gate is FAIL in two arms and PASS in two (on the default machine type), so every gate is observed in both
# states and no gate is confounded with another. H-q35 repeats the hardened arm on the q35 machine type.
ARMS = (
    {"name": "W", "vm": "vsec-gate-a", "listen": "0.0.0.0", "passwd": False, "floppy": True, "mode": 0o644, "machine": "pc"},
    {"name": "M1", "vm": "vsec-gate-a", "listen": "0.0.0.0", "passwd": True, "floppy": False, "mode": 0o644, "machine": "pc"},
    {"name": "M2", "vm": "vsec-gate-b", "listen": "127.0.0.1", "passwd": False, "floppy": True, "mode": 0o600, "machine": "pc"},
    {"name": "H", "vm": "vsec-gate-b", "listen": "127.0.0.1", "passwd": True, "floppy": False, "mode": 0o600, "machine": "pc"},
    {"name": "H-q35", "vm": "vsec-gate-b", "listen": "127.0.0.1", "passwd": True, "floppy": False, "mode": 0o600, "machine": "q35"},
)


def virsh(*args, check=True, timeout=120):
    r = _virsh(*args, timeout=timeout)
    if check and r.returncode:
        raise SystemExit(f"virsh {' '.join(args)} failed: {r.stderr.strip()[-300:]}")
    return r


def image(vm):
    return IMG_DIR / f"{vm}.qcow2"


def own_vm(name):
    if name not in VMS:
        raise SystemExit(f"refusing to act on {name!r}: not a gate-validation VM")
    return name


# ---- protection: prove nothing else changed --------------------------------------------------
def _sha(text):
    return hashlib.sha256(text.encode() if isinstance(text, str) else text).hexdigest()


def protected_state():
    st = {"domains": sorted(n for n in virsh("list", "--all", "--name").stdout.split() if n not in VMS),
          "networks": sorted(n for n in virsh("net-list", "--all", "--name").stdout.split() if n != NET)}
    for vm in PROTECTED_VMS:
        r = virsh("dumpxml", "--inactive", vm, check=False)
        st[f"vm:{vm}"] = {"xml": _sha(r.stdout) if not r.returncode else "absent",
                          "state": virsh("domstate", vm, check=False).stdout.strip()}
    for n in st["networks"]:
        st[f"net:{n}"] = _sha(virsh("net-dumpxml", "--inactive", n, check=False).stdout)
    for f in PROTECTED_FILES:
        st[f"file:{f}"] = _sha(Path(f).read_bytes()) if Path(f).exists() else "absent"
    s = os.stat(SOURCE_IMG)
    st["source_image"] = {"mode": oct(s.st_mode & 0o7777), "uid": s.st_uid, "gid": s.st_gid}
    return st


# ---- resources -------------------------------------------------------------------------------
NET_XML = f"<network><name>{NET}</name><bridge name='{BRIDGE}'/></network>"  # no <forward>, no <ip>: isolated


def domain_xml(arm, passwd=None):
    vm = own_vm(arm["vm"])
    pw = f" passwd='{passwd}'" if passwd else ""
    floppy = "<disk type='file' device='floppy'><target dev='fda' bus='fdc'/></disk>" if arm["floppy"] else ""
    return f"""<domain type='kvm'>
  <name>{vm}</name>
  <description>{MARK}</description>
  <memory unit='MiB'>256</memory><vcpu>1</vcpu>
  <os><type arch='x86_64' machine='{arm["machine"]}'>hvm</type><boot dev='hd'/></os>
  <features><acpi/><apic/></features>
  <devices>
    <disk type='file' device='disk'><driver name='qemu' type='qcow2' cache='none'/>
      <source file='{image(vm)}'/><target dev='vda' bus='virtio'/></disk>
    {floppy}
    <interface type='network'><source network='{NET}'/><model type='virtio'/></interface>
    <serial type='pty'><target port='0'/></serial>
    <console type='pty'><target type='serial' port='0'/></console>
    <graphics type='vnc' port='-1' autoport='yes' listen='{arm["listen"]}'{pw}><listen type='address' address='{arm["listen"]}'/></graphics>
    <video><model type='vga'/></video>
    <memballoon model='none'/>
  </devices>
</domain>"""


def is_ours(vm):
    r = virsh("dumpxml", "--inactive", vm, check=False)
    return r.returncode == 0 and MARK in r.stdout


def exists(vm):
    return virsh("domstate", vm, check=False).returncode == 0


def define(xml):
    """Define (or redefine, keeping the existing uuid) one of OUR domains."""
    name = re.search(r"<name>([^<]+)</name>", xml).group(1)
    if exists(own_vm(name)):
        uuid = virsh("domuuid", name).stdout.strip()
        xml = xml.replace(f"<name>{name}</name>", f"<name>{name}</name>\n  <uuid>{uuid}</uuid>", 1)
    p = ROOT / ".local" / "gate-domain.xml"
    p.parent.mkdir(exist_ok=True)
    p.write_text(xml)
    virsh("define", str(p))


def ensure_network():
    if NET not in virsh("net-list", "--all", "--name").stdout.split():
        p = ROOT / ".local" / "gate-net.xml"
        p.parent.mkdir(exist_ok=True)
        p.write_text(NET_XML)
        virsh("net-define", str(p))
    if NET not in virsh("net-list", "--name").stdout.split():
        if virsh("net-start", NET, check=False).returncode:  # a stale bridge of OUR network after a WSL restart
            subprocess.run(["ip", "link", "delete", BRIDGE], capture_output=True)
            virsh("net-start", NET)


def setup():
    before = protected_state()
    for vm in VMS:
        if exists(vm) and not is_ours(vm):
            raise SystemExit(f"{vm} exists and is not marked as a gate-validation VM: refusing to touch it")
    ensure_network()
    for vm in VMS:
        if not image(vm).exists():
            shutil.copyfile(SOURCE_IMG, image(vm))  # plain read of the source; its mode/owner are not changed
        os.chmod(image(vm), 0o600)
        if not exists(vm):
            define(domain_xml(next(a for a in ARMS if a["vm"] == vm)))
    after = protected_state()
    if before != after:
        raise SystemExit(f"PROTECTED STATE CHANGED during setup:\n{json.dumps([before, after], indent=1)}")
    print(f"ready: {', '.join(VMS)}, network {NET}, images {', '.join(str(image(v)) for v in VMS)}")


def _others_using(text_fragment):
    """Domains other than the gate VMs whose (inactive) XML mentions text_fragment."""
    names = [n for n in virsh("list", "--all", "--name").stdout.split() if n not in VMS]
    return [n for n in names if text_fragment in virsh("dumpxml", "--inactive", n, check=False).stdout]


def cleanup(confirm):
    """Remove ONLY the gate-validation resources. Never automatic. Refuses anything not provably ours: a VM must
    carry MARK; an image or the network must not be referenced by any other domain; the network must use BRIDGE.
    The protected state (vsec-target, other networks, qemu.conf, libvirtd.conf) is hashed before and after."""
    if not confirm:
        raise SystemExit("cleanup deletes vsec-gate-a, vsec-gate-b, their images and the vsec-gate-iso network; "
                         "re-run with --i-really-mean-it")
    before = protected_state()
    for vm in VMS:
        if exists(vm):
            if not is_ours(vm):
                print(f"skipping {vm} and its image: not marked as ours")
                continue
            virsh("destroy", vm, check=False)
            virsh("undefine", vm)  # no --remove-all-storage: only our own image file is deleted, below
        users = _others_using(str(image(vm)))
        if users:
            print(f"keeping {image(vm)}: referenced by {users}")
        elif image(vm).exists():
            image(vm).unlink()
            print(f"deleted {image(vm)}")
    if NET in virsh("net-list", "--all", "--name").stdout.split():
        net_xml = virsh("net-dumpxml", "--inactive", NET).stdout
        users = _others_using(f"network='{NET}'")
        if f"name='{BRIDGE}'" not in net_xml or users:
            print(f"keeping network {NET}: bridge mismatch or used by {users}")
        else:
            virsh("net-destroy", NET, check=False)
            virsh("net-undefine", NET)
            print(f"removed network {NET}")
    if Path(f"/sys/class/net/{BRIDGE}").exists():
        subprocess.run(["ip", "link", "delete", BRIDGE], capture_output=True)
    after = protected_state()
    if before != after:
        raise SystemExit(f"PROTECTED STATE CHANGED during cleanup:\n{json.dumps([before, after], indent=1)}")
    print("protected state unchanged; remaining domains:", " ".join(after["domains"]) or "-",
          "| networks:", " ".join(after["networks"]) or "-")


# ---- guest console ---------------------------------------------------------------------------
class Console:
    """`virsh console` on a pty (same approach as scripts/real_snapshot_test.py)."""

    def __init__(self, vm):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execvp("virsh", ["virsh", "-c", "qemu:///system", "console", own_vm(vm), "--force"])
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

    def run(self, cmd, pattern, timeout):
        """Send a command and wait for `pattern` in what arrives AFTER it was sent."""
        start = len(self.read(0.2))
        os.write(self.fd, cmd.encode() + b"\r")
        return self.expect(pattern, timeout, start=start)

    def expect(self, pattern, timeout, poke=None, start=None):
        end = time.time() + timeout
        start = len(self.buf) if start is None else start
        while time.time() < end:
            m = re.search(pattern, self.read(1.0)[start:])
            if m:
                return m
            if poke:
                os.write(self.fd, poke)
        return None

    def send(self, line, wait=0.5):
        os.write(self.fd, line.encode() + b"\r")
        self.read(wait)

    def close(self):
        try:
            os.write(self.fd, b"\x1d")
            time.sleep(0.3)
            os.close(self.fd)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
            pass


def guest_session(vm):
    """Log in as root on the serial console; read the FDC main status register; prove the disk is usable.
    Returns {'login', 'msr_raw', 'msr', 'disk_ok', 'transcript'}."""
    con = Console(vm)
    res = {"login": False, "msr_raw": "", "msr": None, "disk_ok": False}
    try:
        if not con.expect(rb"login:", 300, poke=b"\r"):
            return {**res, "transcript": con.buf[-2000:].decode("utf-8", "replace")}
        con.send("cirros", 1.0)
        con.send("gocubsgo", 3.0)
        con.send("sudo -s", 1.5)
        res["login"] = True
        # MSR at 0x3F4 = byte offset 1012 of /dev/port. od prints it as two hex digits.
        res["root"] = con.run("id -u; echo UID\"-END\"", rb"\n0\r?\r?\nUID-END", 10) is not None
        # the echoed command line contains MSR"< (quote), so only the output matches MSR<..>
        m = con.run("echo MSR\"<$(dd if=/dev/port bs=1 skip=1012 count=1 2>/dev/null | od -An -tx1)>\"",
                    rb"MSR<([^>\r\n]*)>", 15)
        res["msr_raw"] = m.group(1).decode("ascii", "replace").strip() if m else ""
        res["msr"] = gp.parse_port_byte(res["msr_raw"]) if m else None
        # legitimate access: the guest writes a file to its root disk, syncs, reads it back (QEMU must read+write)
        res["disk_ok"] = con.run("echo vsec-$$ > /root/.vsec-probe && sync && cat /root/.vsec-probe && echo DISK\"OK\"",
                                 rb"DISKOK", 15) is not None
        con.send("exit", 0.5)
        con.send("exit", 0.5)
    finally:
        con.close()
    res["transcript"] = con.buf[-3000:].decode("utf-8", "replace")
    return res


# ---- one observation -------------------------------------------------------------------------
def host_ip():
    out = subprocess.run(["ip", "-4", "-o", "addr", "show", "scope", "global"], capture_output=True, text=True).stdout
    for line in out.splitlines():  # the host's LAN-facing interface: not lo (WSL puts 10.255.255.254 there), no bridge
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", line)
        dev = line.split()[1]
        if m and dev != "lo" and not dev.startswith(("virbr", "docker", "br-")):
            return m.group(1), dev
    raise SystemExit("no non-loopback IPv4 address found for the C12 probe")


def vnc_port(vm):
    disp = virsh("vncdisplay", vm).stdout.strip()
    return 5900 + int(disp.rsplit(":", 1)[1])


def nobody_read(path):
    r = subprocess.run(["runuser", "-u", "nobody", "--", "head", "-c", "16", str(path)], capture_output=True)
    return r.stdout, r.returncode, r.stderr.decode("utf-8", "replace")


def blkstat(vm):
    out = virsh("domblkstat", vm, "vda", check=False).stdout
    return {k: int(v) for k, v in re.findall(r"vda (\w+) (\d+)", out)}


def wait_stopped(vm, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        if virsh("domstate", vm, check=False).stdout.strip() == "shut off":
            return
        time.sleep(0.5)


def one(arm, rep, run_dir, attacks, ip):
    vm = own_vm(arm["vm"])
    if not is_ours(vm):
        raise SystemExit(f"{vm} is not marked as ours: run setup first")
    virsh("destroy", vm, check=False)
    wait_stopped(vm)
    for other in VMS:  # only one gate VM runs at a time; the idle image is always private
        if other != vm:
            virsh("destroy", other, check=False)
            os.chmod(image(other), 0o600)
    define(domain_xml(arm, secrets.token_hex(4) if arm["passwd"] else None))
    os.chmod(image(vm), arm["mode"])
    ensure_network()
    t0 = time.time()
    virsh("start", vm)
    tag = f"{arm['name']}-r{rep}"
    raw = run_dir / tag
    raw.mkdir(parents=True)
    rec = {"arm": arm, "rep": rep, "vm": vm, "started_utc": now()}
    try:
        g = guest_session(vm)
        rec["boot_seconds"] = round(time.time() - t0, 1)
        (raw / "console.txt").write_text(g.pop("transcript"))
        rec["guest"] = g
        port = vnc_port(vm)
        st = os.stat(image(vm))
        rec["image_runtime"] = {"mode": oct(st.st_mode & 0o7777), "uid": st.st_uid, "gid": st.st_gid}
        rec["blkstat"] = blkstat(vm)
        outside = gp.rfb_probe(ip[0], port)
        local = gp.rfb_probe("127.0.0.1", port)
        qt = virsh("qemu-monitor-command", "--hmp", vm, "info qtree", check=False)
        (raw / "qtree.txt").write_text(qt.stdout or qt.stderr)
        qtree = gp.parse_qtree(qt.stdout) if not qt.returncode else {"isa_fdc": None, "floppy_drives": None}
        head, rc, err = nobody_read(image(vm))
        obs = {"C12": gp.observe_c12(outside), "C11": gp.observe_c11(local),
               "C14": gp.observe_c14(g["msr"], qtree), "C17": gp.observe_c17(head, rc, err)}
        # legitimate QEMU access after the C17 setting: booted from the image, guest disk I/O worked, QEMU read it
        rec["legit_access"] = {"booted": g["login"], "guest_disk_rw": g["disk_ok"],
                               "qemu_read_requests": rec["blkstat"].get("rd_req", 0),
                               "ok": bool(g["login"] and g["disk_ok"] and rec["blkstat"].get("rd_req", 0) > 0)}
        # prediction from the M1 audit of THIS running VM (collected after the probes, VM still running)
        case = ROOT / "cases" / f"gate-{run_dir.name}-{tag}"
        collect(vm, case, qemu_devices=QEMU_DEVICES)  # monitor query: approved for these disposable VMs only
        findings = m1_audit.audit(case, env=ENV, vm=vm)
        state = {f["id"]: f["status"] for f in findings}
        for name in ("vm.xml", "perms.txt", "qemu_status", "collect_manifest.json"):
            if (case / name).exists():
                shutil.copyfile(case / name, raw / name)
        (raw / "m1_findings.json").write_text(json.dumps(findings, indent=1))
        rows = []
        for cid, aid, idx in gp.PROBED:
            o = obs[cid]
            pred = gp.predict_blocked(attacks, aid, idx, state)
            rows.append({"arm": arm["name"], "rep": rep, "control": cid, "attack": aid, "stage": idx,
                         "stage_title": gp.stage(attacks, aid, idx)["title"], "m1": state.get(cid),
                         "m1_evidence": next(f["evidence"] for f in findings if f["id"] == cid),
                         "predicted_blocked": pred, "observed_blocked": o["blocked"],
                         "agree": None if o["blocked"] is None else pred == o["blocked"],
                         "note": o.get("note", ""), "observation": o["evidence"]})
        rec["rows"] = rows
        rec["chain_prediction"] = {a["id"]: sim.evaluate(a, state) for a in attacks if a["id"] in ("A01", "A02", "A09")}
    finally:
        virsh("destroy", vm, check=False)
        wait_stopped(vm)
        os.chmod(image(vm), 0o600)
    (raw / "record.json").write_text(json.dumps(rec, indent=1, default=str))
    return rec


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def versions():
    q = subprocess.run(["qemu-system-x86_64", "--version"], capture_output=True, text=True).stdout.splitlines()
    return {"qemu": q[0] if q else "", "libvirt": virsh("--version").stdout.strip(),
            "kernel": os.uname().release, "env": ENV}


def markdown(res):
    s = res["summary"]
    lines = [f"# Attack Lab gate validation ({res['env']['env']}, run {res['run_id']})", "",
             "REAL experiment on disposable CirrOS VMs. Prediction = Attack Lab stage rule on the M1 audit of the "
             "running VM; observation = independent probe (never M1's verdict).", "",
             f"Overall agreement: {s['overall']['agree']}/{s['overall']['n']} "
             f"(Wilson 95% CI {s['overall']['ci'][0]:.2f}-{s['overall']['ci'][1]:.2f}); "
             f"unsafe disagreements (model says blocked, stage open): {s['overall']['unsafe_disagreements']}; "
             f"no observation: {s['overall']['no_observation']}.",
             f"Coverage: {res['coverage'][0]} of {res['coverage'][1]} gated attack stages probed.", "",
             "| Control | Stage | n | agree | CI | unsafe | conservative |", "|---|---|---|---|---|---|---|"]
    titles = {r["control"]: f"{r['attack']} s{r['stage']}: {r['stage_title']}" for r in res["rows"]}
    for c, v in s["per_control"].items():
        ci = f"{v['ci'][0]:.2f}-{v['ci'][1]:.2f}" if v["ci"] else "-"
        lines.append(f"| {c} | {titles[c]} | {v['n']} | {v['agree']} | {ci} | {v['unsafe_disagreements']} | "
                     f"{v['conservative_disagreements']} |")
    lines += ["", "| Arm | rep | Control | M1 | predicted | observed | agree | note |", "|---|---|---|---|---|---|---|---|"]
    word = {True: "blocked", False: "open", None: "-"}
    for r in res["rows"]:
        lines.append(f"| {r['arm']} | {r['rep']} | {r['control']} | {r['m1']} | {word[r['predicted_blocked']]} | "
                     f"{word[r['observed_blocked']]} | {r['agree']} | {r['note']} |")
    lines += ["", "Legitimate access after the C17 setting (boot + guest disk write + QEMU read requests):", ""]
    for rec in res["records"]:
        la = rec.get("legit_access", {})
        lines.append(f"- {rec['arm']['name']} r{rec['rep']}: image {rec.get('image_runtime', {}).get('mode')} "
                     f"-> {'OK' if la.get('ok') else 'FAILED'} ({la})")
    lines += ["", "Disagreements:", ""] + ([f"- {d['arm']} r{d['rep']} {d['control']}: predicted "
                                             f"{word[d['predicted_blocked']]}, observed {word[d['observed_blocked']]}; "
                                             f"M1 evidence: {d['m1_evidence']}; observation: {json.dumps(d['observation'])[:300]}"
                                             for d in res["disagreements"]] or ["- none"])
    lines += ["", f"Protected state unchanged: {res['protected_unchanged']}"]
    return "\n".join(lines) + "\n"


def run(reps, only=None, out=OUT):
    if (out / "gate_validation.json").exists():
        raise SystemExit(f"{out} already holds a run: choose a new --out (earlier evidence is never overwritten)")
    attacks = sim.load_attacks()
    before = protected_state()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = out / "raw" / run_id
    run_dir.mkdir(parents=True)
    ip = host_ip()
    arms = [a for a in ARMS if not only or a["name"] in only]
    records = []
    for rep in range(1, reps + 1):  # interleave arms across repetitions
        for arm in arms:
            print(f"[{now()}] arm {arm['name']} rep {rep} on {arm['vm']}", flush=True)
            rec = one(arm, rep, run_dir, attacks, ip)
            records.append(rec)
            print("   ", [(r["control"], r["m1"], r["predicted_blocked"], r["observed_blocked"]) for r in rec["rows"]],
                  "legit", rec["legit_access"]["ok"], flush=True)
    after = protected_state()
    rows = [r for rec in records for r in rec["rows"]]
    res = {"run_id": run_id, "env": versions(), "probe_address": ip, "arms": list(arms), "reps": reps,
           "coverage": gp.coverage(attacks), "rows": rows, "records": records,
           "summary": gp.summarise(rows, wilson),
           "disagreements": [r for r in rows if r["agree"] is False],
           "protected_before": before, "protected_after": after, "protected_unchanged": before == after,
           "label": "REAL measurement on disposable VMs (E0 = WSL2). Small n, one host, one guest OS."}
    (run_dir / "protected_state.json").write_text(json.dumps({"before": before, "after": after}, indent=1))
    (out / "gate_validation.json").write_text(json.dumps(res, indent=1, default=str))
    (out / "gate_validation.md").write_text(markdown(res))
    print(markdown(res))
    if before != after:
        raise SystemExit("PROTECTED STATE CHANGED: see protected_state.json")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup")
    r = sub.add_parser("run")
    r.add_argument("--reps", type=int, default=3)
    r.add_argument("--arms", nargs="*", help="subset of arm names (debugging)")
    r.add_argument("--out", type=Path, default=OUT, help="output folder (keep earlier runs: use a new one)")
    c = sub.add_parser("cleanup")
    c.add_argument("--i-really-mean-it", action="store_true")
    a = ap.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run as root on the KVM host")
    if a.cmd == "setup":
        setup()
    elif a.cmd == "run":
        run(a.reps, a.arms, a.out)
    else:
        cleanup(a.i_really_mean_it)


if __name__ == "__main__":
    main()
