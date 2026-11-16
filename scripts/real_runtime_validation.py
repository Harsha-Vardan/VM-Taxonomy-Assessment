#!/usr/bin/env python3
"""Runtime validation of M1 on REAL disposable VMs (X1; run as root on the KVM host, inside the repo's venv).
    sudo .venv/bin/python scripts/real_runtime_validation.py setup
    sudo .venv/bin/python scripts/real_runtime_validation.py run [--arms A,B,...]
    sudo .venv/bin/python scripts/real_runtime_validation.py cleanup --i-really-mean-it      # never automatic
Per arm (one configuration of the arm VM and its peer VM): define both, boot both, log in on both serial consoles, then
  PREDICT  `python -m vsec assess <arm-vm> --qemu-devices` (the primary live workflow) -> findings + provenance
  OBSERVE  vsec.runtime_check, separate code paths: C04/C06 validator's own /proc reads (PARTIAL independence),
           C11/C12 RFB handshakes or QEMU's TCP listeners (no console), C14 guest read of port 0x3F4 + info qtree,
           C16 guest-to-guest ping with both NICs verified up (allowed AND blocked paths are exercised)
  COMPARE  per control: agree / disagree / not observable
Touches ONLY vsec-rv-a, vsec-rv-b (marked), networks vsec-rv-iso (virbr-rv) and vsec-rv-iso2 (virbr-rv2) (no forward,
no IP) and the image copies /var/lib/libvirt/images/vsec-rv-{a,b}.qcow2. vsec-target, every other domain/network and
qemu.conf/libvirtd.conf are hashed before and after each run. Results are never overwritten.
Outputs: results/real/runtime_validation/raw/<run-id>/ (run.json, runtime_validation.md, per arm: assess/ + domain XMLs).
"""
import argparse
import hashlib
import json
import re
import secrets
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import real_gate_validation as gv  # noqa: E402  (virsh, Console, protected_state, setup/cleanup machinery)
from vsec import gate_probe as gp  # noqa: E402
from vsec import runtime_check as rc  # noqa: E402

gv.VMS = ("vsec-rv-a", "vsec-rv-b")
gv.NET, gv.BRIDGE = "vsec-rv-iso", "virbr-rv"
gv.NET_XML = f"<network><name>{gv.NET}</name><bridge name='{gv.BRIDGE}'/></network>"  # isolated: no forward, no ip
gv.MARK = "vsec runtime-validation disposable VM: safe to delete with real_runtime_validation.py cleanup"
NET2, BRIDGE2 = "vsec-rv-iso2", "virbr-rv2"
NETS = {"iso": gv.NET, "iso2": NET2}
OUT = ROOT / "results" / "real" / "runtime_validation" / "raw"
WORK = ROOT / ".local" / "rv"
IPS = {"vsec-rv-a": "10.66.0.1", "vsec-rv-b": "10.66.0.2"}
PEER = {"machine": "q35", "listen": "127.0.0.1", "passwd": True, "floppy": False}
# 10 configurations. Each validated control is seen in both states; C16 covers allowed paths (A,B,C,E,H,I) and
# blocked ones (D, J: both ports isolated; F: separate networks; G: no NIC). E = one-sided port isolation (allowed).
ARMS = (
    {"name": "A", "vm": "vsec-rv-a", "machine": "pc", "listen": "0.0.0.0", "passwd": False, "floppy": True, "net": "iso", "iso": False, "peer_net": "iso", "peer_iso": False},
    {"name": "B", "vm": "vsec-rv-b", "machine": "pc", "listen": "127.0.0.1", "passwd": True, "floppy": False, "net": "iso", "iso": False, "peer_net": "iso", "peer_iso": False},
    {"name": "C", "vm": "vsec-rv-b", "machine": "q35", "listen": "127.0.0.1", "passwd": True, "floppy": False, "net": "iso", "iso": False, "peer_net": "iso", "peer_iso": False},
    {"name": "D", "vm": "vsec-rv-b", "machine": "q35", "listen": "127.0.0.1", "passwd": True, "floppy": False, "net": "iso", "iso": True, "peer_net": "iso", "peer_iso": True},
    {"name": "E", "vm": "vsec-rv-b", "machine": "q35", "listen": "127.0.0.1", "passwd": True, "floppy": False, "net": "iso", "iso": True, "peer_net": "iso", "peer_iso": False},
    {"name": "F", "vm": "vsec-rv-b", "machine": "q35", "listen": "127.0.0.1", "passwd": True, "floppy": False, "net": "iso2", "iso": False, "peer_net": "iso", "peer_iso": False},
    {"name": "G", "vm": "vsec-rv-b", "machine": "q35", "listen": None, "passwd": False, "floppy": False, "net": None, "iso": False, "peer_net": "iso", "peer_iso": False},
    {"name": "H", "vm": "vsec-rv-a", "machine": "q35", "listen": "0.0.0.0", "passwd": True, "floppy": False, "net": "iso", "iso": False, "peer_net": "iso", "peer_iso": False},
    {"name": "I", "vm": "vsec-rv-a", "machine": "q35", "listen": "127.0.0.1", "passwd": False, "floppy": False, "net": "iso", "iso": False, "peer_net": "iso", "peer_iso": False},
    {"name": "J", "vm": "vsec-rv-a", "machine": "pc", "listen": "127.0.0.1", "passwd": True, "floppy": True, "net": "iso", "iso": True, "peer_net": "iso", "peer_iso": True},
)


def domain_xml(vm, machine, listen, passwd, floppy, net, iso):
    gv.own_vm(vm)
    floppy_x = "<disk type='file' device='floppy'><target dev='fda' bus='fdc'/></disk>" if floppy else ""
    nic = (f"<interface type='network'><source network='{NETS[net]}'/><model type='virtio'/>"
           f"{'<port isolated=' + chr(39) + 'yes' + chr(39) + '/>' if iso else ''}</interface>") if net else ""
    pw = f" passwd='{passwd}'" if passwd else ""
    gfx = (f"<graphics type='vnc' port='-1' autoport='yes' listen='{listen}'{pw}><listen type='address' address='{listen}'/>"
           f"</graphics><video><model type='vga'/></video>") if listen else ""
    return f"""<domain type='kvm'>
  <name>{vm}</name>
  <description>{gv.MARK}</description>
  <memory unit='MiB'>256</memory><vcpu>1</vcpu>
  <os><type arch='x86_64' machine='{machine}'>hvm</type><boot dev='hd'/></os>
  <features><acpi/><apic/></features>
  <devices>
    <disk type='file' device='disk'><driver name='qemu' type='qcow2' cache='none'/>
      <source file='{gv.image(vm)}'/><target dev='vda' bus='virtio'/></disk>
    {floppy_x}
    {nic}
    <serial type='pty'><target port='0'/></serial>
    <console type='pty'><target type='serial' port='0'/></console>
    {gfx}
    <memballoon model='none'/>
  </devices>
</domain>"""


def ensure_net2():
    names = gv.virsh("net-list", "--all", "--name").stdout.split()
    if NET2 not in names:
        p = ROOT / ".local" / "rv-net2.xml"
        p.parent.mkdir(exist_ok=True)
        p.write_text(f"<network><name>{NET2}</name><bridge name='{BRIDGE2}'/></network>")
        gv.virsh("net-define", str(p))
    if NET2 not in gv.virsh("net-list", "--name").stdout.split():
        if gv.virsh("net-start", NET2, check=False).returncode:
            subprocess.run(["ip", "link", "delete", BRIDGE2], capture_output=True)
            gv.virsh("net-start", NET2)


def protected_state():
    st = gv.protected_state()
    st["networks"] = [n for n in st["networks"] if n != NET2]
    st.pop(f"net:{NET2}", None)
    return st


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def read(path):
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return None


def lsm_state():
    return {"apparmor": read("/sys/module/apparmor/parameters/enabled"), "selinux_enforce": read("/sys/fs/selinux/enforce")}


def qemu_pid(vm):
    t = read(f"/run/libvirt/qemu/{vm}.pid")
    return t.strip() if t else None


def tcp_listeners(pid):
    out = subprocess.run(["ss", "-ltnpH"], capture_output=True, text=True).stdout
    return [ln.split()[3] for ln in out.splitlines() if f"pid={pid}," in ln]


def login(vm):
    con = gv.Console(vm)
    if not con.expect(rb"login:", 300, poke=b"\r"):
        con.close()
        raise SystemExit(f"{vm}: no login prompt")
    con.send("cirros", 1.0)
    con.send("gocubsgo", 3.0)
    con.send("sudo -s", 1.5)
    con.send("unset HISTFILE", 0.3)
    m = con.run(f"if [ -e /sys/class/net/eth0 ]; then ip link set eth0 up; ip addr add {IPS[vm]}/24 dev eth0; "
                f"ip -4 addr show eth0 | grep -q {IPS[vm]} && echo NIC\"=up\" || echo NIC\"=bad\"; else echo NIC\"=none\"; fi",
                rb"NIC=(up|bad|none)", 20)
    return con, (m.group(1).decode() if m else "bad")


def guest_observe(con, peer_ip):
    m = con.run("echo MSR\"<$(dd if=/dev/port bs=1 skip=1012 count=1 2>/dev/null | od -An -tx1)>\"", rb"MSR<([^>\r\n]*)>", 15)
    msr = gp.parse_port_byte(m.group(1).decode("ascii", "replace")) if m else None
    p = con.run(f"ping -c 3 -W 1 {peer_ip} >/dev/null 2>&1; echo PING\"=$?\"", rb"PING=(\d+)", 20)
    return msr, (None if not p else p.group(1) == b"0")


def one_arm(arm, run_dir):
    vm = arm["vm"]
    peer = next(v for v in gv.VMS if v != vm)
    pw = secrets.token_hex(4) if arm["passwd"] else None
    for v in (vm, peer):
        gv.virsh("destroy", v, check=False)
        gv.wait_stopped(v)
    gv.define(domain_xml(vm, arm["machine"], arm["listen"], pw, arm["floppy"], arm["net"], arm["iso"]))
    gv.define(domain_xml(peer, PEER["machine"], PEER["listen"], secrets.token_hex(4), PEER["floppy"], arm["peer_net"], arm["peer_iso"]))
    gv.ensure_network()
    ensure_net2()
    gv.virsh("start", peer)
    gv.virsh("start", vm)
    pcon, pnic = login(peer)
    con, nic = login(vm)
    d = run_dir / f"arm-{arm['name']}"
    work = WORK / run_dir.name / f"arm-{arm['name']}"
    try:
        if work.exists():
            shutil.rmtree(work)
        work.parent.mkdir(parents=True, exist_ok=True)
        cli = subprocess.run([sys.executable, "-m", "vsec", "assess", vm, "--qemu-devices", "--env", gv.ENV,
                              "--out", str(work)], cwd=ROOT, capture_output=True, text=True, timeout=300)
        findings = json.loads((work / "findings.json").read_text())  # PREDICT via the primary workflow
        pid = qemu_pid(vm)
        obs = {"C04": rc.obs_c04(read(f"/proc/{pid}/status") if pid else None),
               "C06": rc.obs_c06(read(f"/proc/{pid}/attr/current") if pid else None, lsm_state())}
        if arm["listen"]:
            port = gv.vnc_port(vm)
            ip, _ = gv.host_ip()
            obs["C11"] = rc.obs_c11(gp.rfb_probe("127.0.0.1", port))
            obs["C12"] = rc.obs_c12(gp.rfb_probe(ip, port))
        else:
            port, ip = None, None
            obs["C11"] = obs["C12"] = rc.obs_no_console(tcp_listeners(pid) if pid else None)
        qt = gv.virsh("qemu-monitor-command", vm, "--hmp", "info qtree", check=False).stdout
        msr, reach = guest_observe(con, IPS[peer])
        obs["C14"] = rc.obs_c14(msr, gp.parse_qtree(qt))
        obs["C16"] = rc.obs_c16(reach, nic=(nic != "none"), ip_ok=(nic == "up" and pnic == "up"))
        xmls = {v: gv.virsh("dumpxml", "--inactive", v).stdout for v in (vm, peer)}
    finally:
        con.close()
        pcon.close()
        for v in (vm, peer):
            gv.virsh("destroy", v, check=False)
    d.mkdir(parents=True)
    shutil.copytree(work, d / "assess")
    (d / "assess_stdout.txt").write_text(cli.stdout + f"\n# exit={cli.returncode}\n" + cli.stderr[-2000:])
    for v, x in xmls.items():
        (d / f"{v}.xml").write_text(re.sub(r"passwd='[^']*'", "passwd='REDACTED'", x))
    cfg = {k: arm[k] for k in ("machine", "listen", "passwd", "floppy", "net", "iso", "peer_net", "peer_iso")}
    return {"arm": arm["name"], "vm": vm, "peer": peer, "config": cfg, "nic": {"vm": nic, "peer": pnic},
            "assess_exit": cli.returncode, "findings": findings,
            "observations": {k: {**v, "evidence": str(v["evidence"])} for k, v in obs.items()},
            "rows": rc.compare(findings, obs), "vnc_port": port, "host_ip_probed": ip}


def run(names):
    for vm in gv.VMS:
        if not gv.is_ours(vm):
            raise SystemExit(f"{vm} missing or not ours: run setup first")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = OUT / run_id
    if run_dir.exists():
        raise SystemExit(f"{run_dir} exists: refusing to overwrite")
    run_dir.mkdir(parents=True)
    ensure_net2()
    before = protected_state()
    started = gv.now()
    arms = []
    for a in ARMS:
        if a["name"] in names:
            arms.append(one_arm(a, run_dir))
            print(f"arm {a['name']}: {rc.summary(arms[-1]['rows'])}", flush=True)
    after = protected_state()
    files = ["vsec/m1_audit.py", "vsec/collect.py", "vsec/runtime_check.py", "vsec/gate_probe.py", "vsec/provenance.py",
             "vsec/__main__.py", "scripts/real_runtime_validation.py", "scripts/real_gate_validation.py"]
    meta = {**gv.versions(), "started": started, "finished": gv.now(), "arms_requested": sorted(names),
            "code_sha256": {f: sha(ROOT / f) for f in files}, "lsm": lsm_state(), "image_source": str(gv.SOURCE_IMG),
            "image_source_sha256": sha(gv.SOURCE_IMG), "protected_state_unchanged": before == after,
            "protected_state_before": before, "provenance": "live-runtime / live-config (real disposable VMs)",
            "reproduce": "sudo .venv/bin/python scripts/real_runtime_validation.py run --arms " + ",".join(sorted(names))}
    res = {"run_id": run_id, "meta": meta, "arms": arms, "summary": rc.summary([r for a in arms for r in a["rows"]])}
    (run_dir / "run.json").write_text(json.dumps(res, indent=1, default=str))
    (run_dir / "runtime_validation.md").write_text(rc.markdown(res))
    print(rc.markdown(res))
    if before != after:
        raise SystemExit("PROTECTED STATE CHANGED: see run.json")


def setup():
    before = protected_state()
    for vm in gv.VMS:
        if gv.exists(vm) and not gv.is_ours(vm):
            raise SystemExit(f"{vm} exists and is not ours: refusing to touch it")
    gv.ensure_network()
    ensure_net2()
    for vm in gv.VMS:
        if not gv.image(vm).exists():
            shutil.copyfile(gv.SOURCE_IMG, gv.image(vm))
        gv.image(vm).chmod(0o600)
        if not gv.exists(vm):
            gv.define(domain_xml(vm, **PEER, net="iso", iso=False))
    if protected_state() != before:
        raise SystemExit("PROTECTED STATE CHANGED during setup")
    print(f"ready: {', '.join(gv.VMS)}, networks {gv.NET}, {NET2}")


def cleanup(confirm):
    gv.cleanup(confirm)
    if confirm and NET2 in gv.virsh("net-list", "--all", "--name").stdout.split():
        users = gv._others_using(f"network='{NET2}'")
        if users:
            print(f"keeping {NET2}: used by {users}")
        else:
            gv.virsh("net-destroy", NET2, check=False)
            gv.virsh("net-undefine", NET2)
            print(f"removed network {NET2}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["setup", "run", "cleanup"])
    ap.add_argument("--arms", default=",".join(a["name"] for a in ARMS))
    ap.add_argument("--i-really-mean-it", action="store_true")
    a = ap.parse_args()
    if a.cmd == "setup":
        setup()
    elif a.cmd == "cleanup":
        cleanup(a.i_really_mean_it)
    else:
        run(set(a.arms.split(",")))


if __name__ == "__main__":
    main()
