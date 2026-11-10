#!/usr/bin/env python3
"""Real before/after on a real KVM host (run as root on the host, inside the repo's venv).

    sudo .venv/bin/python scripts/real_hardening_demo.py <vm-name>

Three audits of the SAME real VM, written to results/real/:
  1. default   the VM as created by virt-install on a stock libvirt
  2. weakened  we add the misconfigurations the survey's attacks need: a floppy controller (VENOM, S4.1),
               VNC open on all interfaces (S2.1, S5.2) and cache='unsafe'
  3. hardened  we apply the fix commands that `vsec audit` printed (remove device, VNC on 127.0.0.1 with a password,
               cache='none', isolated network, no host channel, image and save-dir permissions, nested off,
               explicit unprivileged QEMU user)
It changes only the test VM, libvirt's network definitions, qemu.conf and file modes under /var/lib/libvirt.
It runs no exploit. Controls that the platform cannot provide (IOMMU and an LSM inside WSL2) stay FAIL or NA,
and the summary says so.
"""
import json
import secrets
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "real"
VIRSH = ["virsh", "-c", "qemu:///system"]
# E0 = WSL2 laptop (IOMMU not testable, paper Section 4.4); E1 = native Linux
ENV = "E0" if "microsoft" in Path("/proc/version").read_text().lower() else "E1"
IMAGE = "/var/lib/libvirt/images/cirros.qcow2"  # CirrOS 0.6.2, a 21 MB test image


def sh(*cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode:
        raise SystemExit(f"{' '.join(cmd)} failed: {r.stderr.strip()}")
    return r.stdout


def virsh(*a, check=True):
    return sh(*VIRSH, *a, check=check)


def redefine(vm, edit):
    root = ET.fromstring(virsh("dumpxml", "--inactive", "--security-info", vm))
    edit(root.find("devices"))
    p = Path("/tmp/vsec-domain.xml")
    p.write_text(ET.tostring(root, encoding="unicode"))
    virsh("define", str(p))


def restart(vm):
    virsh("destroy", vm, check=False)
    time.sleep(1)
    virsh("start", vm)
    time.sleep(4)


def audit(vm, tag):
    case = ROOT / "cases" / f"real-{tag}"
    sh("rm", "-rf", str(case))
    sh(sys.executable, "-m", "vsec.collect", vm, str(case))
    r = subprocess.run([sys.executable, "-m", "vsec", "audit", str(case), "--env", ENV], capture_output=True, text=True, cwd=ROOT)
    (OUT / f"{vm}.{tag}.audit.txt").write_text(r.stdout)
    st = {}
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("C") and parts[1] in ("PASS", "FAIL", "NA"):
            st[parts[0]] = parts[1]
    return st


def weaken(dev):
    floppy = ET.SubElement(dev, "disk", type="file", device="floppy")
    ET.SubElement(floppy, "target", dev="fda", bus="fdc")
    for g in dev.findall("graphics"):
        g.set("listen", "0.0.0.0")
        for l in g.findall("listen"):
            l.set("address", "0.0.0.0")
    for d in dev.findall("disk"):
        drv = d.find("driver")
        if d.get("device") == "disk" and drv is not None:
            drv.set("cache", "unsafe")


def harden(dev):
    for d in list(dev.findall("disk")):
        if d.get("device") == "floppy":
            dev.remove(d)
        elif d.find("driver") is not None:
            d.find("driver").set("cache", "none")
    for g in dev.findall("graphics"):
        g.set("listen", "127.0.0.1")
        g.set("passwd", secrets.token_urlsafe(9)[:8])
        for l in g.findall("listen"):
            l.set("address", "127.0.0.1")
    for ch in list(dev.findall("channel")):
        dev.remove(ch)
    for i in dev.findall("interface"):
        src = i.find("source")
        if src is not None:
            src.set("network", "isolated")


# no <forward> AND no <ip>: an <ip> would give the guest a path to services on the host bridge (vsec C16 caught
# exactly that in our first hardening attempt)
ISOLATED = "<network><name>isolated</name><bridge name='virbr-iso'/></network>"


def reset_host():
    """Undo host_fixes so every run starts from the distribution defaults (reproducible audit 1)."""
    conf = Path("/etc/libvirt/qemu.conf")
    t = conf.read_text()
    if "# vsec hardening" in t:
        conf.write_text(t.split("\n# vsec hardening")[0] + "\n")
    if Path(IMAGE).exists():
        Path(IMAGE).chmod(0o644)
    for d in ("/var/lib/libvirt/qemu/save", "/var/lib/libvirt/qemu/dump"):
        if Path(d).exists():
            Path(d).chmod(0o755)
    virsh("net-destroy", "isolated", check=False)
    virsh("net-undefine", "isolated", check=False)
    sh("ip", "link", "delete", "virbr-iso", check=False)  # libvirt can leave the bridge behind
    if subprocess.run(["modprobe", "-r", "kvm_intel"], capture_output=True).returncode == 0:
        subprocess.run(["modprobe", "kvm_intel", "nested=1"])
    sh("systemctl", "restart", "libvirtd")
    time.sleep(2)


def host_fixes():
    done, skipped = [], []
    if "isolated" not in virsh("net-list", "--all", "--name"):
        Path("/tmp/iso.xml").write_text(ISOLATED)
        virsh("net-define", "/tmp/iso.xml")
    virsh("net-start", "isolated", check=False)
    done.append("C15/C16: isolated libvirt network (no <forward>), guest agent channel removed")
    for p in Path("/var/lib/libvirt/images").glob("*"):
        p.chmod(p.stat().st_mode & 0o770)
    done.append("C17: chmod o-rwx on VM images")
    for d in ("/var/lib/libvirt/qemu/save", "/var/lib/libvirt/qemu/dump"):
        if Path(d).exists():
            Path(d).chmod(0o700)
    done.append("C21: chmod 0700 on save and dump dirs")
    conf = Path("/etc/libvirt/qemu.conf")
    t = conf.read_text()
    if "\nuser = " not in t:
        conf.write_text(t + '\n# vsec hardening\nuser = "libvirt-qemu"\ngroup = "kvm"\n')
    done.append('C07: explicit unprivileged QEMU user (user = "libvirt-qemu")')
    sh("systemctl", "restart", "libvirtd")
    time.sleep(2)
    r = subprocess.run(["modprobe", "-r", "kvm_intel"], capture_output=True, text=True)
    if r.returncode == 0 and subprocess.run(["modprobe", "kvm_intel", "nested=0"]).returncode == 0:
        done.append("C10: kvm_intel reloaded with nested=0")
    else:
        skipped.append("C10: nested virtualization is set by the WSL2 kernel (kvm_intel built in); cannot be changed from inside")
    skipped.append("C01/C02: no IOMMU inside WSL2 (needs bare metal with intel_iommu=on)")
    skipped.append("C05/C06: the WSL2 kernel has no AppArmor/SELinux, so sVirt cannot be enabled")
    return done, skipped


def main():
    vm = sys.argv[1] if len(sys.argv) > 1 else "vsec-target"
    OUT.mkdir(parents=True, exist_ok=True)
    if "already in use" in subprocess.run([*VIRSH, "net-start", "default"], capture_output=True, text=True).stderr:
        sh("ip", "link", "delete", "virbr0", check=False)  # stale bridge left after a WSL restart
        virsh("net-start", "default", check=False)
    virsh("destroy", vm, check=False)
    reset_host()
    # start from a freshly created VM so audit 1 really is the virt-install default
    virsh("destroy", vm, check=False)
    virsh("undefine", vm, check=False)
    sh("virt-install", "--name", vm, "--memory", "256", "--vcpus", "1", "--disk", f"{IMAGE},format=qcow2",
       "--import", "--os-variant", "cirros0.5.2", "--network", "network=default", "--graphics", "vnc", "--noautoconsole")
    time.sleep(4)
    res = {"env": ENV, "vm": vm, "host": sh("hostname").strip(), "kernel": sh("uname", "-r").strip()}
    res["default"] = audit(vm, "1-default")
    redefine(vm, weaken)
    restart(vm)
    res["weakened"] = audit(vm, "2-weakened")
    virsh("destroy", vm, check=False)
    res["host_fixes"], res["not_fixable_here"] = host_fixes()
    redefine(vm, harden)
    restart(vm)
    res["hardened"] = audit(vm, "3-hardened")
    (OUT / "hardening.json").write_text(json.dumps(res, indent=1))
    order = sorted(res["default"])
    print("| Control | default | weakened | hardened |\n|---|---|---|---|")
    for c in order:
        print(f"| {c} | {res['default'][c]} | {res['weakened'].get(c)} | {res['hardened'].get(c)} |")
    for k in ("default", "weakened", "hardened"):
        v = list(res[k].values())
        print(f"{k}: FAIL {v.count('FAIL')} PASS {v.count('PASS')} NA {v.count('NA')}")
    print("fixed:", *res["host_fixes"], sep="\n  ")
    print("not fixable on this platform:", *res["not_fixable_here"], sep="\n  ")


if __name__ == "__main__":
    main()
