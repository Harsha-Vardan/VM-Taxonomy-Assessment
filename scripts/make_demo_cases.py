"""Build three hand-made demo targets for the before/after audit demo.

    python scripts/make_demo_cases.py [out_dir]        (default: demo_cases)

weak        a deliberately misconfigured KVM host + VM (many seeded faults)
hardened    the same host with every control set the recommended way
weak-fixed  `weak` after applying the fix commands the audit printed, except what a config edit cannot
            fix (a CPU vulnerability needs a microcode/kernel update and a reboot)

HONEST LABEL: these are CONSTRUCTED to look like captured host files (same layout `vsec collect` writes).
They are NOT captured from a real machine, so an audit of them shows the checker working, not the state of
a real system. Real hosts are collected with `vsec collect` (docs/YOUR_TASKS.md, Task I).
"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("make_fixtures", ROOT / "tests" / "make_fixtures.py")
mf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mf)

WEAK = {
    "cmdline": "ro quiet splash",                                              # C01 IOMMU off
    "iommu_groups": "0",                                                       # C02
    "qconf.seccomp": "seccomp_sandbox = 0",                                    # C03
    "qemu_status": "Name:\tqemu\nSeccomp:\t0\n",                               # C04
    "qconf.driver": 'security_driver = "none"',                                # C05
    "qemu_label": "unconfined",                                                # C06
    "qconf.user": 'user = "root"',                                             # C07
    "qconf.caps": "clear_emulator_capabilities = 0",                           # C08
    "ksm_run": "1",                                                            # C09
    "nested": "Y",                                                             # C10
    "x.graphics": "vnc|0.0.0.0|",                                              # C11 + C12
    "x.redirdev": "1",                                                         # C13
    "x.devices": "floppy",                                                     # C14
    "x.iface": "default",                                                      # C15
    "net_scan.txt": "reachable: 22/tcp open",                                  # C16
    "net_isolation.txt": "not-isolated: network default has <forward mode='nat'>",
    "perm.image": "666", "perm.socket": "777", "perm.savedir": "755",          # C17, C18, C21
    "lconf.sock": 'unix_sock_rw_perms = "0777"',                               # C19
    "lconf.tcp": 'listen_tcp = 1\nauth_tcp = "none"',                          # C20
    "x.cache": "unsafe",                                                       # C22
    "ver.qemu": "4.2.1", "ver.kernel": "5.4.0",                                # C23, C24
    "vuln.a": "spectre_v2: Vulnerable",                                        # C25
    "smt": "1",                                                                # C26
    "x.shmem": "2",                                                            # C27
    "qconf.confined": "security_default_confined = 0",                         # C28
}
HARDENED = {}  # mf.GOOD is the hardened baseline
# After the fixes the audit prints, only what a config edit cannot fix remains.
WEAK_FIXED = {"vuln.a": "spectre_v2: Vulnerable", "ver.qemu": "4.2.1", "ver.kernel": "5.4.0"}


def settings_for(faults):
    """make_fixtures settings that break exactly these controls (the first seeded fault of each)."""
    s = {}
    for cid in faults:
        fault = mf.FAULTS[cid][2] if cid == "C16" else mf.FAULTS[cid][0]
        s.update(fault)
    if "C11" in faults and "C12" in faults:
        s["x.graphics"] = "vnc|0.0.0.0|"  # open to the network AND no password
    return s


def build_fleet(out, fleet):
    """One case folder per host (host-level faults) and per VM (VM-level faults), audited separately by the build."""
    out = Path(out)
    for kind, items in (("host", fleet["hosts"]), ("vm", fleet["vms"])):
        for it in items:
            folder = out / f"{kind}-{it['id']}"
            folder.mkdir(parents=True, exist_ok=True)
            for fn, text in mf.files_for(settings_for(it["faults"]), e0=False).items():
                with open(folder / fn, "w", encoding="utf-8", newline="") as fh:
                    fh.write(text)
    return out


def build(out):
    out = Path(out)
    for name, settings in (("weak", WEAK), ("hardened", HARDENED), ("weak-fixed", WEAK_FIXED)):
        folder = out / name
        folder.mkdir(parents=True, exist_ok=True)
        for fn, text in mf.files_for(settings, e0=False).items():
            with open(folder / fn, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
    return out


if __name__ == "__main__":
    target = build(sys.argv[1] if len(sys.argv) > 1 else ROOT / "demo_cases")
    print(f"wrote weak, hardened, weak-fixed -> {target}  (constructed demo targets, not captured hosts)")
