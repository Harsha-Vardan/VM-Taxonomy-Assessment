"""Where a result comes from. Every finding and every reported number carries exactly one tag:

  live-runtime  read from the running system when the evidence was collected (/proc, sysfs, stat, QEMU monitor)
  live-config   read from a real host's configuration files (domain XML, qemu.conf, libvirtd.conf, version strings);
                says what is DECLARED, not what runs
  constructed   hand-built or generated input (test fixtures, fault-injection E1/E2, the Attack Lab's example-fleet folders): regression and
                consistency testing only, never evidence about a real system
  model         output of the attack-path model (Attack Lab, E4-E6): consequences of our rules, not a measurement

A case folder is live only if `vsec collect` wrote it (collect_manifest.json present) and it has no
PROVENANCE file saying otherwise; anything else is constructed. Results with different tags are never pooled.
"""
from pathlib import Path

TAGS = ("live-runtime", "live-config", "constructed", "model")
MANIFEST = "collect_manifest.json"

# Controls whose M1 input, on a live collect, is runtime state (not a configuration file).
RUNTIME = {"C01", "C02", "C04", "C06", "C09", "C10", "C17", "C18", "C19", "C21", "C25", "C26"}
# C16 is runtime when the kernel bridge-port state (net_peers.txt) was collected.
# C14 is runtime only when the running QEMU's machine type or device list was collected.
C14_RUNTIME_FILES = ("qemu_devices", "qemu_machine")


def case_kind(folder):
    """'live' or 'constructed' for a case folder."""
    p = Path(folder)
    marker = p / "PROVENANCE"
    if marker.is_file():
        text = marker.read_text(encoding="utf-8", errors="replace").strip().lower()
        if text.startswith("constructed"):
            return "constructed"
    return "live" if (p / MANIFEST).is_file() else "constructed"


def control_source(cid, folder, kind=None):
    """Provenance tag of one M1 control's result for this case folder."""
    kind = kind or case_kind(folder)
    if kind != "live":
        return "constructed"
    if cid in RUNTIME:
        return "live-runtime"
    if cid == "C16" and (Path(folder) / "net_peers.txt").is_file():
        return "live-runtime"
    if cid == "C14" and any((Path(folder) / f).is_file() for f in C14_RUNTIME_FILES):
        return "live-runtime"
    return "live-config"
