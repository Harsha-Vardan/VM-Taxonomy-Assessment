"""One-command demo for the professor.   python demo.py        (or double-click demo.bat)

Steps (press Enter between them):
  1. [live] Real KVM host on WSL2: default -> weakened -> hardened (saved real audits)
  2. [live] Runtime validation: M1 prediction vs independent observation on disposable VMs
  3. [live] HTML report built from two REAL collected cases (open VNC vs isolated), then the Attack Lab [model]
Nothing here attacks anything: it runs the real auditor on folders and shows saved real-host results.
"""
import difflib
import os
import subprocess
import sys
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)
os.system("")  # enable ANSI colours on Windows terminals
G, R, Y, B, D, X = "\033[92m", "\033[91m", "\033[93m", "\033[1m", "\033[2m", "\033[0m"
COL = {"PASS": G, "FAIL": R, "NA": Y}
CASES = [("real-open-vnc", "results/real/runtime_validation/raw/20261116T063834Z/arm-A/assess/case"), ("real-isolated", "results/real/runtime_validation/raw/20261116T063834Z/arm-D/assess/case")]  # collected by vsec assess
REAL = [("default", "results/real/vsec-target.1-default.audit.txt"),
        ("weakened", "results/real/vsec-target.2-weakened.audit.txt"),
        ("hardened", "results/real/vsec-target.3-hardened.audit.txt")]


def parse(lines):
    out = {}
    for ln in lines:
        p = ln.split(None, 3)
        if len(p) >= 3 and p[0][:1] == "C" and p[1] in COL:
            out[p[0]] = (p[1], p[2], p[3].strip() if len(p) > 3 else "")
    return out


def audit(folder):
    r = subprocess.run([sys.executable, "-m", "vsec", "audit", folder, "--env", "E1"],
                       capture_output=True, text=True, encoding="utf-8")
    return parse(r.stdout.splitlines())


def pause(msg="Press Enter for the next step..."):
    try:
        input(f"\n{D}{msg}{X}")
    except EOFError:
        pass


def header(t):
    print(f"\n{B}{'=' * 78}\n {t}\n{'=' * 78}{X}")


def table(title, cols):
    header(title)
    ids = sorted({c for _, a in cols for c in a})
    print(f"{B}{'ID':<5}{'control':<23}" + "".join(f"{n:<12}" for n, _ in cols) + f"{X}")
    for cid in ids:
        st = [a.get(cid, ("-", "", ""))[0] for _, a in cols]
        name = next(a[cid][1] for _, a in cols if cid in a)
        mark = f" {Y}<- changed{X}" if len(set(st)) > 1 else ""
        print(f"{cid:<5}{name[:22]:<23}" + "".join(f"{COL.get(s, '')}{s:<12}{X}" for s in st) + mark)
    print(f"{B}{'totals':<28}{X}", end="")
    for _, a in cols:
        v = [s for s, _, _ in a.values()]
        print(f"{R}{v.count('FAIL')}F{X}/{G}{v.count('PASS')}P{X}/{Y}{v.count('NA')}NA{X}  ", end="")
    print()


def file_diff(a, b):
    header(f"Step 3b [constructed] What the fixture fix changed: {a}  ->  {b}  (red = before, green = after)")
    for f in sorted(p.name for p in Path(a).iterdir() if p.is_file()):
        x = (Path(a) / f).read_text(encoding="utf-8", errors="replace").splitlines()
        y = (Path(b) / f).read_text(encoding="utf-8", errors="replace").splitlines() if (Path(b) / f).exists() else []
        ch = [l for l in difflib.unified_diff(x, y, lineterm="", n=0) if l[:1] in "+-" and l[:3] not in ("+++", "---")]
        if ch:
            print(f"\n{B}{f}{X}")
            for l in ch[:8]:
                print(f"  {R if l[0] == '-' else G}{l[:100]}{X}")
            if len(ch) > 8:
                print(f"  {D}... {len(ch) - 8} more lines{X}")


def latest_runtime_validation():
    """The run with the most configurations (the 10-arm X1 run), newest first on ties."""
    import json
    runs = sorted(Path("results/real/runtime_validation/raw").glob("*/run.json"), reverse=True)
    if not runs:
        return None
    best = max(runs, key=lambda r: len(json.loads(r.read_text(encoding="utf-8"))["arms"]))
    return best.with_name("runtime_validation.md")


def main():
    header("vsec demo: taxonomy-driven security audit of KVM (no exploits are run)")
    print("Everything shown is from real KVM VMs, except the Attack Lab, which is a model of the survey.")
    pause("Press Enter for the real KVM host...")

    real = [(n, parse(Path(f).read_text(encoding="utf-8").splitlines())) for n, f in REAL if Path(f).exists()]
    if real:
        table("Step 1  [live] REAL KVM host (WSL2 + KVM, VM 'vsec-target'): default -> weakened -> hardened", real)
        print(f"\n{D}Say: a stock install fails 8. We really added a floppy, open VNC and unsafe cache (11 FAIL).")
        print(f"After the printed fixes 2 remain: C01 IOMMU and C06 AppArmor, which WSL2 cannot provide.")
        print(f"Live command on a KVM host: python -m vsec assess <domain> --qemu-devices{X}")
    pause()

    rv = latest_runtime_validation()
    header("Step 2  [live] Does M1's verdict match the RUNNING system? (disposable VMs, independent probes)")
    if rv:
        text = rv.read_text(encoding="utf-8")
        keep = [l for l in text.splitlines() if l.startswith(("**Totals", "- arm", "- none", "## Arm", "| C"))]
        print("\n".join(keep[:60]))
        print(f"\n{D}Full report: {rv}{X}")
    else:
        print("no runtime-validation run found (scripts/real_runtime_validation.py)")
    pause()

    header("Step 3  [live] HTML report of two real collected VMs  +  [model] Attack Lab")
    subprocess.run([sys.executable, "-m", "vsec", "run"] + sum((["--vm", f"{n}={f}"] for n, f in CASES), [])
                   + ["--env", "E0", "--out", "out"], capture_output=True)
    for page in ("out/report.html", "simulator.html"):
        if Path(page).exists():
            webbrowser.open((ROOT / page).as_uri())
            print(f"opened {page}")
    print(f"\n{D}In the Attack Lab: Simulate tab -> legacy-erp -> Floppy-controller escape -> Apply fix C14.{X}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nstopped")
