"""Independent runtime validation of M1 verdicts (pure functions; the live runner is scripts/real_runtime_validation.py).

M1 PREDICTS a control state from collected evidence. Here a separate code path OBSERVES the running system and
gives its own PASS / FAIL / NA for the same control. Each observation states its method and how independent it is:
  independent  different evidence than M1 uses (a network handshake, a guest-side read, guest-to-guest traffic)
  partial      same kernel interface as M1 but read directly by the validator, plus extra context M1 does not use
Agreement is only computed where both sides are PASS or FAIL. Nothing here exploits anything.
"""
import re

from .gate_probe import observe_c11, observe_c12, observe_c14

VALIDATED = ("C04", "C06", "C11", "C12", "C14", "C16")
METHOD = {
    "C04": ("partial", "validator reads /proc/<qemu-pid>/status itself: Seccomp mode and Seccomp_filters count"),
    "C06": ("partial", "validator reads /proc/<qemu-pid>/attr/current and whether an LSM (AppArmor/SELinux) is enabled"),
    "C11": ("independent", "RFB handshake on the VNC port: does the server offer security type None"),
    "C12": ("independent", "TCP+RFB connect to the VNC port on the host's non-loopback address"),
    "C14": ("independent", "guest reads the floppy controller status port 0x3F4 (0xFF = no device) + QEMU info qtree"),
    "C16": ("independent", "guest pings a second running VM (static addresses, no DHCP; both NICs verified up). "
                           "Reachable = FAIL; unreachable with working NICs, or no NIC at all = PASS"),
}


def _obs(status, evidence, note=""):
    return {"status": status, "evidence": evidence, "note": note}


def obs_c04(status_text):
    if not status_text:
        return _obs("NA", "no /proc status (VM not running?)")
    mode = re.search(r"^Seccomp:\s*(\d+)", status_text, re.M)
    filters = re.search(r"^Seccomp_filters:\s*(\d+)", status_text, re.M)
    if not mode:
        return _obs("NA", "no Seccomp line")
    m, f = int(mode.group(1)), int(filters.group(1)) if filters else None
    ok = m == 2 and (f is None or f >= 1)
    return _obs("PASS" if ok else "FAIL", f"Seccomp={m} Seccomp_filters={f}")


def obs_c06(label, lsm):
    """label: /proc/<pid>/attr/current; lsm: {'apparmor': 'Y'|'N'|None, 'selinux_enforce': '1'|'0'|None}."""
    if label is None:
        return _obs("NA", "no label (VM not running?)")
    enabled = (lsm.get("apparmor") or "").strip().upper() == "Y" or (lsm.get("selinux_enforce") or "").strip() == "1"
    low = label.strip().lower()
    confined = enabled and low not in ("", "unconfined", "kernel") and "unconfined" not in low
    return _obs("PASS" if confined else "FAIL", f"label={label.strip()[:60]!r} lsm={lsm}",
                "" if enabled else "no LSM enabled on this host: QEMU cannot be confined")


def obs_c11(probe):
    o = observe_c11(probe)
    if o["blocked"] is None:
        return _obs("NA", probe, o.get("note", ""))
    return _obs("PASS" if o["blocked"] else "FAIL", probe)


def obs_c12(probe):
    o = observe_c12(probe)
    return _obs("PASS" if o["blocked"] else "FAIL", probe)


def obs_c14(msr, qtree):
    o = observe_c14(msr, qtree)
    if o["blocked"] is None:
        return _obs("NA", o["evidence"], o.get("note", ""))
    return _obs("PASS" if o["blocked"] else "FAIL", o["evidence"], o.get("note", ""))


def obs_c16(peer_reachable, nic=True, ip_ok=True):
    """nic: the guest has a network interface; ip_ok: both guests' addresses were configured (else a failed ping
    proves nothing)."""
    if not nic:
        return _obs("PASS", "guest has no network interface")
    if peer_reachable is None or not ip_ok:
        return _obs("NA", f"guest-to-guest test inconclusive (ping={peer_reachable}, addresses configured={ip_ok})")
    return _obs("FAIL" if peer_reachable else "PASS", f"second VM reachable by ping: {peer_reachable}")


def compare(findings, observations):
    """findings: M1 findings (dicts) for one VM; observations: {cid: obs}. One row per validated control."""
    by_id = {f["id"]: f for f in findings}
    rows = []
    for cid in VALIDATED:
        f, o = by_id.get(cid), observations.get(cid)
        pred = f["status"] if f else "NA"
        obs = o["status"] if o else "NA"
        agree = None if "NA" in (pred, obs) else pred == obs
        rows.append({"id": cid, "predicted": pred, "predicted_evidence": f["evidence"] if f else "",
                     "provenance": f.get("provenance", "") if f else "", "observed": obs,
                     "observed_evidence": str(o["evidence"])[:300] if o else "", "note": o.get("note", "") if o else "",
                     "independence": METHOD[cid][0], "method": METHOD[cid][1], "agree": agree})
    return rows


def summary(all_rows):
    n = {"agree": 0, "disagree": 0, "unobserved": 0}
    for r in all_rows:
        n["unobserved" if r["agree"] is None else "agree" if r["agree"] else "disagree"] += 1
    return n


def markdown(run):
    """run: {'run_id', 'meta', 'arms': [{'arm', 'vm', 'config', 'findings', 'rows'}]}."""
    out = [f"# Runtime validation {run['run_id']} (REAL, disposable VMs on {run['meta'].get('env', '?')})", "",
           "M1 PREDICTS from collected evidence; the validator OBSERVES the running system through a separate path.",
           "Tags: live-runtime / live-config = M1 input source; independence = how separate the observation is.", ""]
    rows = [r for a in run["arms"] for r in a["rows"]]
    s = summary(rows)
    out += [f"**Totals:** {s['agree']} agree, {s['disagree']} disagree, {s['unobserved']} not observable "
            f"({len(run['arms'])} arms x {len(VALIDATED)} controls).", ""]
    for a in run["arms"]:
        out += [f"## Arm {a['arm']} ({a['vm']}): {a['config']}", "",
                "### Predictions (M1) | Observations (runtime) | Comparison", "",
                "| ID | M1 predicts | M1 source | observed | independence | agree | M1 evidence | observation |",
                "|---|---|---|---|---|---|---|---|"]
        for r in a["rows"]:
            ag = "n/a" if r["agree"] is None else ("yes" if r["agree"] else "**NO**")
            out.append(f"| {r['id']} | {r['predicted']} | {r['provenance']} | {r['observed']} | {r['independence']} | {ag} | "
                       f"{r['predicted_evidence'][:60]} | {r['observed_evidence'][:80]} {r['note']} |")
        out.append("")
    dis = [(a["arm"], r) for a in run["arms"] for r in a["rows"] if r["agree"] is False]
    out += ["## Disagreements", ""] + ([f"- arm {arm}, {r['id']}: M1 {r['predicted']} vs observed {r['observed']} "
                                        f"({r['method']}). {r['note']}" for arm, r in dis] or ["- none"])
    out += ["", "## Methods", ""] + [f"- {c} ({METHOD[c][0]}): {METHOD[c][1]}" for c in VALIDATED]
    return "\n".join(out) + "\n"


def obs_no_console(tcp_listeners):
    """C11 and C12 for a VM without graphics: the QEMU process must not listen on any TCP port.
    tcp_listeners: list of 'addr:port' strings owned by the QEMU pid (from `ss -ltnp`)."""
    if tcp_listeners is None:
        return _obs("NA", "listener list unavailable")
    return _obs("FAIL" if tcp_listeners else "PASS", f"QEMU TCP listeners: {tcp_listeners}")
