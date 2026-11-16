"""Attack Lab gate validation: does a gate control that M1 calls PASS really stop the attack stage it gates?

The Attack Lab (vsec/sim.py, vsec/attacks.yaml) assumes that a stage is stopped when any of its gate controls is
PASS. This module turns that assumption into a testable prediction and compares it with what is OBSERVED on a real
VM by a probe that does not use M1's verdict:

  control  attack stage                                   independent observation (benign, no exploit)
  C12      A02 s0 "Scan the network for console ports"   TCP connect + RFB banner on the host's non-loopback address
  C11      A02 s1 "Connect to the guest console"         RFB handshake: is security type 1 (None) offered?
  C14      A01 s1 "Send oversized FIFO command sequences" guest reads the floppy controller's status register
                                                          (port 0x3F4 via /dev/port; 0xFF = nothing decodes it),
                                                          corroborated by `info qtree` (isa-fdc present?)
  C17      A09 s2 "Read the VM disk or memory image"     `nobody` reads the first bytes of the image (qcow2 magic)

Prediction (MODEL): stage blocked  <=>  any gate of that stage is PASS in the M1 audit of the same running VM.
Observation (REAL): stage blocked  <=>  the probe could not do what the stage needs.
Pure functions here; the virsh/console orchestration is in scripts/real_gate_validation.py.
"""
import socket

QCOW2_MAGIC = b"QFI\xfb"
FDC_MSR_PORT = 0x3F4
# (control, attack id, stage index) for the stages this experiment can observe on E0
PROBED = (("C12", "A02", 0), ("C11", "A02", 1), ("C14", "A01", 1), ("C17", "A09", 2))
RFB_NONE, RFB_VNC_AUTH = 1, 2


# ---- model side -------------------------------------------------------------------------------
def stage(attacks, attack_id, index):
    a = next(x for x in attacks if x["id"] == attack_id)
    return a["steps"][index]


def predict_blocked(attacks, attack_id, index, state):
    """The Attack Lab's prediction for one stage: blocked iff any of its gates is PASS (sim.evaluate's rule)."""
    gates = stage(attacks, attack_id, index)["gates"]
    if not gates:
        raise ValueError(f"{attack_id} stage {index} has no gate: nothing to validate")
    return any(state.get(g) == "PASS" for g in gates)


def coverage(attacks, probed=PROBED):
    """(probed gated stages, all gated stages) across every attack."""
    gated = [(a["id"], i) for a in attacks for i, s in enumerate(a["steps"]) if s["gates"]]
    done = {(a, i) for _, a, i in probed}
    return len([g for g in gated if g in done]), len(gated)


# ---- probes and their parsers -----------------------------------------------------------------
def parse_rfb(banner, types_blob):
    """RFB 3.7/3.8 server security-type list -> {'version', 'types', 'none_offered', 'reason'}.
    types_blob = the bytes after the client's version reply: 1 count byte then that many type bytes; count 0
    means the server refused (a reason string follows)."""
    out = {"version": banner.decode("ascii", "replace").strip(), "types": [], "none_offered": False, "reason": ""}
    if not banner.startswith(b"RFB "):
        out["reason"] = "no RFB banner"
        return out
    if not types_blob:
        out["reason"] = "no security types received"
        return out
    n = types_blob[0]
    if n == 0:
        out["reason"] = "server refused: " + types_blob[5:].decode("utf-8", "replace")[:80]
        return out
    out["types"] = list(types_blob[1:1 + n])
    out["none_offered"] = RFB_NONE in out["types"]
    return out


def _recv(s, n, timeout):
    s.settimeout(timeout)
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def rfb_probe(host, port, timeout=4.0):
    """Connect, read the banner, reply with the same version, read the security-type list. Never authenticates.
    Returns {'connected', 'error', 'version', 'types', 'none_offered', 'reason'}."""
    res = {"host": host, "port": port, "connected": False, "error": "", "version": "", "types": [],
           "none_offered": False, "reason": ""}
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            res["connected"] = True
            banner = _recv(s, 12, timeout)
            if banner.startswith(b"RFB "):
                s.sendall(banner)
                types = _recv(s, 1, timeout)
                if types and types[0]:
                    types += _recv(s, types[0], timeout)
                elif types:
                    types += _recv(s, 4, timeout)
                    types += s.recv(200) if len(types) == 5 else b""
            else:
                types = b""
            res.update(parse_rfb(banner, types))
    except OSError as e:
        res["error"] = f"{type(e).__name__}: {e}"
    return res


def observe_c12(probe):
    """A02 s0 open iff an outsider address reached a live RFB server."""
    return {"blocked": not (probe["connected"] and probe["version"].startswith("RFB")), "evidence": probe}


def observe_c11(probe):
    """A02 s1 open iff the console accepts a client with no authentication (security type None)."""
    if not probe["connected"] or not probe["version"].startswith("RFB"):
        return {"blocked": None, "evidence": probe, "note": "console not reachable from the probe point: no observation"}
    return {"blocked": not probe["none_offered"], "evidence": probe}


def parse_qtree(text):
    """`info qtree` -> {'isa_fdc': bool, 'floppy_drives': n}. A drive is a `dev: floppy` node."""
    lines = [ln.strip() for ln in text.splitlines()]
    return {"isa_fdc": any(ln.startswith("dev: isa-fdc") for ln in lines),
            "floppy_drives": sum(ln.startswith("dev: floppy") for ln in lines)}


def parse_port_byte(text):
    """The first hex byte printed by `od -An -tx1` / hexdump inside the guest; None if absent."""
    for tok in text.replace("\r", " ").split():
        if len(tok) == 2:
            try:
                return int(tok, 16)
            except ValueError:
                continue
    return None


def observe_c14(msr, qtree):
    """A01 s1 open iff guest code can talk to a floppy controller (the VENOM code path is the FDC's I/O-port
    handler, reachable whether or not a drive is attached). Primary: guest read of the MSR at 0x3F4 (0xFF = no
    device decodes the port). qtree is host-side corroboration; a disagreement between the two is recorded."""
    if msr is None:
        return {"blocked": None, "evidence": {"msr": None, "qtree": qtree}, "note": "guest port read failed"}
    reachable = msr != 0xFF
    ev = {"msr": f"0x{msr:02x}", "qtree": qtree}
    note = "" if reachable == qtree["isa_fdc"] else "guest MSR read and qtree disagree"
    return {"blocked": not reachable, "evidence": ev, "note": note}


def observe_c17(head_bytes, returncode, stderr=""):
    """A09 s2 open iff an unrelated unprivileged user read real image bytes."""
    ok = returncode == 0 and head_bytes.startswith(QCOW2_MAGIC)
    return {"blocked": not ok, "evidence": {"rc": returncode, "magic_read": head_bytes[:4].hex(),
                                            "stderr": stderr.strip()[:120]}}


# ---- scoring ----------------------------------------------------------------------------------
def summarise(rows, wilson):
    """rows: dicts with control, predicted_blocked, observed_blocked (None = no observation).
    Agreement is counted only where both exist; per-control and overall with Wilson CIs."""
    def block(rs):
        obs = [r for r in rs if r["observed_blocked"] is not None]
        agree = sum(r["predicted_blocked"] == r["observed_blocked"] for r in obs)
        fp = sum(r["predicted_blocked"] and not r["observed_blocked"] for r in obs)   # model says safe, stage open
        fn = sum(not r["predicted_blocked"] and r["observed_blocked"] for r in obs)   # model says open, stage blocked
        return {"n": len(obs), "agree": agree, "ci": list(wilson(agree, len(obs))) if obs else None,
                "unsafe_disagreements": fp, "conservative_disagreements": fn, "no_observation": len(rs) - len(obs)}
    per = {}
    for r in rows:
        per.setdefault(r["control"], []).append(r)
    return {"overall": block(rows), "per_control": {c: block(rs) for c, rs in sorted(per.items())}}
