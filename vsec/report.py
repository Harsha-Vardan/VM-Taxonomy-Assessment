"""Result matrix and JSON/HTML report. Works from findings only, so dummy findings render too."""
import html
from collections import defaultdict
from pathlib import Path

from . import dump_json, load_taxonomy


NOT_TESTED = "Not tested in this run"
PSEUDO_VMS = ("m2-dumps", "m4-sessions")  # module rows, not hosts: kept in JSON, hidden in the host table


def _vm_class_status(ids, statuses):
    """statuses: control -> set of statuses for one VM. PASS only if every control was tested and passed."""
    tested = {i for i in ids if statuses.get(i, set()) - {"NA"}}
    if any("FAIL" in statuses.get(i, ()) for i in ids):
        status = "FAIL"
    elif ids and len(tested) == len(ids):
        status = "PASS"
    else:
        status = "PARTIAL" if tested else "NA"
    return {"status": status, "tested": len(tested), "na": len(ids) - len(tested), "controls": len(ids)}


def matrix(findings):
    """Per threat class: label, controls, tested, N/A. Per VM and class: status/tested/controls (never pooled)."""
    tax = load_taxonomy()
    controls = defaultdict(set)
    for c in tax["controls"]:
        controls[c["threat"]].add(c["id"])
    seen = defaultdict(lambda: defaultdict(set))  # class -> control -> statuses
    per_vm = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))  # vm -> class -> control -> statuses
    for f in findings:
        seen[f["taxonomy"]][f["id"]].add(f["status"])
        per_vm[f["vm"]][f["taxonomy"]][f["id"]].add(f["status"])
    classes = {}
    for cls, label in tax["threat_classes"].items():
        ids = controls[cls]
        tested = {i for i in ids if seen[cls][i] - {"NA"}}
        classes[cls] = {"label": label, "controls": len(ids), "tested": len(tested), "na": len(ids) - len(tested),
                        "effective_label": label if tested else NOT_TESTED}
    vms = {vm: {cls: _vm_class_status(controls[cls], d[cls]) for cls in tax["threat_classes"]}
           for vm, d in per_vm.items()}
    return {"classes": classes, "vms": vms}


def _table(rows, head):
    th = "".join(f"<th>{html.escape(str(h))}</th>" for h in head)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><tr>{th}</tr>{body}</table>"


def _cell(v):
    return f"{v['status']} ({v['tested']}/{v['controls']} tested)" if v else ""


def contains_synthetic(modules):
    """True if any module result is flagged synthetic or simulated."""
    return any(m.get("synthetic") or m.get("simulated") for m in modules.values())


def failed_modules(modules):
    """[{name, reason}] for every module whose status is ERROR (it crashed; NA means no data was supplied)."""
    return [{"name": n, "reason": m.get("reason", "")} for n, m in modules.items() if m.get("status") == "ERROR"]


def na_modules(modules):
    return [{"name": n, "reason": m.get("reason", "")} for n, m in modules.items() if m.get("status") == "NA"]


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1c2430;--mute:#5d6877;--line:#d9dee5;--pass:#1b7f4c;--passbg:#dff3e8;
--fail:#b3261e;--failbg:#fbe3e1;--na:#8a6100;--nabg:#fff1c9;--part:#2a5db0;--partbg:#e0ebfb;--accent:#16325c}
@media (prefers-color-scheme:dark){:root{--bg:#10151c;--card:#1a212b;--ink:#e6eaf0;--mute:#9aa6b6;--line:#2c3644;
--pass:#5fd39a;--passbg:#163626;--fail:#ff8f86;--failbg:#40201d;--na:#f0c14f;--nabg:#3b2f10;--part:#8db7ff;--partbg:#1b2c48;--accent:#8db7ff}}
*{box-sizing:border-box}body{font:15px/1.5 system-ui,Segoe UI,sans-serif;margin:0;background:var(--bg);color:var(--ink)}
main{max-width:1180px;margin:0 auto;padding:24px 16px 64px}h1{margin:.2em 0 0;color:var(--accent);font-size:28px}
h2{margin:34px 0 10px;font-size:20px;border-bottom:2px solid var(--line);padding-bottom:6px}
.sub{color:var(--mute);margin:0 0 14px}.banner{background:#b00020;color:#fff;padding:10px 14px;font-size:16px;border-radius:6px}
.n{background:var(--nabg);color:var(--ink);padding:8px 12px;border-left:4px solid var(--na);border-radius:4px;margin:8px 0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card h3{margin:0 0 6px;font-size:16px}.big{font-size:34px;font-weight:700;line-height:1.1}
.bar{display:flex;height:12px;border-radius:6px;overflow:hidden;margin:8px 0;background:var(--line)}
.bar i{display:block}.bp{background:var(--pass)}.bf{background:var(--fail)}.bn{background:#e0a800}
.mute{color:var(--mute);font-size:13px}table{border-collapse:collapse;width:100%;background:var(--card);margin:8px 0;font-size:14px}
th{background:var(--accent);color:#fff;text-align:left}td,th{border:1px solid var(--line);padding:6px 9px;vertical-align:top}
.pill{display:inline-block;padding:1px 9px;border-radius:99px;font-weight:600;font-size:12px}
.PASS{background:var(--passbg);color:var(--pass)}.FAIL{background:var(--failbg);color:var(--fail)}
.NA{background:var(--nabg);color:var(--na)}.PARTIAL{background:var(--partbg);color:var(--part)}
td.c-PASS{background:var(--passbg)}td.c-FAIL{background:var(--failbg)}td.c-NA{background:var(--nabg)}td.c-PARTIAL{background:var(--partbg)}
code{background:var(--bg);border:1px solid var(--line);padding:1px 5px;border-radius:4px;font-size:12.5px;word-break:break-word}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:8px 0;padding:6px 12px}
summary{cursor:pointer;font-weight:600;padding:4px 0}pre{white-space:pre-wrap;font-size:12.5px;max-height:420px;overflow:auto}
.legend span{margin-right:14px}.tw{overflow-x:auto}.up{color:var(--pass);font-weight:700}.dn{color:var(--fail);font-weight:700}
"""

JS = """document.querySelectorAll('td').forEach(function(td){var m=/^(PASS|FAIL|NA|PARTIAL)\\b/.exec(td.textContent);
if(m&&td.textContent.indexOf('tested)')>-1)td.className='c-'+m[1];});"""


def _pill(s):
    return f"<span class='pill {html.escape(s)}'>{html.escape(s)}</span>"


def _counts(findings, vm):
    c = {"PASS": 0, "FAIL": 0, "NA": 0}
    for f in findings:
        if f["vm"] == vm and f.get("module") == "M1":
            c[f["status"]] = c.get(f["status"], 0) + 1
    return c


def _audited_vms(findings):
    """VMs that have M1 control findings (the pseudo-rows of M2/M4 are not hosts)."""
    seen = {}
    for f in findings:
        if f.get("module") == "M1" and f["vm"]:
            seen.setdefault(f["vm"], True)
    return list(seen)


def _cards(findings, vms):
    out = []
    for vm in vms:
        c = _counts(findings, vm)
        tested = c["PASS"] + c["FAIL"]
        pct = f"{100 * c['PASS'] / tested:.0f}%" if tested else "n/a"
        total = max(1, sum(c.values()))
        bar = "".join(f"<i class='{k}' style='width:{100 * c[x] / total:.1f}%'></i>"
                      for k, x in (("bp", "PASS"), ("bf", "FAIL"), ("bn", "NA")))
        out.append(f"<div class=card><h3>{html.escape(vm)}</h3><div class=big>{pct}</div>"
                   f"<div class=mute>of tested controls passed</div><div class=bar>{bar}</div>"
                   f"<div>{_pill('PASS')} {c['PASS']} &nbsp;{_pill('FAIL')} {c['FAIL']} &nbsp;{_pill('NA')} {c['NA']}</div></div>")
    return "<div class=cards>" + "".join(out) + "</div>"


def _before_after(findings, vms):
    pairs = [(v, v + "-fixed") for v in vms if v + "-fixed" in vms]
    out = []
    for before, after in pairs:
        b = {f["id"]: f for f in findings if f["vm"] == before and f.get("module") == "M1"}
        a = {f["id"]: f for f in findings if f["vm"] == after and f.get("module") == "M1"}
        rows = []
        for cid in sorted(b):
            if cid in a and (b[cid]["status"] != a[cid]["status"] or b[cid]["status"] == "FAIL"):
                moved = b[cid]["status"] == "FAIL" and a[cid]["status"] == "PASS"
                rows.append(f"<tr><td>{html.escape(cid)}</td><td>{html.escape(b[cid]['control'])}</td>"
                            f"<td>{_pill(b[cid]['status'])}</td><td>{_pill(a[cid]['status'])}</td>"
                            f"<td>{'<span class=up>fixed</span>' if moved else '<span class=dn>still open</span>'}</td></tr>")
        cb, ca = _counts(findings, before), _counts(findings, after)
        out.append(f"<h2>Before / after remediation: {html.escape(before)} to {html.escape(after)}</h2>"
                   f"<p class=sub>FAIL count {cb['FAIL']} to {ca['FAIL']}; PASS count {cb['PASS']} to {ca['PASS']}. "
                   f"Only the audit's own fix commands were applied. Remaining items need more than a config edit.</p>"
                   "<div class=tw><table><tr><th>ID</th><th>Control</th><th>Before</th><th>After</th><th>Result</th></tr>"
                   + "".join(rows) + "</table></div>")
    return "".join(out)


def _failed_table(findings, vms):
    out = []
    for vm in vms:
        fails = sorted((f for f in findings if f["vm"] == vm and f.get("module") == "M1" and f["status"] == "FAIL"),
                       key=lambda f: (-f["severity"], f["id"]))
        if not fails:
            continue
        rows = "".join(
            f"<tr><td>{html.escape(f['id'])}</td><td>{f['severity']}</td><td>{html.escape(f['taxonomy'])}</td>"
            f"<td>{html.escape(f['control'])}</td><td>{html.escape(f['evidence'])}</td><td><code>{html.escape(f['fix'])}</code></td></tr>"
            for f in fails)
        out.append(f"<details {'open' if len(out) == 0 else ''}><summary>{html.escape(vm)}: {len(fails)} failed controls "
                   f"(severity 4 = worst)</summary><div class=tw><table><tr><th>ID</th><th>Sev</th><th>Threat class</th>"
                   f"<th>Control</th><th>Evidence</th><th>How to fix</th></tr>{rows}</table></div></details>")
    return "".join(out)


LEGEND = ("<p class=legend><span>" + _pill("PASS") + " passed its defined test (not 'secure')</span><span>"
          + _pill("FAIL") + " test failed, fix shown</span><span>" + _pill("NA")
          + " could not be tested with this input (never counted as PASS)</span><span>" + _pill("PARTIAL")
          + " some controls in the class not tested</span></p>")


def to_html(report):
    m = report["matrix"]
    findings = report.get("findings", [])
    vms = _audited_vms(findings)
    parts = ["<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
             f"<title>vsec report</title><style>{CSS}</style><main>"]
    failed = report.get("modules_failed")
    if failed:
        listing = "; ".join(f"{f['name']}: {f['reason']}" for f in failed)
        parts.append(f"<p class=banner><b>MODULES FAILED: results incomplete.</b> {html.escape(listing)}</p>")
    if report.get("contains_simulated_or_synthetic"):
        parts.append("<p class=banner><b>CONTAINS SIMULATED/SYNTHETIC DATA: not citable</b></p>")
    parts.append("<h1>vsec report</h1><p class=sub>Taxonomy-driven security assessment for KVM virtualization. "
                 "Controls are derived from Sierra-Arriaga, Branco and Lee, ACM Computing Surveys 53(2), 2020.</p>")
    for n in report.get("notes", []):
        parts.append(f"<p class=n>{html.escape(n)}</p>")
    if vms:
        parts.append("<h2>Audit summary (M1 configuration auditor)</h2>" + _cards(findings, vms) + _before_after(findings, vms)
                     + "<h2>Failed controls and how to fix them</h2>" + _failed_table(findings, vms))
    parts.append("<h2>Threat classes</h2><p class=sub>How each class of the survey's taxonomy was covered in this run.</p>"
                 + LEGEND + "<div class=tw>" + _table(
        [(c, v["effective_label"], v["controls"], v["tested"], v["na"]) for c, v in m["classes"].items()],
        ["Threat class", "Label", "Controls", "Tested", "N/A"]) + "</div>")
    if m["vms"]:
        classes = list(m["classes"])
        parts.append("<h2>Per VM</h2><div class=tw>" + _table(
            [(vm, *[_cell(d.get(c)) for c in classes]) for vm, d in m["vms"].items()
             if vm not in PSEUDO_VMS], ["VM", *classes]) + "</div>")
    parts.append("<h2>Module details</h2>")
    for name, sect in report["modules"].items():
        parts.append(f"<details><summary>{html.escape(name)}</summary><pre>{html.escape(_pretty(sect))}</pre></details>")
    parts.append(f"</main><script>{JS}</script>")
    return "".join(parts)


def _pretty(o, ind=0):
    pad = "  " * ind
    if isinstance(o, dict):
        return "\n".join(f"{pad}{k}:" + (("\n" + _pretty(v, ind + 1)) if isinstance(v, (dict, list)) and v else f" {_fmt(v)}")
                         for k, v in o.items())
    if isinstance(o, list):
        if all(not isinstance(x, (dict, list)) for x in o):
            return pad + ", ".join(_fmt(x) for x in o)
        return "\n".join(_pretty(x, ind + 1) for x in o)
    return pad + _fmt(o)


def _fmt(v):
    return f"{v:.3f}" if isinstance(v, float) else str(v)


def write(report, out_dir):
    out = Path(out_dir)
    dump_json(report, out / "report.json")
    (out / "report.html").write_text(to_html(report), encoding="utf-8")
    return out / "report.html"
