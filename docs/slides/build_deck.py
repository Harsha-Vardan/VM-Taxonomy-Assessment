"""Build docs/slides/vsec_deck.pptx from docs/TALK_30MIN.md. Run from repo root: python docs/slides/build_deck.py
Only numbers from results/, the audits in results/real/ and the paper are used."""
from pathlib import Path
from pptx import Presentation
from pptx.dml.color import RGBColor as C
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN
from pptx.util import Inches, Pt

OUT = Path(__file__).with_name("vsec_deck.pptx")
NAVY, TEAL, INK, MUT = C(0x14, 0x2B, 0x3F), C(0x0B, 0x6B, 0x74), C(0x22, 0x2B, 0x33), C(0x5B, 0x67, 0x70)
PALE, WHITE, AMB, RED, GRN = C(0xEA, 0xF3, 0xF4), C(255, 255, 255), C(0x8A, 0x50, 0x00), C(0xA6, 0x1E, 0x1E), C(0x1E, 0x7A, 0x3C)
LIGHT = C(0xBF, 0xE3, 0xE6)
AUTH = "A. Doni Aditya (23BDS007), B. Harsha Vardan (23BDS015), E. Hariteja (23BDS019), L. Sahith Akash Manikanta (23BDS031)"
prs = Presentation()
prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
blank = prs.slide_layouts[6]
N = [0]


def box(s, x, y, w, h, fill=None):
    r = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
    r.fill.solid()
    r.fill.fore_color.rgb = fill
    r.line.fill.background()
    r.shadow.inherit = False
    return r


def text(s, x, y, w, h, lines, size=18, color=INK, bold=False, align=None):
    tb = s.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame
    tf.word_wrap = True
    for i, ln in enumerate(lines if isinstance(lines, list) else [lines]):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.space_after = Pt(6)
        if align:
            p.alignment = align
        r = p.add_run()
        r.text = ln
        r.font.size = Pt(size)
        r.font.color.rgb = color
        r.font.bold = bold
        r.font.name = "Calibri"


def slide(title, bullets=None, note=None, tag=None, size=20):
    s = prs.slides.add_slide(blank)
    N[0] += 1
    box(s, 0, 0, 13.333, 1.1, NAVY)
    text(s, 0.5, 0.22, 10.5, 0.7, title, 30, WHITE, True)
    if tag:
        text(s, 10.3, 0.38, 2.8, 0.5, tag, 14, LIGHT, True, PP_ALIGN.RIGHT)
    if bullets:
        text(s, 0.6, 1.4, 12.1, 4.6, ["•  " + b for b in bullets], size)
    if note:
        box(s, 0.6, 6.15, 12.1, 0.85, PALE)
        text(s, 0.8, 6.22, 11.7, 0.75, note, 16, TEAL, True)
    text(s, 12.3, 7.05, 0.8, 0.3, str(N[0]), 11, MUT, align=PP_ALIGN.RIGHT)
    return s


def table(s, x, y, w, rows, widths, size=14, rh=0.45):
    t = s.shapes.add_table(len(rows), len(rows[0]), Inches(x), Inches(y), Inches(w), Inches(rh * len(rows))).table
    for j, cw in enumerate(widths):
        t.columns[j].width = Inches(cw)
    for i, row in enumerate(rows):
        for j, v in enumerate(row):
            c = t.cell(i, j)
            c.text = v
            for p in c.text_frame.paragraphs:
                for r in p.runs:
                    r.font.size = Pt(size)
                    r.font.name = "Calibri"
                    r.font.bold = (i == 0)
                    r.font.color.rgb = WHITE if i == 0 else INK
            c.fill.solid()
            c.fill.fore_color.rgb = TEAL if i == 0 else (PALE if i % 2 else WHITE)


from pptx.chart.data import CategoryChartData
from pptx.enum.chart import XL_CHART_TYPE, XL_LEGEND_POSITION


def card(s, x, y, w, h, head, body, col, size=14):
    box(s, x, y, w, 0.55, col)
    text(s, x + 0.12, y + 0.07, w - 0.2, 0.45, head, 17, WHITE, True)
    box(s, x, y + 0.55, w, h - 0.55, PALE)
    text(s, x + 0.12, y + 0.65, w - 0.24, h - 0.7, body, size)


def arrow(s, x, y, w=0.45):
    a = s.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, Inches(x), Inches(y), Inches(w), Inches(0.4))
    a.fill.solid()
    a.fill.fore_color.rgb = TEAL
    a.line.fill.background()


def flow(s, y, steps, h=1.3, gap=0.6, x0=0.6, cols=None, w=2.6):
    for i, (head, body) in enumerate(steps):
        x = x0 + i * (w + gap)
        card(s, x, y, w, h, head, body, (cols[i] if cols else TEAL), 13)
        if i < len(steps) - 1:
            arrow(s, x + w + 0.07, y + h / 2 - 0.1, gap - 0.14)


def chart(s, kind, cats, series, x, y, w, h, colors, legend=True, size=12):
    cd = CategoryChartData()
    cd.categories = cats
    for n, v in series:
        cd.add_series(n, v)
    ch = s.shapes.add_chart(kind, Inches(x), Inches(y), Inches(w), Inches(h), cd).chart
    ch.font.size = Pt(size)
    ch.has_legend = legend and len(series) > 1
    if ch.has_legend:
        ch.legend.position = XL_LEGEND_POSITION.BOTTOM
        ch.legend.include_in_layout = False
    for i, ser in enumerate(ch.plots[0].series):
        ser.format.fill.solid()
        ser.format.fill.fore_color.rgb = colors[i % len(colors)]
    ch.plots[0].has_data_labels = True
    ch.plots[0].data_labels.font.size = Pt(size)
    ch.plots[0].gap_width = 60
    return ch


# 1 title
s = prs.slides.add_slide(blank)
N[0] += 1
box(s, 0, 0, 13.333, 7.5, NAVY)
text(s, 0.8, 1.8, 11.7, 1.8, "vsec: Taxonomy-Driven Security Assessment Framework for KVM Virtualization", 40, WHITE, True)
text(s, 0.8, 4.0, 11.7, 1, "Turning a survey of virtualization attacks into a tool that audits a real KVM host", 22, LIGHT)
text(s, 0.8, 5.3, 11.7, 1.2, [AUTH, "Cloud Security & Vulnerabilities  |  Submitted to Malay Kumar"], 16, WHITE)

slide("The problem", [
    "KVM + QEMU + libvirt runs a large share of the cloud.",
    "A VM is only as isolated as the configuration around it.",
    "A 2020 ACM Computing Surveys paper lists how VMs get attacked: escape to host, side channels, DMA, leaking snapshots, hidden hypervisors.",
    "But a survey is text. You cannot run text against a real system."],
    "Question: can we turn the survey into a tool that checks a real KVM setup, shows how weaknesses chain, and says what to fix first?", "1 | Problem")

s = slide("The survey and what we took from it", tag="2 | Inspiration")
table(s, 0.6, 1.4, 7.4, [
    ["From the survey (Sierra-Arriaga et al. 2020)", "What we built"],
    ["Taxonomy of threat classes", "9 classes, 31 controls"],
    ["Concrete attacks (floppy escape, Flip Feng Shui, dedup, DMA, snapshots, VMBR)", "11 attack chains"],
    ["Recommended defences", "28 checks in M1"],
    ["Snapshot privacy, memory forensics", "M2 and M3"],
    ["VMBR and timing literature", "M4 design"]],
    [4.4, 3.0], 14, 0.75)
chart(s, XL_CHART_TYPE.BAR_CLUSTERED, ["Guest to host", "Host to VMM", "Side channels", "Guest to guest", "DMA / IOMMU", "VMM vulns", "Snapshot privacy", "VMI", "VMBR presence"],
      [("Controls", (12, 6, 3, 3, 2, 2, 1, 1, 1))], 8.2, 1.3, 4.7, 4.7, [TEAL], legend=False, size=11)
text(s, 8.3, 6.0, 4.6, 0.4, "31 controls in 9 threat classes", 13, MUT, True)

s = slide("The system at a glance", tag="3 | Overview")
cw = 2.9
for i, (h, b, col) in enumerate([
        ("M1 Auditor", ["28 checks on a KVM host and its VMs", "PASS / FAIL / NA + fix command", "STATUS: built, real host"], GRN),
        ("M2 Snapshots", ["Find and redact secrets in memory dumps", "Planted-secret measurement", "STATUS: built, real dump"], GRN),
        ("M3 Hidden procs", ["Volatility 3: pslist vs psscan", "SHA-256 verified symbols", "STATUS: built, NOT run on a real dump"], AMB),
        ("M4 Hypervisor", ["Combine timing signals", "Pre-specified in prereg.md", "STATUS: design only, no data"], RED)]):
    card(s, 0.6 + i * (cw + 0.17), 1.4, cw, 3.1, h, ["- " + x for x in b], col, 14)
box(s, 0.6, 4.75, 12.1, 0.9, NAVY)
text(s, 0.8, 4.88, 11.7, 0.7, "Attack Lab: 11 attack chains across 6 VMs on 3 hosts. Shows spread and finds the smallest set of fixes.", 18, WHITE, True)
box(s, 0.6, 6.15, 12.1, 0.85, PALE)
text(s, 0.8, 6.22, 11.7, 0.75, "We run no exploits. We show the configuration that would allow an attack, and that the fix closes it.", 16, TEAL, True)

s = slide("M1: configuration auditor", tag="4 | M1")
flow(s, 1.4, [("1  Collect", "VM XML, qemu.conf, kernel flags, KSM, permissions. Passwords redacted."),
              ("2  Audit", "28 controls checked against the survey's recommended values."),
              ("3  Result", "PASS, FAIL or NA, plus the evidence string."),
              ("4  Fix", "Exact fix command for every FAIL.")], h=1.7, gap=0.57, w=2.6)
text(s, 0.6, 3.4, 12.1, 2.7, [
    "Examples:  C03 seccomp sandbox  |  C09 KSM off  |  C14 no floppy device  |  C11/C12 VNC password + loopback  |  C16 guest-to-guest path (live bridge)",
    "Special 1:  NA is never PASS. If a check cannot run, the tool says it does not know.",
    "Special 2:  host-level controls (shared by all VMs) are separated from VM-level controls.",
    "Special 3:  every control traces back to a section of the survey."], 17)
box(s, 0.6, 6.15, 12.1, 0.85, PALE)
text(s, 0.8, 6.22, 11.7, 0.75, "Demo:  python -m vsec assess <domain> --qemu-devices   (live, on the KVM host)", 16, TEAL, True)

s = slide("M1 on a real KVM host (WSL2 + KVM)", tag="5 | M1 evidence")
chart(s, XL_CHART_TYPE.COLUMN_STACKED, ["Default install", "After weakening", "After vsec fixes"],
      [("FAIL", (8, 11, 2)), ("PASS", (15, 12, 22)), ("NA", (5, 5, 4))], 0.6, 1.3, 6.6, 4.7, [RED, GRN, C(0x9A, 0xA5, 0xAD)], size=13)
text(s, 7.5, 1.5, 5.3, 4.5, [
    "Weakened = we added a floppy device, open VNC, unsafe cache. vsec caught all three.",
    "The 2 FAILs left are platform limits: WSL2 has no IOMMU and no AppArmor.",
    "vsec also caught our own mistake: the 'isolated' network had a host IP.",
    "Lynis: 247 tests on the same host, never mentions QEMU, KVM, seccomp, KSM or VNC."], 17)
box(s, 0.6, 6.15, 12.1, 0.85, PALE)
text(s, 0.8, 6.22, 11.7, 0.75, "Caveat: 78/78 seeded faults show consistency (we wrote checks and faults), not accuracy on other servers.", 16, TEAL, True)

s = slide("M2: memory-snapshot privacy scanner", tag="6 | M2")
flow(s, 1.4, [("Plant", "Host plants fake secrets with known bytes (ground truth)."),
              ("Scan", "PEM keys, AWS keys, JWT, 64-hex with entropy filter."),
              ("Redact", "Zero the match in place. File size unchanged."),
              ("Measure", "Recall with Wilson CI, plus false positives.")], h=1.7, gap=0.57, w=2.6)
text(s, 0.6, 3.4, 12.1, 2.7, [
    "Threat (S6.1): a snapshot (virsh save / dump, migration) copies everything in guest memory: keys, tokens, passwords.",
    "The HOST plants the secrets, so a lying guest cannot fake a good score.",
    "We held out encodings on purpose and found a blind spot: v1 found 0 of 120 encoded secrets."], 18)
box(s, 0.6, 6.15, 12.1, 0.85, PALE)
text(s, 0.8, 6.22, 11.7, 0.75, "Next: the real results, including a real 272 MiB virsh dump", 16, TEAL, True)

s = slide("M2 results: found, fixed, still limited", tag="7 | M2 evidence")
chart(s, XL_CHART_TYPE.COLUMN_CLUSTERED, ["Encoded (UTF-16 + base64), 80 secrets", "Real virsh dump (11 planted)"],
      [("Scanner v1", (0, 4)), ("Scanner v2", (80, 11))], 0.6, 1.3, 6.2, 4.7, [C(0x9A, 0xA5, 0xAD), TEAL], size=12)
text(s, 7.1, 1.4, 5.7, 4.6, [
    "Held-out set: v1 found 0 of 120. Fresh dumps for v2: UTF-16 40/40, base64 40/40 (the 80 bar).",
    "Real dump: v1 4/11, v2 11/11, clean after redaction.",
    "13 extra hits; 5 inspected, all public kernel constants.",
    "Still missed: secrets split across pages.",
    "v2 is labelled an improvement made after seeing the result."], 16)

slide("M3: hidden-process detection", [
    "Threat (S7): a rootkit unlinks a process from the kernel list; its structure still sits in memory.",
    "Volatility 3: compare linux.pslist (kernel's list) with linux.psscan (memory scan). In scan but not in list = hidden. Same for modules.",
    "Engineering: symbol files verified by SHA-256, optional sandbox, exited tasks separated from hidden ones.",
    "Stated limit: with no identifying column, tasks match by PID only."],
    "Status: built and unit-tested, NOT run on a real memory dump. Future work.", "8 | M3", 19)

slide("M4: multi-signal hypervisor detection", [
    "Threat (S7.1, S7.2): a VM-based rootkit / hidden hypervisor leaves traces in timing.",
    "Question: does COMBINING weak signals beat the best single signal?",
    "Design: native vs kvm-plain vs kvm-masked; instruction timing, memory latency, scheduler jitter, perf counters.",
    "Logistic regression and random forest, nested session-grouped cross-validation. Hypotheses H1-H4 with Holm correction.",
    "Pre-specified in prereg.md before any data, so the analysis cannot be tuned to results."],
    "Status: design only. Needs native Linux hardware. There is NO M4 data.", "9 | M4", 19)

s = slide("The Attack Lab: what is special", tag="10 | Attack Lab")
text(s, 0.6, 1.25, 12.1, 0.5, "Example chain: floppy-controller escape (S4.1). A stage stops when its gate control PASSES.", 17, MUT, True)
flow(s, 1.9, [("Stage 1", "Reach the VM (attacker foothold)"), ("Stage 2", "Abuse floppy device. GATE: C14"), ("Stage 3", "Escape QEMU sandbox. GATES: C04, C03"), ("Stage 4", "Host compromised, spreads to VMs on host")],
     h=1.6, gap=0.5, cols=[TEAL, AMB, AMB, RED], w=2.75)
text(s, 0.6, 3.8, 12.1, 2.3, [
    "-  6 VMs on 3 hosts: host escapes spread, shared networks allow pivoting, side channels hit neighbours.",
    "-  Computes the exact smallest fix set, blast radius and defence in depth.",
    "-  Control states come from real audits; the attack logic is a model. No exploit runs."], 17)
box(s, 0.6, 6.15, 12.1, 0.85, PALE)
text(s, 0.8, 6.22, 11.7, 0.75, "Live demo: simulator.html - floppy escape on legacy-erp, apply C14, then the neighbour pivot", 16, TEAL, True)

s = slide("What the model taught us", tag="11 | Results")
chart(s, XL_CHART_TYPE.COLUMN_CLUSTERED, ["0.1", "0.2", "0.3", "0.5"],
      [("Hardened host only (% of VMs breached)", (1.8, 7.4, 17.8, 46.9)), ("Host and VMs hardened", (0, 0, 0, 0))], 0.6, 1.3, 7.0, 4.7, [RED, GRN], size=12)
text(s, 7.9, 1.4, 4.9, 4.6, [
    "X axis: per-control fault rate. 2,000 random fleets per cell.",
    "A hardened host does not protect VMs with weak own settings.",
    "C09 (KSM off) blocks 8 attack pairs, more than any other control.",
    "Outsider campaign: 5 to 2 to 0 VMs after two fixes.",
    "57.3% of blocked pairs rely on a single control."], 16)

s = slide("Real vs model vs not done", tag="12 | Honesty")
for i, (h, col, items) in enumerate([
        ("REAL", GRN, ["One real KVM host (WSL2)", "Audited before / after hardening", "Compared with Lynis", "Real 272 MiB memory dump"]),
        ("MODEL", AMB, ["Attack Lab attack logic", "Experiments E4 to E6", "Seeded-fault tests (E1, E2)", "= consistency, not accuracy"]),
        ("NOT DONE", RED, ["M3 on a real dump", "M4 (needs bare metal)", "More than one real host", "Split-page secrets"])]):
    x = 0.6 + i * 4.1
    box(s, x, 1.5, 3.9, 0.7, col)
    text(s, x + 0.2, 1.58, 3.5, 0.5, h, 22, WHITE, True)
    box(s, x, 2.2, 3.9, 3.6, PALE)
    text(s, x + 0.2, 2.35, 3.5, 3.4, ["•  " + t for t in items], 18)

slide("Conclusion", [
    "A survey became 31 traceable controls, a working auditor and scanner, and an attack-path model.",
    "Tested on a real KVM host; one command reproduces the experiments (python scripts/run_experiments.py).",
    "It found and fixed a flaw in its own scanner, and reports what is untested."],
    "We do not run exploits: we show the configuration that would allow an attack and that the fix closes it.", "13 | Close", 22)

slide("Backup: reproduce everything", [
    "python -m vsec assess <domain> --qemu-devices   (live assessment on a KVM host)",
    "sudo python scripts/real_runtime_validation.py run   (M1 vs running VMs, 10 configurations)",
    "python scripts/run_experiments.py   (fixed seed, about 70 s)",
    "pytest   |   open simulator.html",
    "Papers: docs/paper/ieee/vsec_ieee_paper.pdf, docs/paper/vsec_research_paper.pdf"], None, "Backup", 18)
slide("Backup: honest limits (questions we expect)", [
    "Are the attacks simulated? Modelled from the survey on real audit results. No exploit code.",
    "Is 100% accuracy real? Only on our constructed fault set: consistency, not field accuracy.",
    "Why is M4 empty? It needs bare-metal Linux; the plan is pre-specified.",
    "Built with an AI assistant (Claude); tests show internal consistency only."], None, "Backup", 19)

prs.save(OUT)
print("saved", OUT, len(prs.slides._sldIdLst), "slides")
