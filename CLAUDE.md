# CLAUDE.md: vsec (Taxonomy-Driven Security Assessment Framework for KVM)

Read this first. **Do not re-read the two PDFs or the long docs at the start of a session.** Everything needed is
summarised below. Open a deeper file only when the task needs it (see "Where to look").

## What this is

- **Course:** Cloud Security & Vulnerabilities. Instructor: Malay Kumar. The project is **50% of the grade**.
- **Team** (from the case study):
  - A. Doni Aditya (23BDS007)
  - B. Harsha Vardan (23BDS015)
  - E. Hariteja (23BDS019)
  - L. Sahith Akash Manikanta (23BDS031)
- **Deliverables:** (1) a working framework, (2) a research paper, (3) slides and a demo video.
- **Source paper:** Sierra-Arriaga, Branco, Lee, "Security Issues and Challenges for Virtualization Technologies," ACM CSUR 53(2) Art. 45, 2020, doi:10.1145/3382190. The file is `3382190 (1).pdf`.
- **Our case study of it:** `Virtualization_Security_Case_Study_Report.pdf` (desk analysis, 20 Sep 2026). Its **Table 9** (control checklist per threat class) is what this project makes executable.
- **Condensed version of both PDFs:** `docs/SOURCES_SUMMARY.md`. It has section/table numbers, the 6 findings, the survey's limits (= our research gap), and the T9 coverage gaps.

**Research question:** can the survey's threats and controls become experimentally testable controls on a modern KVM stack? Which of them hold, which fail, and which cannot be tested on this hardware?

**Centrepiece (M4):** against a hypervisor that hides its static indicators but does not fake time, do combined behaviour signals beat the best single signal? This is pre-registered in `prereg.md`.

## Architecture (Python 3.12 package `vsec/`, CLI `python -m vsec`)

| Module | File | Survey basis | Ground truth |
|---|---|---|---|
| Common | `taxonomy.yaml` (31 controls C01–C31, 9 threat classes), `report.py`, `score.py`, `collect.py`, `guards.py` | §3.1 classification | Not applicable |
| M1 config auditor | `m1_audit.py` (C01–C28) | §4.1, 4.2, 5.1–5.4, 6.8 | 50 synthetic fixtures (self-consistency only); Lynis/OpenSCAP still to run |
| M2 snapshot privacy | `m2_snapshot.py`, `secrets_gen.py` | §6.1.1 PPVM, §6.3.3 | 12 planted cells (4 secret types × 3 memory states) + held-out variants |
| M3 memory forensics | `m3_forensics.py` (Volatility 3: `pslist` vs `psscan`, `lsmod` vs module scan) | §6.5.1 VMI, §7.2.1 | Public Linux images |
| M4 hypervisor detection | `m4_detect/` (`bench.c`, `features.py`, `classify.py`, `stats.py`, `simulate.py`) | §7.1, 7.2.1, 7.2.2 | 3 classes: native / kvm-plain / kvm-masked, 15 boot sessions each |

**Finding format:** `{id, module, taxonomy, control, status: PASS|FAIL|NA|ERROR, severity 1-4, evidence, fix, env, vm}`.

**Environments:**
- **E0:** WSL2 + KVM on the laptop. Used for M1–M3.
- **E1:** native Ubuntu booted from an external SSD. Used for M4 and the M1 live checks.
- VMs: `weak`, `hardened`, `target`, `kvm-plain`, `kvm-masked`. Their definitions are in `vms/*.xml`.

## Hard rules (the research integrity is the grade, do not break these)

- **PASS = "passed its defined test"**, never "secure".
- Anything this hardware cannot test is **NA, never PASS**. A missing, unreadable or crashed input gives NA or ERROR.
- **Never report simulated or synthetic numbers as findings.** `simulate.py` and the fixtures are pipeline checks only. Tables generated from them must carry "DRAFT: NOT CITABLE" (`make_paper_tables.py --allow-draft`).
- M4 results are **EXPLORATORY** unless there are exactly 15 sessions per class × 4 workloads.
- **`prereg.md` must be committed and tagged before any real M4 session.** Do not change its analysis after tagging; use the Amendments section instead.
- Report negative and null results. A tie on H1 = "not supported". A ceiling = "untestable".
- **Never invent citations.** Mark unknowns `[VERIFY]` or `[CITE]`.
- **Safety:**
  - synthetic or throwaway secrets only
  - rootkit only in the isolated `target` VM, after `scripts/preflight_target.py`
  - no real malware, no time-faking or anti-detection code
- Data, VM images and dumps go in `.local/` (gitignored). Never put them in git.
- Commit only when asked. End commits with the attribution line from the system reminder.

## Commands

```bash
python -m pytest -q -m "not slow"          # fast suite (~1000 tests; POSIX/bash tests skip on Windows)
python -m vsec run --out out [--vm weak=cases/weak ...] [--m2-dumps ...] [--m3-results ...] [--m4-data ... --t-short X]
python -m vsec pilot --data data/m4/pilot  # pick T_short from pilot data
python scripts/make_paper_tables.py out/report.json [--allow-draft]
gcc -O2 -Wall -o bench vsec/m4_detect/bench.c -lm   # on Linux only
python docs/slides/build_deck.py           # regenerate the pptx
python scripts/make_submission_zip.py      # build dist/vsec_submission.zip
```

## Status (update this block when something changes)

- **As of 2026-11-06:**
  - Code is complete. The fast suite passes on Windows.
  - **No real data exists.** No E1 run, no real dump, no Volatility, Lynis or OpenSCAP run. `prereg.md` is not tagged.
  - The only real hardware run: `bench.c` once in WSL2 (a functional check, not a result).
- **2026-11-06:**
  - Each `vsec/taxonomy.yaml` `survey:` field is filled (survey § + case-study table). No code reads it.
  - Added `docs/SOURCES_SUMMARY.md` and `docs/ROADMAP.md`.
- **Next steps:** see `docs/ROADMAP.md`. Hardware Tasks A–J are in `docs/YOUR_TASKS.md`. Order: B → A → C → D (tag prereg) → F, E, G, H, I.

## Known issues to fix in the paper and slides

1. **Authorship conflict.** `docs/paper/paper.md` (header, §1.5, §10.4) says "solo project, one student", but the case study has 3 authors. Confirm with the user, then fix the author line and the AI-assistance statement.
2. DONE 2026-11-06: `build_deck.py` text now says controls are traced to survey sections. **`vsec_deck.pptx` not yet regenerated** (run `python docs/slides/build_deck.py`).
3. DONE 2026-11-06: paper §4.3.1 holds the survey-to-control traceability table (31 rows) and T9 coverage note.
4. Open markers in `paper.md` and `references.md`: `[PENDING REAL DATA]`, `[CITE]`, `[VERIFY]`, `[CHECK]` (about 90). Results and the Abstract wait for real data.
5. Case-study T9 recommendations that are not covered yet (ACS, DMAR lock, Secure Boot/measured launch, SEV/TDX, CAT, kernel integrity, a threat-model doc). They are listed in `docs/SOURCES_SUMMARY.md` §3. Either implement them as C32+ or list them as "not covered" in the paper.
6. The untracked `demo_dashboard.html`, `demo_visual.py`, `index.html` and `run_simulation.bat` are demo-only. Any number they show must be labelled simulated. As of 2026-11-06 they carry an ILLUSTRATIVE banner, but `demo_visual.py` and the dashboard still contain invented numbers (e.g. AUROC 0.988). Never present them as results. Prefer the real commands in `docs/DEMO_SCRIPT.md` Part 1.

## Where to look (only when needed)

| Need | File |
|---|---|
| Complete explanation of the whole project (read this to explain or defend it) | `PROJECT.md` |
| Full design, hypotheses H1–H4, risks, change log | `FINAL_PROJECT_PLAN.md` (long) |
| Pre-registered M4 analysis | `prereg.md` |
| Hands-on hardware steps | `docs/YOUR_TASKS.md`, `docs/E1_CHECKLIST.md` |
| Evidence checklist per module | `docs/DEFINITION_OF_DONE.md` |
| Plan, timeline, team roles | `docs/ROADMAP.md` |
| Paper draft and how to fill it | `docs/paper/paper.md`, `docs/paper/README.md`, `docs/paper/references.md` |
| Datasets and third-party tools | `docs/DATA_SOURCES.md`, `THIRD_PARTY.md` |
| Demo flow | `docs/DEMO_SCRIPT.md` |

## Update 2026-11-08 (demo and report)
- `scripts/make_demo_cases.py` builds `demo_cases/{weak,hardened,weak-fixed}` (constructed, not captured). `tests/test_demo_cases.py` guards the before/after story.
- `vsec/report.py` `to_html` is now a dashboard (summary cards, before/after for any `X` and `X-fixed` VM pair, failed controls with fix commands, matrix). Legacy table cell formats are kept because tests assert them.
- Report notes say `demo_cases` hosts are hand-built. The "solo project" wording in the M1 note is now "same team".

## Update 2026-11-08 (Attack Lab v2: fleet simulator)
- `simulator.html` = fleet what-if simulator: 6 VMs on 3 hosts (`vsec/fleet.yaml`), 11 attacks (`vsec/attacks.yaml`, with severity/origin/scope), tabs Fleet / VM Insights / Attack Lab / Campaign / Hardening Challenge / Survey Map, and import of a real `report.json` or `vsec audit` text.
- Host-level controls are shared by every VM on a host (shared fate); VM-level ones (`vm_level` in fleet.yaml) belong to the VM. Control states come from a REAL `vsec audit` of generated folders (`scripts/make_demo_cases.py build_fleet`).
- Engine: `vsec/sim.py` (evaluate, risk, minimal_fix_set, campaign, blast, containment_advice). The same rules are in the template's `ENGINE-START/END` block. Build: `python scripts/build_simulator.py`. `tests/test_simulator.py` checks data, real-audit equality, campaign stories, and JS == Python parity on random fleet states.
- It is a MODEL of the survey logic, not a measurement. Severity/origin/scope/criticality are the project's own judgement. The fleet scenario is invented. Never add timing numbers, AUROC or accuracy claims to it.
- `demo_dashboard.html` (older, invented numbers) is superseded: do not present it.

## Update 2026-11-08 (paper and slides)
- Paper: all `[CITE]`, `[CHECK]`, `[VERIFY]`, `TODO` markers resolved. New references come from the survey's and case study's own reference lists plus official libvirt/kernel docs. **Documentation URLs were written from memory and not opened: click each before submission.** New section 4.7 describes the Attack Lab, with figures in `docs/paper/figures/`.
- Remaining `*Not yet measured*` lines in Ch. 7/8 are intentional (no real data). Authors are the 4 students (A. Doni Aditya 23BDS007, B. Harsha Vardan 23BDS015, E. Hariteja 23BDS019, L. Sahith Akash Manikanta 23BDS031).
- Slides: Attack Lab is slide 5 (19 slides total). Rendering of the .pptx was not visually checked.

## Update 2026-11-09 (guided Simulate tab)
- `simulator.html` now opens on a **Simulate** tab: 4-step wizard (choose VM -> choose attack -> animated environment diagram with live defence checks -> how it happened + how to protect, apply fixes and re-run, undo). Code: `renderSim`, `playSim`, `simResult`, `protect` in `scripts/simulator_template.html` (outside the ENGINE block; uses `evaluate`). Sidebar is hidden on that tab (`.layout.full`).
- Browser check: Node Playwright from `../QA/node_modules/playwright` (Python playwright is not installed).

## Update 2026-11-09 (experiments for the 35-mark rubric: paper 20, implementation/results 15)
- `python scripts/run_experiments.py` (~70 s, seed 20261109) -> `results/experiments.json`, `docs/paper/results_experiments.md`, figures fig6-fig8. Paper Section 7.7 embeds results_experiments.md verbatim (`tests/test_experiments.py` fails if stale), plus 8.4, abstract, 1.3 item 7, 10.1.
- Results: E1 78/78 single faults; E2 400 folders, 10,400 decisions, P=R=100%, ~40 ms/audit; E3 M2 plain 120/120, encoded (base64/utf16/split) 0/120 = honest blind spot, 0 FP; E4 C09 highest leverage, outsider 5->2->0; E5 hardened host's VMs breached 1.8-46.9% unless VMs hardened (then 0%); E6 57% of blocks single-layer. All constructed ground truth or MODEL, never real hosts.
- Deck now 20 slides (new slide "Results we can run today").

## Update 2026-11-10
- UI restyled (design-system CSS block at end of <style> in the template; app bar, underline tabs, collapsible notice, footer, no emoji glyphs). Paper figs 1-4 regenerated from the new UI.
- Paper: new 3.1.1 novelty comparison table, 9.6 threats to validity.
- EXPLANATION.md = presentation guide (what is real vs model, demo script, 12 viva Q&A, rubric map).
- M2 scanner v2: scan/redact/evaluate(decode=True) add UTF-16LE + base64 passes (v1 = default, pre-specified). E3b in paper 7.7: held-out 0/120 -> 80/120, split still 0, FP 0; v2 scored on seed+1 dumps.
- scripts/real_host_check.sh <vm>: collect + audit + Lynis + compare table into results/real/ (needs a real Linux KVM host; none available here).

## Update 2026-11-10 (REAL host data, WSL2 + KVM)
- Ubuntu-24.04 installed in WSL (`wsl -d Ubuntu-24.04 -u root`); /dev/kvm works; repo copy + venv at /root/vsec; VM `vsec-target` (CirrOS 0.6.2) defined. WSL2 needs `cgroup_controllers = [ ]` in /etc/libvirt/qemu.conf; stale bridges (virbr0, virbr-iso) after WSL idle-stop are deleted by the scripts. Run WSL commands via PowerShell (Git Bash mangles /mnt paths) and via script files (PowerShell mangles $VAR).
- scripts/real_host_check.sh, real_hardening_demo.py (default 8 FAIL -> weakened 11 -> hardened 2, env E0), real_snapshot_test.py (virsh dump 272 MiB; v1 plain 4/4 b64 0/4 utf16 0/3; v2 all; 13 FP = kernel hex constants). Outputs in results/real/. Paper Section 7.8; abstract/7 intro/9.6/10.1 updated. Deck 21 slides.

## Update 2026-11-10 (4th author, PDF, presentation guide)
- Fourth author L. Sahith Akash Manikanta (23BDS031) added to paper, deck, README/SUBMISSION/PROJECT/EXPLANATION/CLAUDE; "three students" -> four; stale "no real measurements" statements fixed (paper header/status, deck, README, SUBMISSION).
- Paper PDF: docs/paper/vsec_research_paper.pdf via `python scripts/make_paper_pdf.py` (markdown + Playwright/Chromium; no pandoc). project_present.md = presentation script (4 presenters).

## Update 2026-11-10 (IEEE paper)
- IEEE-format paper: docs/paper/ieee/paper_ieee.tex (IEEEtran, conference), figs/ from scripts/make_ieee_figures.py + scripts/capture_sim_figure.js, PDF built in WSL Ubuntu (texlive installed there). tests/test_experiments.py checks its numbers against results/. Long paper stays in docs/paper/paper.md.
- Fixed claims: Lynis DOES check AppArmor/SELinux presence and rates libvirtd/virtlockd/virtlogd (no mention of qemu/kvm/seccomp/ksm/nested/vnc); only 5 of 13 hex false positives inspected; audit time is ~40 ms (JSON), not 75; A11 is gated by C10.
