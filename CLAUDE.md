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
```

## Status (update this block when something changes)

- **As of 2026-11-06:**
  - Code is complete. The fast suite passes on Windows.
  - **No real data exists.** No E1 run, no real dump, no Volatility, Lynis or OpenSCAP run. `prereg.md` is not tagged.
  - The only real hardware run: `bench.c` once in WSL2 (a functional check, not a result).
- **2026-11-06:**
  - Each `vsec/taxonomy.yaml` `survey:` field is filled (survey § + case-study table). No code reads it.

## Known issues to fix in the paper and slides

1. **Authorship conflict.** `docs/paper/paper.md` (header, §1.5, §10.4) says "solo project, one student", but the case study has 3 authors. Confirm with the user, then fix the author line and the AI-assistance statement.
2. DONE 2026-11-06: `build_deck.py` text now says controls are traced to survey sections. **`vsec_deck.pptx` not yet regenerated** (run `python docs/slides/build_deck.py`).
3. DONE 2026-11-06: paper §4.3.1 holds the survey-to-control traceability table (31 rows) and T9 coverage note.
4. Open markers in `paper.md` and `references.md`: `[PENDING REAL DATA]`, `[CITE]`, `[VERIFY]`, `[CHECK]` (about 90). Results and the Abstract wait for real data.

## Where to look (only when needed)

| Need | File |
|---|---|
| Complete explanation of the whole project (read this to explain or defend it) | `PROJECT.md` |
| Pre-registered M4 analysis | `prereg.md` |
| Paper draft and how to fill it | `docs/paper/paper.md`, `docs/paper/README.md`, `docs/paper/references.md` |

## Update 2026-11-08 (demo and report)
- `scripts/make_demo_cases.py` builds `demo_cases/{weak,hardened,weak-fixed}` (constructed, not captured). `tests/test_demo_cases.py` guards the before/after story.
- `vsec/report.py` `to_html` is now a dashboard (summary cards, before/after for any `X` and `X-fixed` VM pair, failed controls with fix commands, matrix). Legacy table cell formats are kept because tests assert them.
- Report notes say `demo_cases` hosts are hand-built. The "solo project" wording in the M1 note is now "same team".

## Update 2026-11-08 (Attack Lab v2: fleet simulator)
- `simulator.html` = fleet what-if simulator: 6 VMs on 3 hosts (`vsec/fleet.yaml`), 11 attacks (`vsec/attacks.yaml`, with severity/origin/scope), tabs Fleet / VM Insights / Attack Lab / Campaign / Hardening Challenge / Survey Map, and import of a real `report.json` or `vsec audit` text.
- Host-level controls are shared by every VM on a host (shared fate); VM-level ones (`vm_level` in fleet.yaml) belong to the VM. Control states come from a REAL `vsec audit` of generated folders (`scripts/make_demo_cases.py build_fleet`).
- Engine: `vsec/sim.py` (evaluate, risk, minimal_fix_set, campaign, blast, containment_advice). The same rules are in the template's `ENGINE-START/END` block. Build: `python scripts/build_simulator.py`. `tests/test_simulator.py` checks data, real-audit equality, campaign stories, and JS == Python parity on random fleet states.
- It is a MODEL of the survey logic, not a measurement. Severity/origin/scope/criticality are the project's own judgement. The fleet scenario is invented. Never add timing numbers, AUROC or accuracy claims to it.

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
- M2 scanner v2: scan/redact/evaluate(decode=True) add UTF-16LE + base64 passes (v1 = default, pre-specified). E3b in paper 7.7: held-out 0/120 -> 80/120, split still 0, FP 0; v2 scored on seed+1 dumps.
- scripts/real_host_check.sh <vm>: collect + audit + Lynis + compare table into results/real/ (needs a real Linux KVM host; none available here).

## Update 2026-11-10 (REAL host data, WSL2 + KVM)
- Ubuntu-24.04 installed in WSL (`wsl -d Ubuntu-24.04 -u root`); /dev/kvm works; repo copy + venv at /root/vsec; VM `vsec-target` (CirrOS 0.6.2) defined. WSL2 needs `cgroup_controllers = [ ]` in /etc/libvirt/qemu.conf; stale bridges (virbr0, virbr-iso) after WSL idle-stop are deleted by the scripts. Run WSL commands via PowerShell (Git Bash mangles /mnt paths) and via script files (PowerShell mangles $VAR).
- scripts/real_host_check.sh, real_hardening_demo.py (default 8 FAIL -> weakened 11 -> hardened 2, env E0), real_snapshot_test.py (virsh dump 272 MiB; v1 plain 4/4 b64 0/4 utf16 0/3; v2 all; 13 FP = kernel hex constants). Outputs in results/real/. Paper Section 7.8; abstract/7 intro/9.6/10.1 updated. Deck 21 slides.

## Update 2026-11-10 (4th author, PDF, presentation guide)

## Update 2026-11-10 (IEEE paper)
- IEEE-format paper: docs/paper/ieee/paper_ieee.tex (IEEEtran, conference), figs/ from scripts/make_ieee_figures.py + scripts/capture_sim_figure.js, PDF built in WSL Ubuntu (texlive installed there). tests/test_experiments.py checks its numbers against results/. Long paper stays in docs/paper/paper.md.
- Fixed claims: Lynis DOES check AppArmor/SELinux presence and rates libvirtd/virtlockd/virtlogd (no mention of qemu/kvm/seccomp/ksm/nested/vnc); only 5 of 13 hex false positives inspected; audit time is ~40 ms (JSON), not 75; A11 is gated by C10.

## Update 2026-11-15 (Attack Lab gate validation, REAL, E0)
- `vsec/gate_probe.py` (pure probes/parsers/scoring) + `scripts/real_gate_validation.py setup|run|cleanup --i-really-mean-it` (root in WSL, from /root/vsec; it syncs nothing itself). Touches ONLY vsec-gate-a/b (marked in <description>), network vsec-gate-iso (bridge virbr-gate), images /var/lib/libvirt/images/vsec-gate-{a,b}.qcow2; hashes vsec-target, other networks, qemu.conf, libvirtd.conf before/after. Cleanup is never automatic; the resources still exist.
- Result (run 20261115T140639Z, 5 arms x 3 reps): C11, C12, C17 gates 15/15 each; C14 9/15, all 6 disagreements unsafe: on i440fx without a floppy disk M1 says PASS but the running QEMU still has isa-fdc and the guest reads MSR 0x3F4 = 0x80; q35 has no FDC (0xFF). Legit QEMU access OK at image 0600 (libvirt chowns to libvirt-qemu). Coverage 4/18 gated stages. Repeats are deterministic: report as qualitative, not 60 independent samples. Paper 7.8 R4. `tests/test_gate_probe.py`.

## Update 2026-11-15 (C14 runtime fix, timing sync)
- C14 now checks the RUNNING QEMU: collect always stores `qemu_machine` (machine type token only, from /proc/<pid>/cmdline; a LIVE file); `collect --qemu-devices` (opt-in, taints the domain) stores `qemu_devices` (`info qtree` device types). Rule: declared floppy/sound/parallel -> FAIL; else qemu_devices decides; else machine type (i440fx FAIL, q35 PASS, other NA); no runtime evidence -> NA. Fixtures/demo_cases carry `qemu_machine: pc-q35-8.2`, so E1-E6 counts are unchanged (verified by a full re-run).
- Post-fix gate run: results/real/gate_validation_postfix/ (1 rep x 5 arms, 20/20, collect used --qemu-devices). The original R4 run in results/real/gate_validation/ is kept as recorded (XML-only C14). R1 (results/real/hardening.json) also used XML-only C14 and was not re-run (would modify vsec-target).
- Timing: committed results/experiments.json is the 2026-11-13 run (audit 24.1 ms median / 40.5 p95). A 2026-11-15 re-run gave 22.7 / 32.8 ms with identical counts; the 11-13 run is kept. paper.md 7.7, prose and paper_ieee.tex now use 24 ms.
- `real_gate_validation.py run --out <new dir>` refuses to overwrite an existing run.

## Update 2026-11-15 (M3 real acquisition)
- WSL: Volatility 3 2.26.2 in /opt/vol3 (VOL=/opt/vol3/bin/vol). Disposable VM `vsec-m3` (q35, no NIC, marked) + /var/lib/libvirt/images/vsec-m3.qcow2 STILL EXIST (cleanup: `real_m3_test.py cleanup --i-really-mean-it`). Guest kernel 5.15.0-71-generic.
- Acquisition works: results/real/m3/acquisition_check.json (256 MiB ELF core in 0.4 s, 2 PT_LOAD cover RAM; guest ground truth 87 procs, 47 modules, markers vsgt1-3 + exited vsgtx each found once as bytes). Dump deleted.
- NOT done: ISF build (scripts/m3_fetch_symbols.sh: 1 GB ddeb from Launchpad, sha256 from Launchpad API; dwarf2json v0.9.0 TOFU) was blocked by the session's permission check, so no Volatility result on a real dump yet. Then: `real_m3_test.py run --symbols .local/m3/symbols --sha <isf sha> --reps 3 --keep-dump` and `tamper` (constructed DKOM-style unlink in a dump COPY = positive control). Pure helpers: vsec/m3_dump.py, tests/test_m3_dump.py. Paper 7.5 updated.

## Update 2026-11-15 (M3 REAL Volatility results)
- ISF: .local/m3/symbols/ubuntu-5.15.0-71-generic.json, sha256 859e60f5849858e940fd1e98554b03d8358bdf39cdcd3aeb496bae4389819964 (ddeb sha from Launchpad devel API; dwarf2json built from source v0.9.0 commit 9f14607e with Go 1.26.11 as nobody: scripts/m3_build_dwarf2json.sh, scripts/m3_fetch_symbols.sh). Verified: results/real/m3/isf_verification.json (banner match, pslist 81 rows).
- Run 20261115T154525Z (3 boots): pslist = guest PIDs 3/3, names 3/3, lsmod = /proc/modules 3/3, hidden_modules 0; raw psscan-only 8/dump all EXIT_DEAD -> 0 with exclude_exited. Tamper (copy of r3, PID 475 unlinked): exit-filtered detect = [475]; raw adds the 8 exited. Constructed positive, NOT rootkit detection. Results: results/real/m3/ (*.analysed.json = recomputed after parser fixes). Dumps kept in /root/vsec/.local/m3/dumps (4 x 256 MiB) until `real_m3_test.py cleanup --i-really-mean-it` (also removes vsec-m3 + image).
- Fixed: m3_forensics module_name ("Module Name" in vol 2.26), vol_version (banner on exit 2), m3_dump VA 48-bit compare, kworker /proc comm suffix. Paper 7.5 updated.

## Update 2026-11-16 (limited M4 run, REAL, E0, nested)
- `bench.c`: `#ifndef BUF_SIZE` guard only (default 256 MiB unchanged). `scripts/real_m4_wsl_test.py run` (root in WSL from /root/vsec; uses vsec-m3, fresh boot per session, static binary over serial, sha256 checked) and `scripts/analyse_m4_wsl.py <raw dir>` (Windows ok).
- Run 20261116T053926Z: 5 sessions x 2 envs x 4 workloads x 30 windows, all exit 0. CPUID 9-11x, syscall 3.7-4.3x (Cliff 1.0 everywhere); RDTSC same; perf counters NA in guest; LOSO logreg AUROC 1.0 -> H1 untestable (ceiling). Holm can't pass with 5v5. Confounds: kernel 5.15 vs 6.6, QEMU CPU model, THP, 1 vCPU. NEVER call it native vs VM.
- Docs: paper.md 7.6.0, paper_ieee.tex sec:m4wsl (IEEE PDF rebuilt; long-paper PDF not rebuilt), PROJECT.md M4. Test: tests/test_m4_wsl.py.

## Update 2026-11-16 (Phase A + start of B: provenance, live-first, runtime validation)
- `vsec/provenance.py`: tags live-runtime / live-config / constructed / model. Every M1 finding now has `provenance` (case folder with collect_manifest.json and no PROVENANCE file = live; else constructed). demo_cases/*/PROVENANCE marks the fixtures (make_demo_cases.py writes it). `vsec audit` on a constructed folder prints a stderr warning.
- PRIMARY workflow: `python -m vsec assess <domain> [--qemu-devices] [--env E0|E1]` (collect + audit, findings.json + meta.json in .local/assess/, never overwrites).
- `vsec/runtime_check.py` (pure: obs_c04/c06/c11/c12/c14/c16, compare, markdown) + `scripts/real_runtime_validation.py setup|run|cleanup --i-really-mean-it` (reuses real_gate_validation machinery re-pointed at vsec-rv-a/b, network vsec-rv-iso / virbr-rv). Resources STILL EXIST.
- Run 20261116T060915Z (3 arms, E0): 16 agree / 2 disagree / 0 unobserved; protected state unchanged. Disagreement: C16 PASS ("isolated" libvirt network) but the two guests on that network ping each other (arms B, C) -> libvirt network isolation is host/outside isolation, not guest-to-guest. Arm A C16 agrees but M1's reason was the open VNC listen, not the network (right for the wrong reason). C04/C06 checks are only "partial" independent (same /proc interface). One run, deterministic configs: qualitative, not a rate.
- demo.py order: [live] real host -> [live] runtime validation -> [constructed] fixtures -> [model] Attack Lab. Papers NOT yet updated for this run.

## Update 2026-11-16 (Phase B: C16 fix, X1 10 configs)
- C16 FIXED: collect writes `net_peers.txt` (live: guest tap ports, co-resident bridge ports, kernel brport/isolated flag; only while the VM runs). `m1_audit.peer_paths`: FAIL if any co-resident pair is not isolated on BOTH sides; live case without net_peers cannot PASS (NA); constructed fixtures keep the old host-only rule (E1-E6 unchanged). Provenance: C16 live-runtime when net_peers present. Fix text (taxonomy C16, attacks.yaml A10, simulator rebuilt): own network per VM or `<port isolated='yes'/>` on every interface; a no-<forward> network isolates from host/outside only.
- `scripts/real_runtime_validation.py`: 10 arms A-J (prediction = `vsec assess --qemu-devices` subprocess; C11/C12 no-console via QEMU TCP listeners; C16 with NIC-up check; second network vsec-rv-iso2/virbr-rv2). Resources vsec-rv-a/b, vsec-rv-iso, vsec-rv-iso2 STILL EXIST (cleanup --i-really-mean-it removes both networks).
- Runs: 20261116T060915Z (3 arms, old C16: 16/2) kept as history; 20261116T063834Z (10 arms) 60/60 agree; 20261116T065524Z repeat D,E 12/12. Protected state unchanged in all. C04 always PASS, C06 always FAIL (no LSM) -> not seen in both states; both only partial independence. nwfilter isolation not evaluated.
- Papers: paper.md 7.8 R5, paper_ieee.tex sec:rv + C16 table row + lessons wording; IEEE PDF trimmed back to 8 pages (Operating Workflow subsection removed, M4 confound sentence shortened). Deck slide text updated. tests/test_runtime_check.py pins the recorded runs.

## Update 2026-11-16 (fixed demo configurations REMOVED, at the professor's request)
- Deleted `demo_cases/` (weak / weak-fixed / hardened), `tests/test_demo_cases.py`, `scripts/make_demo_cases.py`. The Attack Lab's example-fleet builder survives as `scripts/make_fleet_cases.py` (model input, writes a PROVENANCE file; used by build_simulator.py and test_simulator.py).
- `demo.py` now shows only real evidence: real vsec-target audits -> runtime validation (10-arm run) -> `vsec run` report built from two REAL collected cases (results/real/runtime_validation/raw/20261116T063834Z/arm-A and arm-D assess/case, env E0) -> Attack Lab (model).
- Docs (README, PROJECT, TALK_30MIN, deck) no longer reference demo_cases. Test fixtures in tests/ (E1/E2 fault injection) remain as regression tests, tag `constructed`. Older CLAUDE.md entries above mentioning demo_cases are historical.
