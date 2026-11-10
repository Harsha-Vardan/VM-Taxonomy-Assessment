# PROJECT.md: the complete explanation of vsec

**vsec: a taxonomy-driven security assessment framework for KVM virtualization**
Course: Cloud Security & Vulnerabilities. Submitted to: Malay Kumar. Team: A. Doni Aditya (23BDS007), B. Harsha Vardan (23BDS015), E. Hariteja (23BDS019), L. Sahith Akash Manikanta (23BDS031). Built with an AI coding assistant (Claude) under the team's direction.

This file explains the whole project in one place: what it is, why it exists, how every part works, how to run it, what is finished, what is not, and how to defend it. Short operating notes for the AI assistant are in `CLAUDE.md`; the plan and history are in `FINAL_PROJECT_PLAN.md`; the paper is `docs/paper/paper.md`.

---


> **Update (real host):** the project now has real measurements on one real KVM host (WSL2 + KVM on the team's laptop): audit before/after hardening, Lynis comparison and a real memory-snapshot test. See paper Section 7.8, `results/real/` and `scripts/real_*.{sh,py}`. `EXPLANATION.md` is the presentation guide.
## 1. The project in one minute

Virtualization (running many virtual machines on one physical server) is the base of cloud computing. A 2020 survey in *ACM Computing Surveys* lists the security problems this creates and the defences recommended against them. A survey, though, is only a list. It does not say **which of those defences can actually be checked on a real KVM system, which hold, and which fail.**

vsec turns the survey's list into something executable:

1. **A taxonomy.** 9 threat classes and 31 concrete controls, each traced to a survey section.
2. **Four modules (M1 to M4)** that test those controls: a configuration auditor, a snapshot-privacy scanner, a memory-forensics checker and a hypervisor-detection experiment.
3. **One common result format and report**, so every module produces the same kind of finding.
4. **The Attack Lab**, an interactive fleet simulator that shows, for several VMs on several hosts, which survey attacks would succeed, how a breach spreads from VM to VM, and what to fix first.

The honest status: the framework, the tests and the simulator are built and verified. **The real-hardware experiments (M2, M3, M4) have not been run yet**, so the project reports a design, an implementation and a model, not measured findings. The paper and every screen say so.

---

## 2. Background and research gap

### 2.1 The two source documents
- **The survey** (`3382190 (1).pdf`): F. Sierra-Arriaga, R. Branco, B. Lee, "Security Issues and Challenges for Virtualization Technologies", *ACM Computing Surveys* 53(2), Article 45, May 2020, doi:10.1145/3382190. A literature survey with no experiments.
- **Our case study** (`Virtualization_Security_Case_Study_Report.pdf`, 20 Sep 2026): a desk analysis of the survey. Its Table 9 is a control checklist per threat class. This project makes that checklist executable.
- A condensed version of both, with exact section and table numbers, is in `docs/SOURCES_SUMMARY.md`.

### 2.2 What the survey says (the parts this project uses)
- Attacks are classified by **source and target**: Guest to VMM, Guest to Host, Host to VMM, Guest to Guest, Guest/Host to Self (survey section 3.1).
- Guest escapes cluster in **device emulation** (floppy controller, VGA, NIC): the device model runs with hypervisor privilege (section 4.1).
- Hardware protections such as the **IOMMU** only work if firmware and the OS configure them correctly (sections 5.1, 5.3).
- **Side channels** (cache timing, memory deduplication, Spectre/L1TF) are systemic: the obvious fix, never sharing a host, defeats the purpose of virtualization (section 5.4).
- **Snapshots leak secrets**, because the memory image contains whatever was in memory (section 6.1.1).
- The hypervisor's privileged position is used for defence (introspection) and for attack (**virtual-machine-based rootkits**: SubVirt, Blue Pill, Vitriol). Detecting a hypervisor is easier than detecting a malicious one, and whether a rootkit can be made undetectable is an open question (section 7).

### 2.3 The gap this project fills
The case study records the survey's own limits: it presents no experiments, does not quantify likelihood or cost, uses examples from around 2007, does not compare mitigation overhead, and stops at 2020. vsec's answer is a testable mapping:

> **Research question.** Can the threats and controls identified in the 2020 survey be turned into experimentally testable controls on a modern KVM stack? Which of them hold, which fail, and which cannot be tested on this hardware?

> **Centrepiece question (M4).** Against a hypervisor that hides its static indicators but does not fake time, does combining several *behaviour* signals detect it with less measurement time, or more reliably, than the best single signal?

---

## 3. Architecture

```
                       survey (S1..S8)  +  case study (T1..T9)
                                    |
                          vsec/taxonomy.yaml
                 9 threat classes, 31 controls, each with test,
                 expected result, fix, test type, survey reference
                                    |
        +---------------+-----------+------------+----------------+
        |               |                        |                |
   M1 audit         M2 snapshot             M3 forensics       M4 detection
   28 controls      secret scanner          hidden processes   multi-signal
   config + live    + redaction             and modules        timing experiment
        |               |                        |                |
        +---------------+-----------+------------+----------------+
                                    |
                 common finding {id, module, taxonomy, control,
                 status PASS|FAIL|NA, severity, evidence, fix, env, vm}
                                    |
                    vsec/report.py  ->  report.json + report.html
                                    |
        vsec/attacks.yaml + vsec/fleet.yaml + real audit states
                                    |
              vsec/sim.py  ->  simulator.html  (the Attack Lab)
```

Code is Python 3.12 (package `vsec/`), plus one C benchmark (`vsec/m4_detect/bench.c`). About 14,000 lines of Python including tests. Command line: `python -m vsec ...`.

---

## 4. The taxonomy: 9 classes, 31 controls

`vsec/taxonomy.yaml` is the backbone. Each control has: id, threat class, module, control name, test type (`live`, `config` or `version`), severity 1 to 4, the expected result, the test, the fix, a source, and the **survey reference** (section of the survey plus the case-study table it comes from).

| Threat class | Controls | How it is tested | Label |
|---|---|---|---|
| Guest to Host | 12 | M1 config and live checks: seccomp, sVirt, QEMU user, capabilities, nested virtualization, console, USB redirection, unused devices, cache mode | Tested |
| Host to VMM | 6 | M1: libvirt and QEMU hardening, socket, image and save-directory permissions, TCP libvirt | Config-proxy |
| Guest to Guest | 3 | M1: network isolation, guest reachability, shared memory | Config-proxy |
| VMM vulnerabilities | 2 | M1: QEMU and kernel version against a CVE list (NA while the list is unverified) | Config-proxy |
| Side channels | 3 | M1: KSM, CPU vulnerability mitigations, SMT | Config-proxy |
| DMA / IOMMU | 2 | M1: IOMMU on the kernel command line, IOMMU groups (needs the native machine E1) | Tested on E1 |
| Snapshot privacy | 1 | M2 | Tested |
| VMI / hidden processes | 1 | M3 | Tested |
| Hypervisor / VMBR presence | 1 | M4 | Tested |

**Labels.** *Tested* means a real experiment; *Config-proxy* means only the configuration or a version is checked, not an attack; anything the hardware cannot test is **NA, never PASS**.
M1 holds 28 controls; M2, M3 and M4 each add one centrepiece control (31 in total).

**Not covered yet** (survey recommendations with no control): PCIe ACS, DMA-remap register lock, device-memory scrubbing on reassignment, Secure Boot or measured launch, SEV/TDX memory encryption, cache partitioning, guest kernel-integrity monitoring, and a written threat model per deployment. They are listed, not hidden.

---

## 5. The four modules

### M1: configuration auditor (`vsec/m1_audit.py`)
**What it does.** Reads a captured "case folder" (the VM definition plus host files such as `qemu.conf`, `libvirtd.conf`, the kernel command line, `/sys` and `/proc` values, file permissions) and returns PASS, FAIL or NA for each of 28 controls, with the evidence and a fix command.
**Two kinds of check.** *Config* checks read files. *Live* checks prove a control is actually active (for example `Seccomp: 2` in the QEMU process status, the process's security label, real file modes, IOMMU groups).
**Safety rules built in.** A missing, unreadable or crashing input gives NA with the reason, never PASS. The CVE checks give NA while the CVE list is unverified.
**How it is evaluated.** 50 generated test cases with 84 seeded faults and a hidden answer key (`tests/make_fixtures.py`); precision, recall, F1 and false-positive rate overall and per control, with Wilson 95% confidence intervals. **This is self-consistency only**: the same team wrote the checker and the fixtures. Independent evidence needs Lynis/OpenSCAP and real configurations (not yet done).
**Collecting a real host.** `python -m vsec.collect <vm> <out>` captures the files M1 reads, redacts passwords and tokens, and refuses symlinks and unsafe output folders.

### M2: snapshot privacy (`vsec/m2_snapshot.py`)
**Question.** Does a memory snapshot of a VM contain secrets, and can they be removed safely?
**Design.** Plant **synthetic** secrets (a fake SSH key, an AWS-style key, a JWT, random hex keys) in three memory states (live, freed, left by an exited process): 12 cells. A scanner with format patterns plus an entropy filter looks for them. Held-out variants (page-split, UTF-16, base64) and real programs (`ssh-agent`, `openssl s_server`) are reported separately. Redaction is tested on `virsh save` images by restoring the VM and checking it still runs.
**Metrics.** Recall per cell, false positives per GB, scan time, restore success.
**Status.** Scanner, redaction and scoring are built and tested on synthetic dumps. **No real VM dump has been taken.**

### M3: offline memory forensics (`vsec/m3_forensics.py`)
**Question.** Can processes or kernel modules hidden from the normal process list be found in a memory dump?
**Design.** Volatility 3 on a `virsh dump`: compare `pslist` against `psscan`, and `lsmod` against a scan for modules. Ground truth is public Linux forensic images with documented hidden processes, plus clean dumps (including dumps taken while processes start and exit, which is a real false-positive source). Results are exact counts with exact (Clopper-Pearson) intervals and a failure table.
**Limits stated.** It only looks when a dump is taken, and only finds *unlinked* processes and modules. It is not live introspection.
**Status.** Wrapper, symbol-hash checks, sandbox and scoring are built and tested against mocked Volatility output. **Volatility has never been run on a real image.**

### M4: multi-signal hypervisor detection (`vsec/m4_detect/`)
**The experiment.** On one machine, compare three classes: `native`, `kvm-plain`, and `kvm-masked` (a KVM guest that hides its static indicators with standard libvirt options). The primary comparison is native versus kvm-masked.
**Signals.** Timing (CPUID latency, RDTSC, syscall and page-fault cost), memory (sequential and random latency, a TLB proxy), performance counters, scheduler jitter. Static indicators (CPUID hypervisor bit, DMI strings, device models) are reported separately in an "indicator-leak" table, not used in the hypothesis.
**Controlled conditions.** Same disk image and kernel, fixed CPU frequency, turbo off, pinned vCPUs, same clock source, random run order, sessions interleaved across classes and days.
**Data design.** One boot session is the unit; 15 sessions per class (45 boots); all tuning inside nested cross-validation grouped by session.
**Pre-specified hypotheses** (`prereg.md`, a draft until committed and tagged):
- **H1 (primary):** combined signals beat the best single signal (session-level AUROC at a short window `T_short`, one-sided paired bootstrap p < 0.05). A tie means "not supported"; a ceiling means "untestable".
- **H2:** lower false-alarm rate at true-positive rate >= 0.90.
- **H3:** robust to unseen workloads (leave-one-workload-out AUROC drop < 0.05).
- **H4:** practical cost (< 10 s per decision and < 5% overhead).
H2 to H4 and the secondary tests use Holm correction. With 15 versus 15 sessions the minimum detectable AUROC difference is about 0.15 to 0.2, so **a null result is not evidence of no difference**.
**Threat model limits.** A *non-adaptive* hypervisor (it does not fake time), one CPU model, one machine. A time-faking hypervisor is out of scope (survey section 7.2.2, "TSC offsetting") and listed as future work.
**Status.** Benchmark program, feature extraction, nested CV, bootstrap, Holm, simulator and pipeline are built and tested on simulated data. `bench.c` ran once in WSL2 as a functional check only. **No real native-versus-VM session exists**, and `prereg.md` is not yet committed and tagged.

---

## 6. The common framework

**Finding format.** Every module emits the same record: `{id, module, taxonomy, control, status (PASS|FAIL|NA), severity, evidence, fix, env, vm}`. Evidence text is stripped of control and invisible characters.
**Result matrix.** Per threat class: label, number of controls, number tested, number NA. Per VM: a class shows PASS only if every control in it was tested and passed; counts are never pooled across VMs.
**Report.** `python -m vsec run` writes `out/report.json` and `out/report.html`. The HTML is a dashboard: per-VM summary cards, before/after remediation for any `X` and `X-fixed` pair, failed controls ranked with their fix commands, and the matrix. Banners state when data is simulated or synthetic ("not citable"), or when a module crashed (a crashed module becomes `ERROR`, never silently clean).
**Environments.** E0 = the laptop (WSL2 + KVM under Hyper-V); E1 = a PC booted from an external SSD running native Ubuntu, the only place M4 and the live IOMMU checks can truly run.

---

## 7. The Attack Lab: the fleet what-if simulator

`simulator.html` is a single self-contained page (no install, nothing leaves the browser). It is built by `python scripts/build_simulator.py` from `vsec/taxonomy.yaml`, `vsec/attacks.yaml`, `vsec/fleet.yaml` and a **real run of the M1 auditor**.

### 7.1 The model
- **A fleet.** 6 example VMs on 3 hosts (an invented scenario to make the lessons visible): `web-frontend`, `ci-runner`, `dev-sandbox`, `legacy-erp`, `payments-db`, `monitoring`. Each has a role, a network segment and a criticality (1 to 3).
- **Shared fate.** Controls that live in a VM's definition (console, devices, network, shared memory, cache) belong to that VM. Every other control belongs to the **host and is shared by all VMs on it**: fixing one host control protects every VM there.
- **Attacks.** 11 attacks taken from the survey and case study (floppy-controller escape, open console, libvirt over TCP, writable libvirt socket, deduplication timing, rowhammer with deduplication, Spectre/L1TF-style read, malicious DMA, snapshot theft, neighbour-VM pivot, rogue hypervisor). Each is a chain of stages. A stage lists the taxonomy controls that stop it: it is stopped if **any** is PASS, and succeeds otherwise. A stage with no listed control is assumed to succeed. NA never counts as protection.
- **Risk score** of a VM = 100 x (sum of severities of its open attacks) / (sum of all severities).
- **Campaign (blast radius).** The attacker starts outside or with root in one VM. Spread rules: a network attack is tried against every VM once; from a compromised VM a *host-reach* attack compromises every VM on that host, a *neighbour-reach* attack compromises VMs on the same network segment if the attack is open on both, a *leak-reach* attack exposes co-resident VMs' data; a *vm-reach* attack records persistence. Local-origin attacks (A04, A09) need a host account and are not part of campaigns.
- **Containment advice.** Single fixes ranked by how much they shrink the blast radius (criticality-weighted); if no single fix helps, pairs of fixes.

### 7.2 What you can do in it
| Tab | Purpose |
|---|---|
| Fleet | Hosts, VMs, risk scores, and a VM-by-attack heatmap (click a cell to replay it) |
| VM Insights | Risk, exposure ranked by severity, the exact smallest fix plan, single points of failure, runbook export (Markdown) |
| Attack Lab | One attack against one VM, stage by stage; fix a control and replay |
| Campaign | Animated breach spread across VMs and hosts, the attack path with survey references, containment advice, greedy auto-harden |
| Hardening Challenge | Block every attack on a VM with as few fixes as possible, against an exact optimum |
| Survey Map | Each attack traced to survey section, case-study table, controls and module; what the model does not claim |

The page can **import** a real `report.json` (from `python -m vsec run`) or the text of `python -m vsec audit`, turning your own audit into a VM in the fleet.

### 7.3 What the example fleet shows
An outsider with no foothold breaches 5 of 6 VMs (83% criticality-weighted). `payments-db` sits on the hardened host and has a risk score of only 8, but is breached because it shares a network with `legacy-erp`: **a hardened host does not protect a badly attached VM.** One console password on `dev-sandbox` cuts the breach from 5 VMs to 2, and three fixes in total contain it. The smallest fix set per VM blocks every modelled attack but leaves most attacks with a single layer of defence, so the page also reports *defence in depth*.

### 7.4 What it does not claim
It is a **model of the survey's logic, not a measurement**. It runs no exploit and contains no exploit code, and makes no claim about real success rates, timing or detection accuracy. Severity, origin, reach and criticality are the project's own judgement. The fleet scenario is invented; only its control states come from the real auditor. M2, M3 and M4 are not part of the simulation.

### 7.5 How it is verified
`tests/test_simulator.py` (19 tests): data validity; every gate is a real M1 control with a fix; NA is never protection; the embedded states equal a fresh real audit; host and VM controls never mix; one host fix protects every VM on that host; the expected campaigns; the greedy plan reaches zero; the minimum fix set blocks everything and is minimal; the committed page is up to date; and the **JavaScript engine gives the same results as the Python engine** (posture, risk, fix size, campaign, containment) on random fleet states.

---

## 8. Honesty rules (the project's integrity)

- **PASS means "passed its defined test"**, never "secure".
- Anything the hardware cannot test is **NA, never PASS**. Missing, unreadable or crashed input gives NA or ERROR.
- **Simulated or synthetic numbers are never findings.** Reports carry a "not citable" banner; paper tables from such data are stamped DRAFT.
- M4 results are **EXPLORATORY** unless there are exactly 15 sessions per class with all 4 workloads.
- `prereg.md` must be **committed and tagged before any real M4 session**; changes afterwards go in an Amendments section.
- Negative and null results are reported. Never invent citations.
- **Safety:** synthetic or throwaway secrets only; any rootkit test only inside the isolated `target` VM after `scripts/preflight_target.py`; no real malware; no time-faking or anti-detection code; data and VM images stay in `.local/` (git-ignored).

---

## 9. Repository map

```
PROJECT.md            this file
README.md             quick start and status table
CLAUDE.md             operating notes for the AI assistant (context, rules, status)
FINAL_PROJECT_PLAN.md full design, hypotheses, risks, change log
prereg.md             M4 analysis plan (DRAFT until committed and tagged)
simulator.html        the Attack Lab (generated; do not edit by hand)
vsec/
  taxonomy.yaml       31 controls, 9 classes
  attacks.yaml        11 attacks (stages, gates, severity, origin, scope)
  fleet.yaml          hosts, VMs, faults of the example fleet
  sim.py              simulator engine (Python twin of the page's engine)
  m1_audit.py m2_snapshot.py m3_forensics.py   modules
  m4_detect/          bench.c, features.py, classify.py, stats.py, simulate.py
  report.py score.py collect.py guards.py __main__.py   framework
scripts/              build_simulator.py, make_demo_cases.py, plan_sessions.py,
                      run_session.sh, preflight_target.py, make_paper_tables.py,
                      make_submission_zip.py, build_symbols.sh, ...
demo_cases/           hand-built weak / hardened / weak-fixed targets (generated)
vms/                  libvirt XML for kvm-plain, kvm-masked, isolated network
tests/                about 1,000 tests
docs/                 paper/, slides/, SOURCES_SUMMARY.md, ROADMAP.md, DEMO_SCRIPT.md,
                      YOUR_TASKS.md, E1_CHECKLIST.md, DATA_SOURCES.md, DEFINITION_OF_DONE.md
.github/workflows/    CI: tests on Linux, simulator freshness
```

---

## 10. How to run it

```
# quick start, no setup beyond Python 3.12 and the requirements
python -m venv .local/venv && .local/venv/Scripts/pip install -r requirements.txt      # Linux: bin/

# the interactive demo: just open the file
start simulator.html

# the command-line tool
python scripts/make_demo_cases.py                                     # weak / hardened / weak-fixed targets
python -m vsec audit demo_cases/weak --env E1                         # M1 on one case (exit 1 if any FAIL)
python -m vsec run --fast --simulate --env E1 \
    --vm weak=demo_cases/weak --vm hardened=demo_cases/hardened --vm weak-fixed=demo_cases/weak-fixed \
    --out .local/work/out                                             # full report (M2/M4 simulated, not citable)
python scripts/build_simulator.py                                     # rebuild simulator.html after editing the YAML files
python -m pytest -q -m "not slow"                                     # fast suite, about 4 minutes
python docs/slides/build_deck.py                                      # rebuild the slide deck
python scripts/make_submission_zip.py                                 # build dist/vsec_submission.zip
```
Real-hardware steps (building the native machine, the pilot, real dumps, Volatility, Lynis and OpenSCAP) are in `docs/YOUR_TASKS.md` (tasks A to J) and `docs/E1_CHECKLIST.md`.

---

## 11. Testing and quality

- **1033 tests passed, 20 skipped** on Windows (the skipped ones need Linux: symlinks, POSIX permissions, bash). CI (`.github/workflows/ci.yml`) runs the fast suite on Linux, where those tests do run, and checks that `simulator.html` is current. It has not been run on GitHub yet.
- Tests were written by the same AI assistant as the code, so they show **internal consistency, not correctness against real systems**; review was by automated AI reviewers only. The paper says so.
- Notable engineering checks: grouped cross-validation to prevent session leakage, a contract test between `bench.c` and the Python feature loader, fail-closed secret redaction, hash-pinned Volatility symbols, a reproducible submission zip with secret and privacy scans.

---

## 12. Status: what is done and what is not

| Part | State | Evidence |
|---|---|---|
| Taxonomy with survey traceability (31 controls) | Done | `taxonomy.yaml`, paper section 4.3.1 |
| M1 auditor, 50 fixtures, scoring | Done (self-consistency) | `tests/test_m1.py` |
| M1 independent evidence (Lynis, OpenSCAP, real configs) | **Not done** | needs Linux hosts |
| M2 scanner, redaction, scoring | Done on synthetic dumps | `tests/test_m2_m3.py` |
| M2 on real VM memory | **Not done** | needs KVM host |
| M3 wrapper and scoring | Done against mocked Volatility | `tests/test_m2_m3.py` |
| M3 on a real image | **Not done** | needs Volatility and an image |
| M4 pipeline and statistics | Done on simulated data | `tests/test_m4.py` |
| M4 real data, tagged `prereg.md` | **Not done** | needs the native machine E1 |
| Report dashboard, demo targets | Done | `tests/test_report.py`, `tests/test_demo_cases.py` |
| Attack Lab fleet simulator | Done | `tests/test_simulator.py` |
| Paper (10 chapters) | Draft complete, results chapters say "not yet measured" | `docs/paper/paper.md` |
| Slides (19) and demo script | Done (layout not visually checked) | `docs/slides/`, `docs/DEMO_SCRIPT.md` |

The checklist with proof requirements is `docs/DEFINITION_OF_DONE.md`.

---

## 13. Limitations (stated in the paper)

- **One machine.** M4 would come from one CPU model and may not generalize.
- **Not a real VMBR.** `kvm-masked` is a full QEMU/KVM stack, and non-adaptive (no time faking).
- **Synthetic ground truth.** M1's fixtures follow our own specification.
- **Dump-time only.** M3 sees only what is in a dump, and only unlinked processes and modules.
- **Config-proxy classes.** Host to VMM, VMM vulnerabilities, Guest to Guest and side channels are checked by configuration or version, not by attack.
- **The simulator is a model.** Its severities and spread rules are our judgement, and its fleet is an invented scenario.

---

## 14. Plan and realistic timeline

Full plan with ideal, minimum and realistic versions, and the split across the team's three roles, is in `docs/ROADMAP.md`. In short: the bottleneck is **real data on a native Linux machine**, not code. Minimum credible path (about 4 weeks at partial allocation): build the native machine, run the pilot, tag `prereg.md`, collect at least 10 sessions per class, run Lynis and OpenSCAP on the demo hosts, run M3 on one public image, and fill the paper's results chapters from `scripts/make_paper_tables.py`. The ideal path adds the missing survey controls (PCIe ACS, Secure Boot, SEV/TDX, cache partitioning), a short IEEE-format paper, and an independent review of the attack rules.

---

## 15. Likely questions and honest answers

**Is this simulating attacks?** No exploit is run or written. The Attack Lab is a what-if model: it decides whether a configuration would stop each stage of a documented attack, as the survey describes.

**Where are your results?** The framework and tests are complete. The real-hardware experiments need a native Linux machine we did not have, so the project reports a design and a pre-specified analysis, and marks untested classes as NA. We say this in the paper rather than showing invented numbers.

**Why should we trust the M1 score?** We do not claim it proves correctness. The fixtures and the checker were written by the same team, so it is a self-consistency test. Independent evidence (Lynis, OpenSCAP, real configurations) is listed as not done.

**Why is `payments-db` breached when its host is hardened?** It shares a network segment with a weak VM. The model shows that host hardening and VM attachment are separate failure points.

**What is novel?** The explicit mapping from survey sections to testable controls; the common finding format; the fleet model with shared host fate, campaigns and containment advice; and the pre-specified, honest multi-signal detection experiment.

**What would you do with more time?** Run on real hardware first; then add the uncovered survey controls; then validate the attack rules with an independent reviewer.

---

## 16. Glossary

- **VMM / hypervisor:** the software layer that runs virtual machines. KVM is a Linux kernel module.
- **Guest escape:** code in a VM breaking the isolation to reach the host.
- **Device model:** the software that emulates hardware (disk, NIC, floppy) for a VM; it runs with hypervisor privilege.
- **seccomp / sVirt:** Linux mechanisms that limit which system calls QEMU may make and which files it may touch (AppArmor/SELinux labels).
- **IOMMU (VT-d, AMD-Vi):** hardware that restricts which memory a device can reach by DMA.
- **KSM / deduplication:** merging identical memory pages across VMs; its timing leaks information.
- **Side channel:** information leak through timing or cache effects, not through a broken access check.
- **VMBR:** a virtual-machine-based rootkit, a malicious hypervisor beneath the OS (SubVirt, Blue Pill).
- **TSC offsetting:** a hypervisor feature that shifts the timestamp counter a guest reads, hiding timing differences.
- **AUROC:** area under the ROC curve; 1.0 is perfect separation, 0.5 is chance.
- **Holm correction:** a way to control false positives when testing several hypotheses.
- **Blast radius:** how many VMs (weighted by criticality) a campaign compromises.
- **Defence in depth:** several independent controls on an attack's path.
- **EXPLORATORY / not citable:** results from fewer sessions than planned, or from simulated or synthetic data.

---

## 17. References

1. F. Sierra-Arriaga, R. Branco and B. Lee, "Security issues and challenges for virtualization technologies", *ACM Computing Surveys* 53(2), Art. 45, 2020. doi:10.1145/3382190.
2. A. Doni Aditya, B. Harsha Vardan, E. Hariteja, *Security Issues and Challenges for Virtualization Technologies: Case Study Report*, 20 September 2026.
3. The paper's reference list (`docs/paper/paper.md`, References) holds the primary sources and the libvirt and kernel documentation used. Check each documentation link opens before submission.
