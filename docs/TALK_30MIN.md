# 30-Minute Talk Script (for the four presenters)

Goal: after 30 minutes the professor can say, in his own words, **what the project does, why it is built the way it is, what is real and what is a model, and what is still missing.**

Time plan (about 30 minutes, trim to 20 by skipping the parts marked *optional*):

| Time | Part | Who (suggested) | Show |
|---|---|---|---|
| 0:00 to 3:00 | 1. Problem and question | Presenter 1 | slides 2 to 3 |
| 3:00 to 6:30 | 2. The survey and what we took from it | Presenter 1 | taxonomy slide, `docs/paper/ieee/vsec_ieee_paper.pdf` Table II |
| 6:30 to 12:00 | 3. M1 configuration auditor | Presenter 2 | terminal audit, `results/real/` |
| 12:00 to 16:30 | 4. M2 snapshot scanner | Presenter 2 or 3 | real snapshot table |
| 16:30 to 19:00 | 5. M3 hidden-process detection | Presenter 3 | code and design, say "not run" |
| 19:00 to 22:00 | 6. M4 hypervisor detection | Presenter 3 | `prereg.md`, say "not run" |
| 22:00 to 27:00 | 7. Attack Lab (what is special) | Presenter 4 | `simulator.html` |
| 27:00 to 30:00 | 8. Results, limits, close | Presenter 4 | results slide |

---

## 0. What you will have open

| What | File / command | Real or model |
|---|---|---|
| Attack Lab | `simulator.html` | Control states from the real auditor; attack logic is a model. **Main demo** |
| Live assessment | `python -m vsec assess <domain> --qemu-devices` (on the KVM host) | Real VM, live evidence |
| Runtime validation | `results/real/runtime_validation/raw/20261116T063834Z/runtime_validation.md` | Real VMs, 60/60 agree |
| Real-host audits | `results/real/vsec-target.{1-default,2-weakened,3-hardened}.audit.txt` | Real KVM host (WSL2). **Strongest evidence** |
| Real report page | `python demo.py` step 3 (two real collected cases), opens `out/report.html` | Optional |
| Slides, papers | `docs/slides/vsec_deck.pptx`, `docs/paper/ieee/vsec_ieee_paper.pdf` | n/a |

Rule: every number you say must come from the real audit, `results/`, or the paper.

---

## 1. Problem and question (3 min)

Say:
> "KVM with QEMU and libvirt runs a large part of the cloud. A virtual machine is only as isolated as the configuration around it. A 2020 survey in ACM Computing Surveys lists how VMs get attacked: escaping to the host, side channels, DMA through devices, leaking snapshots, hiding from the hypervisor. But a survey is text, and you cannot run text against a real system."

Say the question:
> "Can we turn that survey into a tool that checks a real KVM setup, shows how an attacker could chain its weaknesses, and tells you what to fix first?"

Say the limit now: "We do not run exploits."

## 2. The survey and what we took from it (3.5 min)

What the survey is: Sierra-Arriaga, Branco and Lee, ACM Computing Surveys 53(2), 2020. It organises virtualization security by **the boundary an attack crosses**.

What we took from it (this is the "inspiration"):

| From the survey | What we built |
|---|---|
| Its taxonomy of threat classes (guest to host, host to hypervisor, guest to guest, side channels, DMA, snapshot privacy, introspection, hypervisor presence) | **9 classes, 31 controls**, every control tagged with the survey section it comes from (`vsec/taxonomy.yaml`; paper Section III) |
| Its descriptions of concrete attacks (floppy-controller escape S4.1, Flip Feng Shui S4.2, deduplication channel S5.4.3, DMA / Thunderclap S5.1 and S5.3, snapshot privacy S6.1.1, VMBR S7.1 and S7.2) | **11 attack chains** in `vsec/attacks.yaml`, each step gated by named controls |
| Its recommended defences (seccomp, sVirt, IOMMU, no KSM, isolated networks, secure management plane) | The **28 checks of M1** |
| Its snapshot-privacy and memory-forensics sections | **M2** and **M3** |
| Its hypervisor-detection / VMBR section and the timing literature | **M4** |

Say:
> "The survey says what can go wrong. We turned each item into a check with a PASS, FAIL or NA result, a fix command, and a link back to the section it came from."

Show: paper Table II (classes and controls). Point out the labels: Tested, Config-proxy (only a configuration check), Tested on E1 (needs bare metal).

---

## 3. M1: configuration auditor (5.5 min)

**What it is.** The core of the project. It decides, for 28 controls, whether a KVM host and one of its VMs are configured the recommended way.

**How it works.**
1. `python -m vsec.collect <vm> <folder>` (run on the KVM host) copies the files M1 needs: the VM's libvirt XML, `qemu.conf`, `libvirtd.conf`, the kernel command line, the KSM, nested and SMT switches, the CPU vulnerability status, file permissions, versions. It **redacts passwords before writing** and drops any file it cannot prove clean.
2. `python -m vsec audit <folder> --env E0|E1` runs the 28 checks. Each returns **PASS, FAIL or NA**, the evidence string, and the fix command.
3. Examples: C03 is `seccomp_sandbox` on in `qemu.conf`; C04 checks the live QEMU process shows `Seccomp: 2`; C09 is KSM page merging off; C14 is no floppy/sound/parallel device, neither in the VM XML nor built into the running QEMU (an i440fx machine always has a floppy controller; q35 does not); C11 and C12 are a VNC password and a loopback-only listen address; C15 and C16 are the VM's network attachment; C17 and C21 are file permissions.

**What is special.**
- **NA is never PASS.** If a check cannot run (no IOMMU inside WSL2, a CVE list that is not verified, a check that crashes), the result is NA. A security tool must not say "safe" when it does not know.
- Every control is traceable to the survey, and has a fix command.
- It separates **host-level controls** (shared by every VM on that host) from **VM-level controls** (in the VM's own XML). That matters in Part 7.

**Demo (about 2 minutes).** `python demo.py`, steps 1 and 2: the real VM audited three times, then M1's verdicts checked against the running VMs.
Say: "Every result here comes from a real KVM VM. We do not use hand-made configuration folders as evidence."

Then the real evidence:
```
Get-Content results/real/vsec-target.1-default.audit.txt     # 8 FAIL
Get-Content results/real/vsec-target.2-weakened.audit.txt    # 11 FAIL
Get-Content results/real/vsec-target.3-hardened.audit.txt    # 2 FAIL
```
Say: "This is a real KVM VM on our laptop's WSL2. A stock install fails 8 controls. We really added a floppy device, open VNC and unsafe cache, and vsec caught all three. We then really applied the printed fixes, and 2 remain, both platform limits: WSL2 has no IOMMU and no AppArmor. vsec also caught our own mistake: our 'isolated' network still had a host IP."
Say: "Lynis, a standard hardening tool, ran 247 tests on the same host and never mentions QEMU, KVM, seccomp, KSM, nested virtualization or VNC. That is the gap."

**Evidence.** 78/78 single faults found; 10,400 decisions in 400 folders with precision and recall 100% (about 24 ms per audit). **Honest caveat:** we wrote the checks and the faults, so this proves consistency, not accuracy on real servers.

---

## 4. M2: memory-snapshot privacy scanner (4.5 min)

**The threat (survey S6.1).** A snapshot of a VM (`virsh save`, `virsh dump`, migration, backup) is a copy of everything the guest held in memory: passwords, API keys, private keys. Whoever can read the snapshot can read the secrets.

**What M2 does.**
1. **Scan** a memory dump for secrets with rules: private-key blocks, AWS key pairs, JWTs, 64-hex tokens, with an entropy filter so `0000...` is not flagged.
2. **Redact** matches by overwriting them with zeros in place (the file size does not change).
3. **Measure honestly.** We plant fake secrets whose bytes we chose ourselves (ground truth), then count how many the scanner finds (recall, with Wilson confidence intervals) and how many extra hits it makes (false positives).

**What is special.**
- The **planted secrets are chosen by the host**, not described by the guest, so a lying guest cannot fake a good score.
- We **held out three encodings on purpose** (UTF-16, base64, split across pages) to find the scanner's blind spot. It found one: **v1 found 0 of 120 encoded secrets**. We fixed it (v2 decodes UTF-16 and base64) and re-tested on **fresh dumps**: 40/40 and 40/40, with no false positives. **Secrets split across pages are still missed.** We keep both versions and label v2 as an improvement made after seeing the result.

**Demo.** Show the table in paper Section VII-B and the real-snapshot row:
> "We planted fake secrets in the running VM and took a real `virsh dump`, 272 MiB. v1 found the 4 stored as plain text, v2 found all 11, and after redaction none were left. A bonus finding: secrets typed at a shell prompt came back after a reboot through the shell history, so they end up in every later snapshot."
Say: "13 extra hits were reported. We inspected five and they are public constants in the kernel, such as NIST P-256 curve parameters. This is the known limit of a 64-hex rule."

---

## 5. M3: hidden-process detection with Volatility (2.5 min)

**The threat (survey S7, hypervisor memory forensics).** Malware or a rootkit can hide a process by unlinking it from the kernel's process list, while its structure still sits in memory.

**What M3 does.** It runs Volatility 3 on a memory dump and compares two views: `linux.pslist` (the kernel's own list) and `linux.psscan` (found by scanning memory). A task in `psscan` but not in `pslist` is a hidden process. It does the same for kernel modules (`lsmod` and `hidden_modules`).

**What is special (engineering).**
- Symbol files are **verified by SHA-256** before use, so a swapped symbol table cannot change the result.
- Volatility can run **inside a sandbox**.
- It separates **exited** tasks from **hidden** ones, to reduce false alarms.
- It states its own limit: if there is no identifying column, tasks are compared by PID only, so a hidden task that reuses a listed PID is not detected.

**Status. Say it yourself:** "M3 is built and unit-tested, but we have not run it on a real memory dump yet. It is future work."

## 6. M4: multi-signal hypervisor detection (3 min)

**The threat (survey S7.1 and S7.2, VMBR).** A hypervisor hidden under or inside a machine (a VM-based rootkit) can be hard to see. The survey and the timing literature say a hypervisor leaves traces in **timing**.

**The research question.** Does **combining** several weak signals detect a hidden hypervisor faster or more reliably than the best single signal?

**Design.**
- Three machine classes: **native**, **kvm-plain** (default KVM), **kvm-masked** (KVM with static indicators hidden).
- Signals: instruction timing, memory latency, scheduler jitter, performance counters.
- Classifiers: logistic regression and random forest, with **nested, session-grouped cross-validation** (so one boot's data never appears in both training and test).
- Four hypotheses H1 to H4 (combined beats single; fewer false alarms; robust to unseen workloads; practical cost) with fixed pass rules and a Holm correction for testing several at once.
- **Pre-specified:** the plan is written in `prereg.md` before any data, so we cannot tune the analysis to the results.

**Status. Say it yourself:** "M4 needs native Linux hardware, which we do not have, so there is no M4 data. The plan is a draft, not yet committed or tagged."

Why include it: "A research project should say clearly what it designed but could not yet measure."

---

## 7. The Attack Lab: what is special (5 min)

**Why it exists.** M1 gives a flat list. An administrator still cannot tell which attack a failing setting enables, which VMs are at risk, or what to fix first.

**What it does.** Each of the 11 survey attacks is a chain of stages. A stage is stopped if a named control passes. It models 6 VMs on 3 hosts, so it shows spread: a host escape takes every VM on that host, a shared network allows lateral movement, and a side channel exposes neighbours. It computes the **exact smallest set of fixes**, risk scores and defence in depth.

**Demo (4 minutes).** Open `simulator.html`:
1. Simulate tab, choose `legacy-erp`, choose **Floppy-controller escape**. Watch each stage and its live defence check. The host turns red.
2. **Apply the earliest fix (C14).** A green shield stops it at stage 2. "In the model, C14 passing stops it here. On a real i440fx VM, deleting the floppy disk is not enough: QEMU still builds the controller, which our gate validation found (paper 7.8 R4)."
3. **Undo**, **Try another attack**, **Neighbour VM pivot**: `payments-db`, on the hardened host, turns red because it shares a network with a weak VM.
4. Fleet tab, **Import real audit**, load `results/real/vsec-target.1-default.audit.txt`: your real VM joins the fleet.

Say what it is: "The control states are real audit results. The attack logic is a model of the survey's descriptions. It runs no exploit, and 'Apply fix' only changes the model."

**What we learned from it (paper Section VII-C).**
- Turning KSM off (C09) blocks more modelled attacks than any other single control.
- Two well-chosen fixes stop an outsider's campaign (5, then 2, then 0 compromised VMs).
- A VM on a fully hardened host was breached in up to **46.9%** of random fleets unless its own settings were hardened too, and in 0% when they were. A flat checklist cannot show this.

---

## 8. Results, limits and close (3 min)

Say the six experiments in one breath: "One command, `python scripts/run_experiments.py`, fixed seed, about 70 seconds. The auditor matched all 10,400 seeded decisions. The scanner had a blind spot that we found and fixed. And three model studies of the attack chains."

**What is real:** one real KVM host (WSL2), audited before and after hardening, compared with Lynis, with a real memory snapshot.
**What is a model:** the Attack Lab's attack logic and experiments E4 to E6.
**What is not done:** M3 on real dumps; M4 (needs bare metal); more than one real host.

Close:
> "We turned a survey into 31 traceable controls, a working auditor and scanner, and an attack-path model, tested it on a real KVM host, and report what is untested. We do not run exploits: we show the configuration that would allow an attack and show that the fix closes it."

---

## What to avoid

- Saying "we simulated attacks". Say "we modelled the survey's attack chains on real audit results".
- Saying "100% accurate" without "on our constructed fault set".
- Claiming M3 or M4 results.
