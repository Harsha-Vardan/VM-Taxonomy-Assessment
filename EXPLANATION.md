# vsec: How to Explain This Project

Read this before the presentation. It says what the project does, what it does **not** do, why it is useful, how to present it, and how to answer the professor's questions. `PROJECT.md` has the full technical detail.

Team: A. Doni Aditya (23BDS007), B. Harsha Vardan (23BDS015), E. Hariteja (23BDS019), L. Sahith Akash Manikanta (23BDS031). Course: Cloud Security & Vulnerabilities.

---

## 1. The project in three sentences

1. We took the 2020 virtualization-security survey (Sierra-Arriaga, Branco, Lee, ACM Computing Surveys) and turned its taxonomy into **31 checkable security controls in 9 threat classes**, each traced to a section of the survey and of our case study.
2. We built **vsec**, a Python tool that **audits a real KVM/libvirt configuration** against those controls and reports PASS, FAIL or NA, with the fix command for each FAIL.
3. On top of the audit we built the **Attack Lab**, which shows **how the survey's attacks would chain through those misconfigurations**: which stage each attack reaches, how far a breach spreads across VMs and hosts, and the smallest set of fixes that stops it.

---

## 2. "Are we simulating attacks?" The honest answer

**No. We do not run attacks, and the project has no exploit code.** Say this first, before the professor asks.

What the project actually does has two parts. Keep them separate when you explain:

| Part | What it really does | Is it real? |
|---|---|---|
| **Auditor (M1)** | Reads the real configuration of a KVM host and VM: `qemu.conf`, `libvirtd.conf`, the VM's XML, kernel settings such as IOMMU, KSM and nested virtualization, file permissions, CPU vulnerability status. Checks each against the control. | **Yes, and measured on a real host.** We turned the laptop's WSL2 into a real KVM host with a real VM and audited it (Section 7.8 of the paper). |
| **Attack Lab (model)** | Takes those PASS/FAIL results and applies the survey's attack logic. Example: "the floppy-controller escape needs a floppy device; then seccomp must be off; then sVirt must be off; then QEMU must run as root." A stage is stopped if its control passes. | **It is a model.** It shows what the survey's logic **implies** for this configuration. It does not measure whether a real exploit would succeed. |

### Why we model instead of exploiting

1. **Hardware and safety.** Real guest-escape exploits (VENOM, rowhammer, DMA attacks) need specific vulnerable hardware or old QEMU versions, an isolated lab, and permission. Running them on a laptop or a university machine would be unsafe and probably against policy.
2. **It is how defenders actually work.** Security teams don't attack production every day. They audit configuration and reason about attack paths. This is the idea behind attack graphs, threat modelling and tools like BloodHound for Active Directory. We apply that idea to KVM, using the survey as the rulebook.
3. **The configuration is real.** If our auditor runs on a real host tomorrow, the Attack Lab works on that host's real results without any change. The **Import real audit** button already does this.

**Line to use:**
> "We don't fire exploits. We audit the real configuration and then model, using the survey's own attack descriptions, how an attacker could chain those weaknesses. It is the same approach defenders use with attack graphs: you find and fix the path before anyone uses it."

---

## 3. "What's the use of it?"

A normal hardening tool (Lynis, OpenSCAP) gives a flat list, for example "23 settings are wrong". An administrator can't tell which one matters, so either nothing gets fixed or everything is fixed in random order. vsec answers the questions they actually have:

1. **Which attack does this misconfiguration enable?** Each FAIL is linked to the survey attacks it opens.
2. **How bad is it?** You see the breach spread. A guest escape on one VM takes every VM on that host; a shared network lets the attacker move to a VM on a different, hardened host.
3. **What should I fix first?** Fixes are ranked by how many attacks they stop. We compute the exact smallest fix set.
4. **Am I relying on a single defence?** For each blocked attack we show how many controls stop it (defence in depth).

**Two findings to say out loud** (from our experiments, Section 7.7 of the paper):
- **Hardening the host is not enough.** In the model, a VM on a fully hardened host is still breached in up to 47% of random fleets unless the VM's own settings are hardened too. With those settings hardened, the rate is 0%.
- **One fix is worth more than others.** Turning off KSM page merging (C09) blocks more modelled attacks than any other single control in our example fleet. Two well-chosen fixes stop the whole outsider attack campaign (5, then 2, then 0 compromised VMs).

A flat checklist cannot show either.

---

## 4. What is real and what is not (memorise this table)

| Claim | Status |
|---|---|
| 31 controls mapped to survey sections and case-study tables | Done, in `vsec/taxonomy.yaml` and paper Section 4.3.1 |
| M1 auditor checks 28 configuration controls | Done, works on any Linux/KVM host |
| Auditor accuracy | 100% on 10,400 decisions **on constructed inputs** (we wrote the faults, so this checks consistency, not real-world accuracy) |
| M2 snapshot secret scanner | Synthetic dumps: 120/120 plain secrets. v1 found **0/120 encoded**; after our fix (v2, decoding passes, tested on fresh dumps) **80/120**: all UTF-16 and base64, no page-split secret |
| Attack Lab | Working model, with JavaScript and Python engines tested to agree |
| M3 memory forensics, M4 hypervisor detection | Designed and coded, **not yet run on real hardware** |
| Results on a real KVM host | **Yes, one host (WSL2 + KVM on our laptop):** stock install fails 8 controls; 2 after vsec's fixes (platform limits); Lynis has no QEMU/VM checks; a real `virsh dump` leaked all planted secrets, and scanner v2 found and removed all of them |
| Results on many hosts / native bare metal | Not yet: M4 timing and statistics across hosts are future work |
| Any exploit code | **None, by design** |

Be precise about where each number comes from: Section 7.7 numbers are constructed inputs or the model; Section 7.8 numbers are real, from ONE real KVM host running in WSL2 on our laptop, not a production server.

---

## 5. How to present (10 to 12 minutes)

Split it between the four of you (see `project_present.md` for the four-person split).

**Student 1: problem and research (3 minutes)**
1. "KVM runs most clouds. The 2020 survey lists the attacks: guest escape, side channels, DMA, snapshot leaks and others. But it is prose. You can't run it against a system."
2. "Research question: can the survey's taxonomy be turned into a framework that checks a real KVM setup, shows the attack paths, and says what to fix first?"
3. Show the taxonomy slide: 9 threat classes and 31 controls, each traced to a survey section.

**Student 2: the tool and the results (4 minutes)**
0. Start with the real host: show `results/real/vsec-target.1-default.audit.txt`, `vsec-target.2-weakened.audit.txt` and `vsec-target.3-hardened.audit.txt` (8, then 11, then 2 FAIL), and paper Section 7.8. "This is a real KVM VM on our laptop." In the simulator, Fleet tab, press **Import real audit** and load the default audit file: the real VM joins the fleet and you can attack it in the Simulate tab.
1. Run in a terminal: `python -m vsec audit demo_cases/weak --env E1`. Red FAILs appear, each with a fix command.
2. Run `python -m vsec audit demo_cases/weak-fixed --env E1`. Everything is fixed except the CPU flaw, which needs a firmware update. Point out that **NA is never counted as PASS**.
3. Show the results slide or paper Section 7.7:
   - the auditor matched every seeded fault in 10,400 decisions;
   - the scanner found 120/120 plain secrets and 0/120 encoded ones; we fixed it, and v2 finds 80/120 (all UTF-16 and base64; split secrets still missed). "Our own evaluation found the bug, and we fixed it."
   - Figure 8: a hardened host is not enough.

**Student 3: the Attack Lab demo (4 minutes)**

Open `simulator.html` (it starts on the Simulate tab).
1. **Choose a VM:** `legacy-erp`.
2. **Choose an attack:** Floppy-controller escape.
3. **Simulate:** the diagram shows the attacker moving from the guest into the virtual devices and then the host. Each defence check appears live. Result: the whole host is compromised.
4. **Protect:** press "Apply the earliest fix (C14)". The replay shows a green shield at stage 2: blocked.
5. Undo the fix, choose "Neighbour VM pivot": `payments-db` on the **hardened** host turns red. "This is our key finding."
6. If time allows: the Campaign tab with "Outsider", then Auto-harden, which brings the breach to 0.

**Close (30 seconds):**
> "To sum up: we turned the survey into a working audit tool and an attack-path model, evaluated it with six reproducible experiments, and we are open about what is still untested. The next step is running it on real KVM hosts."

---

## 6. Questions the professor may ask, with answers

**Q1. Are you actually attacking anything?**
No. We audit real configuration and model the survey's attack logic. Running real exploits needs vulnerable hardware, an isolated lab and permission, and would be unsafe. Defenders work the same way with attack graphs.

**Q2. Then how do you know your model is correct?**
Each stage and its stopping control comes from the survey text, and the Survey Map tab traces every attack to its section. The model is deterministic and tested: the browser and Python engines give identical results on random states. What we **don't** claim is how often real attacks succeed. That would need real exploitation experiments.

**Q3. Your accuracy is 100%. Isn't that suspicious?**
Yes, and we say so in the paper. We wrote both the checks and the faults, so 100% shows the checks are consistent and don't interfere with each other, even with 70% of controls broken at once. It is not real-world accuracy. The independent check is comparing with Lynis/OpenSCAP on real hosts, which is planned.

**Q4. What is new? Lynis already does hardening checks.**
Lynis gives a flat list. We add the attack-chain layer: which attack each misconfiguration enables, how far the breach spreads across VMs, and which fix to do first. Our two findings (a hardened host is not enough; KSM off has the most leverage) cannot be expressed by a checklist. See the comparison table in paper Section 3.1.1.

**Q5. Did you test on real hardware?**
Yes, on one real KVM host. We turned our laptop's WSL2 into a real KVM host: Ubuntu 24.04, QEMU 8.2.2, libvirt 10, and the VM runs with hardware KVM acceleration. On it:
- A stock VM fails 8 controls. When we weakened it the way the survey's attacks need, all seeded weaknesses were caught (11 FAIL). After vsec's own fix commands, 2 FAIL remain, both things WSL2 cannot provide: IOMMU and AppArmor.
- vsec even caught our own hardening mistake: our 'isolated' network still had a host IP.
- Lynis on the same host has no check for any QEMU or VM setting.
- A real `virsh dump` snapshot leaked every planted fake secret. Scanner v1 found only the plain ones, v2 found all of them, and redaction removed them.
What we don't have is bare metal: the M4 timing experiment needs native Linux, and one laptop is not a statistic across many hosts.

**Q6. Why did the scanner miss encoded secrets?**
v1 matched known patterns in raw bytes, and base64, UTF-16 and split secrets don't look like those patterns. We held these encodings out on purpose to test exactly this. After the result we added decoding passes (v2) and tested them on newly generated dumps, so the fix isn't tuned to the test: all UTF-16 and base64 secrets are found, still with zero false positives. Secrets split across memory pages are still missed, because no single place holds the whole secret. We kept both versions and label v2 as a post-hoc improvement.

**Q7. What is NA, and why not just PASS?**
NA means the check could not run here, for example IOMMU inside WSL2, or a CVE list not verified yet. Calling that PASS would hide risk. A security tool must never report "safe" when it doesn't know.

**Q8. How did you choose severity and the attack stages?**
Stages come from the survey's description of each attack. Severity (1–4) and reach are our own judgement, written in `vsec/attacks.yaml`. They only weight the risk score, and the paper labels them as judgement.

**Q9. What is the pre-registration (`prereg.md`)?**
For M4 (detecting a hidden hypervisor) we wrote the hypotheses and the analysis before collecting any data. Then we can't adjust the analysis to make the results look good. It is still a draft because the hardware runs haven't started.

**Q10. What did the AI do?**
We used an AI assistant for coding help and drafting, as the paper states in Section 1.5. The research question, the mapping decisions and the interpretation are ours, and we checked every result by running it.

**Q11. What would you do with more time?**
- Run the tool on real KVM hosts and compare with Lynis/OpenSCAP.
- Add decoding to the M2 scanner.
- Run the M4 experiment on native hardware.
- Add the survey controls we don't cover yet: PCIe ACS, Secure Boot, AMD SEV / Intel TDX, cache partitioning.

**Q12. Who did what?**
Agree on this before the presentation. One way to split it: taxonomy and paper, auditor and experiments, simulator and demo. Each of you should be able to run the demo alone.

---

## 7. How the project maps to the marking criteria

**Research Paper Writing and Technical Contribution (20 marks)** (`docs/paper/paper.md`)
- Literature review of all 9 threat classes from the survey (Section 2).
- Research gap, plus a novelty comparison table against existing tools (Sections 3 and 3.1.1).
- Framework design, with traceability from survey to control (Section 4, Section 4.3.1).
- Experimental setup and a pre-specified analysis plan (Sections 5 and 5.6).
- Results with 95% confidence intervals and figures (Section 7.7).
- Discussion (Section 8), limitations and threats to validity (Sections 9 and 9.6), and references.

**Implementation, Experimental Evaluation and Result Analysis (15 marks)**
- A working Python package (`vsec/`) with 4 modules and a CLI.
- About 1,036 automated tests.
- The Attack Lab web app (`simulator.html`).
- `python scripts/run_experiments.py`: six reproducible experiments with a fixed seed, writing JSON results, tables and Figures 6–8.
- An analysis of each result, including the failures (the M2 blind spot).

---

## 8. Commands to run during the presentation

```
python -m vsec audit demo_cases/weak --env E1          # many FAILs, each with a fix
python -m vsec audit demo_cases/weak-fixed --env E1    # after fixing: only the CPU flaw remains
python scripts/run_experiments.py                      # reruns all six experiments (about 70 s)
start simulator.html                                   # the Attack Lab (Windows)
python -m pytest -q -m "not slow"                      # the test suite
```

---

## 9. What can still be added, by value

1. ~~Real host~~ **Done on WSL2 + KVM** (paper Section 7.8). Next: repeat `sudo bash scripts/real_host_check.sh <vm-name>` on a native Linux machine with KVM (a friend's PC, a lab machine, a cloud VM with nested virtualization). It collects, audits, runs Lynis if installed, and writes a comparison table in `results/real/`. Import the `.audit.txt` into the simulator. One real result is worth more than any new feature.
2. ~~Fix the M2 blind spot~~ **Done** (v2: 0/120 to 80/120). Page-split secrets remain (future work: reassemble fragments across pages).
3. **Compare with Lynis** on the same machine: the same script does it.
4. **Add the missing survey controls:** PCIe ACS, Secure Boot / measured launch, SEV/TDX, cache partitioning.
5. **Export the paper to PDF** and check the slides in PowerPoint.
6. **Check every reference URL** in the paper by opening it.

---

## 10. Words to avoid and words to use

| Avoid | Say instead |
|---|---|
| "We simulated real attacks" | "We modelled the survey's attack chains on real audit results" |
| "Our tool is 100% accurate" | "100% on our constructed fault set; real-host validation is next" |
| "The system is secure" | "These controls pass their defined tests" |
| "We hacked the VM" | "The model shows the configuration would allow this stage" |
| "payments-db was breached" | "In the model, payments-db is reachable because it shares a network with legacy-erp" |
