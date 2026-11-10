# project_present.md: How to Start and Deliver the Presentation

Team: A. Doni Aditya (23BDS007), B. Harsha Vardan (23BDS015), E. Hariteja (23BDS019), L. Sahith Akash Manikanta (23BDS031).
Course: Cloud Security & Vulnerabilities. Submitted to: Malay Kumar.

This file is the script for the presentation: what to say first, what we did, who presents what, what to click, and which numbers to quote.
`EXPLANATION.md` has the deep explanation and the 12 likely questions with answers. `PROJECT.md` has the full technical reference.

---

## 0. Where everything is

| What | File |
|---|---|
| **Research paper, IEEE format (PDF, two columns, all four authors)** | `docs/paper/ieee/vsec_ieee_paper.pdf` (source `docs/paper/ieee/paper_ieee.tex`, how to rebuild in `docs/paper/ieee/README.md`) |
| Long version of the paper (PDF, 39 pages, extra detail) | `docs/paper/vsec_research_paper.pdf` (source `docs/paper/paper.md`; rebuild with `python scripts/make_paper_pdf.py`) |
| Slides (21: 15 main + 6 backup, with speaker notes) | `docs/slides/vsec_deck.pptx` |
| The interactive Attack Lab | `simulator.html` (double-click, no install) |
| Real-host evidence (real KVM host measurements) | `results/real/` and paper Section 7.8 |
| Experiments (reproducible, one command) | `python scripts/run_experiments.py` and paper Section 7.7 |
| The tool | `python -m vsec audit <folder> --env E0` |
| Demo targets | `demo_cases/weak`, `demo_cases/weak-fixed`, `demo_cases/hardened` |
| Submission package | `dist/vsec_submission.zip` (rebuild with `python scripts/make_submission_zip.py`) |

---

## 1. Your first 30 seconds (say this, nearly word for word)

> "Good morning. Our project is about **security of KVM virtualization**, the technology behind most cloud virtual machines.
> A 2020 survey in ACM Computing Surveys lists the attacks on it: a VM escaping to the host, side channels, DMA attacks, snapshot leaks and others. But a survey is text. You cannot run it against a real system.
> So we asked: **can the survey's taxonomy become a tool that checks a real KVM setup, shows how an attacker could chain its weaknesses, and tells you what to fix first?**
> We built that tool, we tested it on a real KVM host, and we will show it. We also tell you clearly what we did not do."

Then say what the project is **not**, before anyone asks:

> "We do not run exploits. The tool audits real configuration, and the Attack Lab models the survey's attack chains on those real results."

Why this opening works: it states the problem, the question and the honest limit in 30 seconds. It also takes the "are you attacking something?" question off the table.

---

## 2. What we did, in the order we did it

Use this as your story. Each step has the evidence in brackets.

1. **Read the survey and our case study** and built a **taxonomy: 9 threat classes and 31 checkable controls**, each linked to a survey section and a case-study table. (`vsec/taxonomy.yaml`, paper Section 4.3.1)
2. **Built vsec, the tool.** Four modules: **M1** audits 28 configuration controls; **M2** scans memory snapshots for leaked secrets; **M3** looks for hidden processes with Volatility; **M4** is the design for detecting a hidden hypervisor. Result: PASS, FAIL or NA, with the fix command. NA is never counted as PASS. (`vsec/`)
3. **Built the Attack Lab.** 11 attacks from the survey written as stage-by-stage chains. A stage is stopped if a named control passes. It models 6 VMs on 3 hosts, so it shows how a breach spreads, and computes the smallest set of fixes. (`simulator.html`, paper Section 4.7)
4. **Tested everything automatically:** 1,037 passing tests, including a test that the browser engine and the Python engine give identical answers.
5. **Ran six reproducible experiments** on constructed inputs and the model. (`scripts/run_experiments.py`, paper Section 7.7)
6. **Built a real KVM host** (Ubuntu with QEMU/libvirt inside WSL2, hardware KVM) with a real VM, and measured it: audit before and after hardening, comparison with Lynis, and a real memory snapshot with planted fake secrets. (paper Section 7.8)
7. **Found and fixed a weakness in our own scanner.** It missed secrets stored as base64 or UTF-16, so we added decoding and tested again on fresh data.
8. **Wrote the research paper (39 pages) and slides,** and a list of what is still untested.

---

## 3. The 12-minute plan, split between four presenters

About 3 minutes each. Decide among yourselves who takes which part, and practise handing over with one sentence.

### Presenter 1: problem, survey and taxonomy (3 min). Slides 2 to 4
- Say the opening from section 1.
- Slide "Problem and research question": KVM is everywhere; the survey lists attacks but is not executable.
- Slide "From survey taxonomy to a result matrix" and "Taxonomy to modules": **9 threat classes, 31 controls, each traced to a survey section.** Mention the labels: Tested, Config-proxy, Tested on E1, and that "not testable here" is NA, never PASS.
- Hand over: "Now Presenter 2 will show the tool working on a real KVM host."

### Presenter 2: the tool and the real host (3 min). Slides "M1", "Real KVM host"
1. Terminal: `python -m vsec audit demo_cases/weak --env E1`. Point at the red FAILs and the fix commands. Then `demo_cases/weak-fixed`: only the CPU flaw remains, because it needs a firmware update.
2. Real host slide / paper Section 7.8. Say the numbers:
   - "A stock VM created with the default command **fails 8 of 28 controls**."
   - "We weakened it the way the survey's attacks need (floppy device, open VNC, unsafe cache): **11 fail**, and all seeded weaknesses were caught."
   - "After applying vsec's own fix commands: **2 fail**, and both are limits of WSL2: no IOMMU, no AppArmor."
   - "vsec even caught **our own mistake**: our 'isolated' network still had a host IP."
   - "Lynis on the same host ran 247 tests and checked **none** of the QEMU or VM settings. That is the gap our project fills."
3. Say the limit: "This is one real host on WSL2, not bare metal."

### Presenter 3: experiments and results (3 min). Slides "Results we can run today", "Real KVM host" (snapshot part)
- "Six reproducible experiments, one command, fixed seed."
- **E1/E2:** "We seeded known faults into 400 configuration folders, with up to 70% of controls broken at once: **10,400 decisions, precision and recall 100%**. The honest caveat: we wrote both the checks and the faults, so this is **self-consistency**, not real-world accuracy."
- **M2 scanner (our own finding):** "On synthetic dumps v1 found 120/120 plain secrets but **0/120 encoded ones**. We added decoding passes (v2) and tested on fresh data: UTF-16 and base64 now **40/40 each**, zero false positives. Secrets split across pages are still missed."
- **Real snapshot:** "In a real `virsh dump` of the VM, v1 found 4 of the 11 planted secrets, v2 found **all 11**, and redaction removed them. Typed secrets also come back after reboot through shell history."
- **E5 (model):** "A VM on a fully hardened host was still breached in up to **47%** of random fleets, unless the VM's own settings were hardened too, then 0%."

### Presenter 4: Attack Lab demo and close (3 min). Slide "Attack Lab", then `simulator.html`
1. Open `simulator.html` (it starts on **Simulate**). Click **legacy-erp**, then **Floppy-controller escape**. Watch the attacker move through the guest, devices and host; the host turns red: COMPROMISED.
2. Press **Apply the earliest fix (C14)**: a green shield stops it at stage 2.
3. **Undo my fixes**, then **Try another attack**, then **Neighbour VM pivot**: `payments-db` on the **hardened host** turns red. Say: "A hardened host does not protect a VM that is badly attached. A flat checklist cannot show this."
4. If time allows, **Fleet** tab, **Import real audit**, load `results/real/vsec-target.1-default.audit.txt`: the real VM joins the fleet.
5. Close (say this):
   > "To sum up: we turned the survey into an audit tool and an attack-path model, tested it on a real KVM host, evaluated it with reproducible experiments, and we are open about what is untested: bare-metal timing (M4), Volatility on real dumps (M3), and more than one real host. We do not run exploits; we show the configuration that would allow an attack, and prove the fix closes it."

---

## 4. Numbers to remember

| What | Number |
|---|---|
| Threat classes / controls | 9 / 31 (28 configuration checks in M1) |
| Attacks in the Attack Lab | 11, on a fleet of 6 VMs and 3 hosts |
| Automated tests | 1,037 passed, 20 skipped (Linux-only) |
| Auditor on seeded faults (constructed) | 78/78 single faults; 10,400 decisions, P = R = 100%; about 40 ms per audit |
| Scanner on synthetic dumps | v1: plain 120/120, encoded 0/120. v2: UTF-16 40/40, base64 40/40, split 0/40, no false positives |
| Real host: stock VM | 8 FAIL, then 11 after weakening, then 2 after fixes (both platform limits) |
| Lynis on the same host | 247 tests, hardening index 64, no QEMU/VM checks |
| Real snapshot | 272 MiB dump; v1 found 4/11 planted secrets, v2 found 11/11; 13 extra hits are public kernel constants |
| Model: most valuable control | KSM off (C09) blocks the most attacks; 2 fixes stop the outsider campaign (5, then 2, then 0 VMs) |
| Model: hardened host | VM on it breached in up to 46.9% of random fleets unless the VM is hardened too |

---

## 5. Say / do not say

| Do not say | Say instead |
|---|---|
| "We simulated real attacks" | "We modelled the survey's attack chains on real audit results" |
| "Our tool is 100% accurate" | "100% on our constructed fault set; real-host validation is on one host so far" |
| "The system is secure" | "These controls pass their defined tests" |
| "We tested on real servers" | "We tested one real KVM host, our laptop's WSL2" |
| "The AI did it" | "We directed an AI assistant; we chose the topic and scope, and we ran and checked every result" |

Three rules for questions:
1. **If you don't know, say so.** "That is not covered in our work" is better than a guess.
2. **Point to the paper.** "Section 9.6 lists our threats to validity."
3. **Never claim more than the evidence.** Every number has a label in the paper: constructed input, model, or real host.

---

## 6. Before you present: checklist

- [ ] Open `docs/paper/vsec_research_paper.pdf` and check that all four names are on page 1.
- [ ] Open `docs/slides/vsec_deck.pptx` in PowerPoint and flip through all 21 slides (we have not checked the layout in PowerPoint itself).
- [ ] Double-click `simulator.html` and run the floppy-escape demo once.
- [ ] Run `python -m vsec audit demo_cases/weak --env E1` once in a terminal.
- [ ] Each of you has read `EXPLANATION.md` section 6 (the 12 questions).
- [ ] Each of you can run the demo alone, in case one of you is absent.
- [ ] If the browser demo fails, use the screenshots in `docs/paper/figures/` (fig1 to fig4).
- [ ] Optional: open the reference links in the paper and check that each works (written from memory).
- [ ] The real-host demo does **not** need WSL running; the real results are saved text files in `results/real/`.

---

## 7. If the professor asks "who did what?"

Agree on this in advance, and make it true. One way to split:
- **Taxonomy, survey and paper:** mapping the survey to controls, writing the paper.
- **The tool (M1 to M4) and tests:** the auditor, scanner and test suite.
- **Real host and experiments:** the WSL2 KVM host, the real audit and snapshot, `run_experiments.py`.
- **Attack Lab, slides and demo:** the simulator, UI and presentation.

Whatever the split, every one of you should be able to explain the whole project in two minutes.
