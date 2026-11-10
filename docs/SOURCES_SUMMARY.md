# Source Summary: The Two PDFs (read this, not the PDFs)

Condensed on 2026-11-06 from `pdftotext` output of both PDFs. Section and table numbers are exact, so any
claim can be traced back. Re-open a PDF only to quote it word for word or to check a detail not listed here.

---

## 1. The survey (`3382190 (1).pdf`)

**Citation:** F. Sierra-Arriaga, R. Branco, B. Lee, "Security Issues and Challenges for Virtualization
Technologies," *ACM Computing Surveys* 53(2), Article 45, May 2020, 37 pp. doi:10.1145/3382190.

**Scope:** system-level virtualization. It focuses on systemic problems, not bugs that a simple patch fixes.
It is a literature survey with **no experiments**, and it does not measure how likely or costly each issue is.

| § | Topic | What the project uses |
|---|---|---|
| 2 | Type I and Type II VMMs. KVM is Type II, "packaged as a Linux kernel module". Nested virtualization | C10, C24 |
| 2.1 | Five VMM functions (from NIST): execution isolation, device emulation and access control, privileged operations, VM management (snapshots), platform administration | C11–C13 |
| 2.2 | Alternatives: chroot/jails, containers, TEEs (SGX, TrustZone), AMD SEV | Paper background only |
| 3.1 | **Classification by source and target** (from Pék et al.): Guest→VMM, Guest→Host, Host→VMM, Guest→Guest, Guest→Self, Host→Self | Threat classes in `taxonomy.yaml` |
| 3.2 | Threat model: assets, objectives, adversaries, TCB. Primitives (read, write, exec, DoS) convert into one another | Paper framing |
| 4.1 | Guest→Host/VMM examples: Cirrus VGA heap overflow (QEMU 0.8.2), **VENOM floppy FIFO** (2004–2015), VMware SVGA II, Bochs NE2000, QEMU `aam` divide-by-zero DoS, Parallels instruction DoS. The device model runs with VMM privilege | C03–C08, C13, C14, C23 |
| 4.2 | Guest→Guest: GPU pass-through memory not scrubbed, AES cache-timing, **rowhammer + memory deduplication** (Flip Feng Shui) | C09, C15, C16, C27 |
| 4.3 / 4.4 | Guest→Self (Hyper-V instruction emulation), Host→Self (VirtualBox shared folders) | Not tested |
| 5.1 | I/O virtualization, DMA, IOMMU (VT-d/AMD-Vi). DPR (TXT), PMRs. Residual paths: corrupt mapping tables, remap registers, forged PCIe source-id (needs ACS), MSI→NMI (PTFuzz) | C01, C02 |
| 5.2 | Larger attack surface: VMM code, VM exits, hypercalls, management software, add-ons | C11, C18–C20, C23 |
| 5.3 | IOMMU needs correct OS and firmware setup (**Thunderclap**: Windows, macOS, Linux and FreeBSD all affected) | C01, C02 |
| 5.4 | Side channels: 5.4.1 cache-timing keys, 5.4.2 controlled channel, 5.4.3 **dedup timing**, 5.4.4 BTB/ASLR, 5.4.5 **Spectre, L1TF/Foreshadow**. Defences: 5.4.6 cache isolation (StealthMem, CAT), 5.4.7 PMU detection, 5.4.8 scheduler, 5.4.9 Düppel | C09, C25, C26 |
| 6.1.1 | **Privacy-preserving VMs (PPVM): snapshots leak confidential data** | **M2**, C21, C29 |
| 6.2 | Integrity: FSGuard, SecVisor, NICKLE, hvmHarvard, iKGT | Related work |
| 6.3.3 | VM snapshots (recovery, deployment, migration) | M2 |
| 6.5.1 | **VM introspection** (VMwatcher, semantic gap) | **M3**, C30 |
| 6.6–6.9 | Terra, Qubes, driver domains, Proxos, VBS/VSM | Related work |
| 7.1 | Malicious VMMs / **VMBR**: SubVirt, Blue Pill (AMD SVM), Vitriol (VT-x) | **M4** motivation |
| 7.2.1 | **Detecting virtualization**: CPUID 0x40000000 range, DMI/SMBIOS, VMware port 0x5658, SIDT/SGDT/SLDT (Red Pill), **RDTSC timing**, **TLB profiling**, Barbosa counter-based, emulated devices, **memory-dump analysis (Actaeon, VMCS)** | **M4** signals, C30, C31 |
| 7.2.2 | VMBR evasion: thin hypervisor (no CPUID, no devices), EFER interception, **TSC offsetting**, Blue Chicken | M4 threat model: **non-adaptive** only; time-faking is out of scope |
| 7.2.3 | Telling a VMBR from a legitimate VMM: only elements the VMM cannot control count (DeepWatch, HyperCheck/SMM) | Paper discussion |
| 8 | Future: side channels not yet fully understood, gap between academia and real attacks, Pwn2Own, Hyper-V openness | Research gap |

**Undetectable VMBR:** the survey calls this an open question (the Blue Pill challenge was never run).

---

## 2. The case study report (`Virtualization_Security_Case_Study_Report.pdf`)

**Title:** "Security Issues and Challenges for Virtualization Technologies: Case Study", 14 pages.
**Authors:** A. Doni Aditya (23BDS007), B. Harsha Vardan (23BDS015), E. Hariteja (23BDS019), L. Sahith Akash Manikanta (23BDS031).
**Course:** Cloud Security & Vulnerabilities. **Submitted to:** Malay Kumar. **Date:** 20 Sep 2026.
**Method:** desk-based analysis with no experiments. Every incident is read through three lenses: source/target, primitive, threat model.

**Tables we reuse** (the `CS T<n>` references in `taxonomy.yaml`):
- T1: isolation mechanisms compared
- T2: attack classes
- **T3: incident register** (11 cases: class, primitive, root cause, mitigation)
- T4: residual IOMMU attack paths
- T5: side-channel attacks
- T6: side-channel mitigations and where each change is needed
- T7: defensive uses of virtualization (CIA)
- **T8: VMM-detection techniques and their limits**
- **T9: control checklist per threat class.** Its rows are escape, DMA, side-channel, data, kernel tampering, VMBR and governance.

**Six findings (§9.1). Use these as the hypotheses this project turns into experiments:**
1. Isolation is a property of the implementation: escapes cluster in **device emulation** (4 of 6 cases).
2. Whether an issue matters depends on the threat model.
3. Hardware moves the trust boundary, it does not remove it (IOMMU needs config, SGX/Foreshadow).
4. Patchable flaws and systemic flaws need different strategies.
5. Defence and offence use the same privilege (SecVisor vs Blue Pill).
6. Detection is asymmetric and unresolved. Detecting *a* hypervisor is easier than detecting a *malicious* one.

**Stated limits of the survey (§9.2)** give the research gap this project fills:
- (i) no experiments and no quantification
- (ii) examples are from around 2007
- (iii) no systematic comparison of mitigation overhead
- (iv) containers are covered thinly
- (v) nothing after 2020: SEV-SNP, TDX and micro-VMs are not covered

**How the project connects to the two sources.** The case study turns the survey into a checklist (T9).
This project turns that checklist into **tests that can be executed and measured on KVM**:
- M1 makes T9 rows executable.
- M2 measures §6.1.1.
- M3 implements §6.5.1 and §7.2.1.
- M4 tests §7.2.1 detection against a §7.2.2-style masked hypervisor that does not fake time.

---

## 3. T9 coverage gaps (candidate new controls, not implemented yet)

| T9 recommendation | Survey § | Status today | Testable here? |
|---|---|---|---|
| PCIe ACS enabled | 5.1 | missing | E1 only (`lspci -vvv` ACSCtl) |
| DMA-remap register lock / DMAR in firmware | 5.1 | missing | E1, via `dmesg` DMAR lines |
| Device memory scrubbed on reassignment (GPU) | 4.2 | missing | N/A (no GPU passthrough) |
| Secure Boot / measured launch against VMBR | 7.1.1, 7.2.3 | missing | E1: `mokutil --sb-state`, TPM event log |
| Memory encryption (SEV/SEV-SNP/TDX) where the host is not trusted | 2.2, 6.1 | missing | Config check; usually N/A on consumer Intel |
| Cache partitioning (CAT), timer restriction | 5.4.6, 5.4.9 | missing | `resctrl` presence on E1, else N/A |
| Kernel integrity in guest (VBS/NICKLE-style) | 6.2.2 | missing | Out of scope; list as untested class |
| Governance: written threat model, assets and TCB per deployment | 3.2 | missing as artefact | Add `docs/THREAT_MODEL.md` |
