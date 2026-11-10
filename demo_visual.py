#!/usr/bin/env python3
"""
Interactive Visual Demonstration of vsec:
Taxonomy-Driven Security Assessment Framework for KVM Virtualization

Designed for live academic demonstrations to illustrate the security audit,
memory secret scanning, rootkit forensics, and side-channel timing detection pipeline.
"""

import sys
import os
import time
import json
import webbrowser
from pathlib import Path

# Enable ANSI escape sequences on Windows
if os.name == 'nt':
    os.system('')

# ANSI Colors
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
WHITE = "\033[97m"

def slow_print(text, delay=0.01):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def header(title):
    print("\n" + "=" * 76)
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print("=" * 76)
    time.sleep(0.5)

def subheader(title):
    print(f"\n{BOLD}{YELLOW}>>> {title}{RESET}")
    time.sleep(0.3)

def spinner(text, duration=1.2):
    chars = ["|", "/", "-", "\\"]
    t_end = time.time() + duration
    i = 0
    while time.time() < t_end:
        sys.stdout.write(f"\r  {CYAN}{chars[i % 4]}{RESET} {text}...")
        sys.stdout.flush()
        time.sleep(0.08)
        i += 1
    sys.stdout.write(f"\r  {GREEN}[OK]{RESET} {text} - Complete!\n")
    sys.stdout.flush()

def main():
    print(f"\n{BOLD}{CYAN}============================================================================{RESET}")
    print(f"{BOLD}{WHITE}    vsec: TAXONOMY-DRIVEN SECURITY ASSESSMENT FOR KVM VIRTUALIZATION        {RESET}")
    print(f"{BOLD}{CYAN}    ACM CSUR 2020 Taxonomy Mapping | Multi-Vector Isolation Audit          {RESET}")
    print(f"{BOLD}{CYAN}============================================================================{RESET}")
    print(f"{BOLD}{YELLOW}  ILLUSTRATIVE ANIMATION: every value below is SCRIPTED, not measured.{RESET}")
    print(f"{BOLD}{YELLOW}  Nothing here was run on KVM, real memory or real hardware.{RESET}")
    print(f"{BOLD}{YELLOW}  It shows the shape of the pipeline only. It contains no results.{RESET}\n")
    time.sleep(1)

    # ---------------------------------------------------------
    # PHASE 1: CONFIGURATION & HOST ISOLATION AUDIT (M1)
    # ---------------------------------------------------------
    header("PHASE 1: Host & Hypervisor Configuration Audit (Module M1)")
    print(f"{DIM}Evaluating 28 isolation controls across Guest->Host, Guest->Guest, and Host->VMM attack surfaces.{RESET}\n")
    time.sleep(0.5)

    spinner("Connecting to Libvirt hypervisor interface (qemu:///system)")
    spinner("Inspecting host kernel command-line & CPU mitigation parameters")
    spinner("Analyzing guest domain XML architecture and device attachments")
    
    subheader("Simulating Configuration Audit Checks (28 Controls)")
    controls_demo = [
        ("C01", "iommu_cmdline", "intel_iommu=on iommu=pt verified", "PASS", GREEN),
        ("C03", "qemu_seccomp_config", "seccomp_sandbox=1 active in qemu.conf", "PASS", GREEN),
        ("C04", "qemu_seccomp_live", "Live process check: /proc/<pid>/status has Seccomp: 2", "PASS", GREEN),
        ("C05", "svirt_config", "AppArmor sVirt mandatory access control configured", "PASS", GREEN),
        ("C06", "svirt_live", "Live confinement label: libvirt-qemu (enforce)", "PASS", GREEN),
        ("C07", "qemu_not_root", "Unprivileged execution: user=libvirt-qemu", "PASS", GREEN),
        ("C09", "ksm_off", "Kernel Samepage Merging disabled (/sys/kernel/mm/ksm/run=0)", "PASS", GREEN),
        ("C10", "nested_off", "Nested virtualization disabled (prevents nested hypervisor breakout)", "PASS", GREEN),
        ("C13", "no_usb_redirect", "USB device redirection disabled (reduces USB emulation attack surface)", "PASS", GREEN),
        ("C15", "network_mode", "Isolated bridge network configured (prevents L2 sniffing)", "PASS", GREEN),
        ("C25", "cpu_vulnerabilities", "Microcode mitigations for Spectre, Meltdown, MDS active", "PASS", GREEN),
        ("C27", "no_shared_memory", "Shared memory backdoor detected: 3 <shmem> IVSHMEM devices found!", "FAIL", RED),
        ("C28", "default_confined", "libvirt security_default_confined active", "PASS", GREEN),
    ]

    for cid, name, details, status, color in controls_demo:
        time.sleep(0.12)
        print(f"  {BOLD}{cid}{RESET}  {name:<22} [{color}{status:4}{RESET}]  {DIM}{details}{RESET}")

    print(f"\n{BOLD}{YELLOW}>> M1 Result:{RESET} 25 Controls {GREEN}PASSED{RESET}, 1 Critical Control {RED}FAILED{RESET} (C27: Shared Memory)")
    time.sleep(1)

    # ---------------------------------------------------------
    # PHASE 2: MEMORY SNAPSHOT PRIVACY SCANNER (M2)
    # ---------------------------------------------------------
    header("PHASE 2: Memory Snapshot Privacy & Secret Scanner (Module M2)")
    print(f"{DIM}Simulating hypervisor memory dump (virsh dump) and scanning raw pages for secret leakage.{RESET}\n")
    time.sleep(0.5)

    spinner("Acquiring 4.0 GB physical RAM snapshot from QEMU guest memory backend")
    spinner("Streaming memory dump through regex token scanners & entropy analyzer")

    subheader("Live Memory Scanner Output & Hex Inspection")
    time.sleep(0.4)
    print(f"  {CYAN}0x7fff01a0:  48 65 6c 6c 6f 20 57 6f 72 6c 64 21 00 00 00 00  [Hello World!....]{RESET}")
    print(f"  {CYAN}0x7fff01b0:  00 00 00 00 5b 53 45 53 53 49 4f 4e 5f 49 44 5d  [....[SESSION_ID]]{RESET}")
    time.sleep(0.3)
    print(f"  {RED}0x7fff01c0:  41 4b 49 41 4a 53 49 45 34 50 4b 45 59 31 32 33  [AKIAJSIE4PKEY123]{RESET}  <-- {RED}{BOLD}LEAK: AWS Access Key ID{RESET}")
    print(f"  {RED}0x7fff01d0:  2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50  [-----BEGIN RSA P]{RESET}  <-- {RED}{BOLD}LEAK: Private Key Header{RESET}")
    time.sleep(0.4)

    print(f"\n  {BOLD}M2 Scanner Statistics:{RESET}")
    print(f"    * Pages Scanned:      {WHITE}1,048,576 pages (4096 bytes each){RESET}")
    print(f"    * Secrets Detected:   {RED}2 sensitive tokens found{RESET}")
    print(f"    * Automated Action:   {GREEN}Applied cryptographic zeroization & memory redaction{RESET}")
    print(f"    * Assessment Finding: {RED}C29 FAIL: Unencrypted memory snapshots leak keys{RESET}")
    time.sleep(1)

    # ---------------------------------------------------------
    # PHASE 3: VOLATILITY MEMORY FORENSICS & ROOTKIT DETECTION (M3)
    # ---------------------------------------------------------
    header("PHASE 3: Volatility Memory Forensics & Rootkit Detection (Module M3)")
    print(f"{DIM}Verifying kernel structure integrity and detecting unlinked Direct Kernel Object Manipulation (DKOM).{RESET}\n")
    time.sleep(0.5)

    spinner("Resolving kernel symbols from vmlinux DWARF debug structures")
    spinner("Executing Volatility 3 plugins: linux.pslist vs linux.psscan (pool scanning)")

    subheader("Process Cross-Comparison Matrix")
    time.sleep(0.3)
    print(f"  {'PID':<8} {'Process Name':<20} {'Visible in pslist?':<22} {'Visible in psscan?':<22} {'Status'}")
    print(f"  {'-'*8} {'-'*20} {'-'*22} {'-'*22} {'-'*10}")
    print(f"  1        systemd              {GREEN}YES{RESET}                   {GREEN}YES{RESET}                   {GREEN}Normal{RESET}")
    print(f"  542      systemd-journald     {GREEN}YES{RESET}                   {GREEN}YES{RESET}                   {GREEN}Normal{RESET}")
    print(f"  1024     sshd                 {GREEN}YES{RESET}                   {GREEN}YES{RESET}                   {GREEN}Normal{RESET}")
    print(f"  {RED}1337{RESET}     {RED}rootkit_backdoor{RESET}     {RED}NO (Unlinked DKOM){RESET}    {GREEN}YES (Found in Pool){RESET}   {RED}{BOLD}HIDDEN ROOTKIT{RESET}")
    
    print(f"\n  {BOLD}M3 Forensics Result:{RESET} Detected 1 unlinked malicious process attempting kernel evasion.")
    print(f"  {BOLD}Control C30 Status:{RESET}  {RED}FAIL (Hidden Process Detected in Guest Memory){RESET}")
    time.sleep(1)

    # ---------------------------------------------------------
    # PHASE 4: MULTI-SIGNAL HYPERVISOR DETECTION (M4)
    # ---------------------------------------------------------
    header("PHASE 4: Side-Channel Timing & Multi-Signal Hypervisor Detection (M4)")
    print(f"{DIM}Testing whether hypervisor presence can be fingerprinted via CPUID/RDTSC timing side-channels.{RESET}\n")
    time.sleep(0.5)

    spinner("Sampling CPUID execution cycles via RDTSC timestamp counter")
    spinner("Measuring VM-exit trap latency across 4 workloads (idle, cpu, mem, mixed)")
    spinner("Training Nested Cross-Validation Classifier (Logistic Regression + Random Forest)")

    subheader("Side-Channel Hardware Latency Benchmarks (SCRIPTED, NOT MEASURED)")
    time.sleep(0.3)
    print(f"  Workload       Native Hardware     KVM-Masked (Stealth)     KVM-Plain (Default)")
    print(f"  --------       ---------------     --------------------     -------------------")
    print(f"  CPUID Ticks:   ~85 cycles          ~1,340 cycles (Trap)     ~1,480 cycles (Trap)")
    print(f"  Syscall Lat:   ~58 ns              ~142 ns                  ~156 ns")
    print(f"  Sleep Jitter:  ~2.1 us             ~18.4 us                 ~21.6 us")

    subheader("Machine Learning Classification Performance")
    time.sleep(0.3)
    print(f"  * Algorithm:             {WHITE}Nested StratifiedGroupKFold (LogReg + Random Forest){RESET}")
    print(f"  * Single-Signal ROC-AUC: {YELLOW}0.842{RESET} (SCRIPTED ILLUSTRATION, not measured)")
    print(f"  * Multi-Signal ROC-AUC:  {GREEN}{BOLD}0.988{RESET} (SCRIPTED ILLUSTRATION, not measured)")
    print(f"  * Conclusion:            {YELLOW}NONE. No real M4 data exists yet; whether combined signals beat one signal is untested.{RESET}")
    time.sleep(1)

    # ---------------------------------------------------------
    # FINAL SUMMARY
    # ---------------------------------------------------------
    header("SECURITY ASSESSMENT & TAXONOMY COMPLIANCE REPORT")
    print(f"""
  {BOLD}Threat Category Summary (SCRIPTED ILLUSTRATION, ACM CSUR 2020 Taxonomy):{RESET}
  -------------------------------------------------------------
  [1] Guest -> Host Escapes:        {YELLOW}PARTIAL (AppArmor active, seccomp active){RESET}
  [2] Guest -> Guest Cross-Talk:    {RED}HIGH RISK (Shared Memory / IVSHMEM found){RESET}
  [3] Host -> VMM Tampering:        {GREEN}PASS (Permissions & socket modes verified){RESET}
  [4] DMA / IOMMU Isolation:        {GREEN}PASS (VT-d enabled, iommu=pt){RESET}
  [5] Snapshot & Memory Privacy:    {RED}FAIL (Credentials exposed in raw dump){RESET}
  [6] Kernel Structure Integrity:   {RED}FAIL (Unlinked DKOM rootkit process){RESET}
  [7] Side-Channel Evasion:         {YELLOW}NOT TESTED (no real M4 data){RESET}
  -------------------------------------------------------------
  {BOLD}Overall VM Posture:{RESET} {YELLOW}32% Vulnerable (Weak Profile){RESET} -> Remediation Plan Required
    """)

    # Launch dashboard
    dashboard_path = Path(__file__).parent / "demo_dashboard.html"
    if dashboard_path.exists():
        print(f"{GREEN}{BOLD}>>> Opening Interactive Visual Dashboard in browser...{RESET}")
        webbrowser.open(str(dashboard_path))
    else:
        report_html = Path(__file__).parent / "out" / "report.html"
        if report_html.exists():
            print(f"{GREEN}{BOLD}>>> Opening Assessment Report in browser...{RESET}")
            webbrowser.open(str(report_html))

    if sys.stdin.isatty():
        print(f"\n{BOLD}Demonstration complete. Press Enter to return to prompt.{RESET}")
        try:
            input()
        except EOFError:
            pass
    else:
        print(f"\n{BOLD}Demonstration complete.{RESET}")

if __name__ == "__main__":
    main()

