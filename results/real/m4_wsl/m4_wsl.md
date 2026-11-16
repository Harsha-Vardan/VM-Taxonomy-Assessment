# Limited M4 run 20261116T053926Z: WSL2 host vs KVM guest inside WSL2 (EXPLORATORY, not native vs VM)

Units used: 40 (environment x session x workload runs, exit 0). Values = medians of per-run medians.
Note: with 5 vs 5 sessions the smallest two-sided Mann-Whitney p is 2/252 = 0.0079, so after Holm over 10 signals no single signal can reach p < 0.05. Read Cliff's delta (effect size) and AUROC; the p-values only show the limit.

## Workload cpu

| signal | group | host | guest | guest/host | Cliff d | single AUROC | p (Holm) |
|---|---|---|---|---|---|---|---|
| cpuid_tsc | timing | 854.1 | 9229 | 10.8 | +1.00 | 1.00 | 0.0794 |
| rdtsc_tsc | timing | 22 | 24.5 | 1.11 | +0.00 | 0.50 | 1 |
| syscall_ns | timing | 81.29 | 347.8 | 4.28 | +1.00 | 1.00 | 0.0794 |
| pagefault_ns | memory | 906 | 1518 | 1.68 | +0.52 | 0.76 | 1 |
| seq_ns | memory | 11.63 | 8.725 | 0.75 | +0.04 | 0.52 | 1 |
| stride_ns | memory | 13.13 | 9.595 | 0.731 | -0.84 | 0.92 | 0.254 |
| rand_ns | memory | 195.9 | 199.6 | 1.02 | +0.04 | 0.52 | 1 |
| sleep_jitter_us | scheduler | 0.207 | 1.23 | 5.94 | +0.76 | 0.88 | 0.389 |
| ipc | perf | NA (not measurable in both) |  |  |  |  |  |
| dtlb_miss | perf | NA (not measurable in both) |  |  |  |  |  |

Combined (logistic regression, leave-one-session-out): AUROC 1.0, accuracy 1.0

## Workload idle

| signal | group | host | guest | guest/host | Cliff d | single AUROC | p (Holm) |
|---|---|---|---|---|---|---|---|
| cpuid_tsc | timing | 855.8 | 8080 | 9.44 | +1.00 | 1.00 | 0.0794 |
| rdtsc_tsc | timing | 22 | 22 | 1 | +0.00 | 0.50 | 1 |
| syscall_ns | timing | 81.02 | 300.2 | 3.7 | +1.00 | 1.00 | 0.0794 |
| pagefault_ns | memory | 845.8 | 1058 | 1.25 | +0.68 | 0.84 | 0.667 |
| seq_ns | memory | 4.009 | 4.092 | 1.02 | +0.20 | 0.60 | 1 |
| stride_ns | memory | 13.76 | 8.748 | 0.636 | -0.84 | 0.92 | 0.254 |
| rand_ns | memory | 99.7 | 99.13 | 0.994 | +0.20 | 0.60 | 1 |
| sleep_jitter_us | scheduler | 1.155 | 1.337 | 1.16 | +0.04 | 0.52 | 1 |
| ipc | perf | NA (not measurable in both) |  |  |  |  |  |
| dtlb_miss | perf | NA (not measurable in both) |  |  |  |  |  |

Combined (logistic regression, leave-one-session-out): AUROC 1.0, accuracy 1.0

## Workload mem

| signal | group | host | guest | guest/host | Cliff d | single AUROC | p (Holm) |
|---|---|---|---|---|---|---|---|
| cpuid_tsc | timing | 942.3 | 9929 | 10.5 | +1.00 | 1.00 | 0.0794 |
| rdtsc_tsc | timing | 25.5 | 26 | 1.02 | +0.00 | 0.50 | 1 |
| syscall_ns | timing | 92.11 | 349.2 | 3.79 | +1.00 | 1.00 | 0.0794 |
| pagefault_ns | memory | 1054 | 1425 | 1.35 | +0.68 | 0.84 | 0.571 |
| seq_ns | memory | 11.38 | 11.16 | 0.981 | -0.36 | 0.68 | 1 |
| stride_ns | memory | 14.99 | 9.106 | 0.607 | -1.00 | 1.00 | 0.0794 |
| rand_ns | memory | 222 | 211.1 | 0.951 | -0.28 | 0.64 | 1 |
| sleep_jitter_us | scheduler | 0.7325 | 1.395 | 1.91 | +0.76 | 0.88 | 0.389 |
| ipc | perf | NA (not measurable in both) |  |  |  |  |  |
| dtlb_miss | perf | NA (not measurable in both) |  |  |  |  |  |

Combined (logistic regression, leave-one-session-out): AUROC 1.0, accuracy 0.9

## Workload mixed

| signal | group | host | guest | guest/host | Cliff d | single AUROC | p (Holm) |
|---|---|---|---|---|---|---|---|
| cpuid_tsc | timing | 945.7 | 8813 | 9.32 | +1.00 | 1.00 | 0.0794 |
| rdtsc_tsc | timing | 24.5 | 24 | 0.98 | -0.32 | 0.66 | 1 |
| syscall_ns | timing | 90.17 | 329.4 | 3.65 | +1.00 | 1.00 | 0.0794 |
| pagefault_ns | memory | 1027 | 1187 | 1.16 | +0.68 | 0.84 | 0.476 |
| seq_ns | memory | 11.7 | 10.95 | 0.936 | -0.76 | 0.88 | 0.333 |
| stride_ns | memory | 14.71 | 8.864 | 0.602 | -1.00 | 1.00 | 0.0794 |
| rand_ns | memory | 215.7 | 201.3 | 0.933 | +0.04 | 0.52 | 1 |
| sleep_jitter_us | scheduler | 0.983 | 2.016 | 2.05 | +0.92 | 0.96 | 0.111 |
| ipc | perf | NA (not measurable in both) |  |  |  |  |  |
| dtlb_miss | perf | NA (not measurable in both) |  |  |  |  |  |

Combined (logistic regression, leave-one-session-out): AUROC 1.0, accuracy 1.0

Pooled over workloads: AUROC 1.0, accuracy 1.0, features ['cpuid_tsc', 'rdtsc_tsc', 'syscall_ns', 'pagefault_ns', 'seq_ns', 'stride_ns', 'rand_ns', 'sleep_jitter_us']
