| Control | Topic | vsec | Lynis mentions topic? |
|---|---|---|---|
| C17 | file permissions on VM images | FAIL | yes |
| C20 | libvirt/remote management exposure | PASS | yes |
| C25 | CPU vulnerabilities / microcode | PASS | yes |
| C26 | SMT state | PASS | no |
| C24 | kernel version / updates | NA | yes |

vsec controls: 28; FAIL 9, PASS 15, NA 4
Lynis is a general Linux hardening tool: most vsec controls (QEMU seccomp, per-VM sVirt labelling, KSM, nested, VM devices, graphics, network mode) have no Lynis counterpart (Lynis only checks that AppArmor/SELinux is present), which is the gap this project addresses.
