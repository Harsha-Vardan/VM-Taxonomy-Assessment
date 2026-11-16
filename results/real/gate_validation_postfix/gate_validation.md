# Attack Lab gate validation (E0, run 20261115T144004Z)

REAL experiment on disposable CirrOS VMs. Prediction = Attack Lab stage rule on the M1 audit of the running VM; observation = independent probe (never M1's verdict).

Overall agreement: 20/20 (Wilson 95% CI 0.84-1.00); unsafe disagreements (model says blocked, stage open): 0; no observation: 0.
Coverage: 4 of 18 gated attack stages probed.

| Control | Stage | n | agree | CI | unsafe | conservative |
|---|---|---|---|---|---|---|
| C11 | A02 s1: Connect to the guest console | 5 | 5 | 0.57-1.00 | 0 | 0 |
| C12 | A02 s0: Scan the network for console ports | 5 | 5 | 0.57-1.00 | 0 | 0 |
| C14 | A01 s1: Send oversized FIFO command sequences | 5 | 5 | 0.57-1.00 | 0 | 0 |
| C17 | A09 s2: Read the VM disk or memory image | 5 | 5 | 0.57-1.00 | 0 | 0 |

| Arm | rep | Control | M1 | predicted | observed | agree | note |
|---|---|---|---|---|---|---|---|
| W | 1 | C12 | FAIL | open | open | True |  |
| W | 1 | C11 | FAIL | open | open | True |  |
| W | 1 | C14 | FAIL | open | open | True |  |
| W | 1 | C17 | FAIL | open | open | True |  |
| M1 | 1 | C12 | FAIL | open | open | True |  |
| M1 | 1 | C11 | PASS | blocked | blocked | True |  |
| M1 | 1 | C14 | FAIL | open | open | True |  |
| M1 | 1 | C17 | FAIL | open | open | True |  |
| M2 | 1 | C12 | PASS | blocked | blocked | True |  |
| M2 | 1 | C11 | FAIL | open | open | True |  |
| M2 | 1 | C14 | FAIL | open | open | True |  |
| M2 | 1 | C17 | PASS | blocked | blocked | True |  |
| H | 1 | C12 | PASS | blocked | blocked | True |  |
| H | 1 | C11 | PASS | blocked | blocked | True |  |
| H | 1 | C14 | FAIL | open | open | True |  |
| H | 1 | C17 | PASS | blocked | blocked | True |  |
| H-q35 | 1 | C12 | PASS | blocked | blocked | True |  |
| H-q35 | 1 | C11 | PASS | blocked | blocked | True |  |
| H-q35 | 1 | C14 | PASS | blocked | blocked | True |  |
| H-q35 | 1 | C17 | PASS | blocked | blocked | True |  |

Legitimate access after the C17 setting (boot + guest disk write + QEMU read requests):

- W r1: image 0o644 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1311, 'ok': True})
- M1 r1: image 0o644 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1312, 'ok': True})
- M2 r1: image 0o600 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1315, 'ok': True})
- H r1: image 0o600 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1313, 'ok': True})
- H-q35 r1: image 0o600 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1315, 'ok': True})

Disagreements:

- none

Protected state unchanged: True
