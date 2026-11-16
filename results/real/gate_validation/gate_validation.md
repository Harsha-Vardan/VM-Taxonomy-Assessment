# Attack Lab gate validation (E0, run 20261115T140639Z)

REAL experiment on disposable CirrOS VMs. Prediction = Attack Lab stage rule on the M1 audit of the running VM; observation = independent probe (never M1's verdict).

Overall agreement: 54/60 (Wilson 95% CI 0.80-0.95); unsafe disagreements (model says blocked, stage open): 6; no observation: 0.
Coverage: 4 of 18 gated attack stages probed.

| Control | Stage | n | agree | CI | unsafe | conservative |
|---|---|---|---|---|---|---|
| C11 | A02 s1: Connect to the guest console | 15 | 15 | 0.80-1.00 | 0 | 0 |
| C12 | A02 s0: Scan the network for console ports | 15 | 15 | 0.80-1.00 | 0 | 0 |
| C14 | A01 s1: Send oversized FIFO command sequences | 15 | 9 | 0.36-0.80 | 6 | 0 |
| C17 | A09 s2: Read the VM disk or memory image | 15 | 15 | 0.80-1.00 | 0 | 0 |

| Arm | rep | Control | M1 | predicted | observed | agree | note |
|---|---|---|---|---|---|---|---|
| W | 1 | C12 | FAIL | open | open | True |  |
| W | 1 | C11 | FAIL | open | open | True |  |
| W | 1 | C14 | FAIL | open | open | True |  |
| W | 1 | C17 | FAIL | open | open | True |  |
| M1 | 1 | C12 | FAIL | open | open | True |  |
| M1 | 1 | C11 | PASS | blocked | blocked | True |  |
| M1 | 1 | C14 | PASS | blocked | open | False |  |
| M1 | 1 | C17 | FAIL | open | open | True |  |
| M2 | 1 | C12 | PASS | blocked | blocked | True |  |
| M2 | 1 | C11 | FAIL | open | open | True |  |
| M2 | 1 | C14 | FAIL | open | open | True |  |
| M2 | 1 | C17 | PASS | blocked | blocked | True |  |
| H | 1 | C12 | PASS | blocked | blocked | True |  |
| H | 1 | C11 | PASS | blocked | blocked | True |  |
| H | 1 | C14 | PASS | blocked | open | False |  |
| H | 1 | C17 | PASS | blocked | blocked | True |  |
| H-q35 | 1 | C12 | PASS | blocked | blocked | True |  |
| H-q35 | 1 | C11 | PASS | blocked | blocked | True |  |
| H-q35 | 1 | C14 | PASS | blocked | blocked | True |  |
| H-q35 | 1 | C17 | PASS | blocked | blocked | True |  |
| W | 2 | C12 | FAIL | open | open | True |  |
| W | 2 | C11 | FAIL | open | open | True |  |
| W | 2 | C14 | FAIL | open | open | True |  |
| W | 2 | C17 | FAIL | open | open | True |  |
| M1 | 2 | C12 | FAIL | open | open | True |  |
| M1 | 2 | C11 | PASS | blocked | blocked | True |  |
| M1 | 2 | C14 | PASS | blocked | open | False |  |
| M1 | 2 | C17 | FAIL | open | open | True |  |
| M2 | 2 | C12 | PASS | blocked | blocked | True |  |
| M2 | 2 | C11 | FAIL | open | open | True |  |
| M2 | 2 | C14 | FAIL | open | open | True |  |
| M2 | 2 | C17 | PASS | blocked | blocked | True |  |
| H | 2 | C12 | PASS | blocked | blocked | True |  |
| H | 2 | C11 | PASS | blocked | blocked | True |  |
| H | 2 | C14 | PASS | blocked | open | False |  |
| H | 2 | C17 | PASS | blocked | blocked | True |  |
| H-q35 | 2 | C12 | PASS | blocked | blocked | True |  |
| H-q35 | 2 | C11 | PASS | blocked | blocked | True |  |
| H-q35 | 2 | C14 | PASS | blocked | blocked | True |  |
| H-q35 | 2 | C17 | PASS | blocked | blocked | True |  |
| W | 3 | C12 | FAIL | open | open | True |  |
| W | 3 | C11 | FAIL | open | open | True |  |
| W | 3 | C14 | FAIL | open | open | True |  |
| W | 3 | C17 | FAIL | open | open | True |  |
| M1 | 3 | C12 | FAIL | open | open | True |  |
| M1 | 3 | C11 | PASS | blocked | blocked | True |  |
| M1 | 3 | C14 | PASS | blocked | open | False |  |
| M1 | 3 | C17 | FAIL | open | open | True |  |
| M2 | 3 | C12 | PASS | blocked | blocked | True |  |
| M2 | 3 | C11 | FAIL | open | open | True |  |
| M2 | 3 | C14 | FAIL | open | open | True |  |
| M2 | 3 | C17 | PASS | blocked | blocked | True |  |
| H | 3 | C12 | PASS | blocked | blocked | True |  |
| H | 3 | C11 | PASS | blocked | blocked | True |  |
| H | 3 | C14 | PASS | blocked | open | False |  |
| H | 3 | C17 | PASS | blocked | blocked | True |  |
| H-q35 | 3 | C12 | PASS | blocked | blocked | True |  |
| H-q35 | 3 | C11 | PASS | blocked | blocked | True |  |
| H-q35 | 3 | C14 | PASS | blocked | blocked | True |  |
| H-q35 | 3 | C17 | PASS | blocked | blocked | True |  |

Legitimate access after the C17 setting (boot + guest disk write + QEMU read requests):

- W r1: image 0o644 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1310, 'ok': True})
- M1 r1: image 0o644 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1307, 'ok': True})
- M2 r1: image 0o600 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1310, 'ok': True})
- H r1: image 0o600 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1309, 'ok': True})
- H-q35 r1: image 0o600 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1311, 'ok': True})
- W r2: image 0o644 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1311, 'ok': True})
- M1 r2: image 0o644 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1310, 'ok': True})
- M2 r2: image 0o600 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1310, 'ok': True})
- H r2: image 0o600 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1313, 'ok': True})
- H-q35 r2: image 0o600 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1312, 'ok': True})
- W r3: image 0o644 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1313, 'ok': True})
- M1 r3: image 0o644 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1312, 'ok': True})
- M2 r3: image 0o600 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1311, 'ok': True})
- H r3: image 0o600 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1312, 'ok': True})
- H-q35 r3: image 0o600 -> OK ({'booted': True, 'guest_disk_rw': True, 'qemu_read_requests': 1313, 'ok': True})

Disagreements:

- M1 r1 C14: predicted blocked, observed open; M1 evidence: ok; observation: {"msr": "0x80", "qtree": {"isa_fdc": true, "floppy_drives": 0}}
- H r1 C14: predicted blocked, observed open; M1 evidence: ok; observation: {"msr": "0x80", "qtree": {"isa_fdc": true, "floppy_drives": 0}}
- M1 r2 C14: predicted blocked, observed open; M1 evidence: ok; observation: {"msr": "0x80", "qtree": {"isa_fdc": true, "floppy_drives": 0}}
- H r2 C14: predicted blocked, observed open; M1 evidence: ok; observation: {"msr": "0x80", "qtree": {"isa_fdc": true, "floppy_drives": 0}}
- M1 r3 C14: predicted blocked, observed open; M1 evidence: ok; observation: {"msr": "0x80", "qtree": {"isa_fdc": true, "floppy_drives": 0}}
- H r3 C14: predicted blocked, observed open; M1 evidence: ok; observation: {"msr": "0x80", "qtree": {"isa_fdc": true, "floppy_drives": 0}}

Protected state unchanged: True
