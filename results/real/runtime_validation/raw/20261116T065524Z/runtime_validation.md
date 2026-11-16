# Runtime validation 20261116T065524Z (REAL, disposable VMs on E0)

M1 PREDICTS from collected evidence; the validator OBSERVES the running system through a separate path.
Tags: live-runtime / live-config = M1 input source; independence = how separate the observation is.

**Totals:** 12 agree, 0 disagree, 0 not observable (2 arms x 6 controls).

## Arm D (vsec-rv-b): {'machine': 'q35', 'listen': '127.0.0.1', 'passwd': True, 'floppy': False, 'net': 'iso', 'iso': True, 'peer_net': 'iso', 'peer_iso': True}

### Predictions (M1) | Observations (runtime) | Comparison

| ID | M1 predicts | M1 source | observed | independence | agree | M1 evidence | observation |
|---|---|---|---|---|---|---|---|
| C04 | PASS | live-runtime | PASS | partial | yes | Seccomp: 2 | Seccomp=2 Seccomp_filters=1  |
| C06 | FAIL | live-runtime | FAIL | partial | yes | label: kernel | label='kernel\x00' lsm={'apparmor': 'N\n', 'selinux_enforce': None} no LSM enabled on this host: QEMU cannot be confined |
| C11 | PASS | live-config | PASS | independent | yes | ok | {'host': '127.0.0.1', 'port': 5901, 'connected': True, 'error': '', 'version': '  |
| C12 | PASS | live-config | PASS | independent | yes | ok | {'host': '172.31.132.198', 'port': 5901, 'connected': False, 'error': 'Connectio  |
| C14 | PASS | live-runtime | PASS | independent | yes | running QEMU builds no floppy controller, parallel port or s | {'msr': '0xff', 'qtree': {'isa_fdc': False, 'floppy_drives': 0}}  |
| C16 | PASS | live-runtime | PASS | independent | yes | host-verified; 1 co-resident port(s), all port-isolated | second VM reachable by ping: False  |

## Arm E (vsec-rv-b): {'machine': 'q35', 'listen': '127.0.0.1', 'passwd': True, 'floppy': False, 'net': 'iso', 'iso': True, 'peer_net': 'iso', 'peer_iso': False}

### Predictions (M1) | Observations (runtime) | Comparison

| ID | M1 predicts | M1 source | observed | independence | agree | M1 evidence | observation |
|---|---|---|---|---|---|---|---|
| C04 | PASS | live-runtime | PASS | partial | yes | Seccomp: 2 | Seccomp=2 Seccomp_filters=1  |
| C06 | FAIL | live-runtime | FAIL | partial | yes | label: kernel | label='kernel\x00' lsm={'apparmor': 'N\n', 'selinux_enforce': None} no LSM enabled on this host: QEMU cannot be confined |
| C11 | PASS | live-config | PASS | independent | yes | ok | {'host': '127.0.0.1', 'port': 5901, 'connected': True, 'error': '', 'version': '  |
| C12 | PASS | live-config | PASS | independent | yes | ok | {'host': '172.31.132.198', 'port': 5901, 'connected': False, 'error': 'Connectio  |
| C14 | PASS | live-runtime | PASS | independent | yes | running QEMU builds no floppy controller, parallel port or s | {'msr': '0xff', 'qtree': {'isa_fdc': False, 'floppy_drives': 0}}  |
| C16 | FAIL | live-runtime | FAIL | independent | yes | guest-to-guest path: ['vnet3(isolated=1)<->vnet2(isolated=0) | second VM reachable by ping: True  |

## Disagreements

- none

## Methods

- C04 (partial): validator reads /proc/<qemu-pid>/status itself: Seccomp mode and Seccomp_filters count
- C06 (partial): validator reads /proc/<qemu-pid>/attr/current and whether an LSM (AppArmor/SELinux) is enabled
- C11 (independent): RFB handshake on the VNC port: does the server offer security type None
- C12 (independent): TCP+RFB connect to the VNC port on the host's non-loopback address
- C14 (independent): guest reads the floppy controller status port 0x3F4 (0xFF = no device) + QEMU info qtree
- C16 (independent): guest pings a second running VM (static addresses, no DHCP; both NICs verified up). Reachable = FAIL; unreachable with working NICs, or no NIC at all = PASS
