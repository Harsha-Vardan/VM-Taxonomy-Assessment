# Runtime validation 20261116T063834Z (REAL, disposable VMs on E0)

M1 PREDICTS from collected evidence; the validator OBSERVES the running system through a separate path.
Tags: live-runtime / live-config = M1 input source; independence = how separate the observation is.

**Totals:** 60 agree, 0 disagree, 0 not observable (10 arms x 6 controls).

## Arm A (vsec-rv-a): {'machine': 'pc', 'listen': '0.0.0.0', 'passwd': False, 'floppy': True, 'net': 'iso', 'iso': False, 'peer_net': 'iso', 'peer_iso': False}

### Predictions (M1) | Observations (runtime) | Comparison

| ID | M1 predicts | M1 source | observed | independence | agree | M1 evidence | observation |
|---|---|---|---|---|---|---|---|
| C04 | PASS | live-runtime | PASS | partial | yes | Seccomp: 2 | Seccomp=2 Seccomp_filters=1  |
| C06 | FAIL | live-runtime | FAIL | partial | yes | label: kernel | label='kernel\x00' lsm={'apparmor': 'N\n', 'selinux_enforce': None} no LSM enabled on this host: QEMU cannot be confined |
| C11 | FAIL | live-config | FAIL | independent | yes | no password on: ['vnc'] | {'host': '127.0.0.1', 'port': 5901, 'connected': True, 'error': '', 'version': '  |
| C12 | FAIL | live-config | FAIL | independent | yes | listens on: ['0.0.0.0'] | {'host': '172.31.132.198', 'port': 5901, 'connected': True, 'error': '', 'versio  |
| C14 | FAIL | live-runtime | FAIL | independent | yes | declared unused devices: ['floppy'] | {'msr': '0x80', 'qtree': {'isa_fdc': True, 'floppy_drives': 1}}  |
| C16 | FAIL | live-runtime | FAIL | independent | yes | host: not-isolated: <graphics type='vnc'> listens on non-loo | second VM reachable by ping: True  |

## Arm B (vsec-rv-b): {'machine': 'pc', 'listen': '127.0.0.1', 'passwd': True, 'floppy': False, 'net': 'iso', 'iso': False, 'peer_net': 'iso', 'peer_iso': False}

### Predictions (M1) | Observations (runtime) | Comparison

| ID | M1 predicts | M1 source | observed | independence | agree | M1 evidence | observation |
|---|---|---|---|---|---|---|---|
| C04 | PASS | live-runtime | PASS | partial | yes | Seccomp: 2 | Seccomp=2 Seccomp_filters=1  |
| C06 | FAIL | live-runtime | FAIL | partial | yes | label: kernel | label='kernel\x00' lsm={'apparmor': 'N\n', 'selinux_enforce': None} no LSM enabled on this host: QEMU cannot be confined |
| C11 | PASS | live-config | PASS | independent | yes | ok | {'host': '127.0.0.1', 'port': 5901, 'connected': True, 'error': '', 'version': '  |
| C12 | PASS | live-config | PASS | independent | yes | ok | {'host': '172.31.132.198', 'port': 5901, 'connected': False, 'error': 'Connectio  |
| C14 | FAIL | live-runtime | FAIL | independent | yes | running QEMU builds: ['isa-fdc'] | {'msr': '0x80', 'qtree': {'isa_fdc': True, 'floppy_drives': 0}}  |
| C16 | FAIL | live-runtime | FAIL | independent | yes | guest-to-guest path: ['vnet3(isolated=0)<->vnet2(isolated=0) | second VM reachable by ping: True  |

## Arm C (vsec-rv-b): {'machine': 'q35', 'listen': '127.0.0.1', 'passwd': True, 'floppy': False, 'net': 'iso', 'iso': False, 'peer_net': 'iso', 'peer_iso': False}

### Predictions (M1) | Observations (runtime) | Comparison

| ID | M1 predicts | M1 source | observed | independence | agree | M1 evidence | observation |
|---|---|---|---|---|---|---|---|
| C04 | PASS | live-runtime | PASS | partial | yes | Seccomp: 2 | Seccomp=2 Seccomp_filters=1  |
| C06 | FAIL | live-runtime | FAIL | partial | yes | label: kernel | label='kernel\x00' lsm={'apparmor': 'N\n', 'selinux_enforce': None} no LSM enabled on this host: QEMU cannot be confined |
| C11 | PASS | live-config | PASS | independent | yes | ok | {'host': '127.0.0.1', 'port': 5901, 'connected': True, 'error': '', 'version': '  |
| C12 | PASS | live-config | PASS | independent | yes | ok | {'host': '172.31.132.198', 'port': 5901, 'connected': False, 'error': 'Connectio  |
| C14 | PASS | live-runtime | PASS | independent | yes | running QEMU builds no floppy controller, parallel port or s | {'msr': '0xff', 'qtree': {'isa_fdc': False, 'floppy_drives': 0}}  |
| C16 | FAIL | live-runtime | FAIL | independent | yes | guest-to-guest path: ['vnet5(isolated=0)<->vnet4(isolated=0) | second VM reachable by ping: True  |

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
| C16 | FAIL | live-runtime | FAIL | independent | yes | guest-to-guest path: ['vnet9(isolated=1)<->vnet8(isolated=0) | second VM reachable by ping: True  |

## Arm F (vsec-rv-b): {'machine': 'q35', 'listen': '127.0.0.1', 'passwd': True, 'floppy': False, 'net': 'iso2', 'iso': False, 'peer_net': 'iso', 'peer_iso': False}

### Predictions (M1) | Observations (runtime) | Comparison

| ID | M1 predicts | M1 source | observed | independence | agree | M1 evidence | observation |
|---|---|---|---|---|---|---|---|
| C04 | PASS | live-runtime | PASS | partial | yes | Seccomp: 2 | Seccomp=2 Seccomp_filters=1  |
| C06 | FAIL | live-runtime | FAIL | partial | yes | label: kernel | label='kernel\x00' lsm={'apparmor': 'N\n', 'selinux_enforce': None} no LSM enabled on this host: QEMU cannot be confined |
| C11 | PASS | live-config | PASS | independent | yes | ok | {'host': '127.0.0.1', 'port': 5901, 'connected': True, 'error': '', 'version': '  |
| C12 | PASS | live-config | PASS | independent | yes | ok | {'host': '172.31.132.198', 'port': 5901, 'connected': False, 'error': 'Connectio  |
| C14 | PASS | live-runtime | PASS | independent | yes | running QEMU builds no floppy controller, parallel port or s | {'msr': '0xff', 'qtree': {'isa_fdc': False, 'floppy_drives': 0}}  |
| C16 | PASS | live-runtime | PASS | independent | yes | host-verified; no other port on the guest's bridge(s) now | second VM reachable by ping: False  |

## Arm G (vsec-rv-b): {'machine': 'q35', 'listen': None, 'passwd': False, 'floppy': False, 'net': None, 'iso': False, 'peer_net': 'iso', 'peer_iso': False}

### Predictions (M1) | Observations (runtime) | Comparison

| ID | M1 predicts | M1 source | observed | independence | agree | M1 evidence | observation |
|---|---|---|---|---|---|---|---|
| C04 | PASS | live-runtime | PASS | partial | yes | Seccomp: 2 | Seccomp=2 Seccomp_filters=1  |
| C06 | FAIL | live-runtime | FAIL | partial | yes | label: kernel | label='kernel\x00' lsm={'apparmor': 'N\n', 'selinux_enforce': None} no LSM enabled on this host: QEMU cannot be confined |
| C11 | PASS | live-config | PASS | independent | yes | ok | QEMU TCP listeners: []  |
| C12 | PASS | live-config | PASS | independent | yes | ok | QEMU TCP listeners: []  |
| C14 | PASS | live-runtime | PASS | independent | yes | running QEMU builds no floppy controller, parallel port or s | {'msr': '0xff', 'qtree': {'isa_fdc': False, 'floppy_drives': 0}}  |
| C16 | PASS | live-runtime | PASS | independent | yes | host-verified; no network interface | guest has no network interface  |

## Arm H (vsec-rv-a): {'machine': 'q35', 'listen': '0.0.0.0', 'passwd': True, 'floppy': False, 'net': 'iso', 'iso': False, 'peer_net': 'iso', 'peer_iso': False}

### Predictions (M1) | Observations (runtime) | Comparison

| ID | M1 predicts | M1 source | observed | independence | agree | M1 evidence | observation |
|---|---|---|---|---|---|---|---|
| C04 | PASS | live-runtime | PASS | partial | yes | Seccomp: 2 | Seccomp=2 Seccomp_filters=1  |
| C06 | FAIL | live-runtime | FAIL | partial | yes | label: kernel | label='kernel\x00' lsm={'apparmor': 'N\n', 'selinux_enforce': None} no LSM enabled on this host: QEMU cannot be confined |
| C11 | PASS | live-config | PASS | independent | yes | ok | {'host': '127.0.0.1', 'port': 5901, 'connected': True, 'error': '', 'version': '  |
| C12 | FAIL | live-config | FAIL | independent | yes | listens on: ['0.0.0.0'] | {'host': '172.31.132.198', 'port': 5901, 'connected': True, 'error': '', 'versio  |
| C14 | PASS | live-runtime | PASS | independent | yes | running QEMU builds no floppy controller, parallel port or s | {'msr': '0xff', 'qtree': {'isa_fdc': False, 'floppy_drives': 0}}  |
| C16 | FAIL | live-runtime | FAIL | independent | yes | host: not-isolated: <graphics type='vnc'> listens on non-loo | second VM reachable by ping: True  |

## Arm I (vsec-rv-a): {'machine': 'q35', 'listen': '127.0.0.1', 'passwd': False, 'floppy': False, 'net': 'iso', 'iso': False, 'peer_net': 'iso', 'peer_iso': False}

### Predictions (M1) | Observations (runtime) | Comparison

| ID | M1 predicts | M1 source | observed | independence | agree | M1 evidence | observation |
|---|---|---|---|---|---|---|---|
| C04 | PASS | live-runtime | PASS | partial | yes | Seccomp: 2 | Seccomp=2 Seccomp_filters=1  |
| C06 | FAIL | live-runtime | FAIL | partial | yes | label: kernel | label='kernel\x00' lsm={'apparmor': 'N\n', 'selinux_enforce': None} no LSM enabled on this host: QEMU cannot be confined |
| C11 | FAIL | live-config | FAIL | independent | yes | no password on: ['vnc'] | {'host': '127.0.0.1', 'port': 5901, 'connected': True, 'error': '', 'version': '  |
| C12 | PASS | live-config | PASS | independent | yes | ok | {'host': '172.31.132.198', 'port': 5901, 'connected': False, 'error': 'Connectio  |
| C14 | PASS | live-runtime | PASS | independent | yes | running QEMU builds no floppy controller, parallel port or s | {'msr': '0xff', 'qtree': {'isa_fdc': False, 'floppy_drives': 0}}  |
| C16 | FAIL | live-runtime | FAIL | independent | yes | guest-to-guest path: ['vnet16(isolated=0)<->vnet15(isolated= | second VM reachable by ping: True  |

## Arm J (vsec-rv-a): {'machine': 'pc', 'listen': '127.0.0.1', 'passwd': True, 'floppy': True, 'net': 'iso', 'iso': True, 'peer_net': 'iso', 'peer_iso': True}

### Predictions (M1) | Observations (runtime) | Comparison

| ID | M1 predicts | M1 source | observed | independence | agree | M1 evidence | observation |
|---|---|---|---|---|---|---|---|
| C04 | PASS | live-runtime | PASS | partial | yes | Seccomp: 2 | Seccomp=2 Seccomp_filters=1  |
| C06 | FAIL | live-runtime | FAIL | partial | yes | label: kernel | label='kernel\x00' lsm={'apparmor': 'N\n', 'selinux_enforce': None} no LSM enabled on this host: QEMU cannot be confined |
| C11 | PASS | live-config | PASS | independent | yes | ok | {'host': '127.0.0.1', 'port': 5901, 'connected': True, 'error': '', 'version': '  |
| C12 | PASS | live-config | PASS | independent | yes | ok | {'host': '172.31.132.198', 'port': 5901, 'connected': False, 'error': 'Connectio  |
| C14 | FAIL | live-runtime | FAIL | independent | yes | declared unused devices: ['floppy'] | {'msr': '0x80', 'qtree': {'isa_fdc': True, 'floppy_drives': 1}}  |
| C16 | PASS | live-runtime | PASS | independent | yes | host-verified; 1 co-resident port(s), all port-isolated | second VM reachable by ping: False  |

## Disagreements

- none

## Methods

- C04 (partial): validator reads /proc/<qemu-pid>/status itself: Seccomp mode and Seccomp_filters count
- C06 (partial): validator reads /proc/<qemu-pid>/attr/current and whether an LSM (AppArmor/SELinux) is enabled
- C11 (independent): RFB handshake on the VNC port: does the server offer security type None
- C12 (independent): TCP+RFB connect to the VNC port on the host's non-loopback address
- C14 (independent): guest reads the floppy controller status port 0x3F4 (0xFF = no device) + QEMU info qtree
- C16 (independent): guest pings a second running VM (static addresses, no DHCP; both NICs verified up). Reachable = FAIL; unreachable with working NICs, or no NIC at all = PASS
