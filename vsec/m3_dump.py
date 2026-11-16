"""Pure helpers for the real M3 experiment (scripts/real_m3_test.py): ELF core layout of a `virsh dump --memory-only`
file, the ground-truth comparison, and the DKOM-style unlink used ONLY on a copy of a dump as a positive control."""
import json
import lzma

from .m3_forensics import exit_reason, module_name
import struct
from pathlib import Path


def elf_loads(f):
    """[(paddr, file_offset, filesz)] of the PT_LOAD segments of a 64-bit little-endian ELF core."""
    f.seek(0)
    h = f.read(64)
    if len(h) < 64 or h[:4] != b"\x7fELF" or h[4] != 2 or h[5] != 1:
        raise ValueError("not a 64-bit little-endian ELF core (use virsh dump --memory-only, format elf)")
    phoff, = struct.unpack_from("<Q", h, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", h, 0x36)
    out = []
    for i in range(phnum):
        f.seek(phoff + i * phentsize)
        p_type, _flags, off, _va, pa, filesz = struct.unpack("<IIQQQQ", f.read(40))
        if p_type == 1:
            out.append((pa, off, filesz))
    return out


def phys_to_file(loads, pa, size=8):
    for base, off, n in loads:
        if base <= pa and pa + size <= base + n:
            return off + pa - base
    raise ValueError(f"physical address {pa:#x} is not in the dump")


def tasks_offset(isf_dir):
    """Offset of task_struct.tasks (a list_head: next, prev) in the ISF found in isf_dir."""
    files = sorted(p for p in Path(isf_dir).iterdir() if p.name.endswith((".json", ".json.xz")))
    if not files:
        raise ValueError(f"no ISF in {isf_dir}")
    data = files[0].read_bytes()
    if files[0].name.endswith(".xz"):
        data = lzma.decompress(data)
    return json.loads(data)["user_types"]["task_struct"]["fields"]["tasks"]["offset"]


VA_MASK = (1 << 48) - 1  # x86-64 4-level paging: 48-bit virtual addresses


def unlink_task(f, loads, t_off, victim_pa, va_to_pid, pa_by_pid):
    """Remove one task from the kernel's circular task list IN THE FILE f (a copy of a dump): prev->next =
    victim->next and next->prev = victim->prev. Pointers are virtual addresses of the neighbours' `tasks` members.
    Returns (prev_pid, next_pid). Raises ValueError if a neighbour cannot be resolved."""
    def rd(pa):
        f.seek(phys_to_file(loads, pa))
        return struct.unpack("<Q", f.read(8))[0]

    def wr(pa, value):
        f.seek(phys_to_file(loads, pa))
        f.write(struct.pack("<Q", value))
    v_next, v_prev = rd(victim_pa + t_off), rd(victim_pa + t_off + 8)
    # Volatility prints kernel VAs without the canonical sign extension (0x8d36... for 0xffff8d36...): compare the
    # low 48 bits; the pointers written back are the full values read from memory
    by_va = {va & VA_MASK: pid for va, pid in va_to_pid.items()}
    n_pid, p_pid = by_va.get((v_next - t_off) & VA_MASK), by_va.get((v_prev - t_off) & VA_MASK)
    if n_pid not in pa_by_pid or p_pid not in pa_by_pid:
        raise ValueError(f"neighbours not resolvable (next pid {n_pid}, prev pid {p_pid})")
    wr(pa_by_pid[p_pid] + t_off, v_next)
    wr(pa_by_pid[n_pid] + t_off + 8, v_prev)
    return p_pid, n_pid


def same_name(proc_comm, task_comm):
    """/proc/<pid>/comm vs task->comm from memory. For a workqueue worker the kernel's /proc view appends the
    workqueue ('kworker/0:0-events' for task->comm 'kworker/0:0'); everything else must match exactly."""
    task_comm = str(task_comm).strip()
    return proc_comm == task_comm or (task_comm.startswith("kworker/") and proc_comm.startswith(task_comm + "-"))


def rows_by_pid(rows):
    out = {}
    for r in rows:
        if isinstance(r.get("PID"), int):
            out.setdefault(r["PID"], []).append(r)
    return out


def compare(gt, raw, det):
    """Ground truth recorded in the guest vs Volatility's views of the same dump."""
    listed, scanned = rows_by_pid(raw["pslist"]), rows_by_pid(raw["psscan"])
    gpids = set(gt["procs"])
    lsmod = sorted({str(module_name(r)) for r in raw["lsmod"]})
    hidden_mods = sorted({str(module_name(r)) for r in raw["hidden_modules"]})
    only_scan = sorted(set(scanned) - set(listed))
    exited = {p for p in only_scan if any(exit_reason(r) for r in scanned[p])}
    markers = gt["marker_pids"]
    return {
        "guest_pids": len(gpids), "pslist_pids": len(listed), "psscan_pids": len(scanned),
        "guest_not_in_pslist": sorted(gpids - set(listed)),
        "pslist_not_in_guest": sorted(set(listed) - gpids),
        "markers_in_pslist": {n: bool(ps) and all(p in listed for p in ps) for n, ps in markers.items()},
        "markers_in_psscan": {n: bool(ps) and all(p in scanned for p in ps) for n, ps in markers.items()},
        "name_mismatches": sorted(p for p in gpids & set(listed)
                                  if not same_name(gt["procs"][p], listed[p][0].get("COMM", ""))),
        "exited_pid": gt["exited_pid"], "exited_in_pslist": gt["exited_pid"] in listed,
        "exited_in_psscan": gt["exited_pid"] in scanned,
        "psscan_only": only_scan,                                   # the raw detector's "hidden" set
        "psscan_only_exited": sorted(exited),                       # EXIT_DEAD/zombie rows: dead, not hidden
        "psscan_only_live_in_guest": sorted(set(only_scan) & gpids),  # would be a real hidden process
        "hidden_pids": det["hidden_pids"],
        "false_hidden": only_scan,  # clean dump: the true number of hidden tasks is zero, so every alarm is false
        "false_hidden_after_exit_filter": [p for p in only_scan if p not in exited],
        "guest_modules": len(gt["modules"]), "lsmod_modules": len(lsmod),
        "modules_only_guest": sorted(set(gt["modules"]) - set(lsmod)),
        "modules_only_lsmod": sorted(set(lsmod) - set(gt["modules"])),
        "hidden_modules": hidden_mods,
    }


def summarise(records):
    """Aggregate the per-boot comparisons of a run (clean dumps: the true number of hidden objects is zero)."""
    cs = [r["comparison"] for r in records]
    n = len(cs)
    return {
        "boots": n,
        "names_equal_guest": sum(not c["name_mismatches"] for c in cs),
        "pslist_equals_guest": sum(not c["guest_not_in_pslist"] and not c["pslist_not_in_guest"] for c in cs),
        "markers_in_pslist": sum(all(c["markers_in_pslist"].values()) for c in cs),
        "markers_in_psscan": sum(all(c["markers_in_psscan"].values()) for c in cs),
        "exited_in_psscan": sum(bool(c["exited_in_psscan"]) for c in cs),
        "exited_in_pslist": sum(bool(c["exited_in_pslist"]) for c in cs),
        "dumps_with_false_hidden_raw": sum(bool(c["false_hidden"]) for c in cs),
        "false_hidden_raw_per_dump": [len(c["false_hidden"]) for c in cs],
        "dumps_with_false_hidden_after_exit_filter": sum(bool(c["false_hidden_after_exit_filter"]) for c in cs),
        "dumps_with_live_hidden": sum(bool(c["psscan_only_live_in_guest"]) for c in cs),
        "lsmod_equals_guest": sum(not c["modules_only_guest"] and not c["modules_only_lsmod"] for c in cs),
        "dumps_with_hidden_modules": sum(bool(c["hidden_modules"]) for c in cs),
    }
