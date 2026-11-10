"""Figures for the IEEE-format paper (docs/paper/ieee/figs/). Data comes from results/experiments.json.

    python scripts/make_ieee_figures.py

fig_arch.png: framework architecture. fig_leverage.png, fig_hardhost.png: model studies E4, E5 (95% Wilson bands).
The Attack Lab screenshot (fig_sim.png) is captured by scripts/capture_sim_figure.js.
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "paper" / "ieee" / "figs"
OUT.mkdir(parents=True, exist_ok=True)
plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
                     "font.size": 8, "axes.linewidth": 0.6})
R = json.loads((ROOT / "results" / "experiments.json").read_text(encoding="utf-8"))


def box(ax, x, y, w, h, text, fc="#ffffff", ec="#222222", fs=7.2, bold=False, ls="-"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06", fc=fc, ec=ec, lw=0.8, ls=ls))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, fontweight="bold" if bold else "normal", linespacing=1.25)


def arrow(ax, x1, y1, x2, y2):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=8, lw=0.9, color="#222222"))


fig, ax = plt.subplots(figsize=(7.1, 2.5))
ax.set_xlim(0, 14.2); ax.set_ylim(0, 5.1); ax.axis("off")
box(ax, 0.1, 1.9, 2.2, 1.4, "Survey taxonomy\n9 threat classes\n31 controls", "#eef2f7", fs=6.6, bold=True)
box(ax, 2.75, 1.9, 2.2, 1.4, "Collector\nXML, conf files,\nkernel, permissions", "#ffffff", fs=6.4)
mods = [("M1  Config auditor", 3.55), ("M2  Snapshot scanner", 2.65), ("M3  Memory forensics", 1.75), ("M4  Hypervisor detection", 0.85)]
ax.add_patch(FancyBboxPatch((5.4, 0.5), 3.5, 4.0, boxstyle="round,pad=0.02,rounding_size=0.06", fc="#f7f7f7", ec="#555555", lw=0.8, ls="--"))
ax.text(7.15, 4.2, "vsec modules", ha="center", fontsize=6.8, fontweight="bold")
for t_, y in mods:
    box(ax, 5.6, y - 0.35, 3.1, 0.7, t_, "#ffffff", fs=6.4)
box(ax, 9.35, 1.9, 2.2, 1.4, "Findings\nPASS / FAIL / NA\n+ fix command", "#e9f5ec", fs=6.4)
box(ax, 12.0, 2.95, 2.1, 1.55, "Attack-path\nmodel: 11 chains,\ncampaign, min. fix", "#fdf1e3", fs=6.2, bold=True)
box(ax, 12.0, 0.5, 2.1, 1.55, "Outputs\nreport, runbook,\nAttack Lab app", "#ffffff", fs=6.2)
arrow(ax, 2.3, 2.6, 2.75, 2.6); arrow(ax, 4.95, 2.6, 5.4, 2.6); arrow(ax, 8.9, 2.6, 9.35, 2.6)
arrow(ax, 11.55, 2.95, 12.0, 3.5); arrow(ax, 11.55, 2.25, 12.0, 1.6); arrow(ax, 13.05, 2.95, 13.05, 2.05)
ax.text(7.15, 0.12, "real data: audit of a real host, snapshot scan", fontsize=6.0, ha="center", color="#2d6a3e")
ax.text(13.05, 4.78, "model of the survey's logic", fontsize=6.0, ha="center", color="#a05a00")
fig.savefig(OUT / "fig_arch.png", dpi=300, bbox_inches="tight", pad_inches=0.03); plt.close(fig)

lev = R["E4"]["leverage"][:8]
fig, ax = plt.subplots(figsize=(3.45, 2.3))
ax.barh([f"{r['control']} ({r['level']})" for r in lev][::-1], [r["blocked_pairs"] for r in lev][::-1], color="#2b5c9e", height=0.65)
ax.set_xlabel("open (VM, attack) pairs blocked by the fix")
ax.tick_params(labelsize=7); ax.spines[["top", "right"]].set_visible(False)
fig.savefig(OUT / "fig_leverage.png", dpi=300, bbox_inches="tight", pad_inches=0.03); plt.close(fig)

fig, ax = plt.subplots(figsize=(3.45, 2.3))
ps = [float(p) for p in R["E5"]]
for key, label, col, mk in (("host_only", "host hardened, its VMs not", "#b23a3a", "o"), ("host_and_vms", "host and its VMs hardened", "#2d6a3e", "s")):
    y = [100 * R["E5"][p][key]["hardened_host_breached"] / R["E5"][p][key]["n"] for p in R["E5"]]
    lo = [100 * R["E5"][p][key]["ci"][0] for p in R["E5"]]; hi = [100 * R["E5"][p][key]["ci"][1] for p in R["E5"]]
    ax.plot(ps, y, marker=mk, ms=3.5, lw=1.1, color=col, label=label); ax.fill_between(ps, lo, hi, color=col, alpha=0.18, lw=0)
ax.set_xlabel("fault probability elsewhere in the fleet"); ax.set_ylabel("fleets with a breached VM on\nthe hardened host (%)")
ax.legend(fontsize=6.5, frameon=False, loc="upper left"); ax.tick_params(labelsize=7); ax.spines[["top", "right"]].set_visible(False)
fig.savefig(OUT / "fig_hardhost.png", dpi=300, bbox_inches="tight", pad_inches=0.03); plt.close(fig)
print("figures written to", OUT)
