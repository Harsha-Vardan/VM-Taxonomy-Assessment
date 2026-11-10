# Roadmap to the Final Grade and the Paper (from 2026-11-06)

Read with `CLAUDE.md`. Detailed hardware steps are in `docs/YOUR_TASKS.md` (Tasks A–J). Evidence boxes are in
`docs/DEFINITION_OF_DONE.md`.

## Where things stand (2026-11-06)

- **Code: about 95% done.** M1–M4, the report and the CLI exist, with about 1000 tests (all synthetic or simulated).
- **Real data: 0%.** No run on E1, no real dump, no Volatility run, no Lynis/OpenSCAP run. `prereg.md` is not tagged.
- **Paper: about 50%.** `docs/paper/paper.md` has 10 chapters, but Results and the Abstract are placeholders. Authorship says "solo", which conflicts with the 3-person case study. Several `[CITE]` and `[VERIFY]` markers are still open.
- **Taxonomy traceability: fixed 2026-11-06.** Every control in `vsec/taxonomy.yaml` now cites a survey section and a case-study table. The slides (`docs/slides/build_deck.py` line ~177) still say "not mapped to the survey's sections" and must be updated.

**The grade bottleneck is real data plus the paper, not code.** Every week spent on more code instead of E1 data lowers the grade.

---

## A. Ideal / best-practice solution (what a reviewer would want)

1. **Pre-registered M4** on native E1: `prereg.md` tagged before the first session, 45 interleaved sessions, H1–H4 with Holm correction, and an indicator-leak table.
2. **Independent M1 evidence:**
   - Lynis and OpenSCAP on live `weak` and `hardened` hosts
   - about 10 real-world configs (Ubuntu default, Proxmox, OpenStack XML)
   - per-control P/R/F1 with Wilson CIs
3. **Real M2:** 12 cells × 10 dumps, held-out variants, `ssh-agent` and `openssl` cells, redaction plus restore test.
4. **Real M3:** public Linux images with documented hidden processes, Clopper-Pearson CIs, clean dumps under process churn.
5. **Full T9 coverage:** add controls C32–C38 from `docs/SOURCES_SUMMARY.md` §3 (ACS, DMAR, Secure Boot, SEV/TDX, CAT, kernel-integrity N/A). Each needs fixtures and tests. Then report a **survey coverage ratio**: tested / config-proxy / N/A / not covered, for each survey section.
6. **Reproducibility:**
   - CI on Linux (GitHub Actions, pytest including the POSIX and bash tests)
   - a tagged release
   - a Zenodo DOI for the artefact
   - `requirements.lock`
7. **Paper in two forms:**
   - the full 10-chapter course report
   - a condensed 8–10 page **IEEE conference** version (IEEEtran LaTeX) with real tables, figures (architecture, result matrix, F1-vs-time curve, indicator-leak) and verified references, including post-2020 work (SEV-SNP, TDX, Firecracker micro-VMs, recent VM-detection papers). Every reference must be verified, with no invented citations.
8. **Threat model document** (`docs/THREAT_MODEL.md`): assets, adversaries and TCB for each environment. This is case-study T9 "Governance".
9. **Dashboard:** only after real data exists. It renders `out/report.json`. The existing `demo_dashboard.html` must be labelled clearly as a demo with simulated data.

## B. Minimum viable implementation (what is needed for a strong grade)

Keep, never cut: the tagged `prereg.md`, real M4 data (at least 10 sessions per class, labelled EXPLORATORY if fewer than 15), M1 self-consistency results, and the result matrix.

1. Build E1, run the pilot, tag `prereg.md` (Tasks B, C, D).
2. Run M4 with ≥10 (target 15) sessions per class.
3. Run Lynis and OpenSCAP on `weak` and `hardened` (Task I). This is the cheapest independent evidence.
4. Run M3 on **one** public image (Task H).
5. Do M2 at n=5 per cell (60 dumps) instead of 10.
6. Fix the paper:
   - authorship
   - Results filled from `scripts/make_paper_tables.py`
   - Abstract
   - references verified
   - survey mapping table added as a new table in Chapter 4
7. Update the slides and record the demo video.

Cut if behind: C32–C38, IEEE short version, dashboard, M2 redaction, M3 rootkit test, perf counters, SHAP.

## C. Realistic delivery timeline for this team

**Team** (all partially allocated to other ongoing work; assume about 40% each, roughly 2 days per week):

| Role | Owns | Absorbs (missing specialist) |
|---|---|---|
| **Backend & Cloud Engineer** | E1 build, KVM/libvirt VMs, M4 collection, M2/M3 real runs, Volatility, symbols | DevOps, SRE and lab ops: BitLocker, boot chain, package freeze, data backups |
| **Full-Stack Engineer** | Analysis runs (`vsec pilot`, `vsec run`), stats sanity checks, Lynis/OpenSCAP comparison, C32–C38 if time, CI | QA, data engineering, the first statistics review |
| **Frontend Engineer & Graphic Designer** | Paper figures, slides, demo video, dashboard (late), IEEE formatting | Technical writing, PM (weekly tracker) |

**Not covered by anyone:** an independent statistician and a security reviewer. The mitigation is to ask the instructor (Malay Kumar) to review `prereg.md` **before** it is tagged.

**Calendar estimate** (rough, from 2026-11-09). Hardware work is serial and cannot be parallelised much: interleaving needs sessions spread over days.

| Week | Backend & Cloud | Full-Stack | Frontend & Design | Gate |
|---|---|---|---|---|
| 1 | E1 build (Task B), bench compile (A), pilot 10 boots (C) | CI on Linux, Linux test run, start Lynis/OpenSCAP setup | Fix paper authorship and Ch. 4 mapping table, update slides | E1 frozen, pilot done |
| 2 | Fill PILOT, **tag prereg** (D), M4 batch 1 (F) | `vsec pilot` analysis, T_short sanity check, Lynis/OpenSCAP on weak/hardened (I) | Architecture and taxonomy figures | prereg tagged |
| 3 | M4 batch 2, M3 symbols (G) | M1 real-world configs, M1 tables | Literature review with post-2020 work, reference verification | ≥10 sessions per class |
| 4 | M4 batch 3, M2 dumps n=5 (E) | M3 public image (H), M2 scoring | Results chapter skeleton from `make_paper_tables.py` | 45 sessions, or EXPLORATORY |
| 5 | Re-run failed sessions, backups | `vsec run` end to end, H1–H4, balance check | Figures from real data, discussion | Full report renders |
| 6 | Buffer / M2 to n=10 | Review of stats and claims | Final paper, slides, demo video | **Submission** |

- **Realistic:** 6 weeks at partial allocation.
- **MVP:** about 4 weeks if E1 builds the first time.
- **Ideal (A1–A9):** about 9–10 weeks.

Main schedule risks:
- E1 boot or BitLocker trouble (+1 week)
- the clocksource confound
- noisy timing that forces longer windows
- no suitable public Linux forensic image (M3 falls back to the rootkit test, +1 week)
