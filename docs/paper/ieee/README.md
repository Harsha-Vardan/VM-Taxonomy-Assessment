# IEEE-format paper

| File | What it is |
|---|---|
| `vsec_ieee_paper.pdf` | The paper in IEEE conference format (two columns, `IEEEtran`). Submit or present this one. |
| `paper_ieee.tex` | LaTeX source (`\documentclass[conference]{IEEEtran}`) |
| `figs/` | Figures used by the paper |
| `../paper.md`, `../vsec_research_paper.pdf` | The long version (about 39 pages, section-by-section detail and the full pre-specified analysis plan) |

## Rebuild the PDF

**Option 1: Overleaf (easiest).** Create a blank project, upload `paper_ieee.tex` and the `figs/` folder, set the compiler to pdfLaTeX, and press Recompile. Overleaf already has the `IEEEtran` class.

**Option 2: Ubuntu in WSL.**

```
sudo apt install texlive-latex-recommended texlive-publishers texlive-fonts-recommended texlive-latex-extra
cd docs/paper/ieee
pdflatex paper_ieee.tex && pdflatex paper_ieee.tex   # twice, so cross-references resolve
```

## Regenerate figures

```
python scripts/make_ieee_figures.py        # architecture, leverage, hardened-host figures (needs results/experiments.json)
node scripts/capture_sim_figure.js         # Attack Lab screenshot (needs Playwright)
```

## Keep the numbers honest

Every number in the paper comes from `results/experiments.json` (reproduce with `python scripts/run_experiments.py`) or from `results/real/` (real KVM host, scripts `scripts/real_*.py`). `tests/test_experiments.py` fails if the paper's key numbers no longer match those files.

## Before you submit

- Add your institution's name under the author names in `paper_ieee.tex` (the repository does not name it, so we did not invent one).
- Check the reference URLs and bibliographic details once; they were written from the sources' public pages and from memory.
- If your instructor requires a page limit (IEEE conferences commonly use 6 to 8 pages plus references), tell us and we will trim it.
