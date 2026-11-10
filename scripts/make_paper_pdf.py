import pathlib, subprocess, sys
import markdown

"""Build docs/paper/vsec_research_paper.pdf from docs/paper/paper.md (pandoc is not needed).

    python scripts/make_paper_pdf.py

Needs: pip install markdown, and Node.js with Playwright + Chromium (scripts/html_to_pdf.js looks for `playwright`,
then for ../QA/node_modules/playwright). Page count and figures are checked by eye after a build.
"""
import tempfile

root = pathlib.Path(__file__).resolve().parent.parent
scratch = pathlib.Path(tempfile.mkdtemp())
paper = root / "docs" / "paper"
md = (paper / "paper.md").read_text(encoding="utf-8")
body = markdown.markdown(md, extensions=["tables", "fenced_code", "sane_lists", "toc", "attr_list"],
                         extension_configs={"toc": {"toc_depth": "2-3"}})
CSS = """
@page { size: A4; }
html { font-size: 10.5pt; }
body { font-family: "Cambria", "Georgia", "Times New Roman", serif; color: #111; line-height: 1.45; max-width: 100%; margin: 0; text-align: justify; hyphens: auto; }
h1 { font-size: 20pt; line-height: 1.2; text-align: center; margin: 0 0 10pt; }
h2 { font-size: 14pt; margin: 22pt 0 6pt; border-bottom: 1px solid #999; padding-bottom: 2pt; page-break-after: avoid; }
h3 { font-size: 12pt; margin: 14pt 0 4pt; page-break-after: avoid; }
h4 { font-size: 10.5pt; margin: 10pt 0 3pt; font-style: italic; page-break-after: avoid; }
p, li { orphans: 3; widows: 3; }
table { border-collapse: collapse; width: 100%; margin: 8pt 0 10pt; font-size: 8.8pt; font-family: "Calibri", "Segoe UI", sans-serif; text-align: left; page-break-inside: auto; }
tr { page-break-inside: avoid; }
th, td { border: 1px solid #888; padding: 2.5pt 5pt; vertical-align: top; }
th { background: #e9edf2; }
code { font-family: "Consolas", "Courier New", monospace; font-size: 8.8pt; background: #f1f1f1; padding: 0 2pt; word-break: break-word; }
pre { background: #f5f5f5; border: 1px solid #ccc; padding: 6pt; overflow-wrap: anywhere; white-space: pre-wrap; font-size: 8.5pt; page-break-inside: avoid; }
pre code { background: none; }
img { max-width: 100%; height: auto; display: block; margin: 8pt auto 2pt; page-break-inside: avoid; }
p:has(> img) + p, p:has(> img) { text-align: center; }
a { color: #0b4a8f; text-decoration: none; word-break: break-word; }
hr { border: 0; border-top: 1px solid #bbb; margin: 14pt 0; }
blockquote { border-left: 3px solid #999; margin: 8pt 0; padding: 0 10pt; color: #333; }
em { font-style: italic; }
"""
html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><base href="{(paper).as_uri()}/"><title>A Taxonomy-Driven Security Assessment Framework for KVM Virtualization</title><style>{CSS}</style></head><body>{body}</body></html>'
out_html = scratch / "paper.html"
out_html.write_text(html, encoding="utf-8")
print("html", len(html) // 1024, "KB ->", out_html)

subprocess.run(["node", str(root / "scripts" / "html_to_pdf.js"), str(out_html), str(paper / "vsec_research_paper.pdf")], check=True)
print("wrote", paper / "vsec_research_paper.pdf")
