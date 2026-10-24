#!/usr/bin/env python3
"""Build ``docs/REPORT.pdf`` from ``docs/REPORT.md``.

Markdown -> LaTeX (pandoc) -> PDF (xelatex), with a purpose-built cover page,
a table of contents and running headers/footers. xelatex is run three times so
the contents list and cross-references settle.

Requirements (already present on this machine):
    pandoc   - installed as a Python wheel (``pip install pypandoc-binary``)
    xelatex  - MiKTeX

Usage:
    python tools/build_report_pdf.py
    python tools/build_report_pdf.py --keep        # keep the .tex/.log for debugging
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "REPORT.md"
OUT = ROOT / "docs" / "REPORT.pdf"
HEADER = ROOT / "tools" / "pdf" / "header.tex"
BUILD = ROOT / "build" / "report"

# ---------------------------------------------------------------------------
# Cover page. Emitted as a raw-LaTeX block so pandoc passes it through verbatim.
# ---------------------------------------------------------------------------
COVER = r"""
```{=latex}
\begin{titlepage}
\thispagestyle{empty}
\centering

\vspace*{1.6cm}
{\color{accentrule}\rule{\linewidth}{1.6pt}}\\[0.55cm]
{\sffamily\Huge\bfseries\color{accent}
AI-Driven Network Traffic\\[0.28cm]
Analysis and Intrusion\\[0.28cm]
Detection System\par}
\vspace{0.45cm}
{\color{accentrule}\rule{\linewidth}{1.6pt}}

\vspace{1.7cm}
{\sffamily\LARGE\color{muted} Technical Report\par}

\vspace{1.5cm}
{\sffamily\large Practical Technical Assessment\par}
\vspace{0.25cm}
{\sffamily\large Cybersecurity \& Network Security Research Intern\par}

\vspace{1.6cm}
{\sffamily\Large\bfseries\color{accent} MegaMinds IT Services\par}

\vfill

{\sffamily\small
\begin{tabular}{@{}r@{\hspace{1.1cm}}l@{}}
\textcolor{muted}{Prepared by}    & Ifrah Hasware \\[0.22cm]
\textcolor{muted}{Repository}     & \texttt{megaminds-ids} \\[0.22cm]
\textcolor{muted}{Report length}  & 1{,}898 words (excluding tables) \\[0.22cm]
\textcolor{muted}{Date}           & 24 October 2026 \\
\end{tabular}\par}

\vspace{0.9cm}
\end{titlepage}

\pagenumbering{roman}
\tableofcontents
\clearpage
\pagenumbering{arabic}
```
"""


# ---------------------------------------------------------------------------
def find_tool(name: str) -> str:
    path = shutil.which(name)
    if path:
        return path
    raise SystemExit(f"error: '{name}' not found on PATH")


def find_pandoc() -> str:
    """pandoc is installed as a Python wheel here, so PATH is not reliable."""
    try:
        import pypandoc  # type: ignore

        return pypandoc.get_pandoc_path()
    except Exception:
        pass
    return find_tool("pandoc")


def strip_cover(markdown: str) -> str:
    """Drop the title block from REPORT.md; the PDF has a real cover page."""
    match = re.search(r"^---\s*$", markdown, flags=re.MULTILINE)
    if not match:
        return markdown
    return markdown[match.end():].lstrip("\n")


def run(cmd: list[str], cwd: Path, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=str(cwd), env=env, capture_output=True, text=True, errors="replace"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--keep", action="store_true",
                        help="keep the intermediate .tex/.log/.aux files")
    args = parser.parse_args(argv)

    if not SRC.exists():
        raise SystemExit(f"error: missing {SRC}")
    if not HEADER.exists():
        raise SystemExit(f"error: missing {HEADER}")

    pandoc = find_pandoc()
    xelatex = find_tool("xelatex")

    BUILD.mkdir(parents=True, exist_ok=True)
    body = strip_cover(SRC.read_text(encoding="utf-8"))
    tmp_md = BUILD / "REPORT.md"
    tmp_md.write_text(COVER + "\n" + body, encoding="utf-8")

    tex = BUILD / "REPORT.tex"
    print(f"  pandoc  : {pandoc}")
    print(f"  xelatex : {xelatex}")
    print("  markdown -> latex ...", end=" ", flush=True)

    result = run([
        pandoc, str(tmp_md),
        "--output", str(tex),
        "--standalone",
        "--from", "markdown+pipe_tables+raw_tex+smart",
        "--to", "latex",
        "--include-in-header", str(HEADER),
        "--highlight-style", "tango",
        "--columns", "110",
        "--metadata", "lang=en-GB",
        "--resource-path", str(ROOT),
        "-V", "documentclass=article",
        "-V", "fontsize=11pt",
        "-V", "geometry:a4paper,margin=2.5cm,headheight=15pt,headsep=14pt",
    ], cwd=BUILD)

    if result.returncode != 0:
        print("FAILED")
        print(result.stdout[-3000:])
        print(result.stderr[-3000:])
        return 1
    print("ok")

    env = os.environ.copy()
    env["MIKTEX_AUTOINSTALL"] = "yes"   # never block waiting for a prompt
    env["max_print_line"] = "1000"

    for pass_no in (1, 2, 3):
        print(f"  xelatex : pass {pass_no}/3 ...", end=" ", flush=True)
        result = run([
            xelatex,
            "-interaction=nonstopmode",
            "-file-line-error",
            "REPORT.tex",
        ], cwd=BUILD, env=env)

        if result.returncode != 0:
            print("FAILED")
            log = BUILD / "REPORT.log"
            if log.exists():
                text = log.read_text(encoding="utf-8", errors="replace")
                errors = [ln for ln in text.splitlines() if ln.startswith("!")]
                print("\n".join(errors[:20]) or text[-2500:])
            return 1
        print("ok")

    pdf = BUILD / "REPORT.pdf"
    if not pdf.exists():
        raise SystemExit("error: xelatex produced no PDF")

    log_text = (BUILD / "REPORT.log").read_text(encoding="utf-8", errors="replace")
    missing = sorted({m for m in re.findall(r"Missing character: There is no (.+?) in font", log_text)})
    if missing:
        print(f"\n  warning: {len(missing)} glyph(s) missing from the chosen fonts:")
        for glyph in missing[:15]:
            print(f"    {glyph}")
    else:
        print("  glyphs  : all characters rendered")

    pages = re.search(r"Output written on REPORT\.pdf \((\d+) pages?", log_text)
    if pages:
        print(f"  pages   : {pages.group(1)}")

    overfull = log_text.count("Overfull \\hbox")
    if overfull:
        print(f"  note    : {overfull} overfull hbox warning(s) (cosmetic only)")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(pdf, OUT)

    if not args.keep:
        for pattern in ("*.aux", "*.log", "*.out", "*.toc", "*.tex", "*.md"):
            for path in BUILD.glob(pattern):
                path.unlink(missing_ok=True)

    size_kb = OUT.stat().st_size / 1024
    print(f"\n  written : {OUT}  ({size_kb:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
