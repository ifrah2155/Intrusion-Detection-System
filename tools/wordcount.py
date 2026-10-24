"""Count the prose words in the technical report, excluding non-prose blocks.

Excluded: fenced code blocks, tables, headings, horizontal rules and blank lines.
That is the honest "words of written argument" figure, and the one quoted on the
report cover and in the submission summary.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

FENCE = "`" * 3


def count(path: Path) -> tuple[int, int, int]:
    lines = path.read_text(encoding="utf-8").splitlines()
    in_code = False
    prose: list[str] = []
    tables = 0
    headings = 0

    for line in lines:
        stripped = line.strip()
        if stripped.startswith(FENCE):
            in_code = not in_code
            continue
        if in_code:
            continue
        if stripped.startswith("|"):
            tables += 1
            continue
        if re.match(r"^#{1,6}\s", stripped):
            headings += 1
            continue
        if stripped in ("", "---"):
            continue
        prose.append(stripped)

    body = " ".join(prose)
    words = re.findall(r"[A-Za-z0-9][A-Za-z0-9'\u2019\-.]*", body)
    return len(words), tables, headings


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else Path("docs/REPORT.md")
    words, tables, headings = count(path)
    print(f"{path}")
    print(f"  prose words : {words}")
    print(f"  table rows  : {tables}")
    print(f"  headings    : {headings}")
    print(f"  in range    : {'yes' if 1500 <= words <= 2000 else 'NO'} (target 1500-2000)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
