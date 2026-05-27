#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["markdown>=3.6"]
# ///
"""
Convert a release-notes Markdown file into the HTML fragment that Sparkle
embeds inside an appcast item's <description><![CDATA[...]]></description>.

Run via `uv run convert-md-to-html.py path/to/notes.md` - or executable
directly via the shebang since it uses uv's `--script` mode (auto-creates
an isolated venv with the markdown library on first run).

uv is the only build dependency the release pipeline adds; install with:
  curl -LsSf https://astral.sh/uv/install.sh | sh
"""
from __future__ import annotations

import sys
from pathlib import Path

import markdown


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} path/to/notes.md", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.is_file():
        print(f"{path}: not a file", file=sys.stderr)
        return 1

    md_text = path.read_text(encoding="utf-8")
    html = markdown.markdown(
        md_text,
        extensions=["fenced_code", "tables", "sane_lists"],
        output_format="html5",
    )
    # Sparkle only renders the HTML inside the CDATA verbatim; trim trailing
    # whitespace so the appcast diff stays tidy.
    print(html.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
