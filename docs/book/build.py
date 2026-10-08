"""Build the SentinelEdge engineering book: Markdown chapters -> HTML -> PDF (WeasyPrint).

Usage: python docs/book/build.py [output.pdf]     (or `make book` from the repository root)

The default output is docs/book/SentinelEdge-Engineering-Blueprint.pdf, which is committed so the
current edition can be read on GitHub. Diagrams are Graphviz sources (diagrams/*.dot) with their
rendered SVGs committed; re-render one with `dot -Tsvg name.dot -o name.svg` after editing it.

Conventions in chapters/*.md (processed in filename order):
  - A file whose first line is `%% part: <title>` renders as a part divider page.
  - `# Title` starts a chapter (numbered automatically; files named 9x-* are appendices).
  - `{{figure:name|Caption|width%}}` embeds diagrams/name.svg as a numbered figure.
  - `{{flow:name|Caption}}` renders a step flow from FLOWS below as a numbered figure.
  - `:::note Title` ... `:::` renders a callout (also :::why, :::evidence, :::planned, :::lesson).
"""

from __future__ import annotations

import html
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import markdown
from weasyprint import HTML

ROOT = Path(__file__).parent
DEFAULT_OUTPUT = ROOT / "SentinelEdge-Engineering-Blueprint.pdf"
EDITION = {
    "number": 2,
    "version": "v0.4.0",
    "phases": "Phases 1, 2, 6 and 7",
    "date": "October 7, 2026",
}
MD_EXT = ["tables", "fenced_code", "attr_list", "md_in_html", "sane_lists", "smarty"]
SHORT_TABLE_ROWS = 9  # tables up to this many rows are kept on one page

# Step flows: (key, title, subtitle, style) where style is done | next | plan | aws.
FLOWS: dict[str, list[tuple[str, str, str, str]]] = {
    "order": [
        ("P1", "Architecture", "v0.1.0", "done"),
        ("P2", "App foundation", "v0.2.0", "done"),
        ("P6", "API security", "v0.3.0", "done"),
        ("P7", "Security ops", "v0.4.0", "done"),
        ("P8", "AppSec scanning", "next", "next"),
        ("P10", "Threat model & governance", "", "plan"),
        ("P9", "AI security", "Bedrock", "plan"),
        ("P3·4·5", "AWS window", "deploy · demo · destroy", "aws"),
        ("P11", "Pipeline", "", "plan"),
        ("P12", "Hardening", "", "plan"),
    ],
    "release": [
        ("1", "Approve phase", "", "plan"),
        ("2", "Branch", "phase/N-name", "plan"),
        ("3", "Milestones", "M0 … Mn commits", "plan"),
        ("4", "Bundle + zip", "sha256 checksum", "plan"),
        ("5", "Verify locally", "check · smoke · hardening", "plan"),
        ("6", "Push branch", "token per push", "plan"),
        ("7", "Pull request", "green CI", "plan"),
        ("8", "Merge to main", "", "plan"),
        ("9", "Signed tag", "vX.Y.0", "done"),
        ("10", "Release", "notes + walkthrough", "done"),
    ],
}

FIGURE = re.compile(r"\{\{(figure|flow):([\w-]+)\|(.+?)(?:\|(\d+))?\}\}")
CALLOUT = re.compile(r"^:::(\w+)[ \t]*(.*?)\n(.*?)^:::\s*$", re.S | re.M)


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", re.sub("<.*?>", "", text).lower()).strip("-")


def embed_svg(name: str) -> str:
    svg = (ROOT / "diagrams" / f"{name}.svg").read_text()
    svg = svg[svg.index("<svg") :]
    return re.sub(r'width="[^"]+pt" height="[^"]+pt"', 'width="100%"', svg, count=1)


def render_flow(name: str, caption_html: str) -> str:
    steps = FLOWS[name]
    rows = []
    for start in range(0, len(steps), 5):
        cells = "".join(
            f'<td class="step {style}"><div class="k">{html.escape(key)}</div>'
            f'<div class="t">{html.escape(title)}</div><div class="s">{html.escape(sub)}</div></td>'
            for key, title, sub, style in steps[start : start + 5]
        )
        rows.append(f"<tr>{cells}</tr>")
    table = f'<table class="flow">{"".join(rows)}</table>'
    return f"\n<figure>{table}<figcaption>{caption_html}</figcaption></figure>\n"


def render_callouts(src: str) -> str:
    def repl(m: re.Match[str]) -> str:
        kind, title, body = m.group(1), m.group(2).strip(), m.group(3)
        inner = markdown.markdown(body, extensions=MD_EXT)
        head = f'<div class="callout-title">{html.escape(title)}</div>' if title else ""
        return f'\n<div class="callout {kind}">{head}{inner}</div>\n'

    return CALLOUT.sub(repl, src)


def keep_short_tables(body: str) -> str:
    def repl(m: re.Match[str]) -> str:
        if m.group(1).count("<tr>") <= SHORT_TABLE_ROWS:
            return f'<table class="keep">{m.group(1)}</table>'
        return m.group(0)

    return re.sub(r"<table>(.*?)</table>", repl, body, flags=re.S)


@dataclass
class Book:
    sections: list[str] = field(default_factory=list)
    toc: list[tuple[int, str, str, str]] = field(default_factory=list)  # level, no., title, id
    figures: int = 0
    chapters: int = 0

    def figure(self, m: re.Match[str]) -> str:
        self.figures += 1
        kind, name, caption, width = m.group(1), m.group(2), m.group(3), m.group(4) or "100"
        label = f"<b>Figure {self.figures}.</b> {html.escape(caption)}"
        if kind == "flow":
            return render_flow(name, label)
        svg = embed_svg(name)
        return (
            f'\n<figure><div class="svg" style="width:{width}%">{svg}</div>'
            f"<figcaption>{label}</figcaption></figure>\n"
        )

    def add_part(self, src: str) -> None:
        first, _, rest = src.partition("\n")
        title = first.split(":", 1)[1].strip()
        pid = "part-" + slug(title)
        self.toc.append((0, "", title, pid))
        body = markdown.markdown(rest, extensions=MD_EXT)
        self.sections.append(
            f'<section class="part" id="{pid}">'
            f'<h1 class="part-title">{html.escape(title)}</h1>{body}</section>'
        )

    def add_chapter(self, path: Path) -> None:
        src = FIGURE.sub(self.figure, render_callouts(path.read_text()))
        body = keep_short_tables(markdown.markdown(src, extensions=MD_EXT))
        h1 = re.search(r"<h1>(.*?)</h1>", body)
        if h1 is None:
            raise ValueError(f"{path.name} has no '# Title' heading")
        title = h1.group(1)
        appendix = path.stem.startswith("9")
        if appendix:
            label = path.stem.split("-")[0][-1].upper()
            number = f"Appendix {label}"
        else:
            self.chapters += 1
            label = str(self.chapters)
            number = f"Chapter {label}"
        cid = slug(title)
        self.toc.append((1, number, title, cid))
        heading = (
            f'<h1 class="chapter" id="{cid}"><span class="chapter-no">{number}</span>'
            f'<span class="chapter-title">{title}</span></h1>'
        )
        body = body.replace(h1.group(0), heading, 1)
        body = self.number_sections(body, cid, label)
        cls = "appendix" if appendix else "chapter-body"
        self.sections.append(f'<section class="{cls}">{body}</section>')

    def number_sections(self, body: str, cid: str, label: str) -> str:
        counter = 0

        def h2(m: re.Match[str]) -> str:
            nonlocal counter
            counter += 1
            text = m.group(1)
            sid = f"{cid}-{slug(text)}"
            self.toc.append((2, f"{label}.{counter}", text, sid))
            return f'<h2 id="{sid}"><span class="sec-no">{label}.{counter}</span>{text}</h2>'

        return re.sub(r"<h2>(.*?)</h2>", h2, body)

    def contents(self) -> str:
        items = []
        for level, number, title, tid in self.toc:
            if level == 0:
                items.append(f'<li class="toc-part"><a href="#{tid}">{title}</a></li>')
                continue
            cls = "toc-ch" if level == 1 else "toc-sec"
            link = f'<a href="#{tid}"><span class="n">{number}</span>{title}</a>'
            items.append(f'<li class="{cls}">{link}</li>')
        heading = '<h1 class="toc-title">Contents</h1>'
        return f'<section class="toc">{heading}<ul>{"".join(items)}</ul></section>'


def build() -> str:
    book = Book()
    for path in sorted((ROOT / "chapters").glob("*.md")):
        src = path.read_text()
        if src.startswith("%% part:"):
            book.add_part(src)
        else:
            book.add_chapter(path)

    front = (ROOT / "front.html").read_text().format(**EDITION)
    edition = f"Edition {EDITION['number']} · {EDITION['version']}"
    css = (ROOT / "book.css").read_text().replace("__EDITION__", edition)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        "<title>SentinelEdge: Engineering Blueprint</title>"
        '<meta name="author" content="Bionic-Hacker">'
        '<meta name="description" content="Design, build plan and reproduction guide">'
        f"<style>{css}</style></head><body>"
        f"{front}{book.contents()}{''.join(book.sections)}</body></html>"
    )


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUTPUT
    doc = build()
    (ROOT / "build").mkdir(exist_ok=True)
    (ROOT / "build" / "book.html").write_text(doc)  # for debugging layout; git-ignored
    HTML(string=doc, base_url=str(ROOT)).write_pdf(out)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
