# SentinelEdge — Engineering Blueprint (the book)

A running, chaptered technical book about this project: the build plan, the architecture and
security design, each completed phase as built, the remaining phases as designed, and the
commands that reproduce the build. A new edition is produced with every phase release.

- **Read it:** [SentinelEdge-Engineering-Blueprint.pdf](SentinelEdge-Engineering-Blueprint.pdf)
- **Rebuild it:** `make book` from the repository root (needs the Pango library, present on most
  Linux desktops; on Arch/Garuda: `sudo pacman -S --needed pango`).

## Layout

| Path | Contents |
|---|---|
| `chapters/NN-*.md` | Chapters in filename order. `%% part:` files are part dividers; `9x-*.md` are appendices |
| `front.html` | Cover, "at a glance" page and edition notes |
| `book.css` | Page layout and typography (WeasyPrint, US Letter) |
| `diagrams/*.dot`, `*.svg` | Graphviz sources and their rendered figures |
| `build.py` | Markdown → HTML → PDF, numbering chapters, sections and figures, building the contents |
| `requirements.txt` | Hash-pinned build dependencies (`requirements.in` is the source) |

Markup beyond standard Markdown: `{{figure:name|Caption|width%}}` embeds a diagram,
`{{flow:name|Caption}}` renders a step flow defined in `build.py`, and `:::note|why|evidence|planned|lesson Title`
… `:::` makes a callout.

## Updating for a new edition

1. Bump `EDITION` in `build.py` and the at-a-glance figures in `front.html`.
2. Move the completed phase's chapter from Part III (`2x-*.md`) to Part II (`1x-*.md`) and rewrite
   it as built; update status tables, appendices, lessons learned and the edition history.
3. `make book`, check the pages, commit the PDF with the release.
