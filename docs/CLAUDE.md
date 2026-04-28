# Documentation — MkDocs Site

Public docs at <https://boogy.github.io/iam-policy-validator/>. Extends the root
[CLAUDE.md](../CLAUDE.md).

---

## Build & serve

```bash
uv run --extra docs mkdocs build --strict       # strict catches broken links
uv run --extra docs mkdocs serve -w docs/       # auto-reload on http://localhost:8000
```

CI: `.github/workflows/docs.yml` rebuilds on pushes to `main` that touch `docs/`,
`mkdocs.yml`, or `iam_validator/`.

---

## Layout (top-level)

```
docs/
├── index.md                  # landing page
├── changelog.md              # mirrors CHANGELOG.md
├── getting-started/          # install + quickstart + first validation
├── user-guide/               # CLI ref, configuration, output formats, troubleshooting, checks/
├── integrations/             # github-actions, gitlab-ci, pre-commit, mcp-server
├── developer-guide/          # architecture, sdk/, custom-checks/
├── api-reference/            # mkdocstrings-generated from docstrings
├── contributing/             # dev setup, testing, releasing
├── includes/abbreviations.md # auto-expanded snippets
└── stylesheets/extra.css
```

Navigation lives in `mkdocs.yml` under `nav:`. Adding a page: create the `.md`,
add it to `nav:`, link from related pages.

---

## Conventions

- **Theme**: Material for MkDocs (light/dark toggle).
- **Plugins**: search, mkdocstrings (Python, Google-style docstrings).
- **Extensions**: admonitions, code blocks with copy/title, tabbed content, Mermaid, task lists.
- **Material grid cards**: 4-space indentation, `---` separators (NOT `***`, NOT 2-space). Affects
  `index.md`, `getting-started/index.md`, `user-guide/index.md`, `user-guide/checks/index.md`,
  `integrations/index.md`, `developer-guide/index.md`.

### Snippet patterns

- **Admonitions**: `!!! note "Title"` / `!!! warning` / `!!! tip "Pro Tip"` / `!!! danger`
  followed by 4-space-indented content.
- **Tabs**: `=== "uv"` / `=== "pip"` blocks, body indented 4 spaces — code fences inside
  must also be indented to belong to the tab.
- **Cross-reference a page**: `[Configuration](user-guide/configuration.md)`.
- **Cross-reference a Python symbol** (mkdocstrings): ``[`validate_file`][iam_validator.sdk.shortcuts.validate_file]``.

---

## When updating

User-facing changes require touching `docs/` + `mkdocs.yml` + `README.md` +
`CHANGELOG.md` in the same commit (see root `CLAUDE.md` rules). The docs build
must pass `--strict` before merging.
