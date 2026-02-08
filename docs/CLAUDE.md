# Documentation - MkDocs Site

**Purpose**: Public documentation site built with MkDocs Material
**Parent Context**: Extends [../CLAUDE.md](../CLAUDE.md)
**Live site**: https://boogy.github.io/iam-policy-validator/

---

## Quick Start

```bash
# Build docs
uv run --extra docs mkdocs build --strict

# Serve locally (auto-reload)
uv run --extra docs mkdocs serve -w docs/

# Open at http://localhost:8000
```

---

## Structure

```
docs/
├── index.md                           # Landing page
├── changelog.md                       # Release changelog
├── getting-started/                   # Installation + quickstart
│   ├── index.md
│   ├── installation.md
│   ├── quickstart.md
│   └── first-validation.md
├── user-guide/                        # End-user documentation
│   ├── index.md
│   ├── cli-reference.md              # CLI command reference
│   ├── configuration.md              # YAML config reference
│   ├── output-formats.md             # 7 formatter descriptions
│   ├── troubleshooting.md
│   └── checks/                       # Check documentation
│       ├── index.md                  # Check overview
│       ├── aws-validation.md         # AWS correctness checks
│       ├── security-checks.md        # Security checks
│       └── advanced-checks.md        # Advanced checks
├── integrations/                      # Integration guides
│   ├── index.md
│   ├── github-actions.md
│   ├── gitlab-ci.md
│   ├── pre-commit.md
│   └── mcp-server.md
├── developer-guide/                   # Developer documentation
│   ├── index.md
│   ├── architecture.md               # System architecture
│   ├── sdk/                          # SDK reference
│   │   ├── index.md
│   │   ├── quickstart.md
│   │   ├── validation.md
│   │   ├── policy-utilities.md
│   │   └── advanced.md
│   └── custom-checks/                # Custom check guide
│       ├── index.md
│       ├── tutorial.md
│       ├── examples.md
│       └── best-practices.md
├── api-reference/                     # Auto-generated API docs
│   ├── index.md
│   ├── sdk.md
│   ├── models.md
│   ├── checks.md
│   └── exceptions.md
├── contributing/                      # Contribution guide
│   ├── index.md
│   ├── development-setup.md
│   ├── testing.md
│   └── releasing.md
├── includes/
│   └── abbreviations.md              # Snippet abbreviations
└── stylesheets/
    └── extra.css                      # Custom CSS
```

---

## Configuration (`mkdocs.yml`)

- **Theme**: Material for MkDocs with light/dark toggle
- **Plugins**: search, mkdocstrings (Python, Google-style docstrings)
- **Key Extensions**: admonitions, code blocks with copy, tabbed content, Mermaid diagrams, task lists
- **Auto-API**: mkdocstrings generates API reference from docstrings

---

## Writing Conventions

### Admonitions

```markdown
!!! note "Title"
Content here.

!!! warning
Important warning.

!!! tip "Pro Tip"
Helpful hint.

!!! danger "Breaking Change"
This change is not backward compatible.
```

### Code Blocks

````markdown
```python title="example.py"
from iam_validator.sdk import validate_file

result = await validate_file("policy.json")
```

```bash title="Terminal"
iam-validator validate --path policy.json
```
````

### Tabs

```markdown
=== "pip"
`bash
    pip install iam-policy-validator
    `

=== "uv"
`bash
    uv add iam-policy-validator
    `
```

### Cross-References

```markdown
See [Configuration](user-guide/configuration.md) for details.
See the [`validate_file`][iam_validator.sdk.shortcuts.validate_file] function.
```

---

## Navigation

Navigation is defined in `mkdocs.yml` under the `nav:` key. When adding a new page:

1. Create the `.md` file in the appropriate directory
2. Add the page to `nav:` in `mkdocs.yml`
3. Link from related pages

### Abbreviations

Common abbreviations are defined in `includes/abbreviations.md` and auto-expanded via the snippets extension.

---

## Building & Deploying

```bash
# Build with strict mode (catches broken links)
uv run --extra docs mkdocs build --strict

# Deploy to GitHub Pages (only from main branch)
# Handled automatically by .github/workflows/docs.yml
```

**CI trigger**: Docs rebuild on push to `docs/`, `mkdocs.yml`, or `iam_validator/` source changes.

---

## Quick Search

```bash
# Find a docs page by topic
rg -n "title:|#" docs/ --glob "*.md"

# Find navigation entry
rg -n "index.md|\.md" mkdocs.yml

# Find admonition usage
rg -n "^!!!" docs/

# Find broken internal links
rg -n "\]\(" docs/ --glob "*.md" | rg -v "http"
```
