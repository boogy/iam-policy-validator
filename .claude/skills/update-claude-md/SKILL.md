---
name: update-claude-md
description: Analyse codebase and generate a hierarchical CLAUDE.md system optimized for Claude Code. Use when the user wants to update, regenerate, or create CLAUDE.md files, set up project documentation for Claude Code, or optimize the CLAUDE.md hierarchy. Triggers on "/update-claude-md", "update CLAUDE.md", "regenerate CLAUDE.md", or "set up Claude Code docs".
---

# Update CLAUDE.md

Analyze the codebase and generate a hierarchical CLAUDE.md system optimized for Claude Code.

## Key Principles

- CLAUDE.md is **authoritative** — treated as system rules, not suggestions
- Use **modular sections** with clear markdown headers
- **Front-load critical context** — large CLAUDE.md files improve instruction adherence
- **Hierarchical strategy**: Root = universal rules; Subdirs = specific context
- Keep root CLAUDE.md under 400 lines

## Workflow

### Phase 1: Repository Analysis

Analyze and present:

1. **Architecture** — monorepo/standard, tech stack, testing, CI/CD
2. **Claude Code opportunities** — hooks, MCP servers, commands, subagents
3. **Directory map** — where CLAUDE.md files should exist
4. **Dangerous patterns** — commands to block, files to protect
5. **Tool permissions** — defaults vs explicit permission required

Present analysis as a structured map before generating files.

### Phase 2: Generate Root CLAUDE.md

Include these sections (see [references/claude-md-guide.md](references/claude-md-guide.md) for detailed templates):

1. **Project Identity** (5-10 lines) — type, stack, architecture
2. **Universal Rules** (10-20 lines) — MUST/SHOULD/MUST NOT with RFC-2119 language
3. **Core Commands** (10-20 lines) — development, quality, testing
4. **Project Structure Map** (15-30 lines) — with links to subdirectory CLAUDE.md
5. **Quick Find Commands** (10-15 lines) — JIT search patterns
6. **Security & Secrets** (5-10 lines)
7. **Git Workflow** (5-10 lines)
8. **Testing Strategy** (5-10 lines)
9. **Tool Permissions** (5-10 lines)
10. **Subdirectory Context** (5-10 lines) — links to specialized CLAUDE.md

### Phase 3: Generate Subdirectory CLAUDE.md Files

For each major package/directory (100-200 lines each):

1. Package identity and parent context link
2. Setup and commands
3. **Architecture and patterns** (most important)
4. Key files and touch points
5. JIT search hints
6. Common gotchas
7. Package-specific testing
8. Pre-PR validation

### Phase 4: Claude Code Configuration

1. Hooks configuration (`.claude/settings.json`)
2. Custom slash commands (`.claude/commands/`)
3. MCP server recommendations
4. Subagent recommendations (if applicable)

## Quality Checklist

- [ ] Root CLAUDE.md under 400 lines
- [ ] All subdirectory CLAUDE.md files link back to root
- [ ] Every "DO" has a real file example with path
- [ ] Every "DON'T" references actual anti-pattern
- [ ] Commands are copy-paste ready
- [ ] JIT search commands use actual file patterns
- [ ] No duplication between hierarchy levels
