# CLAUDE.md Generation Guide

## Table of Contents

1. [Root CLAUDE.md Section Templates](#root-claudemd-section-templates)
2. [Subdirectory CLAUDE.md Template](#subdirectory-claudemd-template)
3. [Hooks Configuration Template](#hooks-configuration-template)
4. [Best Practices](#best-practices)

## Root CLAUDE.md Section Templates

### Project Identity

```markdown
# [Project Name]

## Overview

- **Type**: [Monorepo/Standard project]
- **Stack**: [Primary technologies]
- **Architecture**: [Brief architectural summary]

This CLAUDE.md is the authoritative source for development guidelines.
Subdirectories contain specialized CLAUDE.md files that extend these rules.
```

### Universal Rules

Use RFC-2119 language with emphasis:

```markdown
## Universal Development Rules

### Code Quality (MUST)

- **MUST** write TypeScript in strict mode
- **MUST** include tests for all new features
- **MUST NOT** commit secrets, API keys, or tokens

### Best Practices (SHOULD)

- **SHOULD** prefer functional components
- **SHOULD** keep functions under 50 lines

### Anti-Patterns (MUST NOT)

- **MUST NOT** use `any` type without justification
- **MUST NOT** push directly to main branch
```

### Core Commands

````markdown
## Core Commands

```bash
bun dev         # Start development servers
bun build       # Build all packages
bun test        # Run all tests
bun typecheck   # TypeScript validation
bun lint        # ESLint all code
```

### Quality Gates (run before PR)

```bash
bun typecheck && bun lint && bun test
```
````

### Project Structure Map

```markdown
## Project Structure

- **`apps/web/`** -> Frontend ([CLAUDE.md](apps/web/CLAUDE.md))
- **`apps/api/`** -> API ([CLAUDE.md](apps/api/CLAUDE.md))
- **`packages/ui/`** -> Shared components ([CLAUDE.md](packages/ui/CLAUDE.md))
- **`tests/`** -> Test suite ([CLAUDE.md](tests/CLAUDE.md))
```

### Quick Find Commands

````markdown
## Quick Find Commands

```bash
# Find component definition
rg -n "export (function|const) .*Button" src/

# Find API endpoint
rg -n "export (async )?function (GET|POST)" src/

# Find type definition
rg -n "^export (type|interface)" src/
```
````

### Security & Secrets

```markdown
## Security Guidelines

- **NEVER** commit tokens, API keys, or credentials
- Use `.env.local` for local secrets (gitignored)
- PII must be redacted in logs
- Confirm before: git force push, rm -rf, database drops
```

### Tool Permissions

```markdown
## Tool Permissions

| Tool              | Permission | Notes                     |
| ----------------- | ---------- | ------------------------- |
| Read any file     | Allowed    | Full codebase access      |
| Write code files  | Allowed    | Auto-formatted            |
| Run tests/linting | Allowed    |                           |
| Edit .env files   | Blocked    | Requires explicit consent |
| Force push        | Blocked    | Safety hook prevents      |
```

## Subdirectory CLAUDE.md Template

````markdown
# [Package Name] - [Purpose]

**Technology**: [Framework/language]
**Entry Point**: [Main file]
**Parent Context**: Extends [../CLAUDE.md](../CLAUDE.md)

## Development Commands

```bash
# From package directory
bun dev          # Start dev server
bun test         # Run tests
bun typecheck    # Type checking
```
````

## Architecture

### Directory Structure

```
src/
├── components/   # UI components
├── hooks/        # Custom hooks
├── lib/          # Utilities
└── types/        # TypeScript definitions
```

### Code Organization Patterns

- Components: Functional with hooks, one per file, co-locate tests
- State: Zustand stores in `src/stores/`
- Data: TanStack Query hooks in `src/hooks/`

## Key Files

- `src/app/layout.tsx` — root layout, providers
- `src/lib/api/client.ts` — API client
- `src/types/index.ts` — shared types

## Common Gotchas

- Client-side vars need `NEXT_PUBLIC_` prefix
- Always use `@/` prefix for imports from `src/`
- Server Components are default, add `"use client"` only when needed

````

## Hooks Configuration Template

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "if [[ \"$CLAUDE_TOOL_INPUT\" == *\"rm -rf\"* ]]; then echo 'BLOCKED: Dangerous command' && exit 2; fi"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "if [[ \"$CLAUDE_FILE_PATHS\" =~ \\.(ts|tsx)$ ]]; then prettier --write \"$CLAUDE_FILE_PATHS\" 2>/dev/null || true; fi"
          }
        ]
      }
    ]
  }
}
````

## Best Practices

### Memory System

- Use `#` during sessions to add memories organically
- Review and refactor CLAUDE.md monthly
- Keep sections modular to prevent instruction bleeding

### Hooks Strategy

- PreToolUse: Validation and safety checks
- PostToolUse: Formatting, linting, auto-testing
- Start conservative, expand based on needs

### Context Management

- Use `/clear` between unrelated tasks
- Use `/compact` for long sessions
- Reference specific files with `@` rather than reading entire directories

### Custom Commands

- Start with 3-5 most common workflows
- Use descriptive names (e.g., `/fix-issue`, not `/fi`)
- Include validation steps in commands
