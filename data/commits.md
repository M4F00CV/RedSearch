# Conventional Commits Guide

All commits in English, imperative mood, present tense.

## Format

`<type>(<scope>): <description>`

Optional body (blank line after description, wrapped at 72 chars).
Optional footer for `BREAKING CHANGE:`, `Closes #N`, `Refs #N`.

## Types

- `feat` — new feature or functionality
- `fix` — bug fix or error correction
- `docs` — documentation only
- `style` — formatting, no logic change
- `refactor` — restructuring, no behavior change
- `test` — add or modify tests
- `chore` — maintenance, config, deps

If behavior changed, use `feat` or `fix`, not `refactor`.

## Rules

- Description: <=50 chars, imperative ("add" not "added"), lowercase, no period
- Scope: lowercase, specific but not too granular
- Body: only when "why" is not obvious. Wrap at 72 chars. Bullets for multiple items
- Footer: `BREAKING CHANGE:` prefix for breaking changes
- Atomic: one logical change per commit

## Scopes for this project

- `core` — agent_tools.py, planner.py, orchestrator.py
- `tools` — individual tool implementations
- `rag` — build_index.py, corpus.json
- `agent` — ReAct loop, prompt
- `orchestrator` — deterministic pipeline
- `planner` — external planner
- `docs` — README, DEUDA, structure, commits
- `deps` — venv, requirements
- `data` — corpus, test targets

## Examples

Simple: `fix(tools): handle gitleaks 8.16 without dir subcommand`
Simple: `docs(readme): add venv setup instructions`
Simple: `chore(deps): pin dirsearch to 0.5.0`

Medium (with body):

    feat(tools): add dirsearch integration for web path discovery

    Implement dirsearch_tool using the Python API (FuzzerConfig +
    DirsearchFuzzer). Returns metadata only (status, path, length,
    redirect) to avoid prompt injection from HTTP response bodies.

    Requires --allow-network flag.

Complex (with footer):

    refactor(core)!: split agent_tools.py into src/ modules

    Break 500-line monolith into:
    - src/core/ (llm, react_loop, utils)
    - src/tools/ (one file per tool, registry)
    - src/rag/
    - src/agent/
    - src/orchestrator/
    - src/planner/

    BREAKING CHANGE: import paths change. scripts/ wrappers
    preserve `python agent_tools.py ...` compatibility.

    Refs #1

## Anti-patterns

- `fix: bug fix` — vague
- `feat: add login and fix dashboard` — mixed concerns, split
- `feat(auth): added login` — wrong tense
- `docs(readme): update README.md file with new info` — redundant
