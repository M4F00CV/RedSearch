# Conventional Commits Guide

Reference for this project. All commits in English, imperative mood.

## Format

<type>(<scope>): <description>

[optional body]

[optional footer]


## Types

| Type | When to use |
|---|---|
| `feat` | New feature or functionality |
| `fix` | Bug fix or error correction |
| `docs` | Documentation changes only |
| `style` | Code formatting (no logic changes) |
| `refactor` | Code restructuring (no functionality change) |
| `test` | Adding or modifying tests |
| `chore` | Maintenance, config, dependencies |

Choose the RIGHT type. If behavior changed, it's `feat` or `fix`, not `refactor`.

## Rules

- **Description**: ≤50 chars, imperative mood ("add" not "added"), lowercase, no period.
- **Scope**: lowercase, specific but not too granular (`auth`, not `auth/login/validation`).
- **Body**: only when the "why" isn't obvious. Wrap at 72 chars. Bullet points for multiple items.
- **Footer**: use for `BREAKING CHANGE:`, `Closes #N`, `Refs #N`.
- **Atomic**: one logical change per commit. If unrelated, split.

## Scopes for this project

- `core` — `agent_tools.py`, `planner.py`, `orchestrator.py`
- `tools` — specific tool implementations (semgrep, gitleaks, dirsearch)
- `rag` — `build_index.py`, `corpus.json`, embeddings
- `agent` — ReAct loop, prompt, fallback logic
- `orchestrator` — pipeline determinista
- `planner` — external planner
- `docs` — README, DEUDA, structure, commits
- `deps` — venv, requirements
- `data` — corpus, test targets

## Examples

### Simple

fix(tools): handle gitleaks 8.16 without 'dir' subcommand
docs(readme): add venv setup instructions
chore(deps): pin dirsearch to 0.5.0

### Medium (with body)

feat(tools): add dirsearch integration for web path discovery

Implement dirsearch_tool using the Python API (FuzzerConfig +
DirsearchFuzzer) instead of CLI wrapper. Returns metadata only
(status, path, length, redirect) — not body — to avoid prompt
injection from HTTP responses.

Requires --allow-network flag to be enabled.

### Complex (with footer)

efactor(core)!: split agent_tools.py into src/ modules

Break 500-line monolith into:

src/core/ (llm, react_loop, utils)

src/tools/ (one file per tool, registry)

src/rag/ (index, retrieve)

src/agent/ (run_agent + CLI)

src/orchestrator/ (pipeline, verify, report_md)

src/planner/

BREAKING CHANGE: import paths change. scripts/ wrappers
preserve python agent_tools.py ... compatibility.

Refs #1

## Anti-patterns

- `fix: bug fix` — too vague
- `feat: add login and fix dashboard` — mixed concerns, split it
- `feat(auth): added login` — wrong tense, use "add"
- `docs(readme): update README.md file with new info` — redundant

## Checklist

- [ ] Type accurately reflects the change
- [ ] Scope is specific and lowercase
- [ ] Description is imperative, specific, ≤50 chars
- [ ] Body explains WHY (if not obvious)
- [ ] Breaking changes marked with `!` and `BREAKING CHANGE:`
- [ ] One logical change per commit
