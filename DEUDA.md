# Technical Debt — RedSearch

Last updated: 2026-11-03

## High priority

None. The system is functional and tested.

## Medium priority

### Limited RAG corpus (17 CWEs)
- **Impact:** limited coverage for non-indexed CWEs
- **Fix:** add 8+ CWEs (CWE-434 upload, CWE-287 auth, CWE-306 missing auth, CWE-862/863, CWE-1333 ReDoS, CWE-400, CWE-770)
- **Effort:** 1-2 hours

### Heuristic noise filter (`NOISE_PATH_PATTERNS`)
- **Impact:** hides findings in `/test/`, `/tests/`, `/docs/`, `/.github/workflows/`
- **Risk:** may hide credentials in tests and secrets in CI
- **Fix:** `--no-noise-filter` flag, or split into two invocations
- **Effort:** 30 min

### `server.js:78` — 6 check_ids, partial fix
- **Impact:** the LLM only covers `name` of 6 cookie flags
- **Cause:** `num_predict=500` is not enough for 6 dimensions
- **Fix:** raise `num_predict` to 800, or group by check_id
- **Effort:** 1 hour

### `write_report_tool` default filename is `agent_report.md`
- **Impact:** low (gitignored, but creates local noise)
- **Fix:** make `filename` a required parameter, remove default from schema
- **Effort:** 5 min

### No pytest suite
- **Impact:** low (manual smoke tests via `test_retrieval.py` and CLI)
- **Fix:** create `tests/` with pytest; imports from `src.*` now work cleanly
- **Effort:** 2-3 hours

## Low priority

### Inconsistent language (Spanish/English)
- **Impact:** cosmetic (runtime messages in Spanish, docstrings in English)
- **Fix:** reinforce the prompt with "Respond ALWAYS in Spanish" for user-facing output
- **Effort:** 10 min

### `suggested_fix` sometimes copies the corpus literally
- **Impact:** low (affects docs and tutorial files)
- **Fix:** strengthen the prompt with "preserve the EXACT values of the fragment"
- **Effort:** 20 min

### Generic env names in `db-reset.js`
- **Impact:** low (`process.env.USER1_123` instead of `process.env.ADMIN_PASSWORD`)
- **Fix:** improve the CWE-798 corpus entry
- **Effort:** 15 min

### CWE-319-server: 7B writes `http.createServer({key, cert})`
- **Impact:** low (technically invalid fix for TLS)
- **Fix:** add to corpus that the `http` module does NOT accept TLS; must use `https`
- **Effort:** 10 min

### `min_score=0.65` lets CWE-798-JS through at 0.685
- **Impact:** low (minor contamination in eval-related findings)
- **Fix:** raise to 0.70 if noisy in large reports
- **Effort:** 5 min

## Model limits (not bugs)

### Qwen 7B does not emit reliable native `tool_calls`
- The text fallback covers 100% of observed cases
- `tool_choice: "required"` forces parsing when the model gets stuck

### Qwen 7B repeats patterns in long contexts
- `is_stuck_in_loop` and `is_stuck_within` detect and abort
- `planner.py` mitigates by resetting the session between sub-goals

### Dependent-step limit: 2-3

| Steps | Result |
|---|---|
| 1 | ✅ |
| 2 | ✅ |
| 3 | ✅ |
| 4 | ❌ |

Solution: `planner.py` splits complex goals into sub-goals.

## Resolved

### v0.1 — initial working system
- [x] `num_predict: 500` applied in `call_ollama`
- [x] `gitleaks` integrated (secret detection)
- [x] Markdown reports
- [x] Qwen tool calling (5 tools)
- [x] RAG corpus expanded 12 → 17 CWEs
- [x] Switch from 3B to 7B
- [x] Loop detection (inter- and intra-turn)
- [x] External planner
- [x] Noise file cleanup in planner
- [x] Prompt without cross-contamination (verifier vs agent)

### v0.2 — bug fixes
- [x] Duplicate `subprocess.run` in `run_sub_goal` (was doubling planner time)
- [x] `ALLOW_NETWORK` as explicit parameter in `dirsearch_tool`
- [x] `dirsearch` wordlist fallback when preset exceeds `max_entries`
- [x] Finalization on textual summary after tool execution (`_looks_like_summary`)

### v0.3 — modular refactor
- [x] Monoliths (300+ lines) split into `src/` (max 186 lines per file)
- [x] Legacy entry points as thin wrappers (8-10 lines) for backward compatibility
- [x] Duplicate `call_ollama` removed (single source in `src/core/llm.py`)
- [x] `read_fragment` unified in `src/core/utils.py`
- [x] `.gitignore` covers generated Markdown reports (`reports/report_*.md`)
- [x] Dirsearch integration as `src/tools/dirsearch.py` (Python API, metadata-only output)