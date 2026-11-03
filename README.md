# RedSearch

Local-first security analysis agent: deterministic tools (Semgrep, gitleaks, dirsearch) + local LLM (Qwen 2.5 Coder 7B via Ollama) enriched with RAG over CWEs.

## Key Features

- **Deterministic detection**: Semgrep (SAST), gitleaks (secrets), dirsearch (web paths). Objective findings with no LLM involvement in the detection layer.
- **LLM verification with RAG**: each finding is verified by a local LLM with context retrieved from a curated CWE corpus (17 entries, 768-dim embeddings).
- **ReAct agent with tool calling**: 6 tools available (`run_semgrep_tool`, `gitleaks_tool`, `read_file_tool`, `search_corpus_tool`, `write_report_tool`, `dirsearch_tool`). A text-fallback parser handles models that emit tool calls inline instead of via native `tool_calls`.
- **External planner**: splits complex goals into 2-step sub-goals that the 7B model handles reliably.
- **Markdown reports**: structured JSON + human-readable Markdown with code excerpts, reasoning, and concrete fixes.

## Tech Stack

| Layer | Technology |
|---|---|
| LLM runtime | Ollama 0.35.1 (CPU only) |
| Models | Qwen 2.5 Coder 7B (primary), 3B (fast), nomic-embed-text (RAG) |
| Static analysis | Semgrep, gitleaks, dirsearch |
| Language | Python 3.12 |
| RAG storage | NumPy vectors + SQLite |
| Environment | WSL2 Ubuntu 24.04 (`networkingMode=mirrored`) |

## Prerequisites

- Ollama natively installed on Windows (verify with `ollama --version`)
- WSL2 Ubuntu 24.04 with `networkingMode=mirrored` in `~/.wslconfig` (Windows user home):

  ```ini
  [wsl2]
  networkingMode=mirrored
  ```

- WSL packages: `semgrep`, `gitleaks`, `python3`, `python3-venv`, `pipx`

## Installation

### 1. System tools (WSL)

```bash
sudo apt install -y gitleaks pipx python3-venv
pipx install semgrep
```

### 2. Models (Windows PowerShell)

```powershell
ollama pull qwen2.5-coder:7b
ollama pull qwen2.5-coder:3b
ollama pull nomic-embed-text
```

### 3. Python environment (WSL)

`dirsearch` requires a dedicated venv: its dependencies pin specific versions of `requests`, `httpx`, and `cryptography` that may conflict with system packages.

```bash
cd ~/RedSearch
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools
pip install dirsearch numpy
```

### 4. RAG index

```bash
cd ~/RedSearch
source .venv/bin/activate
python3 build_index.py       # generates data/embeddings.npy + data/index.db
python3 test_retrieval.py    # expected: 9/9 passed
```

## Configuration

| Variable / Flag | Where | Default | Purpose |
|---|---|---|---|
| `OLLAMA_HOST` | Windows env var | `127.0.0.1:11434` | Ollama bind address. Leave default if using WSL mirrored networking. |
| `--allow-network` | CLI flag | `False` | Enables `dirsearch_tool` (makes HTTP requests to the target). |

## Usage

### Deterministic pipeline

Recommended for automation. Detects, verifies, and writes a JSON report.

```bash
source .venv/bin/activate
python3 orchestrator.py targets/NodeGoat/app --max 20 --min-severity WARNING
python3 report_to_md.py reports/report_YYYYMMDD_HHMMSS.json
```

Module entry points (new, preferred for scripting):

```bash
python3 -m src.orchestrator.pipeline targets/NodeGoat/app --max 20 --min-severity WARNING
python3 -m src.orchestrator.report_md reports/report_YYYYMMDD_HHMMSS.json
```

### ReAct agent (ad-hoc tasks)

```bash
python3 agent_tools.py "Escanea targets/vuln_test.py con Semgrep y dime qué encontró"
python3 agent_tools.py "Escanea X y lee las líneas 30-36 para explicarme la vulnerabilidad"

# With network access (enables dirsearch)
python3 agent_tools.py --allow-network "Escanea http://127.0.0.1:8000 y reporta las rutas encontradas"
```

> **Known limit:** the 7B model handles 2-3 dependent tool calls per loop. For 4+, use the planner.

### External planner (complex goals)

```bash
python3 planner.py targets/vuln_test.py       # code target (Semgrep + gitleaks + RAG)
python3 planner.py http://127.0.0.1:8000      # URL target (dirsearch)
```

Splits the goal into 3 sub-tasks of at most 2 steps each, in clean sessions. Generates `reports/agent_vuln_test.md`.

## Project Structure

```text
RedSearch/
├── src/
│   ├── core/
│   │   ├── llm.py            # Ollama HTTP layer (chat, generate, embed)
│   │   └── utils.py          # pure helpers (parse, normalize, loop detection)
│   ├── tools/
│   │   ├── semgrep.py
│   │   ├── gitleaks.py
│   │   ├── dirsearch.py
│   │   ├── files.py
│   │   ├── corpus.py
│   │   └── registry.py       # TOOLS, TOOL_MAP, ALLOW_NETWORK
│   ├── rag/
│   │   ├── retrieve.py       # vector search
│   │   └── index.py          # build embeddings + SQLite
│   ├── agent/
│   │   ├── react_loop.py     # run_agent + SYSTEM_PROMPT
│   │   └── cli.py            # argparse + registry.ALLOW_NETWORK
│   ├── orchestrator/
│   │   ├── pipeline.py       # main(): detect + verify + write JSON
│   │   ├── verify.py         # per-finding LLM verification
│   │   └── report_md.py      # JSON → Markdown
│   └── planner/
│       └── planner.py        # split complex goals into sub-goals
├── agent_tools.py            # legacy wrapper → src.agent.cli
├── orchestrator.py           # legacy wrapper → src.orchestrator.pipeline
├── report_to_md.py           # legacy wrapper → src.orchestrator.report_md
├── planner.py                # legacy wrapper → src.planner.planner
├── build_index.py            # legacy wrapper → src.rag.index
├── test_retrieval.py         # 9-query retrieval check
├── data/
│   ├── corpus.json           # 17 CWEs
│   ├── structure.md          # documentation guide for this project
│   └── embeddings.npy        # generated (gitignored)
├── targets/                  # repos / URLs to scan (gitignored if large)
└── reports/                  # JSON + Markdown output (gitignored except samples)
```

**Design constraint:** no source file exceeds 200 lines. Root-level scripts are thin wrappers (8-10 lines) kept for backward compatibility.

## Architecture

### Deterministic pipeline

```text
Semgrep  ─┐
          ├─→ dedup ─→ stack filter ─→ noise filter ─┐
gitleaks ─┘                                          │
                                                     ▼
                       ┌──────── per finding ─────────┐
                       ▼                              │
                  RAG (CWE + lang + msg)              │
                       ▼                              │
                  Qwen verify (verdict + fix)         │
                       ▼                              │
                  JSON report ─→ report_md.py ─→ Markdown
```

**Design rule:** the LLM never provides line numbers or file paths. Coordinates come from Semgrep/gitleaks. The LLM only returns verdict, confidence, reasoning, and suggested fix.

### ReAct agent

```text
System prompt (anti-hallucination)
      │
      ▼
Qwen 7B ──→ tool_calls (native or text fallback)
      ▲             │
      │             ▼
      │       Tool executed
      │             │
      │             ▼
      └──── result (role: tool)
            New iteration?
```

**Fallback:** if the model emits the tool call as plain text in `content`, a regex + JSON parser recovers it and executes it. Qwen via Ollama does not emit native `tool_calls` reliably.

### Planner

Spawns `agent_tools.py` as subprocesses with bounded `--max-iter`. Each sub-goal runs in an independent session, avoiding context contamination across tasks.

## Design Decisions

- **Qwen over Llama:** Llama 3.2 refuses security analysis. Qwen 2.5 Coder does not.
- **7B over 3B:** the 3B reliably handles ≤2 dependent tool calls; the 7B handles 2-3. The deterministic pipeline works with either, but the agent needs the 7B.
- **External planner:** the 7B cannot sustain 4 dependent steps in a single loop, but 2-step sub-goals work reliably. Deterministic backbone + LLM reasoning is more robust than full LLM autonomy.
- **NumPy + SQLite RAG instead of ChromaDB/FAISS:** 17 docs × 768 dims ≈ 52 KB. Cosine similarity in NumPy is instant and dependency-free.
- **Modular `src/` instead of monoliths:** each module has a single responsibility; max 186 lines per file; unit-testable imports.

## RAG Corpus

`data/corpus.json` has 17 entries:

| Category | CWEs |
|---|---|
| Injection | CWE-89 (SQLi), CWE-95 (Eval), CWE-78 (OS Command), CWE-79 (XSS) |
| Redirect / network | CWE-601 (Open Redirect), CWE-918 (SSRF), CWE-352 (CSRF) |
| Transport | CWE-319 (Cleartext, HTML and Server) |
| Files / data | CWE-22 (Path Traversal), CWE-502 (Deserialization), CWE-611 (XXE) |
| Credentials / session | CWE-798 (Hardcoded, JS and Python), CWE-522 (Session cookies) |
| Infrastructure | CWE-1357 (GitHub Actions mutable), CWE-732 (Docker permissions) |

Each entry has `description`, `vulnerable` (pattern), and `fix` (concrete solution in the target language).

## Metrics

Tested on NodeGoat `/app` (Node.js, 7B model, Ryzen 7 5700U):

| Metric | Value |
|---|---|
| Raw findings | 15 (7 after filters) |
| LLM verification | 7/7 correct (4 TP + 3 FP skipped) |
| Time per finding | ~30 s (7B), ~12 s (3B) |
| Planner full run | ~3 min (3 sub-goals) |
| Retrieval test | 9/9 CWEs matched at top-1 |
| Corpus size | 17 CWEs, 52 KB embeddings |

## Development

### Add a new tool

1. Create `src/tools/your_tool.py` with a single function `your_tool(...) -> str`.
2. Append its schema to `TOOLS` in `src/tools/registry.py`.
3. Add the function to `TOOL_MAP` in `src/tools/registry.py`.
4. If the tool makes network requests, gate it behind `ALLOW_NETWORK` (like `dirsearch_tool`).

### Add a new CWE to the corpus

1. Append an entry to `data/corpus.json` with `cwe`, `name`, `description`, `vulnerable`, `fix`, `owasp`.
2. Rebuild the index: `python3 build_index.py`.
3. Verify retrieval: `python3 test_retrieval.py`.

### Documentation guide

Project documentation (docstrings, comments, README) follows the style rules in `data/structure.md`: English only, PEP 8 / PEP 257 for Python, `#` single-line comments for inline notes, `TODO`/`FIXME`/`HACK` prefixes for exceptional cases.

### Testing

```bash
source .venv/bin/activate
python3 test_retrieval.py
# Expected: 9/9 passed
```

No pytest suite yet. See [DEUDA.md](DEUDA.md).

## License

MIT