# ollama-agente

Agente de análisis de seguridad estático que combina herramientas deterministas (Semgrep, gitleaks) con un LLM local (Qwen2.5-Coder 7B vía Ollama) enriquecido con RAG sobre CWEs.

## Estado

5 componentes funcionales, probados sobre NodeGoat y targets sintéticos.

| Componente | Función |
|---|---|
| `orchestrator.py` | Pipeline determinista: Semgrep + gitleaks + RAG + verificación LLM → JSON |
| `report_to_md.py` | Convierte el JSON a Markdown legible |
| `agent_tools.py` | Agente ReAct con tool calling (5 herramientas) |
| `planner.py` | Planner externo: divide objetivos complejos en sub-tareas de 2 pasos |
| `build_index.py` | Construye el índice RAG de 17 CWEs |

## Hardware y entorno

- CPU: AMD Ryzen 7 5700U (8c/16t), 16 GB RAM
- Ollama 0.35.1 nativo en Windows, WSL2 Ubuntu 24.04 (`networkingMode=mirrored`)
- Ollama corre en CPU (sin aceleración GPU en Docker Desktop)

### Modelos

| Modelo | Uso | Notas |
|---|---|---|
| `qwen2.5-coder:7b` | Verificación y agente | ~5-6 tok/s en CPU. Modo principal. |
| `qwen2.5-coder:3b` | Alternativa rápida | ~11 tok/s. No sostiene >2 tool calls dependientes. |
| `nomic-embed-text` | Embeddings RAG | 768 dims, 274 MB |
| `llama3.2:3b` | **Descartado** | Rechaza (refusal) temas de seguridad |

## Setup

### 1. Prerrequisitos

- Ollama nativo en Windows (verificar con `ollama --version`)
- WSL2 Ubuntu 24.04 con el archivo `.wslconfig` en el home de Windows (`~`):

  ```ini
  [wsl2]
  networkingMode=mirrored
  ```

- Dentro de WSL: `semgrep`, `gitleaks`, `python3`, `pipx`, `numpy`

### 2. Instalación

En WSL:

```bash
sudo apt install -y gitleaks pipx python3-venv
pipx install semgrep
```

En Windows PowerShell:

```powershell
ollama pull qwen2.5-coder:7b
ollama pull qwen2.5-coder:3b
ollama pull nomic-embed-text
```

### 3. Índice RAG

```bash
cd ~/ollama-agente
python3 build_index.py
python3 test_retrieval.py
```

## Uso

### Pipeline determinista (recomendado para automatización)

```bash
python3 orchestrator.py targets/NodeGoat/app --max 20 --min-severity WARNING
python3 report_to_md.py reports/report_YYYYMMDD_HHMMSS.json
```

Salida: JSON con hallazgos + Markdown con tabla resumen y detalle por hallazgo.

### Agente con tool calling (tareas ad-hoc)

```bash
python3 agent_tools.py "Escanea targets/vuln_test.py con Semgrep y dime qué encontró"
python3 agent_tools.py "Escanea X y lee las líneas 30-36 para explicarme la vulnerabilidad"
```

Herramientas disponibles: `run_semgrep_tool`, `gitleaks_tool`, `read_file_tool`, `search_corpus_tool`, `write_report_tool`.

> **Límite conocido:** el 7B sostiene 2-3 pasos dependientes en un solo loop. Para 4 o más, usar `planner.py`.

### Planner externo (objetivos complejos)

```bash
python3 planner.py targets/vuln_test.py
```

Divide el objetivo en 3 sub-tareas de 2 pasos máximo, cada una en sesión limpia. Genera `reports/agent_vuln_test.md`.

## Arquitectura

### Pipeline determinista

```text
Semgrep ─┐
         ├─→ dedup ─→ filtro stack ─→ filtro ruido ─┐
gitleaks ┘                                          │
                                                    ▼
                         ┌──────── por hallazgo ────────┐
                         ▼                              │
                  RAG (CWE + lang + msg)                │
                         ▼                              │
                  Qwen verifica (verdict + fix)         │
                         ▼                              │
                  Reporte JSON ─→ report_to_md.py ─→ Markdown
```

**Regla de diseño:** el LLM nunca provee línea ni ruta. Solo veredicto, confianza, reasoning y fix. Las coordenadas las dan Semgrep y gitleaks.

### Agente con tool calling

```text
System prompt (anti-alucinación)
      │
      ▼
Qwen 7B ──→ tool_calls (o fallback de texto)
      ▲             │
      │             ▼
      │       Herramienta ejecutada
      │             │
      │             ▼
      └──── result (role: tool)
            ¿Nueva iteración?
```

**Fallback:** si el modelo emite los tool calls como texto en `content`, se extraen con regex + parseo JSON y se ejecutan igualmente. Qwen no emite `tool_calls` nativos de forma fiable vía Ollama.

### Planner

Ejecuta `agent_tools.py` en subprocesos con `--max-iter` acotado. Cada sub-objetivo es una sesión independiente, sin contaminación de contexto.

## Decisiones de diseño

- **¿Por qué Qwen y no Llama?** Llama3.2 se niega a analizar temas de seguridad. Qwen2.5-Coder no.
- **¿Por qué 7B y no 3B?** El 3B sostiene ≤2 tool calls; el 7B sostiene 2-3 con fiabilidad. Para el pipeline determinista ambos funcionan, pero para el agente el 7B es necesario.
- **¿Por qué planner externo?** El 7B no sostiene 4 pasos dependientes en un loop, pero cada sub-objetivo de 2 pasos sí. Determinista + LLM para razonamiento es más robusto que autonomía total del LLM.
- **¿Por qué RAG con numpy y no ChromaDB/FAISS?** 17 documentos × 768 dims ≈ 13 KB (en float32 son ~52 KB, igualmente despreciable). La similitud coseno en numpy es instantánea y sin dependencias extra.

## Corpus RAG

`data/corpus.json` contiene 17 entradas:

| Categoría | CWEs |
|---|---|
| Inyección | CWE-89 (SQLi), CWE-95 (Eval), CWE-78 (OS Command), CWE-79 (XSS) |
| Redirección / red | CWE-601 (Open Redirect), CWE-918 (SSRF), CWE-352 (CSRF) |
| Transporte | CWE-319 (Cleartext, HTML y Server) |
| Archivos / datos | CWE-22 (Path Traversal), CWE-502 (Deserialization), CWE-611 (XXE) |
| Credenciales / sesión | CWE-798 (Hardcoded creds, JS y Python), CWE-522 (Session cookies) |
| Infraestructura | CWE-1357 (GitHub Actions mutable), CWE-732 (Docker permisos) |

Cada entrada tiene `description`, `vulnerable` (patrón) y `fix` (solución concreta en el lenguaje).

## Métricas (NodeGoat/app, Ryzen 7 5700U)

| Métrica | Valor |
|---|---|
| Hallazgos brutos | 15 (7 tras filtros) |
| Verificación LLM (7B) | 7/7 correctos (4 TP + 3 FP omitidos) |
| Tiempo por hallazgo | ~30 s (7B), ~12 s (3B) |
| Planner completo | ~5 min (3 sub-objetivos) |
| Corpus RAG | 17 CWEs, retrieval 4/4 en test |

## Estructura

```text
ollama-agente/
├── README.md
├── DEUDA.md                 # deuda técnica priorizada
├── orchestrator.py          # pipeline determinista
├── report_to_md.py          # JSON → Markdown
├── agent_tools.py           # agente ReAct con tool calling
├── planner.py               # planner externo
├── build_index.py           # construye índice RAG
├── test_retrieval.py        # test del retrieval
├── data/
│   ├── corpus.json          # 17 CWEs
│   ├── embeddings.npy       # vectores (17×768)
│   └── index.db             # textos (SQLite)
├── reports/                 # reportes generados
└── targets/                 # código a escanear
```

## Referencias

- [Ollama Chat API](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [Semgrep Registry](https://semgrep.dev/explore)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)


