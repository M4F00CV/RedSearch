# Deuda técnica — ollama-agente

Última actualización: 2026-10-28

## Alta prioridad

Ninguna. El sistema está funcional y probado.

## Media prioridad

### Corpus RAG limitado (17 CWEs)
- **Impacto:** cobertura limitada para CWEs no indexados
- **Fix:** añadir 8+ CWEs (CWE-434 upload, CWE-287 auth, CWE-306 missing auth, CWE-862/863, CWE-1333 ReDoS, CWE-400, CWE-770)
- **Esfuerzo:** 1-2 horas

### Filtro de ruido heurístico (`NOISE_PATH_PATTERNS`)
- **Impacto:** oculta hallazgos en `/test/`, `/tests/`, `/docs/`, `/.github/workflows/`
- **Riesgo:** puede ocultar credenciales en tests y secrets en CI
- **Fix:** flag `--no-noise-filter` o separar en dos invocaciones
- **Esfuerzo:** 30 min

### `server.js:78` — 6 check_ids, fix parcial
- **Impacto:** el LLM cubre solo `name` de 6 flags de cookie
- **Causa:** `num_predict=500` no alcanza para 6 dimensiones
- **Fix:** subir `num_predict` a 800 o agrupar por check_id
- **Esfuerzo:** 1 hora

## Baja prioridad

### Idioma inconsistente (español/inglés)
- **Impacto:** cosmético
- **Fix:** reforzar el prompt con "Responde SIEMPRE en español"
- **Esfuerzo:** 10 min

### `suggested_fix` a veces copia el corpus literalmente
- **Impacto:** bajo (afecta documentación)
- **Fix:** añadir al prompt "preserva los valores EXACTOS del fragmento"
- **Esfuerzo:** 20 min

### Nombres de env genéricos en `db-reset.js`
- **Impacto:** bajo (`process.env.USER1_123` en lugar de `process.env.ADMIN_PASSWORD`)
- **Fix:** mejorar el corpus de CWE-798
- **Esfuerzo:** 15 min

### CWE-319-server: el 7B escribe `http.createServer({key, cert})`
- **Impacto:** bajo (fix técnicamente inválido para TLS)
- **Fix:** añadir al corpus que el módulo `http` NO acepta TLS y debe usarse `https`
- **Esfuerzo:** 10 min

### `min_score=0.65` deja pasar CWE-798-JS a 0.685
- **Impacto:** bajo (contaminación menor)
- **Fix:** subir a 0.70 si molesta en reportes grandes
- **Esfuerzo:** 5 min

## Límites del modelo (no son bugs)

### Qwen 7B no emite `tool_calls` nativos fiables
- El fallback de texto cubre el 100% de los casos observados
- `tool_choice: "required"` fuerza el parseo cuando el modelo se atasca

### Qwen 7B repite patrones en contextos largos
- `is_stuck_in_loop` y `is_stuck_within` detectan y abortan
- `planner.py` lo mitiga reiniciando la sesión entre sub-objetivos

### Límite de pasos dependientes: 2-3

| Pasos | Resultado |
|---|---|
| 1 | ✅ |
| 2 | ✅ |
| 3 | ✅ |
| 4 | ❌ |

Solución: `planner.py` divide los objetivos complejos.

## Resuelto

- [x] `num_predict: 500` aplicado en `call_ollama`
- [x] `gitleaks` integrado (detección de secretos)
- [x] Reporte Markdown (`report_to_md.py`)
- [x] Tool calling de Qwen (5 herramientas)
- [x] Corpus RAG de 12 a 17 CWEs
- [x] Cambio de 3B a 7B
- [x] Detección de bucles (inter e intra-turno)
- [x] Planner externo
- [x] Limpieza de archivos de ruido
- [x] Prompt sin contaminación cruzada (verificador vs agente)


### `write_report_tool` default filename is agent_report.md
- Impacto: bajo (gitignored, pero crea ruido local)
- Fix: make filename required, remove default from schema
- Esfuerzo: 5 min
- Se hará en commit 10 post-refactor