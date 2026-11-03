#!/usr/bin/env python3
"""
agent_tools.py — Agente ReAct con tool calling (Qwen2.5-Coder 7B vía Ollama).

Flujo: el LLM decide qué herramienta llamar, el orquestador ejecuta,
el resultado vuelve al historial, y se repite hasta que el modelo
responde con contenido final o se alcanza MAX_ITERATIONS.

Fallback: cuando el modelo emite tool calls como texto en `content`
en lugar de `tool_calls` nativos, se extraen y ejecutan igualmente.
"""

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
import signal

OLLAMA_CHAT_URL = "http://localhost:11434/v1/chat/completions"
MODEL = "qwen2.5-coder:7b"
MAX_ITERATIONS = 6
ALLOW_NETWORK = False


# ---------- Fallback y normalización ----------

def extract_tool_calls_from_text(content: str):
    """Fallback: extrae TODOS los tool calls si el modelo los emitió como texto."""
    if not content:
        return []
    candidates = []

    # 1) Bloque markdown
    for m in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL):
        candidates.append(m.group(1))

    # 2) JSON puro
    stripped = content.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        candidates.append(stripped)

    # 3) Bloques {...} equilibrados (todos)
    depth = 0
    start = None
    for i, ch in enumerate(content):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                candidates.append(content[start:i + 1])
                start = None

    found = []
    seen_names = set()
    for cand in candidates:
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            continue

        objs = []
        if isinstance(obj, list):
            objs = obj
        elif isinstance(obj, dict):
            if "tool_calls" in obj and isinstance(obj["tool_calls"], list):
                objs = [tc.get("function", tc) for tc in obj["tool_calls"]]
            else:
                objs = [obj]

        for o in objs:
            if "name" not in o:
                continue
            key = (o["name"], json.dumps(o.get("arguments", {}), sort_keys=True))
            if key in seen_names:
                continue
            seen_names.add(key)
            found.append(o)

    return found


def normalize_args(name: str, args: dict) -> dict:
    """Arregla el patrón {type, description, value} que el 7B a veces mete."""
    fixed = {}
    for k, v in args.items():
        if isinstance(v, dict) and "value" in v:
            fixed[k] = v["value"]
        else:
            fixed[k] = v
    return fixed


def is_stuck_in_loop(current: str, previous: str, threshold: float = 0.9) -> bool:
    """Detecta bucles inter-turno (content similar al turno anterior)."""
    if not previous or not current:
        return False
    curr_lines = [l.strip() for l in current.splitlines() if l.strip()]
    prev_lines = [l.strip() for l in previous.splitlines() if l.strip()]
    if not curr_lines or not prev_lines:
        return False
    if curr_lines[0] == prev_lines[0]:
        return True
    curr_set = set(curr_lines)
    prev_set = set(prev_lines)
    overlap = len(curr_set & prev_set) / max(len(curr_set), 1)
    return overlap >= threshold


def is_stuck_within(content: str, min_repeats: int = 4, min_len: int = 20) -> bool:
    """Detecta bucles intra-turno (misma línea repetida N veces en el mismo content)."""
    if not content:
        return False
    from collections import Counter
    lines = [l.strip() for l in content.splitlines() if len(l.strip()) >= min_len]
    if not lines:
        return False
    counts = Counter(lines)
    _, count = counts.most_common(1)[0]
    return count >= min_repeats


# ---------- Herramientas reales ----------

def run_semgrep_tool(target: str) -> str:
    """Escanea con Semgrep y devuelve un resumen de hallazgos."""
    import subprocess
    try:
        result = subprocess.run(
            ["semgrep", "--config=auto", "--quiet", "--json", target],
            capture_output=True, text=True, timeout=300,
        )
        data = json.loads(result.stdout)
        findings = data.get("results", [])
        if not findings:
            return f"Semgrep no encontró hallazgos en {target}."
        summary = []
        for f in findings[:5]:
            summary.append(
                f"{f['check_id']} en {f['path']}:{f['start']['line']} "
                f"({f['extra'].get('severity', 'INFO')})"
            )
        return f"Semgrep encontró {len(findings)} hallazgos:\n" + "\n".join(summary)
    except Exception as e:
        return f"Error ejecutando Semgrep: {e}"


def read_file_tool(path: str, start_line: int = 1, num_lines: int = 30) -> str:
    """Lee un fragmento de un archivo."""
    p = Path(path)
    if not p.exists():
        return f"Archivo no encontrado: {path}"
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(0, start_line - 1)
    end = min(len(lines), start + num_lines)
    return "\n".join(f"{i+1:4d} | {lines[i]}" for i in range(start, end))


def gitleaks_tool(target: str) -> str:
    """Escanea secretos hardcodeados con gitleaks."""
    import shutil
    import subprocess
    import tempfile

    gl = shutil.which("gitleaks")
    if not gl:
        return "gitleaks no está instalado."

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = tmp.name
    try:
        result = subprocess.run(
            [gl, "detect", "--source", target, "--no-git",
             "--report-format", "json", "--report-path", report_path,
             "--no-banner", "--redact"],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode not in (0, 1):
            return f"gitleaks falló: {result.stderr[:200]}"
        try:
            raw = json.loads(Path(report_path).read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return "gitleaks: reporte inválido"
        if not raw:
            return f"gitleaks no encontró secretos en {target}."
        lines = []
        for f in raw[:5]:
            lines.append(
                f"{f.get('RuleID', '?')} en {f.get('File', '?')}:{f.get('StartLine', '?')} "
                f"({f.get('Description', 'secret')})"
            )
        return f"gitleaks encontró {len(raw)} secretos:\n" + "\n".join(lines)
    finally:
        try:
            Path(report_path).unlink()
        except Exception:
            pass


def search_corpus_tool(query: str, k: int = 2) -> str:
    """Busca en el corpus RAG de CWEs para obtener patrones y fixes."""
    import sqlite3
    import numpy as np

    data_dir = Path(__file__).parent / "data"
    embeddings = data_dir / "embeddings.npy"
    index_db = data_dir / "index.db"
    if not embeddings.exists() or not index_db.exists():
        return "Corpus RAG no disponible (ejecuta build_index.py primero)."

    payload = {"model": "nomic-embed-text", "prompt": query}
    req = urllib.request.Request(
        "http://localhost:11434/api/embeddings",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        q = np.array(json.loads(r.read())["embedding"], dtype=np.float32)
    q /= (np.linalg.norm(q) + 1e-8)
    vecs = np.load(embeddings)
    vecs /= (np.linalg.norm(vecs, axis=1, keepdims=True) + 1e-8)
    scores = vecs @ q
    top = np.argsort(-scores)[:k]

    conn = sqlite3.connect(index_db)
    out = []
    for i in top:
        s = float(scores[i])
        if s < 0.50:
            continue
        row = conn.execute(
            "SELECT cwe, name, vulnerable, fix FROM docs WHERE id=?", (int(i),)
        ).fetchone()
        if row:
            out.append(
                f"[{row[0]} {row[1]}] (score {s:.2f})\n"
                f"  Patrón vulnerable: {row[2]}\n"
                f"  Fix recomendado: {row[3]}"
            )
    conn.close()
    if not out:
        return f"Sin resultados relevantes en el corpus para: {query}"
    return "\n\n".join(out)


def write_report_tool(content: str, filename: str = "agent_report.md") -> str:
    """Escribe un reporte a reports/<filename>."""
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    out = reports_dir / filename
    out.write_text(content, encoding="utf-8")
    return f"Reporte escrito en {out} ({len(content)} bytes)."

class ScanTimeout(Exception):
    pass


def _timeout_handler(signum, frame):
    raise ScanTimeout()


def dirsearch_tool(
    target_url: str,
    wordlist: str = "quick",
    extensions: str = "",
    max_entries: int = 200,
) -> str:
    """
    Escanea rutas web con dirsearch (API Python).
    Devuelve SOLO metadatos: status, path, length, content_type, redirect.
    No devuelve body (evita prompt injection desde respuestas HTTP).
    Requiere --allow-network.
    """
    if not ALLOW_NETWORK:
        return "Escaneo de red deshabilitado. Ejecuta con --allow-network para permitir dirsearch."

    if not target_url.startswith(("http://", "https://")):
        return "target_url debe empezar con http:// o https://"

    try:
        from dirsearch import (
            DirsearchFuzzer, FuzzerConfig, Wordlist,
            WordlistTemplate, WordlistLimitError,
        )
    except ImportError:
        return "dirsearch no está instalado en este Python. Activa el venv: source .venv/bin/activate"

    # Cap de entradas y timeout duro para no colgar al agente
    max_entries = min(max(1, int(max_entries)), 2000)
    hard_timeout = 120  # segundos totales

    # Construir wordlist
    try:
        if Path(wordlist).exists():
            wl = Wordlist.from_file(wordlist)
        elif "," in wordlist:
            wl = Wordlist([p.strip() for p in wordlist.split(",") if p.strip()])
        else:
            preset = (wordlist or "quick").lower()
            if preset == "api":
                tmpl = WordlistTemplate.from_builtin("api")
            elif preset == "admin":
                tmpl = WordlistTemplate.from_builtin("admin")
            elif preset == "backups":
                tmpl = WordlistTemplate([
                    "%CATEGORY:backups%", "%CATEGORY:db%",
                    "%CATEGORY:logs%", "%CATEGORY:keys%", "%CATEGORY:vcs%",
                ])
            else:  # quick
                tmpl = WordlistTemplate(["%CATEGORY:common%", "%CATEGORY:web%"])
            wl = Wordlist.from_template(tmpl, max_entries=max_entries)
    except WordlistLimitError:
        return f"Wordlist excedió max_entries={max_entries}. Reduce el preset o usa una lista explícita."
    except Exception as e:
        return f"Error construyendo wordlist: {e}"

    ext_tuple = tuple(e.strip() for e in extensions.split(",") if e.strip()) if extensions else ()

    config = FuzzerConfig(
        url=target_url,
        wordlist=wl,
        extensions=ext_tuple,
        timeout=3.0,
        follow_redirects=False,
        verify_tls=False,
        include_status_codes={200, 204, 301, 302, 401, 403},
        exclude_status_codes={404},
        user_agent="ollama-agente/1.0",
    )

    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(hard_timeout)
    try:
        results = DirsearchFuzzer(config).run()
    except ScanTimeout:
        return f"dirsearch alcanzó el límite de {hard_timeout}s. Usa menos entradas o un timeout menor."
    except Exception as e:
        return f"Error ejecutando dirsearch: {e}"
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

    if not results:
        return f"dirsearch no encontró rutas en {target_url} (wordlist={wordlist}, max_entries={max_entries})."

    # Ordenar: 200 primero, luego por longitud descendente
    results.sort(key=lambda r: (r.status != 200, -r.length))
    lines = []
    for r in results[:25]:
        redir = f" -> {r.redirect}" if r.redirect else ""
        lines.append(f"{r.status} {r.length:>7}B {r.path}{redir}")
    more = f"\n... y {len(results) - 25} más" if len(results) > 25 else ""
    return f"dirsearch encontró {len(results)} rutas en {target_url}:\n" + "\n".join(lines) + more


# ---------- Schemas de herramientas ----------

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_semgrep_tool",
            "description": "Escanea un archivo o directorio con Semgrep.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Ruta a escanear."}
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file_tool",
            "description": "Lee líneas de un archivo de código.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Ruta del archivo."},
                    "start_line": {"type": "integer"},
                    "num_lines": {"type": "integer"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "gitleaks_tool",
            "description": "Detecta secretos hardcodeados (API keys, passwords, tokens) con gitleaks.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Ruta a escanear."}
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_corpus_tool",
            "description": "Consulta el corpus RAG de CWEs para obtener patrones vulnerables y fixes concretos.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Descripción del problema (ej. 'SQL injection python f-string')."},
                    "k": {"type": "integer", "description": "Número de resultados (default 2)."},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_report_tool",
            "description": "Guarda un reporte en formato Markdown en reports/.",
            "parameters": {
                "type": "object",
                "properties": {
                    "content": {"type": "string", "description": "Contenido del reporte en Markdown."},
                    "filename": {"type": "string", "description": "Nombre del archivo (default agent_report.md)."},
                },
                "required": ["content"],
            },
        },
    },
        {
        "type": "function",
        "function": {
            "name": "dirsearch_tool",
            "description": (
                "Escanea rutas y directorios web con dirsearch. "
                "Devuelve solo metadatos (status, path, length, content_type, redirect), "
                "NO el cuerpo de la respuesta. Requiere --allow-network."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "URL base, ej. https://example.com"},
                    "wordlist": {
                        "type": "string",
                        "description": "Preset: quick, api, admin, backups; ruta a archivo; o lista separada por comas. Default quick.",
                    },
                    "extensions": {"type": "string", "description": "Extensiones separadas por coma, ej. php,html,js"},
                    "max_entries": {"type": "integer", "description": "Máximo de rutas a probar (default 200, cap 2000)."},
                },
                "required": ["target_url"],
            },
        },
    },
]

TOOL_MAP = {
    "run_semgrep_tool": run_semgrep_tool,
    "read_file_tool": read_file_tool,
    "gitleaks_tool": gitleaks_tool,
    "search_corpus_tool": search_corpus_tool,
    "write_report_tool": write_report_tool,
    "dirsearch_tool": dirsearch_tool,
}

# ---------- Loop ReAct ----------

def chat_with_tools(messages, force_tool=False):
    payload = {
        "model": MODEL,
        "messages": messages,
        "tools": TOOLS,
        "tool_choice": "required" if force_tool else "auto",
        "temperature": 0.0,
        "max_tokens": 900,
    }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        OLLAMA_CHAT_URL, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"\n[HTTP {e.code}] {e.reason}")
        print(f"[BODY] {body[:1000]}")
        raise


def run_agent(goal, max_iter=MAX_ITERATIONS):
    print(f"\n{'='*60}")
    print(f"OBJETIVO: {goal}")
    print(f"{'='*60}")

    seen_calls = set()

    system_prompt = (
        "Eres un agente de análisis de seguridad. Tienes herramientas disponibles. "
        "Cuando necesites información o realizar una acción, llama a la herramienta adecuada.\n\n"
        "REGLAS CRÍTICAS — VIOLARLAS INVALIDA TU RESPUESTA:\n"
        "- NUNCA inventes el contenido de un archivo. Si necesitas leer código, usa read_file_tool.\n"
        "- NUNCA afirmes que ejecutaste una acción (ej. 'reporte generado', 'archivo escrito') "
        "si no llamaste explícitamente a la herramienta correspondiente en este turno. "
        "Si necesitas escribir un reporte, USA write_report_tool — no lo describas como hecho.\n"
        "- Si el objetivo pide varias acciones, ejecútalas UNA POR UNA en iteraciones separadas, "
        "esperando el resultado de cada una.\n"
        "- NO emitas múltiples tool calls en el mismo turno si dependen entre sí.\n"
        "- Cuando uses una herramienta, cita en el resumen final: check_id, línea y severidad "
        "tal como aparecen en la observación.\n"
        "- Si el objetivo NO pide explícitamente escribir un archivo, responde con texto en el chat "
        "sin usar write_report_tool.\n"
        "- Si no puedes cumplir una parte del objetivo, dilo explícitamente."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": goal},
    ]

    previous_content = ""
    consecutive_no_action = 0

    for iteration in range(1, max_iter  + 1):
        print(f"\n--- Iteración {iteration} ---")
        response = chat_with_tools(messages, force_tool=(consecutive_no_action >= 1))
        msg = response["choices"][0]["message"]

        content = (msg.get("content") or "").strip()
        if content:
            print(f"[THOUGHT] {content[:300]}{'...' if len(content) > 300 else ''}")

        # Detección de bucle: inter-turno o intra-turno
        if is_stuck_in_loop(content, previous_content) or is_stuck_within(content):
            print("\n[ABORT] Bucle detectado (inter o intra-turno). Abortando.")
            print(f"         Último tool call exitoso: {list(seen_calls)[-1] if seen_calls else 'ninguno'}")
            return
        previous_content = content

        tool_calls = msg.get("tool_calls") or []
        fallback_list = []

        if not tool_calls:
            fallback_list = extract_tool_calls_from_text(content)
            if fallback_list:
                print(f"[FALLBACK] {len(fallback_list)} tool call(s) extraídos de texto")
                tool_calls = []
                for idx, fb in enumerate(fallback_list):
                    call_id = f"call_{iteration}_{idx}"
                    tool_calls.append({
                        "id": call_id,
                        "type": "function",
                        "function": {
                            "name": fb.get("name", ""),
                            "arguments": json.dumps(fb.get("arguments", {})),
                        },
                    })
                messages.append({
                    "role": "assistant",
                    "content": "",
                    "tool_calls": tool_calls,
                })
                consecutive_no_action = 0
            else:
                # Sin tool calls ni fallback: no hubo acción este turno
                consecutive_no_action += 1

                # Validación de archivos claimed
                claimed_files = re.findall(r"reports/[\w\-\.]+\.md", content)
                missing = [f for f in claimed_files if not Path(f).exists()]

                # 1) Archivo reclamado Y existe → objetivo cumplido
                if claimed_files and not missing:
                    print("\n[FINAL] Objetivo completado (archivos verificados).")
                    print(content)
                    return

                # Aviso si el modelo miente
                if missing:
                    print(f"\n[ALERTA] El modelo afirma haber generado {missing}, pero no existen.")
                    print("         (posible alucinación de acción)")

                # 2) Herramientas ejecutadas + 2 turnos sin acción → el modelo está resumiendo
                if consecutive_no_action >= 2 and seen_calls:
                    print(f"\n[FINAL] Resumen tras {len(seen_calls)} herramienta(s) ejecutada(s).")
                    print(content or "(respuesta vacía)")
                    return

                # 3) Sin herramientas nunca + 2 turnos sin acción → abort
                if consecutive_no_action >= 2 and not seen_calls:
                    print("\n[ABORT] Sin acción ejecutada tras reintentos. Abortando.")
                    print(content or "(respuesta vacía)")
                    return

                # Reintento con tool_choice=required
                print("[RETRY] Forzando tool call en el próximo turno.")
                messages.append({"role": "assistant", "content": content})
                messages.append({
                    "role": "user",
                    "content": "Debes llamar a una herramienta ahora. No respondas con texto sin acción.",
                })
                continue

        # Ejecutar todos los tool calls del turno
        for tc in tool_calls:
            fn = tc.get("function", {})
            name = fn.get("name")
            args = fn.get("arguments", {})

            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}

            if isinstance(args, dict):
                args = normalize_args(name, args)
            else:
                args = {}

            # Guard anti-repetición
            call_key = (name, json.dumps(args, sort_keys=True))
            if call_key in seen_calls:
                result = "(ya ejecutado antes en esta sesión con los mismos argumentos; no repetir)"
                print(f"[OBSERVATION] {result}")
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", f"call_{iteration}"),
                    "content": result,
                })
                continue
            seen_calls.add(call_key)

            print(f"[ACTION] {name}({json.dumps(args, ensure_ascii=False)})")

            if name in TOOL_MAP:
                try:
                    result = TOOL_MAP[name](**args)
                except Exception as e:
                    result = f"Error ejecutando {name}: {e}"
            else:
                result = f"Herramienta desconocida: {name}"

            print(f"[OBSERVATION] {str(result)[:300]}{'...' if len(str(result)) > 300 else ''}")

            messages.append({
                "role": "tool",
                "tool_call_id": tc.get("id", f"call_{iteration}"),
                "content": str(result),
            })

    # Se agotaron las iteraciones
    if seen_calls:
        print(f"\n[FINAL] Se agotaron {max_iter} iteraciones. "
              f"{len(seen_calls)} herramienta(s) ejecutada(s).")
    else:
        print(f"\n[LÍMITE] {max_iter} iteraciones sin ejecutar ninguna herramienta.")



if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("goal")
    parser.add_argument("--max-iter", type=int, default=MAX_ITERATIONS)
    parser.add_argument(
        "--allow-network",
        action="store_true",
        help="Permite herramientas que hacen peticiones de red (dirsearch).",
    )
    args = parser.parse_args()

    ALLOW_NETWORK = args.allow_network
    run_agent(args.goal, max_iter=args.max_iter)