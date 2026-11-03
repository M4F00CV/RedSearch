#!/usr/bin/env python3
"""
orchestrator.py — Orquestador mínimo de análisis de vulnerabilidades.
Semgrep (detección determinista) + Qwen2.5-Coder 3B (verificación) = reporte fusionado.

Regla de diseño: el LLM NUNCA provee línea ni ruta. Solo veredicto, confianza,
razonamiento y fix sugerido. Las coordenadas las da Semgrep.
"""

import argparse
import json
import shutil
import sqlite3
import subprocess
import sys
import urllib.request
from pathlib import Path
from datetime import datetime

import numpy as np

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5-coder:7b"
CONTEXT_LINES = 3
SEVERITY_RANK = {"ERROR": 3, "WARNING": 2, "INFO": 1}
EMBED_URL = "http://localhost:11434/api/embeddings"
EMBED_MODEL = "nomic-embed-text"
DATA_DIR = Path(__file__).parent / "data"
EMBEDDINGS = DATA_DIR / "embeddings.npy"
INDEX_DB = DATA_DIR / "index.db"
GITLEAKS_BIN = shutil.which("gitleaks")

def embed_query(text):
    payload = {"model": EMBED_MODEL, "prompt": text}
    req = urllib.request.Request(
        EMBED_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return np.array(json.loads(r.read())["embedding"], dtype=np.float32)


def retrieve(query, k=2, min_score=0.65):
    """Devuelve [(score, {cwe, name, fix, vulnerable})] top-k del corpus."""
    if not EMBEDDINGS.exists() or not INDEX_DB.exists():
        return []
    q = embed_query(query)
    q /= (np.linalg.norm(q) + 1e-8)
    vecs = np.load(EMBEDDINGS)
    vecs = vecs / (np.linalg.norm(vecs, axis=1, keepdims=True) + 1e-8)
    scores = vecs @ q
    top = np.argsort(-scores)[:k]
    conn = sqlite3.connect(INDEX_DB)
    out = []
    for i in top:
        s = float(scores[i])
        if s < min_score:
            continue
        row = conn.execute(
            "SELECT cwe, name, fix, vulnerable FROM docs WHERE id=?", (int(i),)
        ).fetchone()
        if row:
            out.append((s, {
                "cwe": row[0], "name": row[1], "fix": row[2], "vulnerable": row[3],
            }))
    conn.close()
    return out

def run_semgrep(target):
    cmd = ["semgrep", "--config=auto", "--quiet", "--json", target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"Semgrep falló:\nSTDERR: {result.stderr}\nSTDOUT: {result.stdout[:500]}", file=sys.stderr)
        sys.exit(2)


def read_fragment(path, line, context=CONTEXT_LINES):
    p = Path(path)
    if not p.exists():
        print(f"ADVERTENCIA: archivo no encontrado: {path}", file=sys.stderr)
        return f"<<archivo no encontrado: {path}>>"
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    out = []
    for i in range(start, end):
        marker = ">>" if (i + 1) == line else "  "
        out.append(f"{marker} {i+1:4d} | {lines[i]}")
    return "\n".join(out)


def call_ollama(prompt, timeout=300):
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1, "num_predict": 500, "num_ctx": 4096},
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(OLLAMA_URL, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    return body.get("response", "")


def build_prompt(check_ids, cwe, message, fragment, stack, lang, refs):
    rules_txt = "\n".join(f"- {r}" for r in check_ids)
    if refs:
        refs_txt = "\n\n".join(
            f"[{r['cwe']} — {r['name']}] (similitud {score:.2f})\n"
            f"  Patrón vulnerable: {r['vulnerable']}\n"
            f"  Fix recomendado: {r['fix']}"
            for score, r in refs
        )
    else:
        refs_txt = "(sin referencias del corpus; describe el cambio conceptual, no inventes APIs)"

    lang_note = (
        f"LENGUAJE DEL FRAGMENTO: {lang}. El suggested_fix DEBE estar escrito en {lang}."
        if lang != "generic"
        else "LENGUAJE DEL FRAGMENTO: inferido del código. Adapta el fix a ese lenguaje."
    )

    return f"""Eres un analista de seguridad. Verificas un hallazgo de Semgrep. Debes decidir si el CÓDIGO es vulnerable, NO si la regla es perfecta.

Stack del proyecto: {stack}
{lang_note}

Reglas activadas:
{rules_txt}

CWE: {cwe}
Mensaje de Semgrep: {message}

Código (>> = línea reportada):
{fragment}

REFERENCIA (usa estos patrones para construir el suggested_fix):
{refs_txt}

Proceso obligatorio:
PASO 1 — Analiza el código. ¿Hay input controlable por el usuario que llega sin sanitizar a una operación peligrosa (eval, SQL, redirect, exec)? Si SÍ, es true_positive aunque la regla esté mal etiquetada.
PASO 2 — Solo si el código claramente NO es vulnerable, revisa si la regla es incompatible con el lenguaje del proyecto.

Responde SOLO JSON:
{{"verdict": "true_positive|false_positive|uncertain", "confidence": "high|medium|low", "reasoning": "por qué, en 1-2 frases en español", "suggested_fix": "fix CONCRETO con código, en el lenguaje del fragmento. Vacío si FP"}}

Reglas estrictas:
- El suggested_fix debe ser CÓDIGO concreto, no descripción. Si el fragmento tiene N variables controlables, escribe N líneas (una por variable).
- Usa la misma FORMA de la REFERENCIA (parseFloat, process.env, whitelist, prepared statement), pero adaptada a las variables, tipos y LENGUAJE del fragmento.
- Preserva los valores exactos del fragmento (URLs, nombres de variables, strings). Aplica el cambio mínimo.
- NUNCA uses el lenguaje de la referencia si difiere del fragmento: fragmento Python → fix Python (os.environ); fragmento JS → fix JS (process.env); fragmento HTML → fix HTML.
- Si la REFERENCIA está vacía, describe el cambio conceptual en lugar de inventar APIs o funciones que no conoces.
- NO menciones nombres de archivo ni contenido que no aparezca en el fragmento.
- Si el código es vulnerable, es true_positive aunque la regla esté mal etiquetada.
- Ante duda real, uncertain (no false_positive por defecto)."""


def validate_llm_response(llm):
    required = {"verdict", "confidence", "reasoning", "suggested_fix"}
    if not isinstance(llm, dict):
        raise ValueError(f"Respuesta no es dict: {type(llm)}")
    missing = required - llm.keys()
    if missing:
        raise ValueError(f"Faltan claves: {missing}")
    if llm["verdict"] not in {"true_positive", "false_positive", "uncertain"}:
        raise ValueError(f"verdict inválido: {llm['verdict']}")
    if llm["confidence"] not in {"high", "medium", "low"}:
        raise ValueError(f"confidence inválida: {llm['confidence']}")


def detect_stack(target):
    """Detecta el stack del proyecto por archivos indicadores."""
    t = Path(target).resolve()
    root = t if t.is_dir() else t.parent
    for _ in range(4):
        if (root / "package.json").exists():
            return "Node.js/JavaScript (package.json encontrado)"
        if (root / "requirements.txt").exists() or (root / "pyproject.toml").exists():
            return "Python (requirements.txt o pyproject.toml encontrado)"
        if (root / "go.mod").exists():
            return "Go (go.mod encontrado)"
        root = root.parent
    return "desconocido (no se encontró archivo indicador)"

def detect_language(path):
    """Detecta el lenguaje por extensión de archivo (fallback de stack)."""
    ext = Path(path).suffix.lower()
    return {
        ".py": "python",
        ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
        ".ts": "typescript", ".jsx": "javascript", ".tsx": "typescript",
        ".go": "go", ".rb": "ruby", ".php": "php", ".java": "java",
        ".rs": "rust", ".cs": "csharp", ".kt": "kotlin",
    }.get(ext, "generic")


def is_rule_compatible(check_id, stack):
    """Filtro heurístico: descarta reglas cuyo namespace no corresponde al stack."""
    if check_id.startswith("gitleaks."):
        return True  
    stack_lower = stack.lower()
    if "node" in stack_lower and check_id.startswith("python."):
        return False
    if "python" in stack_lower and check_id.startswith(("javascript.", "typescript.")):
        return False
    return True

def verify(grouped, stack):
    meta = grouped.get("metadata", {})
    cwe_raw = (meta.get("cwe") or ["desconocido"])[0]
    cwe = cwe_raw if len(cwe_raw) > 3 else "desconocido"

    compatible_ids = [c for c in grouped["check_ids"] if is_rule_compatible(c, stack)]
    if not compatible_ids:
        llm = {
            "verdict": "false_positive",
            "confidence": "high",
            "reasoning": f"Ninguna regla es compatible con el stack ({stack}): {grouped['check_ids']}",
            "suggested_fix": "",
        }
        return {
            "file": grouped["path"],
            "line": grouped["start"]["line"],
            "check_ids": grouped["check_ids"],
            "semgrep_severity": grouped["max_severity"],
            "cwe": cwe,
            "llm": llm,
            "skipped_llm": True,
            "refs_used": [],
        }

    lang = detect_language(grouped["path"])
    query = f"{cwe} {lang} {grouped.get('message', '')} {' '.join(compatible_ids)}"
    refs = retrieve(query, k=2)

    fragment = read_fragment(grouped["path"], grouped["start"]["line"])
    prompt = build_prompt(compatible_ids, cwe, grouped.get("message", ""), fragment, stack, lang, refs)
    try:
        llm = json.loads(call_ollama(prompt))
        validate_llm_response(llm)
    except Exception as e:
        llm = {"verdict": "uncertain", "confidence": "low",
               "reasoning": f"Error LLM: {e}", "suggested_fix": ""}

    return {
        "file": grouped["path"],
        "line": grouped["start"]["line"],
        "check_ids": grouped["check_ids"],
        "semgrep_severity": grouped["max_severity"],
        "cwe": cwe,
        "llm": llm,
        "skipped_llm": False,
        "refs_used": [{"cwe": r["cwe"], "name": r["name"], "score": round(s, 3)} for s, r in refs],
    }

def dedup(findings):
    grouped = {}
    for f in findings:
        key = (f["path"], f["start"]["line"])
        if key not in grouped:
            grouped[key] = {
                "path": f["path"],
                "start": f["start"],
                "check_ids": [f["check_id"]],
                "max_severity": f["extra"].get("severity", "INFO"),
                "message": f["extra"].get("message", ""),
                "metadata": f["extra"].get("metadata", {}),
            }
        else:
            g = grouped[key]
            if f["check_id"] not in g["check_ids"]:
                g["check_ids"].append(f["check_id"])
            sev = f["extra"].get("severity", "INFO")
            if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(g["max_severity"], 0):
                g["max_severity"] = sev
    return list(grouped.values())


def parse_args():
    parser = argparse.ArgumentParser(
        description="Semgrep + Qwen2.5-Coder: detección determinista con verificación LLM."
    )
    parser.add_argument("target", help="Archivo o directorio a escanear")
    parser.add_argument("--max", type=int, default=10,
                        help="Máximo de hallazgos a verificar con LLM (default: 10)")
    parser.add_argument("--min-severity", choices=["ERROR", "WARNING", "INFO"], default="INFO",
                        help="Severidad mínima para verificar (default: INFO)")
    args = parser.parse_args()
    if args.max <= 0:
        parser.error("--max debe ser > 0")
    return args

def run_gitleaks(target):
    """Ejecuta gitleaks (>=8.16) con 'detect --no-git' y normaliza al formato Semgrep."""
    if not GITLEAKS_BIN:
        print("ADVERTENCIA: gitleaks no está instalado. Omitiendo escaneo de secretos.", file=sys.stderr)
        return []

    report_path = Path("reports") / "gitleaks_raw.json"
    report_path.parent.mkdir(exist_ok=True)

    cmd = [
        GITLEAKS_BIN, "detect",
        "--source", target,
        "--no-git",
        "--report-format", "json",
        "--report-path", str(report_path),
        "--no-banner",
        "--redact",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    if result.returncode not in (0, 1):
        print(f"gitleaks falló (exit {result.returncode}):\n{result.stderr[:500]}", file=sys.stderr)
        return []

    if not report_path.exists():
        print("      gitleaks: 0 hallazgos (sin reporte generado)")
        return []

    try:
        raw = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print("      gitleaks: reporte JSON inválido", file=sys.stderr)
        return []

    normalized = []
    for f in raw:
        normalized.append({
            "check_id": f"gitleaks.{f.get('RuleID', 'unknown')}",
            "path": f.get("File", ""),
            "start": {"line": f.get("StartLine", 0)},
            "extra": {
                "severity": "ERROR",
                "message": f.get("Description", "Secret detected"),
                "metadata": {
                    "cwe": ["CWE-798: Use of hard-coded Credentials"],
                    "tool": "gitleaks",
                    "rule_id": f.get("RuleID", ""),
                },
            },
        })
    print(f"      {len(normalized)} hallazgos de gitleaks (secretos)")
    return normalized


def main():
    args = parse_args()

    stack = detect_stack(args.target)
    print(f"[1/4] Semgrep sobre {args.target}...")
    print(f"      Stack detectado: {stack}")

    semgrep_result = run_semgrep(args.target)
    semgrep_findings = semgrep_result.get("results", [])
    print(f"      {len(semgrep_findings)} hallazgos de Semgrep")

    gitleaks_findings = run_gitleaks(args.target)
    findings = semgrep_findings + gitleaks_findings
    print(f"      {len(findings)} hallazgos totales (Semgrep + gitleaks)")

    if not findings:
        print("Sin hallazgos. Fin.")
        return

    unique = dedup(findings)
    print(f"      {len(unique)} únicos tras dedup (file+line)")

    NOISE_PATH_PATTERNS = [
        "/tutorial/", "/docs/", "/test/", "/tests/", "/examples/",
        "/.github/workflows/",    
    ]
    unique = [g for g in unique if not any(p in g["path"] for p in NOISE_PATH_PATTERNS)]
    print(f"      {len(unique)} tras filtrar rutas de ruido")

    min_rank = SEVERITY_RANK[args.min_severity]
    unique = [g for g in unique if SEVERITY_RANK.get(g["max_severity"], 0) >= min_rank]
    print(f"      {len(unique)} tras filtro --min-severity {args.min_severity}")

    unique = unique[:args.max]
    print(f"      {len(unique)} a verificar (--max {args.max})")

    print(f"[2/4] Verificando con {MODEL}...")
    verified = []
    for i, g in enumerate(unique, 1):
        print(f"      [{i}/{len(unique)}] {g['max_severity']} @ {g['path']}:{g['start']['line']} ({len(g['check_ids'])} reglas)")
        verified.append(verify(g, stack))

    print("[3/4] Escribiendo reporte...")
    report = {
        "generated_at": datetime.now().isoformat(),
        "target": args.target,
        "model": MODEL,
        "stack": stack,
        "min_severity": args.min_severity,
        "total_findings": len(verified),
        "findings": verified,
    }
    Path("reports").mkdir(exist_ok=True)
    out = Path("reports") / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"      → {out}")
    print("[4/4] Listo.")


if __name__ == "__main__":
    main()