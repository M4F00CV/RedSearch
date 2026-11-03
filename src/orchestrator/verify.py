"""Verification of individual findings using LLM + RAG context.

Each finding from Semgrep or gitleaks is sent to the LLM along with
the code fragment, relevant CWE references from the RAG corpus, and
the project stack. The LLM returns a verdict (true_positive,
false_positive, uncertain), confidence level, reasoning, and a
concrete suggested fix.

Design rule: the LLM never provides line numbers or file paths.
Coordinates come from the deterministic tool (Semgrep/gitleaks).
"""

import json
import sys
from pathlib import Path

from src.core.llm import call_ollama
from src.core.utils import read_fragment_optional
from src.rag.retrieve import retrieve

SEVERITY_RANK = {"ERROR": 3, "WARNING": 2, "INFO": 1}
CONTEXT_LINES = 3


def detect_stack(target: str) -> str:
    """Detect project stack from indicator files (package.json, etc.)."""
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


def detect_language(path: str) -> str:
    """Detect language by file extension (fallback for stack detection)."""
    ext = Path(path).suffix.lower()
    return {
        ".py": "python",
        ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
        ".ts": "typescript", ".jsx": "javascript", ".tsx": "typescript",
        ".go": "go", ".rb": "ruby", ".php": "php", ".java": "java",
        ".rs": "rust", ".cs": "csharp", ".kt": "kotlin",
    }.get(ext, "generic")


def is_rule_compatible(check_id: str, stack: str) -> bool:
    """Discard rules whose namespace mismatches the stack.

    gitleaks rules apply to any stack. Django rules in a Node project
    are false positives even if the pattern matches.
    """
    if check_id.startswith("gitleaks."):
        return True
    stack_lower = stack.lower()
    if "node" in stack_lower and check_id.startswith("python."):
        return False
    if "python" in stack_lower and check_id.startswith(("javascript.", "typescript.")):
        return False
    return True


def validate_llm_response(llm):
    """Ensure the LLM response has the expected shape before accepting it."""
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


def build_prompt(check_ids, cwe, message, fragment, stack, lang, refs):
    """Build the verification prompt for the LLM."""
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


def verify(grouped, stack):
    """Verify a single grouped finding (multiple rules on same line)."""
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

    frag = read_fragment_optional(grouped["path"], grouped["start"]["line"], CONTEXT_LINES)
    if frag is None:
        print(f"ADVERTENCIA: archivo no encontrado: {grouped['path']}", file=sys.stderr)
        frag = f"<<archivo no encontrado: {grouped['path']}>>"

    prompt = build_prompt(compatible_ids, cwe, grouped.get("message", ""), frag, stack, lang, refs)
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