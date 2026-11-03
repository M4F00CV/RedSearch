#!/usr/bin/env python3
"""
planner.py — Planner externo determinista.

Divide un objetivo complejo (4+ pasos) en sub-objetivos de 2 pasos máximo,
cada uno ejecutado por agent_tools.py en una sesión independiente.

Por qué: el 7B sostiene ≤3 pasos dependientes en un solo loop. Cada
sub-objetivo acotado a 2 pasos está probado (C1 y C2 pasaron).
"""

import json
import subprocess
import sys
from pathlib import Path

OLLAMA_CHAT = "http://localhost:11434/v1/chat/completions"
MODEL = "qwen2.5-coder:7b"
NOISE_FILES = ["agent_report.md", "agent_security_recommendations.md", "agent_report_1.md"]

def clean_noise():
    for noise in NOISE_FILES:
        p = Path("reports") / noise
        if p.exists():
            p.unlink()

def run_sub_goal(goal: str, max_iter: int = 3, timeout: int = 300, allow_network: bool = False) -> str:
    """Ejecuta agent_tools.py con un sub-objetivo y devuelve su salida."""
    cmd = [sys.executable, "agent_tools.py", goal, "--max-iter", str(max_iter)]
    if allow_network:
        cmd.append("--allow-network")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    print(f"\n{'#'*60}")
    print(f"# SUB-OBJETIVO: {goal}")
    print(f"{'#'*60}")
    try:
        result = subprocess.run(
            [sys.executable, "agent_tools.py", goal, "--max-iter", str(max_iter)],
            capture_output=True, text=True, timeout=timeout,
        )
        print(result.stdout)
        if result.returncode != 0:
            print(f"[ERROR sub-objetivo] {result.stderr[:500]}", file=sys.stderr)
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"[TIMEOUT] Sub-objetivo excedió {timeout}s")
        return ""


def extract_tool_calls_from_output(output: str):
    """Extrae los [ACTION] ejecutados del output del agente."""
    actions = []
    for line in output.splitlines():
        if line.startswith("[ACTION]"):
            actions.append(line)
    return actions


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "targets/vuln_test.py"
    report_name = "agent_vuln_test.md"
    report_path = Path("reports") / report_name

    # Limpiar reporte previo
    if report_path.exists():
        report_path.unlink()

    clean_noise()

    is_url = target.startswith(("http://", "https://"))

    if is_url:
        run_sub_goal(
            f"Escanea {target} con dirsearch_tool usando wordlist='quick' y max_entries=200. "
            f"Responde con las rutas encontradas y sus estados. NO escribas archivos.",
            max_iter=2,
            allow_network=True,
        )
        # Opcional: aquí podrías encadenar otro sub-objetivo de análisis
        return

    print(f"\n{'='*60}")
    print(f"PLANNER: análisis completo de {target}")
    print(f"{'='*60}")

    # ---- Sub-objetivo 1: DETECCIÓN (2 herramientas, independientes) ----
    # Semgrep + gitleaks: dos escaneos paralelos, sin dependencia.
    run_sub_goal(
        f"Escanea {target} con run_semgrep_tool. "
        f"Luego escanea {target} con gitleaks_tool. "
        f"Responde con un resumen en texto citando los check_id, líneas y severidades. "
        f"NO escribas archivos, solo responde en el chat.",
        max_iter=3,
    )
    clean_noise()

    # ---- Sub-objetivo 2: RAG (1 herramienta, 1 paso) ----
    # Buscar fix del CWE más común en el archivo.
    run_sub_goal(
        f"Busca en el corpus con search_corpus_tool el fix para SQL injection en Python. "
        f"Responde en texto con el CWE, el patrón vulnerable y el fix recomendado. "
        f"NO escribas archivos.",
        max_iter=2,
    )
    clean_noise()

    # ---- Sub-objetivo 3: ESCRITURA (2 pasos: semgrep + write) ----
    # Re-escanear y escribir el reporte. Semgrep ya cachea los resultados.
    run_sub_goal(
        f"Ejecuta run_semgrep_tool sobre {target}. "
        f"Después, con los hallazgos que devuelva, llama a write_report_tool "
        f"con filename='{report_name}'. "
        f"El contenido debe listar check_id, línea y severidad por hallazgo.",
        max_iter=4,
    )
    clean_noise()

    # ---- Verificación ----
    print(f"\n{'='*60}")
    if report_path.exists():
        size = report_path.stat().st_size
        print(f"[OK] Reporte generado: {report_path} ({size} bytes)")
        print(f"\n--- Contenido ---")
        print(report_path.read_text(encoding="utf-8"))
    else:
        print(f"[FALLO] {report_path} no existe.")
        print("       Ver output de sub-objetivo 3 para diagnóstico.")


if __name__ == "__main__":
    main()