"""External planner: split complex goals into 2-step sub-goals.

The 7B model reliably handles 2-3 dependent tool calls per session
but not 4+. This planner spawns an independent agent process for
each sub-goal, avoiding context contamination across tasks.
"""

import subprocess
import sys
from pathlib import Path

NOISE_FILES = [
    "agent_report.md",
    "agent_security_recommendations.md",
    "agent_report_1.md",
]

# Project root: src/planner/planner.py -> src/planner -> src -> root
PROJECT_ROOT = Path(__file__).parent.parent.parent
AGENT_SCRIPT = PROJECT_ROOT / "agent_tools.py"


def clean_noise():
    """Delete files the model writes when it has nothing else to do."""
    for noise in NOISE_FILES:
        p = Path("reports") / noise
        if p.exists():
            p.unlink()


def run_sub_goal(goal: str, max_iter: int = 3, timeout: int = 300,
                 allow_network: bool = False) -> str:
    """Execute agent_tools.py with a single sub-goal and return stdout.

    Args:
        goal: Natural language sub-objective.
        max_iter: Hard limit on agent iterations for this sub-goal.
        timeout: Process-level timeout in seconds.
        allow_network: Pass --allow-network to the agent subprocess.

    Returns:
        Agent stdout, or empty string on timeout.
    """
    cmd = [sys.executable, str(AGENT_SCRIPT), goal, "--max-iter", str(max_iter)]
    if allow_network:
        cmd.append("--allow-network")

    print(f"\n{'#'*60}")
    print(f"# SUB-OBJETIVO: {goal}")
    print(f"{'#'*60}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        print(result.stdout)
        if result.returncode != 0:
            print(f"[ERROR sub-objetivo] {result.stderr[:500]}", file=sys.stderr)
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"[TIMEOUT] Sub-objetivo excedió {timeout}s")
        return ""


def main_cli():
    """Run the full planner workflow (code or URL target)."""
    target = sys.argv[1] if len(sys.argv) > 1 else "targets/vuln_test.py"
    report_name = "agent_vuln_test.md"
    report_path = Path("reports") / report_name

    if report_path.exists():
        report_path.unlink()
    clean_noise()

    is_url = target.startswith(("http://", "https://"))

    if is_url:
        run_sub_goal(
            f"Escanea {target} con dirsearch_tool usando wordlist='quick' y "
            f"max_entries=200. Responde con las rutas encontradas y sus "
            f"estados. NO escribas archivos.",
            max_iter=2,
            allow_network=True,
        )
        return

    print(f"\n{'='*60}")
    print(f"PLANNER: análisis completo de {target}")
    print(f"{'='*60}")

    # Sub-goal 1: detection (independent tools)
    run_sub_goal(
        f"Escanea {target} con run_semgrep_tool. "
        f"Luego escanea {target} con gitleaks_tool. "
        f"Responde con un resumen en texto citando los check_id, líneas "
        f"y severidades. NO escribas archivos, solo responde en el chat.",
        max_iter=3,
    )
    clean_noise()

    # Sub-goal 2: RAG (single lookup)
    run_sub_goal(
        f"Busca en el corpus con search_corpus_tool el fix para SQL "
        f"injection en Python. Responde en texto con el CWE, el patrón "
        f"vulnerable y el fix recomendado. NO escribas archivos.",
        max_iter=2,
    )
    clean_noise()

    # Sub-goal 3: write report (2 dependent steps)
    run_sub_goal(
        f"Ejecuta run_semgrep_tool sobre {target}. "
        f"Después, con los hallazgos que devuelva, llama a write_report_tool "
        f"con filename='{report_name}'. "
        f"El contenido debe listar check_id, línea y severidad por hallazgo.",
        max_iter=4,
    )
    clean_noise()

    # Verification
    print(f"\n{'='*60}")
    if report_path.exists():
        size = report_path.stat().st_size
        print(f"[OK] Reporte generado: {report_path} ({size} bytes)")
        print("\n--- Contenido ---")
        print(report_path.read_text(encoding="utf-8"))
    else:
        print(f"[FALLO] {report_path} no existe.")
        print("       Ver output de sub-objetivo 3 para diagnóstico.")


if __name__ == "__main__":
    main_cli()