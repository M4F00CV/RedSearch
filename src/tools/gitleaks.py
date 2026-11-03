"""gitleaks integration: detect hardcoded secrets."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path


def gitleaks_tool(target: str) -> str:
    """Scan for hardcoded secrets using gitleaks.

    Args:
        target: File or directory path to scan.

    Returns:
        Summary of secrets found (RuleID, file:line, description) or error.
    """
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