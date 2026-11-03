"""Semgrep integration: static analysis of source code."""

import json
import subprocess


def run_semgrep_tool(target: str) -> str:
    """Run Semgrep on a file or directory and return a summary.

    Args:
        target: File or directory path to scan.

    Returns:
        Summary of findings (check_id, path:line, severity) or error message.
    """
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