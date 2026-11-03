"""Markdown report generation from orchestrator JSON output."""

import json
import sys
from pathlib import Path

from src.core.utils import read_fragment_optional

VERDICT_ICON = {
    "true_positive": "🔴",
    "false_positive": "🟢",
    "uncertain": "🟡",
}
VERDICT_LABEL = {
    "true_positive": "Vulnerable",
    "false_positive": "Falso positivo",
    "uncertain": "Incierto",
}
SEVERITY_ICON = {"ERROR": "❗", "WARNING": "⚠️", "INFO": "ℹ️"}


def render_summary_table(findings):
    tp = sum(1 for f in findings if f["llm"]["verdict"] == "true_positive")
    fp = sum(1 for f in findings if f["llm"]["verdict"] == "false_positive")
    un = sum(1 for f in findings if f["llm"]["verdict"] == "uncertain")
    rows = [
        "| # | Severidad | Archivo:línea | CWE | Veredicto | Confianza |",
        "|---|---|---|---|---|---|",
    ]
    for i, f in enumerate(findings, 1):
        v_icon = VERDICT_ICON.get(f["llm"]["verdict"], "?")
        s_icon = SEVERITY_ICON.get(f["semgrep_severity"], "")
        cwe = f["cwe"].split(":")[0] if f["cwe"] != "desconocido" else "—"
        rows.append(
            f"| {i} | {s_icon} {f['semgrep_severity']} | "
            f"`{f['file']}:{f['line']}` | {cwe} | "
            f"{v_icon} {VERDICT_LABEL.get(f['llm']['verdict'], f['llm']['verdict'])} | "
            f"{f['llm']['confidence']} |"
        )
    rows.append("")
    rows.append(f"**Total**: {len(findings)} | "
                f"🔴 {tp} vulnerables | 🟢 {fp} falsos positivos | 🟡 {un} inciertos")
    return "\n".join(rows)


def render_finding_detail(idx, f):
    v = f["llm"]
    lines = [
        f"### {idx}. `{f['file']}:{f['line']}`",
        "",
        f"- **Severidad**: {f['semgrep_severity']}",
        f"- **CWE**: {f['cwe']}",
        f"- **Veredicto**: {VERDICT_ICON.get(v['verdict'], '?')} "
        f"**{VERDICT_LABEL.get(v['verdict'], v['verdict'])}** "
        f"(confianza: {v['confidence']})",
        f"- **Reglas activadas**: {', '.join(f'`{c}`' for c in f['check_ids'])}",
    ]
    if f.get("skipped_llm"):
        lines.append("- **Nota**: verificación LLM omitida (regla incompatible con el stack)")
    if f.get("refs_used"):
        refs_txt = ", ".join(f"{r['cwe']} ({r['score']})" for r in f["refs_used"])
        lines.append(f"- **Referencias RAG**: {refs_txt}")

    lines.append("")
    lines.append("**Código:**")
    lines.append("```")
    frag = read_fragment_optional(f["file"], f["line"], context=3)
    lines.append(frag if frag is not None else f"_(archivo no accesible: {f['file']})_")
    lines.append("```")
    lines.append("")
    lines.append("**Razonamiento:**")
    lines.append(f"> {v['reasoning']}")
    lines.append("")

    if v.get("suggested_fix"):
        lines.append("**Fix sugerido:**")
        lines.append("```")
        lines.append(v["suggested_fix"])
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


def generate_md(report):
    findings = report["findings"]
    md = [
        f"# Reporte de Análisis de Seguridad",
        "",
        f"- **Fecha**: {report['generated_at']}",
        f"- **Target**: `{report['target']}`",
        f"- **Modelo**: `{report['model']}`",
        f"- **Stack detectado**: {report.get('stack', 'desconocido')}",
        f"- **Severidad mínima**: {report.get('min_severity', 'INFO')}",
        "",
        "## Resumen",
        "",
        render_summary_table(findings),
        "",
        "---",
        "",
        "## Hallazgos detallados",
        "",
    ]
    for i, f in enumerate(findings, 1):
        md.append(render_finding_detail(i, f))
        md.append("---")
        md.append("")

    md.append("_Generado por orchestrator.py + report_to_md.py_")
    return "\n".join(md)


def convert_json_to_md(in_path: Path) -> Path:
    """Convert a single report JSON file to Markdown.

    Args:
        in_path: Path to report_YYYYMMDD_HHMMSS.json.

    Returns:
        Path to the generated .md file.
    """
    report = json.loads(in_path.read_text(encoding="utf-8"))
    md = generate_md(report)
    out_path = in_path.with_suffix(".md")
    out_path.write_text(md, encoding="utf-8")
    return out_path


def main_cli():
    """CLI entry point for report conversion."""
    if len(sys.argv) < 2:
        print("Uso: python3 report_to_md.py <report.json> [<report2.json> ...]", file=sys.stderr)
        sys.exit(1)

    for arg in sys.argv[1:]:
        in_path = Path(arg)
        if not in_path.exists():
            print(f"No existe: {in_path}", file=sys.stderr)
            continue
        out = convert_json_to_md(in_path)
        print(f"→ {out}")