"""Deterministic security pipeline: detect + verify + report.

Coordinates Semgrep (SAST), gitleaks (secrets), deduplication,
noise filtering, and LLM verification for each finding. Outputs a
timestamped JSON report to reports/.
"""

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
import os

from src.orchestrator.verify import detect_stack, verify, SEVERITY_RANK

DEFAULT_MODEL = "qwen2.5-coder:7b"
GITLEAKS_BIN = shutil.which("gitleaks")

NOISE_PATH_PATTERNS = [
    "/tutorial/", "/docs/", "/test/", "/tests/", "/examples/",
    "/.github/workflows/",
]


def run_semgrep(target):
    """Run Semgrep with configurable rulesets.

    SEMGREP_CONFIGS env var (space-separated) or 'auto'.
    --no-git-ignore is required because the benchmark subset lives
    in a .gitignore'd directory.
    """
    configs = os.environ.get("SEMGREP_CONFIGS", "auto").split()
    cmd = ["semgrep"]
    for c in configs:
        cmd.append(f"--config={c}")
    cmd.extend(["--no-git-ignore", "--quiet", "--json", target])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"Semgrep falló:\nSTDERR: {result.stderr}\nSTDOUT: {result.stdout[:500]}", file=sys.stderr)
        sys.exit(2)


def run_gitleaks(target):
    """Run gitleaks and return normalized findings (Semgrep-compatible shape)."""
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


def dedup(findings):
    """Group findings by (file, line) and merge multiple rules on same line."""
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


def main():
    """Run the full pipeline: detect → dedup → filter → verify → write JSON."""
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

    unique = [g for g in unique if not any(p in g["path"] for p in NOISE_PATH_PATTERNS)]
    print(f"      {len(unique)} tras filtrar rutas de ruido")

    min_rank = SEVERITY_RANK[args.min_severity]
    unique = [g for g in unique if SEVERITY_RANK.get(g["max_severity"], 0) >= min_rank]
    print(f"      {len(unique)} tras filtro --min-severity {args.min_severity}")

    unique = unique[:args.max]
    print(f"      {len(unique)} a verificar (--max {args.max})")

    print(f"[2/4] Verificando con {DEFAULT_MODEL}...")
    verified = []
    for i, g in enumerate(unique, 1):
        print(f"      [{i}/{len(unique)}] {g['max_severity']} @ {g['path']}:{g['start']['line']} ({len(g['check_ids'])} reglas)")
        verified.append(verify(g, stack))

    print("[3/4] Escribiendo reporte...")
    report = {
        "generated_at": datetime.now().isoformat(),
        "target": args.target,
        "model": DEFAULT_MODEL,
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