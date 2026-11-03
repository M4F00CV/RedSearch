"""Unit tests for src/orchestrator/pipeline.py and src/orchestrator/report_md.py.

Covers:
- dedup: single, merge same (file,line), severity upgrade, dedup of
  identical check_ids, separate on different lines/files
- parse_args: defaults, custom flags, --max=0 rejected
- run_semgrep: valid JSON, invalid JSON → SystemExit
- run_gitleaks: no binary, no findings, normalizes findings, unexpected exit
- render_summary_table: header, TP/FP/uncertain counts, unknown CWE
- render_finding_detail: basic, with/without fix, skipped_llm note, refs
- generate_md: full structure, missing stack field default

subprocess.run mocked via monkeypatch. CWD changed to tmp_path so
"reports/" resolves inside the sandbox.
"""

import json
from pathlib import Path

import pytest

from src.orchestrator.pipeline import (
    dedup,
    parse_args,
    run_gitleaks,
    run_semgrep,
)
from src.orchestrator.report_md import (
    generate_md,
    render_finding_detail,
    render_summary_table,
)


# ---------- helpers ----------

def _finding(path="a.py", line=1, check_id="rule.a", severity="ERROR"):
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line},
        "extra": {
            "severity": severity,
            "message": f"msg for {check_id}",
            "metadata": {"cwe": ["CWE-1"]},
        },
    }


def _verified(
    file_path="a.py",
    verdict="true_positive",
    severity="ERROR",
    cwe="CWE-89: SQL Injection",
    with_fix=True,
    with_refs=False,
    skipped=False,
):
    return {
        "file": file_path,
        "line": 2,
        "check_ids": ["rule.a"],
        "semgrep_severity": severity,
        "cwe": cwe,
        "llm": {
            "verdict": verdict,
            "confidence": "high",
            "reasoning": "razonamiento de prueba",
            "suggested_fix": "fix code" if with_fix else "",
        },
        "skipped_llm": skipped,
        "refs_used": (
            [{"cwe": "CWE-89", "name": "SQLi", "score": 0.75}]
            if with_refs else []
        ),
    }


# ---------- dedup ----------

class TestDedup:
    def test_empty(self):
        assert dedup([]) == []

    def test_single(self):
        result = dedup([_finding()])
        assert len(result) == 1
        assert result[0]["path"] == "a.py"
        assert result[0]["check_ids"] == ["rule.a"]
        assert result[0]["max_severity"] == "ERROR"

    def test_two_rules_same_line_merged(self):
        f1 = _finding(check_id="rule.a", severity="WARNING")
        f2 = _finding(check_id="rule.b", severity="ERROR")
        result = dedup([f1, f2])
        assert len(result) == 1
        assert sorted(result[0]["check_ids"]) == ["rule.a", "rule.b"]
        assert result[0]["max_severity"] == "ERROR"

    def test_duplicate_check_id_not_repeated(self):
        result = dedup([_finding(check_id="rule.a"), _finding(check_id="rule.a")])
        assert len(result) == 1
        assert result[0]["check_ids"] == ["rule.a"]

    def test_different_lines_kept_separate(self):
        result = dedup([_finding(line=1), _finding(line=2)])
        assert len(result) == 2

    def test_different_files_kept_separate(self):
        result = dedup([_finding(path="a.py"), _finding(path="b.py")])
        assert len(result) == 2

    def test_severity_upgrade_warning_to_error(self):
        f1 = _finding(check_id="rule.a", severity="WARNING")
        f2 = _finding(check_id="rule.b", severity="ERROR")
        assert dedup([f1, f2])[0]["max_severity"] == "ERROR"

    def test_severity_not_downgraded(self):
        f1 = _finding(check_id="rule.a", severity="ERROR")
        f2 = _finding(check_id="rule.b", severity="INFO")
        assert dedup([f1, f2])[0]["max_severity"] == "ERROR"


# ---------- parse_args ----------

class TestParseArgs:
    def test_defaults(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog", "targets/foo"])
        args = parse_args()
        assert args.target == "targets/foo"
        assert args.max == 10
        assert args.min_severity == "INFO"

    def test_custom_flags(self, monkeypatch):
        monkeypatch.setattr(
            "sys.argv",
            ["prog", "targets/foo", "--max", "5", "--min-severity", "WARNING"],
        )
        args = parse_args()
        assert args.max == 5
        assert args.min_severity == "WARNING"

    def test_max_zero_exits(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog", "foo", "--max", "0"])
        with pytest.raises(SystemExit):
            parse_args()


# ---------- run_semgrep ----------

class TestRunSemgrep:
    def test_valid_json_returned(self, monkeypatch):
        def fake_subprocess(cmd, **kwargs):
            class R:
                stdout = '{"results": [{"check_id": "r1"}]}'
                stderr = ""
            return R()

        monkeypatch.setattr(
            "src.orchestrator.pipeline.subprocess.run", fake_subprocess
        )
        result = run_semgrep("targets")
        assert result == {"results": [{"check_id": "r1"}]}

    def test_invalid_json_exits(self, monkeypatch):
        def fake_subprocess(cmd, **kwargs):
            class R:
                stdout = "not valid json"
                stderr = "semgrep error"
            return R()

        monkeypatch.setattr(
            "src.orchestrator.pipeline.subprocess.run", fake_subprocess
        )
        with pytest.raises(SystemExit) as exc_info:
            run_semgrep("targets")
        assert exc_info.value.code == 2


# ---------- run_gitleaks ----------

class TestRunGitleaks:
    def test_no_binary(self, monkeypatch):
        monkeypatch.setattr("src.orchestrator.pipeline.GITLEAKS_BIN", None)
        assert run_gitleaks("targets") == []

    def test_no_findings(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        def fake_subprocess(cmd, **kwargs):
            idx = cmd.index("--report-path")
            Path(cmd[idx + 1]).write_text("[]")

            class R:
                returncode = 0
                stderr = ""
            return R()

        monkeypatch.setattr(
            "src.orchestrator.pipeline.GITLEAKS_BIN", "/fake/gitleaks"
        )
        monkeypatch.setattr(
            "src.orchestrator.pipeline.subprocess.run", fake_subprocess
        )
        assert run_gitleaks("targets") == []

    def test_normalizes_findings(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        fake_data = [{
            "RuleID": "aws-key",
            "File": "config.py",
            "StartLine": 5,
            "Description": "AWS access key",
        }]

        def fake_subprocess(cmd, **kwargs):
            idx = cmd.index("--report-path")
            Path(cmd[idx + 1]).write_text(json.dumps(fake_data))

            class R:
                returncode = 1  # 1 = findings present
                stderr = ""
            return R()

        monkeypatch.setattr(
            "src.orchestrator.pipeline.GITLEAKS_BIN", "/fake/gitleaks"
        )
        monkeypatch.setattr(
            "src.orchestrator.pipeline.subprocess.run", fake_subprocess
        )

        result = run_gitleaks("targets")
        assert len(result) == 1
        assert result[0]["check_id"] == "gitleaks.aws-key"
        assert result[0]["path"] == "config.py"
        assert result[0]["start"]["line"] == 5
        assert result[0]["extra"]["severity"] == "ERROR"
        assert "CWE-798" in result[0]["extra"]["metadata"]["cwe"][0]

    def test_unexpected_exit_code(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        def fake_subprocess(cmd, **kwargs):
            class R:
                returncode = 2
                stderr = "boom"
            return R()

        monkeypatch.setattr(
            "src.orchestrator.pipeline.GITLEAKS_BIN", "/fake/gitleaks"
        )
        monkeypatch.setattr(
            "src.orchestrator.pipeline.subprocess.run", fake_subprocess
        )
        assert run_gitleaks("targets") == []


# ---------- render_summary_table ----------

class TestRenderSummaryTable:
    def test_header_present(self):
        result = render_summary_table([_verified()])
        assert "| # | Severidad | Archivo:línea | CWE | Veredicto | Confianza |" in result

    def test_single_tp_counted(self):
        result = render_summary_table([_verified()])
        assert "🔴 1 vulnerables" in result
        assert "🟢 0 falsos positivos" in result
        assert "🟡 0 inciertos" in result

    def test_mixed_verdicts(self):
        findings = [
            _verified(verdict="true_positive"),
            _verified(verdict="false_positive"),
            _verified(verdict="uncertain"),
        ]
        result = render_summary_table(findings)
        assert "🔴 1 vulnerables" in result
        assert "🟢 1 falsos positivos" in result
        assert "🟡 1 inciertos" in result

    def test_unknown_cwe_shows_dash(self):
        result = render_summary_table([_verified(cwe="desconocido")])
        assert "—" in result

    def test_known_cwe_shows_only_id(self):
        result = render_summary_table([_verified(cwe="CWE-89: SQL Injection")])
        assert "CWE-89" in result
        assert "SQL Injection" not in result  # solo el ID en la tabla


# ---------- render_finding_detail ----------

class TestRenderFindingDetail:
    def test_basic(self, tmp_path):
        sample = tmp_path / "sample.py"
        sample.write_text("l1\nl2\nl3\n")
        result = render_finding_detail(1, _verified(file_path=str(sample)))
        assert "### 1." in result
        assert "sample.py" in result
        assert "CWE-89" in result
        assert "razonamiento de prueba" in result

    def test_with_fix(self, tmp_path):
        sample = tmp_path / "sample.py"
        sample.write_text("l1\nl2\nl3\n")
        result = render_finding_detail(
            1, _verified(file_path=str(sample), with_fix=True)
        )
        assert "**Fix sugerido:**" in result
        assert "fix code" in result

    def test_without_fix(self, tmp_path):
        sample = tmp_path / "sample.py"
        sample.write_text("l1\nl2\nl3\n")
        result = render_finding_detail(
            1, _verified(file_path=str(sample), with_fix=False)
        )
        assert "**Fix sugerido:**" not in result

    def test_skipped_llm_note(self, tmp_path):
        sample = tmp_path / "sample.py"
        sample.write_text("l1\nl2\nl3\n")
        result = render_finding_detail(
            1, _verified(file_path=str(sample), skipped=True)
        )
        assert "verificación LLM omitida" in result

    def test_with_refs(self, tmp_path):
        sample = tmp_path / "sample.py"
        sample.write_text("l1\nl2\nl3\n")
        result = render_finding_detail(
            1, _verified(file_path=str(sample), with_refs=True)
        )
        assert "Referencias RAG" in result
        assert "CWE-89 (0.75)" in result


# ---------- generate_md ----------

class TestGenerateMd:
    def _report(self, tmp_path, stack="Python", min_severity="WARNING"):
        sample = tmp_path / "sample.py"
        sample.write_text("l1\nl2\nl3\n")
        finding = _verified(file_path=str(sample))
        report = {
            "generated_at": "2026-11-03T12:00:00",
            "target": "targets/foo",
            "model": "qwen2.5-coder:7b",
            "min_severity": min_severity,
            "findings": [finding],
        }
        if stack is not None:
            report["stack"] = stack
        return report

    def test_full_structure(self, tmp_path):
        result = generate_md(self._report(tmp_path))
        assert "# Reporte de Análisis de Seguridad" in result
        assert "targets/foo" in result
        assert "qwen2.5-coder:7b" in result
        assert "Python" in result
        assert "WARNING" in result
        assert "## Resumen" in result
        assert "## Hallazgos detallados" in result
        assert "_Generado por orchestrator.py + report_to_md.py_" in result

    def test_missing_stack_defaults(self, tmp_path):
        result = generate_md(self._report(tmp_path, stack=None))
        assert "desconocido" in result

    def test_missing_min_severity_defaults(self, tmp_path):
        report = self._report(tmp_path)
        report.pop("min_severity", None)
        result = generate_md(report)
        assert "INFO" in result

    def test_convert_json_to_md_roundtrip(self, tmp_path, monkeypatch):
        """Covers convert_json_to_md end-to-end."""
        from src.orchestrator.report_md import convert_json_to_md
        sample = tmp_path / "sample.py"
        sample.write_text("l1\nl2\nl3\n")
        finding = _verified(file_path=str(sample))
        report = {
            "generated_at": "2026-11-03T12:00:00",
            "target": "targets/foo",
            "model": "m",
            "stack": "Python",
            "min_severity": "INFO",
            "findings": [finding],
        }
        json_path = tmp_path / "report_test.json"
        json_path.write_text(json.dumps(report), encoding="utf-8")
        md_path = convert_json_to_md(json_path)
        assert md_path.exists()
        assert md_path.read_text(encoding="utf-8").startswith(
            "# Reporte de Análisis de Seguridad"
        )