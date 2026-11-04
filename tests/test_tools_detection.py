"""Unit tests for src/tools/{semgrep,gitleaks,files}.py.

Covers the three detection/I/O tools:
- semgrep.run_semgrep_tool
- gitleaks.gitleaks_tool
- files.read_file_tool, write_report_tool

subprocess.run is mocked via monkeypatch for semgrep/gitleaks.
files module uses tmp_path for real filesystem I/O.
"""

import json
from pathlib import Path

import pytest

from src.tools.files import read_file_tool, write_report_tool
from src.tools.gitleaks import gitleaks_tool
from src.tools.semgrep import run_semgrep_tool


# ---------- run_semgrep_tool ----------

class TestRunSemgrepTool:
    def test_no_findings(self, monkeypatch):
        def fake(cmd, **kw):
            class R:
                stdout = '{"results": []}'
                stderr = ""
            return R()

        monkeypatch.setattr("src.tools.semgrep.subprocess.run", fake)
        result = run_semgrep_tool("targets")
        assert "no encontró hallazgos" in result
        assert "targets" in result

    def test_with_findings(self, monkeypatch):
        fake_out = json.dumps({"results": [{
            "check_id": "rule.x",
            "path": "a.py",
            "start": {"line": 7},
            "extra": {"severity": "ERROR"},
        }]})

        def fake(cmd, **kw):
            class R:
                stdout = fake_out
                stderr = ""
            return R()

        monkeypatch.setattr("src.tools.semgrep.subprocess.run", fake)
        result = run_semgrep_tool("targets")
        assert "encontró 1 hallazgos" in result
        assert "rule.x" in result
        assert "a.py:7" in result
        assert "ERROR" in result

    def test_truncates_after_5_findings(self, monkeypatch):
        findings = [
            {
                "check_id": f"rule.{i}",
                "path": "a.py",
                "start": {"line": i},
                "extra": {"severity": "INFO"},
            }
            for i in range(10)
        ]

        def fake(cmd, **kw):
            class R:
                stdout = json.dumps({"results": findings})
                stderr = ""
            return R()

        monkeypatch.setattr("src.tools.semgrep.subprocess.run", fake)
        result = run_semgrep_tool("targets")
        assert "encontró 10 hallazgos" in result
        # Only first 5 details shown
        assert "rule.0" in result
        assert "rule.4" in result
        assert "rule.5" not in result

    def test_subprocess_exception_returns_error(self, monkeypatch):
        def fake(cmd, **kw):
            raise FileNotFoundError("semgrep not installed")

        monkeypatch.setattr("src.tools.semgrep.subprocess.run", fake)
        result = run_semgrep_tool("targets")
        assert "Error ejecutando Semgrep" in result


# ---------- gitleaks_tool ----------

class TestGitleaksTool:
    def test_no_binary(self, monkeypatch):
        monkeypatch.setattr("src.tools.gitleaks.shutil.which", lambda name: None)
        assert gitleaks_tool("targets") == "gitleaks no está instalado."

    def test_no_findings(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "src.tools.gitleaks.shutil.which", lambda name: "/fake/gitleaks"
        )

        def fake(cmd, **kw):
            idx = cmd.index("--report-path")
            Path(cmd[idx + 1]).write_text("[]")

            class R:
                returncode = 0
                stderr = ""
            return R()

        monkeypatch.setattr("src.tools.gitleaks.subprocess.run", fake)
        result = gitleaks_tool("targets")
        assert "no encontró secretos" in result

    def test_with_findings(self, monkeypatch):
        monkeypatch.setattr(
            "src.tools.gitleaks.shutil.which", lambda name: "/fake/gitleaks"
        )

        def fake(cmd, **kw):
            idx = cmd.index("--report-path")
            Path(cmd[idx + 1]).write_text(json.dumps([{
                "RuleID": "aws-key",
                "File": "config.py",
                "StartLine": 5,
                "Description": "AWS access key",
            }]))

            class R:
                returncode = 1
                stderr = ""
            return R()

        monkeypatch.setattr("src.tools.gitleaks.subprocess.run", fake)
        result = gitleaks_tool("targets")
        assert "encontró 1 secretos" in result
        assert "aws-key" in result
        assert "config.py:5" in result

    def test_unexpected_exit_code(self, monkeypatch):
        monkeypatch.setattr(
            "src.tools.gitleaks.shutil.which", lambda name: "/fake/gitleaks"
        )

        def fake(cmd, **kw):
            class R:
                returncode = 2
                stderr = "fatal error"
            return R()

        monkeypatch.setattr("src.tools.gitleaks.subprocess.run", fake)
        result = gitleaks_tool("targets")
        assert "gitleaks falló" in result
        assert "fatal error" in result

    def test_invalid_json_in_report(self, monkeypatch):
        monkeypatch.setattr(
            "src.tools.gitleaks.shutil.which", lambda name: "/fake/gitleaks"
        )

        def fake(cmd, **kw):
            idx = cmd.index("--report-path")
            Path(cmd[idx + 1]).write_text("not valid json")

            class R:
                returncode = 0
                stderr = ""
            return R()

        monkeypatch.setattr("src.tools.gitleaks.subprocess.run", fake)
        result = gitleaks_tool("targets")
        assert "reporte inválido" in result

    def test_truncates_after_5(self, monkeypatch):
        monkeypatch.setattr(
            "src.tools.gitleaks.shutil.which", lambda name: "/fake/gitleaks"
        )
        fake_data = [
            {
                "RuleID": f"rule-{i}",
                "File": "f.py",
                "StartLine": i,
                "Description": f"secret {i}",
            }
            for i in range(10)
        ]

        def fake(cmd, **kw):
            idx = cmd.index("--report-path")
            Path(cmd[idx + 1]).write_text(json.dumps(fake_data))

            class R:
                returncode = 1
                stderr = ""
            return R()

        monkeypatch.setattr("src.tools.gitleaks.subprocess.run", fake)
        result = gitleaks_tool("targets")
        assert "encontró 10 secretos" in result
        assert "rule-0" in result
        assert "rule-4" in result
        assert "rule-5" not in result

    def test_temp_file_cleanup_does_not_raise(self, monkeypatch):
        """Covers the finally block (lines 50-51): unlink failure is swallowed."""
        monkeypatch.setattr(
            "src.tools.gitleaks.shutil.which", lambda name: "/fake/gitleaks"
        )

        def fake(cmd, **kw):
            idx = cmd.index("--report-path")
            Path(cmd[idx + 1]).write_text("[]")

            class R:
                returncode = 0
                stderr = ""
            return R()

        monkeypatch.setattr("src.tools.gitleaks.subprocess.run", fake)

        # Force unlink to raise so the except branch runs
        def boom(self):
            raise OSError("permission denied")

        monkeypatch.setattr("pathlib.Path.unlink", boom)

        result = gitleaks_tool("targets")
        # Must not raise, must return normal "no findings" message
        assert "no encontró secretos" in result


# ---------- read_file_tool ----------

class TestReadFileTool:
    def test_missing_file(self, tmp_path):
        missing = tmp_path / "nope.py"
        result = read_file_tool(str(missing))
        assert "Archivo no encontrado" in result

    def test_default_reads_first_30_lines(self, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("\n".join(f"line {i}" for i in range(1, 101)))
        result = read_file_tool(str(f))
        assert "line 1" in result
        assert "line 30" in result
        assert "line 31" not in result

    def test_custom_range(self, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("\n".join(f"line {i}" for i in range(1, 21)))
        result = read_file_tool(str(f), start_line=5, num_lines=3)
        assert "line 5" in result
        assert "line 7" in result
        assert "line 4" not in result
        assert "line 8" not in result

    def test_start_line_beyond_file_returns_empty(self, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("uno\ndos\n")
        result = read_file_tool(str(f), start_line=100)
        assert result == ""

    def test_line_numbers_padded(self, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("uno\ndos\n")
        result = read_file_tool(str(f))
        assert "   1 | uno" in result
        assert "   2 | dos" in result


# ---------- write_report_tool ----------

class TestWriteReportTool:
    def test_creates_file_in_reports(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = write_report_tool("# Test", "my_report.md")
        target = tmp_path / "reports" / "my_report.md"
        assert target.exists()
        assert target.read_text(encoding="utf-8") == "# Test"
        assert "Reporte escrito en" in result
        assert "6 bytes" in result  # "# Test" = 6 chars

    def test_default_filename(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        write_report_tool("content")
        target = tmp_path / "reports" / "agent_report.md"
        assert target.exists()

    def test_creates_reports_dir_if_missing(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert not (tmp_path / "reports").exists()
        write_report_tool("x")
        assert (tmp_path / "reports").exists()

    def test_overwrites_existing_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        write_report_tool("first")
        write_report_tool("second")
        target = tmp_path / "reports" / "agent_report.md"
        assert target.read_text(encoding="utf-8") == "second"