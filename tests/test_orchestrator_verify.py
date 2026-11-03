"""Unit tests for src/orchestrator/verify.py.

Covers: is_rule_compatible, detect_language, detect_stack,
validate_llm_response, and verify() with mocked LLM + RAG.

Mocks:
- monkeypatch src.orchestrator.verify.call_ollama  (LLM)
- monkeypatch src.orchestrator.verify.retrieve     (RAG)

Both are imported into verify's namespace via `from X import Y`, so
we patch the names as seen from verify.py, not the originals.
"""

import json

import pytest

from src.orchestrator.verify import (
    build_prompt,
    detect_language,
    detect_stack,
    is_rule_compatible,
    validate_llm_response,
    verify,
)


# ---------- is_rule_compatible ----------

class TestIsRuleCompatible:
    def test_gitleaks_always_compatible(self):
        assert is_rule_compatible("gitleaks.aws-key", "Node.js") is True
        assert is_rule_compatible("gitleaks.aws-key", "Python") is True
        assert is_rule_compatible("gitleaks.aws-key", "desconocido") is True

    def test_node_stack_rejects_python_rules(self):
        assert is_rule_compatible(
            "python.django.security.csrf", "Node.js/JavaScript"
        ) is False

    def test_node_stack_accepts_javascript_rules(self):
        assert is_rule_compatible(
            "javascript.express.open-redirect", "Node.js/JavaScript"
        ) is True

    def test_python_stack_rejects_javascript_rules(self):
        assert is_rule_compatible(
            "javascript.express.open-redirect", "Python (requirements.txt)"
        ) is False

    def test_python_stack_accepts_python_rules(self):
        assert is_rule_compatible(
            "python.django.security.csrf", "Python (requirements.txt)"
        ) is True

    def test_unknown_stack_accepts_anything(self):
        assert is_rule_compatible("python.django.x", "desconocido") is True
        assert is_rule_compatible("javascript.express.y", "desconocido") is True


# ---------- detect_language ----------

class TestDetectLanguage:
    @pytest.mark.parametrize("path,expected", [
        ("targets/vuln_test.py", "python"),
        ("app/routes/contributions.js", "javascript"),
        ("app/routes/contributions.mjs", "javascript"),
        ("app/routes/contributions.cjs", "javascript"),
        ("app/index.tsx", "typescript"),
        ("app/index.jsx", "javascript"),
        ("main.go", "go"),
        ("Gemfile.rb", "ruby"),
        ("script.php", "php"),
        ("Main.java", "java"),
        ("lib.rs", "rust"),
        ("Program.cs", "csharp"),
        ("Main.kt", "kotlin"),
    ])
    def test_known_extensions(self, path, expected):
        assert detect_language(path) == expected

    def test_unknown_extension_returns_generic(self):
        assert detect_language("file.xyz") == "generic"
        assert detect_language("no_extension") == "generic"


# ---------- detect_stack ----------

class TestDetectStack:
    def test_package_json_detected(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        result = detect_stack(str(tmp_path))
        assert "Node.js" in result

    def test_requirements_txt_detected(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("")
        result = detect_stack(str(tmp_path))
        assert "Python" in result

    def test_pyproject_detected(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("")
        result = detect_stack(str(tmp_path))
        assert "Python" in result

    def test_go_mod_detected(self, tmp_path):
        (tmp_path / "go.mod").write_text("module x")
        result = detect_stack(str(tmp_path))
        assert "Go" in result

    def test_no_indicator_returns_desconocido(self, tmp_path):
        result = detect_stack(str(tmp_path))
        assert "desconocido" in result

    def test_file_target_uses_parent_directory(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        f = tmp_path / "index.js"
        f.write_text("")
        result = detect_stack(str(f))
        assert "Node.js" in result


# ---------- validate_llm_response ----------

class TestValidateLlmResponse:
    def test_valid_response(self):
        llm = {
            "verdict": "true_positive",
            "confidence": "high",
            "reasoning": "SQL injection confirmed",
            "suggested_fix": "Use params",
        }
        validate_llm_response(llm)  # no raise

    def test_missing_key_raises(self):
        llm = {
            "verdict": "true_positive",
            "confidence": "high",
            "reasoning": "x",
            # suggested_fix missing
        }
        with pytest.raises(ValueError, match="Faltan claves"):
            validate_llm_response(llm)

    def test_invalid_verdict_raises(self):
        llm = {
            "verdict": "maybe",
            "confidence": "high",
            "reasoning": "x",
            "suggested_fix": "y",
        }
        with pytest.raises(ValueError, match="verdict inválido"):
            validate_llm_response(llm)

    def test_invalid_confidence_raises(self):
        llm = {
            "verdict": "true_positive",
            "confidence": "very high",
            "reasoning": "x",
            "suggested_fix": "y",
        }
        with pytest.raises(ValueError, match="confidence inválida"):
            validate_llm_response(llm)

    def test_non_dict_raises(self):
        with pytest.raises(ValueError, match="no es dict"):
            validate_llm_response("string")


# ---------- verify ----------

@pytest.fixture
def grouped_python_sql():
    """A grouped finding compatible with Python stack."""
    return {
        "path": "targets/vuln_test.py",
        "start": {"line": 7},
        "check_ids": [
            "python.lang.security.audit.formatted-sql-query.formatted-sql-query"
        ],
        "max_severity": "ERROR",
        "message": "Detected possible formatted SQL query",
        "metadata": {"cwe": ["CWE-89: SQL Injection"]},
    }


@pytest.fixture
def grouped_node_python_rule():
    """A finding with python.* rule but Node stack → should be skipped."""
    return {
        "path": "targets/NodeGoat/app/views/benefits.html",
        "start": {"line": 54},
        "check_ids": [
            "python.django.security.django-no-csrf-token.django-no-csrf-token"
        ],
        "max_severity": "WARNING",
        "message": "No CSRF token",
        "metadata": {"cwe": ["CWE-352: CSRF"]},
    }


class TestVerify:
    def test_incompatible_rule_skips_llm(
        self, monkeypatch, grouped_node_python_rule
    ):
        # If verify accidentally calls the LLM, this will fail hard.
        def boom(*args, **kwargs):
            raise AssertionError("call_ollama should not be called")

        monkeypatch.setattr("src.orchestrator.verify.call_ollama", boom)

        result = verify(
            grouped_node_python_rule, stack="Node.js/JavaScript"
        )
        assert result["skipped_llm"] is True
        assert result["llm"]["verdict"] == "false_positive"
        assert result["llm"]["confidence"] == "high"
        assert "Ninguna regla es compatible" in result["llm"]["reasoning"]
        assert result["refs_used"] == []

    def test_compatible_rule_true_positive(
        self, monkeypatch, grouped_python_sql
    ):
        llm_response = json.dumps({
            "verdict": "true_positive",
            "confidence": "high",
            "reasoning": "f-string en SQL sin parametrizar",
            "suggested_fix": 'cursor.execute("SELECT * FROM users WHERE name = ?", (username,))',
        })
        monkeypatch.setattr(
            "src.orchestrator.verify.call_ollama", lambda prompt: llm_response
        )

        refs = [
            (0.75, {
                "cwe": "CWE-89",
                "name": "SQL Injection",
                "fix": "Use parameterized queries",
                "vulnerable": "cursor.execute(f\"...\")",
            }),
        ]
        monkeypatch.setattr(
            "src.orchestrator.verify.retrieve", lambda query, k=2: refs
        )

        result = verify(
            grouped_python_sql,
            stack="Python (requirements.txt encontrado)",
        )

        assert result["skipped_llm"] is False
        assert result["file"] == "targets/vuln_test.py"
        assert result["line"] == 7
        assert result["cwe"] == "CWE-89: SQL Injection"
        assert result["semgrep_severity"] == "ERROR"
        assert result["llm"]["verdict"] == "true_positive"
        assert result["llm"]["confidence"] == "high"
        assert result["llm"]["suggested_fix"].startswith("cursor.execute")
        assert len(result["refs_used"]) == 1
        assert result["refs_used"][0]["cwe"] == "CWE-89"
        assert result["refs_used"][0]["score"] == 0.75

    def test_compatible_rule_false_positive(
        self, monkeypatch, grouped_python_sql
    ):
        llm_response = json.dumps({
            "verdict": "false_positive",
            "confidence": "medium",
            "reasoning": "sanitizado en contexto",
            "suggested_fix": "",
        })
        monkeypatch.setattr(
            "src.orchestrator.verify.call_ollama", lambda prompt: llm_response
        )
        monkeypatch.setattr(
            "src.orchestrator.verify.retrieve", lambda query, k=2: []
        )

        result = verify(
            grouped_python_sql,
            stack="Python (requirements.txt encontrado)",
        )
        assert result["llm"]["verdict"] == "false_positive"
        assert result["refs_used"] == []

    def test_invalid_llm_json_returns_uncertain(
        self, monkeypatch, grouped_python_sql
    ):
        monkeypatch.setattr(
            "src.orchestrator.verify.call_ollama",
            lambda prompt: "not valid json at all",
        )
        monkeypatch.setattr(
            "src.orchestrator.verify.retrieve", lambda query, k=2: []
        )

        result = verify(
            grouped_python_sql,
            stack="Python (requirements.txt encontrado)",
        )
        assert result["llm"]["verdict"] == "uncertain"
        assert result["llm"]["confidence"] == "low"
        assert "Error LLM" in result["llm"]["reasoning"]

    def test_llm_exception_returns_uncertain(
        self, monkeypatch, grouped_python_sql
    ):
        def boom(prompt):
            raise RuntimeError("connection refused")

        monkeypatch.setattr("src.orchestrator.verify.call_ollama", boom)
        monkeypatch.setattr(
            "src.orchestrator.verify.retrieve", lambda query, k=2: []
        )

        result = verify(
            grouped_python_sql,
            stack="Python (requirements.txt encontrado)",
        )
        assert result["llm"]["verdict"] == "uncertain"
        assert "connection refused" in result["llm"]["reasoning"]

    def test_truncated_cwe_becomes_unknown(
        self, monkeypatch, grouped_python_sql
    ):
        grouped_python_sql["metadata"]["cwe"] = ["C"]
        monkeypatch.setattr(
            "src.orchestrator.verify.call_ollama",
            lambda prompt: json.dumps({
                "verdict": "uncertain",
                "confidence": "low",
                "reasoning": "x",
                "suggested_fix": "",
            }),
        )
        monkeypatch.setattr(
            "src.orchestrator.verify.retrieve", lambda query, k=2: []
        )

        result = verify(
            grouped_python_sql,
            stack="Python (requirements.txt encontrado)",
        )
        assert result["cwe"] == "desconocido"

    def test_missing_file_fragment_uses_placeholder(self, monkeypatch):
        """Covers the frag-is-None branch (file not found on disk)."""
        captured_prompts = []

        def capture_call(prompt):
            captured_prompts.append(prompt)
            return json.dumps({
                "verdict": "uncertain",
                "confidence": "low",
                "reasoning": "file not accessible",
                "suggested_fix": "",
            })

        monkeypatch.setattr(
            "src.orchestrator.verify.call_ollama", capture_call
        )
        monkeypatch.setattr(
            "src.orchestrator.verify.retrieve", lambda query, k=2: []
        )

        grouped = {
            "path": "targets/does_not_exist.py",
            "start": {"line": 7},
            "check_ids": [
                "python.lang.security.audit.formatted-sql-query.formatted-sql-query"
            ],
            "max_severity": "ERROR",
            "message": "fake",
            "metadata": {"cwe": ["CWE-89: SQL Injection"]},
        }

        result = verify(
            grouped, stack="Python (requirements.txt encontrado)"
        )
        assert result["llm"]["verdict"] == "uncertain"
        assert len(captured_prompts) == 1
        assert "archivo no encontrado" in captured_prompts[0]
    

    def test_missing_cwe_becomes_unknown(
        self, monkeypatch, grouped_python_sql
    ):
        grouped_python_sql["metadata"].pop("cwe", None)
        monkeypatch.setattr(
            "src.orchestrator.verify.call_ollama",
            lambda prompt: json.dumps({
                "verdict": "uncertain",
                "confidence": "low",
                "reasoning": "x",
                "suggested_fix": "",
            }),
        )
        monkeypatch.setattr(
            "src.orchestrator.verify.retrieve", lambda query, k=2: []
        )

        result = verify(
            grouped_python_sql,
            stack="Python (requirements.txt encontrado)",
        )
        assert result["cwe"] == "desconocido"


# ---------- build_prompt ----------

class TestBuildPrompt:
    def test_prompt_includes_critical_fields(self):
        prompt = build_prompt(
            check_ids=["rule.a", "rule.b"],
            cwe="CWE-89: SQL Injection",
            message="Formatted query",
            fragment=">> 7 | cursor.execute(f'...')",
            stack="Python",
            lang="python",
            refs=[(0.8, {
                "cwe": "CWE-89",
                "name": "SQL Injection",
                "vulnerable": "v",
                "fix": "f",
            })],
        )
        assert "CWE-89" in prompt
        assert "Formatted query" in prompt
        assert "rule.a" in prompt
        assert "rule.b" in prompt
        assert "LENGUAJE DEL FRAGMENTO: python" in prompt
        assert "SQL Injection" in prompt
        assert "similitud 0.80" in prompt

    def test_prompt_without_refs(self):
        prompt = build_prompt(
            check_ids=["rule.a"],
            cwe="CWE-89",
            message="msg",
            fragment="code",
            stack="Python",
            lang="generic",
            refs=[],
        )
        assert "(sin referencias del corpus" in prompt
        assert "LENGUAJE DEL FRAGMENTO: inferido" in prompt