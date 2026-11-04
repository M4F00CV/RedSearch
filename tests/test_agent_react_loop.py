"""Unit tests for src/agent/react_loop.py.

Covers:
- _looks_like_summary: strong/weak signals, planning rejection,
  short content, code block combos
- run_agent: single tool call flow, immediate FINAL, text fallback,
  loop detection abort, claimed-file verification (exists/missing),
  max iterations exhausted (with and without tool calls)

Strategy: monkeypatch chat_with_tools to return scripted responses.
Fake TOOL_MAP records invocations. capsys captures stdout for
[FINAL]/[ABORT]/[RETRY] assertions.
"""

import json
from pathlib import Path

import pytest

from src.agent import react_loop
from src.agent.react_loop import _looks_like_summary, run_agent


# ---------- helpers ----------

def make_response(content=None, tool_calls=None):
    return {
        "choices": [{
            "message": {
                "content": content or "",
                "tool_calls": tool_calls or [],
            }
        }]
    }


def make_tool_call(call_id, name, arguments):
    return {
        "id": call_id,
        "type": "function",
        "function": {
            "name": name,
            "arguments": json.dumps(arguments) if isinstance(arguments, dict) else arguments,
        },
    }


@pytest.fixture
def scripted_chat(monkeypatch):
    """Return a controller that installs scripted chat responses."""
    state = {"responses": [], "calls": []}

    def fake_chat(messages, tools, force_tool=False):
        state["calls"].append({
            "n_messages": len(messages),
            "force_tool": force_tool,
        })
        if not state["responses"]:
            raise AssertionError("No more scripted responses")
        return state["responses"].pop(0)

    monkeypatch.setattr(react_loop, "chat_with_tools", fake_chat)

    def set_responses(responses):
        state["responses"] = list(responses)
        state["calls"] = []

    return state, set_responses


@pytest.fixture
def fake_tools(monkeypatch):
    """Install a single fake tool 'fake_tool' that records calls."""
    invocations = []

    def fake_tool(**kwargs):
        invocations.append(kwargs)
        return f"fake_tool result: {kwargs}"

    monkeypatch.setattr(react_loop, "TOOL_MAP", {"fake_tool": fake_tool})
    return invocations


# ---------- _looks_like_summary ----------

class TestLooksLikeSummary:
    def test_empty_and_short_rejected(self):
        assert _looks_like_summary("") is False
        assert _looks_like_summary("short") is False
        assert _looks_like_summary("a" * 79) is False

    def test_strong_signal_check_id(self):
        # >80 chars, includes "check_id"
        text = (
            "El hallazgo principal corresponde al check_id "
            "python.lang.security.audit.formatted-sql-query en la "
            "línea 7 del archivo, con severidad WARNING asignada."
        )
        assert _looks_like_summary(text) is True

    def test_strong_signal_cwe(self):
        # >80 chars, includes "CWE-"
        text = (
            "Se identificó CWE-89 en la consulta SQL construida con "
            "f-string, lo cual permite manipular la consulta mediante "
            "input no validado del usuario."
        )
        assert _looks_like_summary(text) is True

    def test_strong_signal_severity(self):
        # >80 chars, includes "severidad"
        text = (
            "Los hallazgos presentan distintos niveles de severidad: "
            "ERROR y WARNING según el reporte de Semgrep, lo cual "
            "permite priorizar la remediación."
        )
        assert _looks_like_summary(text) is True

    def test_strong_signal_found_n(self):
        # >80 chars, includes "encontr"
        text = (
            "Semgrep encontró varios hallazgos relevantes en el "
            "archivo analizado, incluyendo dos con severidad ERROR y "
            "dos con severidad WARNING que requieren revisión."
        )
        assert _looks_like_summary(text) is True

    def test_two_weak_signals(self):
        text = (
            "La consulta es insegura y debe usar un parámetro en lugar de "
            "concatenar el input del usuario directamente."
        )
        assert _looks_like_summary(text) is True

    def test_one_weak_signal_with_code_block(self):
        text = (
            "El problema es que la consulta concatena directamente:\n"
            "```python\ncursor.execute(f\"SELECT * FROM users WHERE name = '{u}'\")\n```\n"
            "Cambiar por parámetro es lo recomendado."
        )
        assert _looks_like_summary(text) is True

    def test_short_planning_rejected(self):
        # "voy a" + < 200 chars → rejected even with one weak signal
        text = "Voy a buscar el fix para la consulta vulnerable ahora mismo."
        assert _looks_like_summary(text) is False

    def test_long_planning_accepted_if_signals(self):
        # >200 chars bypasses the planning rejection
        text = (
            "Voy a buscar el fix para la consulta vulnerable. "
            + "El check_id indica SQL injection. " * 10
            + "Severidad alta."
        )
        assert _looks_like_summary(text) is True

    def test_no_signals_rejected(self):
        text = (
            "Este texto es suficientemente largo como para pasar el "
            "umbral de longitud pero no contiene ninguna palabra clave "
            "relevante para ser considerado un resumen tecnico del "
            "análisis realizado hasta este momento."
        )
        assert _looks_like_summary(text) is False

# ---------- run_agent ----------

class TestRunAgent:
    def test_single_tool_then_final(
        self, scripted_chat, fake_tools, capsys
    ):
        state, set_responses = scripted_chat
        set_responses([
            make_response(
                content="",
                tool_calls=[make_tool_call("c1", "fake_tool", {"x": 1})],
            ),
            make_response(
                content=(
                    "El check_id es rule.x en línea 7 con severidad ERROR. "
                    "Aplicar el fix recomendado."
                ),
            ),
        ])

        run_agent("analiza", max_iter=3)

        out = capsys.readouterr().out
        assert "[ACTION] fake_tool" in out
        assert "[OBSERVATION] fake_tool result" in out
        assert "[FINAL] Objetivo completado (resumen" in out
        assert len(fake_tools) == 1
        assert fake_tools[0] == {"x": 1}

    def test_immediate_final_no_tools(self, scripted_chat, fake_tools, capsys):
        state, set_responses = scripted_chat
        # No tools called, but content has strong signals → FINAL via summary
        # Note: with seen_calls empty, _looks_like_summary path is skipped
        # and it falls to RETRY. This tests the RETRY path.
        set_responses([
            make_response(
                content="Este es un resumen con CWE-89 y severidad ERROR detectada.",
            ),
            make_response(
                content="Otra respuesta sin acción alguna, lo siento.",
            ),
            make_response(
                content="Otra respuesta sin acción alguna, lo siento.",
            ),
        ])

        run_agent("x", max_iter=3)
        out = capsys.readouterr().out
        assert "[RETRY]" in out
        assert "[ABORT] Sin acción ejecutada" in out

    def test_fallback_from_text(self, scripted_chat, fake_tools, capsys):
        state, set_responses = scripted_chat
        text_with_tool = (
            'Aquí está la llamada:\n'
            '{"name": "fake_tool", "arguments": {"y": "z"}}\n'
        )
        # Iter 2 content must be >80 chars to trigger _looks_like_summary
        final_summary = (
            "Listo. El check_id rule.x aparece en la línea 3 con "
            "severidad ERROR. Se recomienda aplicar el fix sugerido "
            "para evitar inyección de código en el flujo analizado."
        )
        set_responses([
            make_response(content=text_with_tool),
            make_response(content=final_summary),
        ])

        run_agent("x", max_iter=3)
        out = capsys.readouterr().out
        assert "[FALLBACK] 1 tool call(s) extraídos de texto" in out
        assert "[ACTION] fake_tool" in out
        assert fake_tools[0] == {"y": "z"}
        assert "[FINAL] Objetivo completado (resumen tras 1 herramienta(s))" in out

    def test_loop_detection_aborts(
        self, scripted_chat, fake_tools, capsys
    ):
        state, set_responses = scripted_chat
        same = "Estoy pensando en la estrategia para resolver este objetivo"
        set_responses([
            make_response(content=same),
            make_response(content=same),
        ])

        run_agent("x", max_iter=4)
        out = capsys.readouterr().out
        assert "[ABORT] Bucle detectado" in out

    def test_claimed_file_exists_completes(
        self, scripted_chat, fake_tools, capsys, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        report = tmp_path / "reports" / "r.md"
        report.parent.mkdir(parents=True)
        report.write_text("test report content")

        state, set_responses = scripted_chat
        set_responses([
            make_response(
                tool_calls=[make_tool_call("c1", "fake_tool", {})],
            ),
            make_response(
                content="He guardado el reporte en reports/r.md con todo.",
            ),
        ])

        run_agent("x", max_iter=3)
        out = capsys.readouterr().out
        assert "[FINAL] Objetivo completado (archivos verificados)" in out

    def test_claimed_file_missing_alerts(
        self, scripted_chat, fake_tools, capsys, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        state, set_responses = scripted_chat
        set_responses([
            make_response(
                tool_calls=[make_tool_call("c1", "fake_tool", {})],
            ),
            make_response(
                content="He guardado el reporte en reports/missing.md con todo.",
            ),
            make_response(content="Segundo intento sin acción, igual sin archivo."),
            make_response(content="Tercer intento sin acción."),
        ])

        run_agent("x", max_iter=4)
        out = capsys.readouterr().out
        assert "[ALERTA]" in out
        assert "reports/missing.md" in out

    def test_max_iterations_with_tools(
        self, scripted_chat, fake_tools, capsys
    ):
        state, set_responses = scripted_chat
        # Every iteration has a tool call, no final
        set_responses([
            make_response(tool_calls=[make_tool_call(f"c{i}", "fake_tool", {"i": i})])
            for i in range(3)
        ])

        run_agent("x", max_iter=3)
        out = capsys.readouterr().out
        assert "[FINAL] Se agotaron 3 iteraciones" in out
        assert "3 herramienta(s) ejecutada(s)" in out

    def test_aborts_without_action_after_retries(
        self, scripted_chat, fake_tools, capsys
    ):
        state, set_responses = scripted_chat
        # Unique content each turn → no loop detection, no action
        # After 2 consecutive no-action turns → ABORT
        set_responses([
            make_response(content=f"Intentando sin acción, intento {i} con texto único diferente al anterior.")
            for i in range(3)
        ])

        run_agent("x", max_iter=3)
        out = capsys.readouterr().out
        # The flow aborts at the 2nd no-action iteration before
        # reaching max_iter, because no tools were ever executed.
        assert "[ABORT] Sin acción ejecutada" in out

    def test_duplicate_tool_call_guarded(
        self, scripted_chat, fake_tools, capsys
    ):
        state, set_responses = scripted_chat
        same_call = make_tool_call("c1", "fake_tool", {"target": "x"})
        final_summary = (
            "Resumen final: el check_id rule.x aparece en la línea 7 "
            "con severidad ERROR. Aplicar el fix de SQL injection "
            "recomendado en el corpus para resolver el hallazgo."
        )
        set_responses([
            make_response(tool_calls=[same_call]),
            make_response(tool_calls=[same_call]),
            make_response(content=final_summary),
        ])

        run_agent("x", max_iter=4)
        out = capsys.readouterr().out
        # First call executes; second is intercepted by the dedup guard
        assert "ya ejecutado antes en esta sesión" in out
        assert len(fake_tools) == 1  # only one real invocation
        assert "[FINAL] Objetivo completado (resumen tras 1 herramienta(s))" in out

    def test_force_tool_after_no_action(
        self, scripted_chat, fake_tools, capsys
    ):
        state, set_responses = scripted_chat
        set_responses([
            make_response(content="Primera respuesta sin acción explicativa."),
            make_response(
                tool_calls=[make_tool_call("c1", "fake_tool", {})],
            ),
            make_response(content="Resumen: hallazgos con severidad ERROR en línea 7."),
        ])

        run_agent("x", max_iter=3)
        # Second call must have force_tool=True
        assert state["calls"][0]["force_tool"] is False
        assert state["calls"][1]["force_tool"] is True