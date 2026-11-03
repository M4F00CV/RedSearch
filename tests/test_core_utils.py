"""Unit tests for src/core/utils.py.

Covers: extract_tool_calls_from_text, normalize_args,
is_stuck_in_loop, is_stuck_within, read_fragment_optional.

All functions are pure (no I/O, no LLM, no subprocess), so these
tests run in milliseconds and need zero mocking.
"""

import json

import pytest

from src.core.utils import (
    extract_tool_calls_from_text,
    is_stuck_in_loop,
    is_stuck_within,
    normalize_args,
    read_fragment_optional,
)


# ---------- extract_tool_calls_from_text ----------

class TestExtractToolCallsFromText:
    def test_empty_content(self):
        assert extract_tool_calls_from_text("") == []
        assert extract_tool_calls_from_text(None) == []

    def test_plain_json_single_call(self):
        content = '{"name": "foo", "arguments": {"x": 1}}'
        result = extract_tool_calls_from_text(content)
        assert len(result) == 1
        assert result[0]["name"] == "foo"
        assert result[0]["arguments"] == {"x": 1}

    def test_markdown_fenced_json(self):
        content = 'Voy a usar la herramienta:\n```json\n{"name": "bar", "arguments": {"y": "z"}}\n```'
        result = extract_tool_calls_from_text(content)
        assert len(result) == 1
        assert result[0]["name"] == "bar"

    def test_multiple_calls_in_one_content(self):
        content = (
            '{"name": "first", "arguments": {}}\n'
            '{"name": "second", "arguments": {}}'
        )
        result = extract_tool_calls_from_text(content)
        assert len(result) == 2
        assert {r["name"] for r in result} == {"first", "second"}

    def test_native_tool_calls_wrapper(self):
        content = json.dumps({
            "tool_calls": [
                {"function": {"name": "tool_a", "arguments": {"k": 1}}},
                {"function": {"name": "tool_b", "arguments": {"k": 2}}},
            ]
        })
        result = extract_tool_calls_from_text(content)
        assert len(result) == 2
        assert {r["name"] for r in result} == {"tool_a", "tool_b"}

    def test_array_of_calls(self):
        content = json.dumps([
            {"name": "a", "arguments": {}},
            {"name": "b", "arguments": {}},
        ])
        result = extract_tool_calls_from_text(content)
        assert len(result) == 2

    def test_deduplicates_identical_calls(self):
        call = '{"name": "dup", "arguments": {"x": 1}}'
        content = f"{call}\n{call}"
        result = extract_tool_calls_from_text(content)
        assert len(result) == 1

    def test_content_without_json(self):
        assert extract_tool_calls_from_text("solo texto sin JSON") == []

    def test_json_without_name_field(self):
        content = '{"arguments": {"x": 1}}'
        assert extract_tool_calls_from_text(content) == []


# ---------- normalize_args ----------

class TestNormalizeArgs:
    def test_plain_args_pass_through(self):
        assert normalize_args("foo", {"a": 1, "b": "two"}) == {"a": 1, "b": "two"}

    def test_unwrap_type_description_value_pattern(self):
        args = {"target": {"type": "string", "description": "path", "value": "x.py"}}
        assert normalize_args("foo", args) == {"target": "x.py"}

    def test_mixed_args(self):
        args = {
            "plain": 42,
            "wrapped": {"type": "string", "value": "hello"},
        }
        result = normalize_args("foo", args)
        assert result == {"plain": 42, "wrapped": "hello"}

    def test_empty_args(self):
        assert normalize_args("foo", {}) == {}


# ---------- is_stuck_in_loop ----------

class TestIsStuckInLoop:
    def test_identical_content(self):
        text = "El mismo texto repetido.\nSegunda línea."
        assert is_stuck_in_loop(text, text) is True

    def test_completely_different(self):
        assert is_stuck_in_loop("contenido A", "contenido B") is False

    def test_same_first_line_triggers(self):
        a = "Primera línea.\nDetalle A."
        b = "Primera línea.\nDetalle B distinto."
        assert is_stuck_in_loop(a, b) is True

    def test_high_overlap_triggers(self):
        # First line differs, but "a" is a subset of "b" → overlap = 1.0
        a = "linea2\nlinea3\nlinea4\nlinea5\nlinea6"
        b = "inicio\nlinea2\nlinea3\nlinea4\nlinea5\nlinea6"
        assert is_stuck_in_loop(a, b) is True

    def test_overlap_below_threshold_no_trigger(self):
        # First line differs; 4/5 lines shared = 0.8 < 0.9 threshold
        a = "inicio\nlinea2\nlinea3\nlinea4\nlinea5"
        b = "otro\nlinea2\nlinea3\nlinea4\nlinea6"
        # overlap: linea2, linea3, linea4 = 3/5 = 0.6 (below threshold)
        assert is_stuck_in_loop(a, b) is False

    def test_whitespace_only_returns_false(self):
        # Non-empty strings but all lines are whitespace → filtered to empty
        assert is_stuck_in_loop("   \n\n\t", "   \n\n\t") is False

    def test_empty_inputs(self):
        assert is_stuck_in_loop("", "") is False
        assert is_stuck_in_loop("text", "") is False
        assert is_stuck_in_loop("", "text") is False


# ---------- is_stuck_within ----------

class TestIsStuckWithin:
    def test_repeated_line_4_times(self):
        text = "\n".join(["Estoy buscando el fix para esta vulnerabilidad SQL"] * 4)
        assert is_stuck_within(text) is True

    def test_repeated_line_3_times_below_threshold(self):
        text = "\n".join(["Estoy buscando el fix para esta vulnerabilidad SQL"] * 3)
        assert is_stuck_within(text) is False

    def test_short_lines_ignored(self):
        # Lines < min_len (20 chars) are ignored
        text = "\n".join(["corto"] * 10)
        assert is_stuck_within(text) is False

    def test_empty_content(self):
        assert is_stuck_within("") is False


# ---------- read_fragment_optional ----------

class TestReadFragmentOptional:
    def test_missing_file_returns_none(self, tmp_path):
        missing = tmp_path / "nope.py"
        assert read_fragment_optional(str(missing), line=1) is None

    def test_reads_fragment_with_marker(self, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("\n".join(f"line {i}" for i in range(1, 11)), encoding="utf-8")
        result = read_fragment_optional(str(f), line=5, context=2)
        assert result is not None
        assert ">>" in result
        assert "line 5" in result
        assert "line 3" in result
        assert "line 7" in result
        assert "line 2" not in result
        assert "line 8" not in result

    def test_marker_on_correct_line(self, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("uno\ndos\ntres\ncuatro\n", encoding="utf-8")
        result = read_fragment_optional(str(f), line=2, context=1)
        assert result is not None
        # The >> marker must be on the line containing "dos"
        for line in result.splitlines():
            if "dos" in line:
                assert line.startswith(">>")
            else:
                assert not line.startswith(">>")