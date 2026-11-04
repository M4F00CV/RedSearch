"""Unit tests for src/core/llm.py.

Mocks urllib.request.urlopen to simulate Ollama HTTP responses
without a running daemon. Covers chat_with_tools, call_ollama,
and embed_query, including HTTPError paths.
"""

import io
import json
import urllib.error

import numpy as np
import pytest

from src.core.llm import call_ollama, chat_with_tools, embed_query


class FakeResponse:
    """Context-manager stand-in for urlopen's return value."""
    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


# ---------- chat_with_tools ----------

class TestChatWithTools:
    def test_success(self, monkeypatch):
        expected = {
            "choices": [{"message": {"content": "hi", "tool_calls": []}}]
        }
        captured = {}

        def fake_urlopen(req, timeout):
            captured["url"] = req.full_url
            captured["data"] = json.loads(req.data.decode())
            captured["timeout"] = timeout
            return FakeResponse(json.dumps(expected).encode())

        monkeypatch.setattr(
            "src.core.llm.urllib.request.urlopen", fake_urlopen
        )

        result = chat_with_tools(
            messages=[{"role": "user", "content": "x"}],
            tools=[{"type": "function", "function": {"name": "t"}}],
        )

        assert result == expected
        assert "/v1/chat/completions" in captured["url"]
        assert captured["data"]["model"] == "qwen2.5-coder:7b"
        assert captured["data"]["tool_choice"] == "auto"
        assert captured["data"]["temperature"] == 0.0
        assert captured["data"]["max_tokens"] == 900

    def test_force_tool_sets_required(self, monkeypatch):
        captured = {}

        def fake_urlopen(req, timeout):
            captured["data"] = json.loads(req.data.decode())
            return FakeResponse(
                json.dumps({"choices": [{"message": {"content": ""}}]}).encode()
            )

        monkeypatch.setattr(
            "src.core.llm.urllib.request.urlopen", fake_urlopen
        )

        chat_with_tools([], [], force_tool=True)
        assert captured["data"]["tool_choice"] == "required"

    def test_custom_model_and_tokens(self, monkeypatch):
        captured = {}

        def fake_urlopen(req, timeout):
            captured["data"] = json.loads(req.data.decode())
            return FakeResponse(b'{"choices": []}')

        monkeypatch.setattr(
            "src.core.llm.urllib.request.urlopen", fake_urlopen
        )

        chat_with_tools(
            [], [], model="custom:3b", max_tokens=1234, temperature=0.5
        )
        assert captured["data"]["model"] == "custom:3b"
        assert captured["data"]["max_tokens"] == 1234
        assert captured["data"]["temperature"] == 0.5

    def test_http_error_propagates(self, monkeypatch, capsys):
        def fake_urlopen(req, timeout):
            raise urllib.error.HTTPError(
                "http://x/v1/chat/completions", 500,
                "Internal Server Error", {},
                io.BytesIO(b'{"error":"boom"}'),
            )

        monkeypatch.setattr(
            "src.core.llm.urllib.request.urlopen", fake_urlopen
        )

        with pytest.raises(urllib.error.HTTPError):
            chat_with_tools([], [])

        out = capsys.readouterr().out
        assert "[HTTP 500]" in out
        assert "boom" in out


# ---------- call_ollama ----------

class TestCallOllama:
    def test_success_returns_response_field(self, monkeypatch):
        captured = {}

        def fake_urlopen(req, timeout):
            captured["url"] = req.full_url
            captured["data"] = json.loads(req.data.decode())
            return FakeResponse(
                json.dumps({"response": '{"verdict":"true_positive"}'}).encode()
            )

        monkeypatch.setattr(
            "src.core.llm.urllib.request.urlopen", fake_urlopen
        )

        result = call_ollama("prompt here")
        assert result == '{"verdict":"true_positive"}'
        assert "/api/generate" in captured["url"]
        assert captured["data"]["prompt"] == "prompt here"
        assert captured["data"]["stream"] is False
        assert captured["data"]["format"] == "json"

    def test_missing_response_field_returns_empty(self, monkeypatch):
        def fake_urlopen(req, timeout):
            return FakeResponse(json.dumps({"other": "data"}).encode())

        monkeypatch.setattr(
            "src.core.llm.urllib.request.urlopen", fake_urlopen
        )

        assert call_ollama("prompt") == ""

    def test_custom_model(self, monkeypatch):
        captured = {}

        def fake_urlopen(req, timeout):
            captured["data"] = json.loads(req.data.decode())
            return FakeResponse(b'{"response": ""}')

        monkeypatch.setattr(
            "src.core.llm.urllib.request.urlopen", fake_urlopen
        )

        call_ollama("p", model="custom:3b")
        assert captured["data"]["model"] == "custom:3b"


# ---------- embed_query ----------

class TestEmbedQuery:
    def test_success_returns_float32_array(self, monkeypatch):
        fake_vec = [0.1, 0.2, 0.3, 0.4]

        def fake_urlopen(req, timeout):
            return FakeResponse(
                json.dumps({"embedding": fake_vec}).encode()
            )

        monkeypatch.setattr(
            "src.core.llm.urllib.request.urlopen", fake_urlopen
        )

        result = embed_query("query text")
        assert isinstance(result, np.ndarray)
        assert result.dtype == np.float32
        assert result.shape == (4,)
        np.testing.assert_array_almost_equal(
            result, np.array(fake_vec, dtype=np.float32)
        )

    def test_sends_correct_payload(self, monkeypatch):
        captured = {}

        def fake_urlopen(req, timeout):
            captured["url"] = req.full_url
            captured["data"] = json.loads(req.data.decode())
            return FakeResponse(b'{"embedding": [0.0]}')

        monkeypatch.setattr(
            "src.core.llm.urllib.request.urlopen", fake_urlopen
        )

        embed_query("hello world")
        assert "/api/embeddings" in captured["url"]
        assert captured["data"]["prompt"] == "hello world"
        assert captured["data"]["model"] == "nomic-embed-text"

    def test_custom_model(self, monkeypatch):
        captured = {}

        def fake_urlopen(req, timeout):
            captured["data"] = json.loads(req.data.decode())
            return FakeResponse(b'{"embedding": [0.0]}')

        monkeypatch.setattr(
            "src.core.llm.urllib.request.urlopen", fake_urlopen
        )

        embed_query("q", model="custom-embed")
        assert captured["data"]["model"] == "custom-embed"