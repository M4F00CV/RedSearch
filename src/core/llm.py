"""LLM communication layer (Ollama HTTP endpoints).

This module isolates all HTTP calls to Ollama. No agent logic, no
tools, no file I/O. Just request/response against the local API.
"""

import json
import urllib.error
import urllib.request

import numpy as np

OLLAMA_CHAT_URL = "http://localhost:11434/v1/chat/completions"
OLLAMA_GENERATE_URL = "http://localhost:11434/api/generate"
OLLAMA_EMBED_URL = "http://localhost:11434/api/embeddings"

DEFAULT_MODEL = "qwen2.5-coder:7b"
EMBED_MODEL = "nomic-embed-text"


def chat_with_tools(messages, tools, model=DEFAULT_MODEL, force_tool=False,
                    max_tokens=900, temperature=0.0, timeout=300):
    """Call Ollama's OpenAI-compatible chat endpoint with tool definitions.

    Args:
        messages: Conversation history (list of role/content dicts).
        tools: Tool schemas (OpenAI function-calling format).
        model: Model name served by Ollama.
        force_tool: If True, sets tool_choice='required' to force a
            tool call (used when the model is stuck emitting text).
        max_tokens: Maximum tokens in the response.
        temperature: Sampling temperature. 0.0 for deterministic output.
        timeout: HTTP timeout in seconds.

    Returns:
        Parsed JSON response dict from Ollama.

    Raises:
        urllib.error.HTTPError: On non-2xx responses (body printed).
    """
    payload = {
        "model": model,
        "messages": messages,
        "tools": tools,
        "tool_choice": "required" if force_tool else "auto",
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        OLLAMA_CHAT_URL, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"\n[HTTP {e.code}] {e.reason}")
        print(f"[BODY] {body[:1000]}")
        raise


def call_ollama(prompt, model=DEFAULT_MODEL, timeout=300):
    """Call Ollama's /api/generate with JSON output format.

    Used by the orchestrator for structured verification responses.
    """
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1, "num_predict": 500, "num_ctx": 4096},
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OLLAMA_GENERATE_URL, data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    return body.get("response", "")


def embed_query(text, model=EMBED_MODEL, timeout=60):
    """Generate an embedding vector for a text query.

    Returns:
        np.ndarray of shape (768,) as float32.
    """
    payload = {"model": model, "prompt": text}
    req = urllib.request.Request(
        OLLAMA_EMBED_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return np.array(json.loads(r.read())["embedding"], dtype=np.float32)