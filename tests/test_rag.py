"""Unit tests for src/rag/retrieve.py and src/tools/corpus.py.

Uses a temporary corpus (numpy + SQLite) in tmp_path, with
embed_query mocked to return deterministic unit vectors. This
exercises the real retrieval logic without Ollama or the
project's data/ directory.
"""

import sqlite3

import numpy as np
import pytest

from src.rag.retrieve import retrieve
from src.tools.corpus import search_corpus_tool


@pytest.fixture
def fake_corpus(tmp_path, monkeypatch):
    """Create a 3-doc corpus with orthogonal 4-dim embeddings.

    Monkeypatches:
    - src.rag.retrieve.EMBEDDINGS -> tmp npy
    - src.rag.retrieve.INDEX_DB -> tmp sqlite
    - src.rag.retrieve.embed_query -> deterministic fake
    """
    vecs = np.array([
        [1.0, 0.0, 0.0, 0.0],  # CWE-89 (SQLi)
        [0.0, 1.0, 0.0, 0.0],  # CWE-95 (Eval)
        [0.0, 0.0, 1.0, 0.0],  # CWE-601 (Redirect)
    ], dtype=np.float32)
    emb_path = tmp_path / "embeddings.npy"
    np.save(emb_path, vecs)

    db_path = tmp_path / "index.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE docs (id INTEGER PRIMARY KEY, cwe TEXT, "
        "name TEXT, description TEXT, vulnerable TEXT, fix TEXT, owasp TEXT)"
    )
    conn.execute(
        "INSERT INTO docs VALUES (?, ?, ?, ?, ?, ?, ?)",
        (0, "CWE-89", "SQL Injection", "d", "vuln", "fix A", "A03"),
    )
    conn.execute(
        "INSERT INTO docs VALUES (?, ?, ?, ?, ?, ?, ?)",
        (1, "CWE-95", "Eval Injection", "d", "vuln", "fix B", "A03"),
    )
    conn.execute(
        "INSERT INTO docs VALUES (?, ?, ?, ?, ?, ?, ?)",
        (2, "CWE-601", "Open Redirect", "d", "vuln", "fix C", "A01"),
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr("src.rag.retrieve.EMBEDDINGS", emb_path)
    monkeypatch.setattr("src.rag.retrieve.INDEX_DB", db_path)

    def fake_embed(query):
        q = query.lower()
        if "sql" in q:
            return np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
        if "eval" in q:
            return np.array([0.0, 1.0, 0.0, 0.0], dtype=np.float32)
        if "redirect" in q:
            return np.array([0.0, 0.0, 1.0, 0.0], dtype=np.float32)
        # Orthogonal to all docs (unknown query)
        return np.array([0.0, 0.0, 0.0, 1.0], dtype=np.float32)

    monkeypatch.setattr("src.rag.retrieve.embed_query", fake_embed)
    return tmp_path


# ---------- retrieve ----------

class TestRetrieve:
    def test_exact_match_sql(self, fake_corpus):
        results = retrieve("SQL injection", k=1, min_score=0.5)
        assert len(results) == 1
        score, doc = results[0]
        assert doc["cwe"] == "CWE-89"
        assert doc["fix"] == "fix A"
        assert doc["vulnerable"] == "vuln"
        assert score > 0.5

    def test_exact_match_eval(self, fake_corpus):
        results = retrieve("eval injection", k=1, min_score=0.5)
        assert len(results) == 1
        assert results[0][1]["cwe"] == "CWE-95"

    def test_exact_match_redirect(self, fake_corpus):
        results = retrieve("redirect vuln", k=1, min_score=0.5)
        assert len(results) == 1
        assert results[0][1]["cwe"] == "CWE-601"

    def test_orthogonal_query_returns_empty(self, fake_corpus):
        # Query vector [0,0,0,1] is orthogonal to all docs -> score 0 < 0.5
        results = retrieve("totally unrelated term", k=2, min_score=0.5)
        assert results == []

    def test_k_limits_results(self, fake_corpus, monkeypatch):
        # Force a query that matches docs 0 and 1 equally
        monkeypatch.setattr(
            "src.rag.retrieve.embed_query",
            lambda q: np.array([0.7, 0.7, 0.0, 0.0], dtype=np.float32),
        )
        results_k1 = retrieve("x", k=1, min_score=0.0)
        results_k2 = retrieve("x", k=2, min_score=0.0)
        assert len(results_k1) == 1
        assert len(results_k2) == 2

    def test_result_shape(self, fake_corpus):
        results = retrieve("sql", k=1, min_score=0.5)
        assert len(results) == 1
        score, doc = results[0]
        assert isinstance(score, float)
        assert set(doc.keys()) == {"cwe", "name", "fix", "vulnerable"}

    def test_corpus_missing_returns_empty(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "src.rag.retrieve.EMBEDDINGS", tmp_path / "no_such.npy"
        )
        monkeypatch.setattr(
            "src.rag.retrieve.INDEX_DB", tmp_path / "no_such.db"
        )
        assert retrieve("sql") == []

    def test_min_score_filters_low(self, fake_corpus, monkeypatch):
        # Uniform vector -> all cosines ~0.5, below 0.9
        monkeypatch.setattr(
            "src.rag.retrieve.embed_query",
            lambda q: np.array([0.5, 0.5, 0.5, 0.5], dtype=np.float32),
        )
        results = retrieve("anything", k=3, min_score=0.9)
        assert results == []

    def test_embeddings_missing_but_db_present(self, monkeypatch, tmp_path):
        # Only one of the two files missing is enough to short-circuit
        db_path = tmp_path / "index.db"
        sqlite3.connect(db_path).close()
        monkeypatch.setattr(
            "src.rag.retrieve.EMBEDDINGS", tmp_path / "missing.npy"
        )
        monkeypatch.setattr("src.rag.retrieve.INDEX_DB", db_path)
        assert retrieve("sql") == []


# ---------- search_corpus_tool ----------

class TestSearchCorpusTool:
    def test_formats_results(self, fake_corpus):
        result = search_corpus_tool("SQL injection", k=1)
        assert "[CWE-89 SQL Injection]" in result
        assert "Patrón vulnerable:" in result
        assert "Fix recomendado:" in result
        assert "fix A" in result
        assert "score" in result

    def test_no_results_message(self, fake_corpus):
        result = search_corpus_tool("orthogonal unknown term", k=2)
        assert "Sin resultados relevantes" in result
        assert "orthogonal unknown term" in result

    def test_corpus_missing_message(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "src.rag.retrieve.EMBEDDINGS", tmp_path / "no_such.npy"
        )
        monkeypatch.setattr(
            "src.rag.retrieve.INDEX_DB", tmp_path / "no_such.db"
        )
        result = search_corpus_tool("sql")
        assert "Sin resultados relevantes" in result