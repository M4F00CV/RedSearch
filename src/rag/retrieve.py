"""Vector retrieval from the local RAG corpus."""

import sqlite3
from pathlib import Path

import numpy as np

from src.core.llm import embed_query

DATA_DIR = Path(__file__).parent.parent.parent / "data"
EMBEDDINGS = DATA_DIR / "embeddings.npy"
INDEX_DB = DATA_DIR / "index.db"


def retrieve(query: str, k: int = 2, min_score: float = 0.65):
    """Top-k retrieval from the CWE corpus.

    Args:
        query: Natural language or keywords.
        k: Number of candidates to consider.
        min_score: Cosine similarity threshold (0-1). Results below
            this are dropped to avoid unrelated matches.

    Returns:
        List of (score, dict) tuples with keys cwe, name, fix,
        vulnerable. Empty list if corpus unavailable or no match.
    """
    if not EMBEDDINGS.exists() or not INDEX_DB.exists():
        return []

    q = embed_query(query)
    q /= (np.linalg.norm(q) + 1e-8)
    vecs = np.load(EMBEDDINGS)
    vecs = vecs / (np.linalg.norm(vecs, axis=1, keepdims=True) + 1e-8)
    scores = vecs @ q
    top = np.argsort(-scores)[:k]

    conn = sqlite3.connect(INDEX_DB)
    out = []
    for i in top:
        s = float(scores[i])
        if s < min_score:
            continue
        row = conn.execute(
            "SELECT cwe, name, fix, vulnerable FROM docs WHERE id=?", (int(i),)
        ).fetchone()
        if row:
            out.append((s, {
                "cwe": row[0], "name": row[1], "fix": row[2], "vulnerable": row[3],
            }))
    conn.close()
    return out