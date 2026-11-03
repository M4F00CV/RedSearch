"""RAG corpus tool: search CWEs and fixes."""

import json
import sqlite3
import urllib.request
from pathlib import Path

import numpy as np

EMBED_URL = "http://localhost:11434/api/embeddings"
EMBED_MODEL = "nomic-embed-text"


def search_corpus_tool(query: str, k: int = 2) -> str:
    """Search the RAG corpus for CWEs, vulnerable patterns, and fixes.

    Args:
        query: Natural language or keywords (e.g. 'SQL injection python f-string').
        k: Number of top results to return.

    Returns:
        Formatted results with CWE, vulnerable pattern, and recommended fix.
    """
    data_dir = Path(__file__).parent.parent.parent / "data"
    embeddings = data_dir / "embeddings.npy"
    index_db = data_dir / "index.db"
    if not embeddings.exists() or not index_db.exists():
        return "Corpus RAG no disponible (ejecuta build_index.py primero)."

    payload = {"model": EMBED_MODEL, "prompt": query}
    req = urllib.request.Request(
        EMBED_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        q = np.array(json.loads(r.read())["embedding"], dtype=np.float32)
    q /= (np.linalg.norm(q) + 1e-8)
    vecs = np.load(embeddings)
    vecs /= (np.linalg.norm(vecs, axis=1, keepdims=True) + 1e-8)
    scores = vecs @ q
    top = np.argsort(-scores)[:k]

    conn = sqlite3.connect(index_db)
    out = []
    for i in top:
        s = float(scores[i])
        if s < 0.50:
            continue
        row = conn.execute(
            "SELECT cwe, name, vulnerable, fix FROM docs WHERE id=?", (int(i),)
        ).fetchone()
        if row:
            out.append(
                f"[{row[0]} {row[1]}] (score {s:.2f})\n"
                f"  Patrón vulnerable: {row[2]}\n"
                f"  Fix recomendado: {row[3]}"
            )
    conn.close()
    if not out:
        return f"Sin resultados relevantes en el corpus para: {query}"
    return "\n\n".join(out)