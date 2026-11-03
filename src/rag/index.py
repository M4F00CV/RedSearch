"""Build the RAG index from data/corpus.json."""

import json
import sqlite3
import sys
from pathlib import Path

import numpy as np

from src.core.llm import embed_query

DATA_DIR = Path(__file__).parent.parent.parent / "data"
CORPUS = DATA_DIR / "corpus.json"
DB = DATA_DIR / "index.db"
NPY = DATA_DIR / "embeddings.npy"


def build_index() -> None:
    """Build embeddings and SQLite index from the corpus JSON.

    Reads data/corpus.json, generates one embedding per document,
    and writes data/embeddings.npy + data/index.db.
    """
    if not CORPUS.exists():
        print(f"Falta {CORPUS}", file=sys.stderr)
        sys.exit(1)
    docs = json.loads(CORPUS.read_text(encoding="utf-8"))
    print(f"Corpus: {len(docs)} documentos")

    vectors = []
    for i, doc in enumerate(docs, 1):
        text = (
            f"{doc['cwe']} {doc['name']}. {doc['description']} "
            f"Vulnerable: {doc['vulnerable']} Fix: {doc['fix']}"
        )
        vec = embed_query(text)
        vectors.append(vec)
        print(f"  [{i}/{len(docs)}] {doc['cwe']} {doc['name']} ({len(vec)} dims)")

    arr = np.array(vectors, dtype=np.float32)
    np.save(NPY, arr)

    conn = sqlite3.connect(DB)
    conn.execute("DROP TABLE IF EXISTS docs")
    conn.execute("""CREATE TABLE docs (
        id INTEGER PRIMARY KEY, cwe TEXT, name TEXT, description TEXT,
        vulnerable TEXT, fix TEXT, owasp TEXT
    )""")
    for i, doc in enumerate(docs):
        conn.execute("INSERT INTO docs VALUES (?,?,?,?,?,?,?)",
                     (i, doc["cwe"], doc["name"], doc["description"],
                      doc["vulnerable"], doc["fix"], doc.get("owasp", "")))
    conn.commit()
    conn.close()
    print(f"\nOK:\n  vectores: {NPY}  shape={arr.shape}\n  textos:   {DB}")