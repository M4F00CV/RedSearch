#!/usr/bin/env python3
"""
build_index.py — Construye el índice vectorial del corpus RAG.
- Lee data/corpus.json
- Genera embeddings con nomic-embed-text vía Ollama (host Windows)
- Guarda SQLite (textos) + numpy (vectores)
"""

import json
import sqlite3
import sys
import urllib.request
from pathlib import Path

import numpy as np

OLLAMA_URL = "http://localhost:11434/api/embeddings"
EMBED_MODEL = "nomic-embed-text"
DATA_DIR = Path(__file__).parent / "data"
CORPUS = DATA_DIR / "corpus.json"
DB = DATA_DIR / "index.db"
NPY = DATA_DIR / "embeddings.npy"


def embed(text):
    payload = {"model": EMBED_MODEL, "prompt": text}
    data = json.dumps(payload).encode()
    req = urllib.request.Request(OLLAMA_URL, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = json.loads(resp.read().decode())
    return body["embedding"]


def main():
    if not CORPUS.exists():
        print(f"Falta {CORPUS}", file=sys.stderr)
        sys.exit(1)
    docs = json.loads(CORPUS.read_text(encoding="utf-8"))
    print(f"Corpus: {len(docs)} documentos")

    vectors = []
    for i, doc in enumerate(docs, 1):
        text = f"{doc['cwe']} {doc['name']}. {doc['description']} Vulnerable: {doc['vulnerable']} Fix: {doc['fix']}"
        vec = embed(text)
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
    print(f"\nOK:")
    print(f"  vectores: {NPY}  shape={arr.shape}")
    print(f"  textos:   {DB}")


if __name__ == "__main__":
    main()