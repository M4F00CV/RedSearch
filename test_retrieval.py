#!/usr/bin/env python3
"""test_retrieval.py — Prueba el retrieval del índice RAG."""
import json, sqlite3, urllib.request
from pathlib import Path
import numpy as np

def embed(text):
    payload = {"model": "nomic-embed-text", "prompt": text}
    req = urllib.request.Request(
        "http://localhost:11434/api/embeddings",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return np.array(json.loads(r.read())["embedding"], dtype=np.float32)

def retrieve(query, k=2):
    q = embed(query)
    q /= np.linalg.norm(q)
    vecs = np.load("data/embeddings.npy")
    vecs /= np.linalg.norm(vecs, axis=1, keepdims=True)
    scores = vecs @ q
    top = np.argsort(-scores)[:k]
    conn = sqlite3.connect("data/index.db")
    out = []
    for i in top:
        row = conn.execute("SELECT cwe, name, fix FROM docs WHERE id=?", (int(i),)).fetchone()
        out.append((float(scores[i]), row))
    conn.close()
    return out

queries = [
    "eval() on req.body in Node.js",
    "SQL string formatting with user input",
    "redirect to req.query.url",
    "user-controlled URL fetched by server",
]
for q in queries:
    print(f"\nQuery: {q}")
    for score, row in retrieve(q):
        print(f"  [{score:.3f}] {row[0]} {row[1]}")

extra_queries = [
    "CWE-798 python hardcoded AWS key",
    "CWE-732 docker no-new-privileges",
    "CWE-522 session cookie httponly secure",
    "CWE-1357 github actions mutable tag",
    "CWE-319 node http.createServer",
]

for q in extra_queries:
    print(f"\nQuery: {q}")
    for score, row in retrieve(q):
        print(f"  [{score:.3f}] {row[0]} {row[1]}")