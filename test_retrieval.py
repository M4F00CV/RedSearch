#!/usr/bin/env python3
"""Retrieval quality test against the RAG corpus.

Moved here in the same shape as before, but consuming src.rag.retrieve
instead of duplicating the embedding logic.

TODO: move to tests/ with pytest in a future commit.
"""

from src.rag.retrieve import retrieve


QUERIES = [
    ("eval() on req.body in Node.js", "CWE-95"),
    ("SQL string formatting with user input", "CWE-89"),
    ("redirect to req.query.url", "CWE-601"),
    ("user-controlled URL fetched by server", "CWE-918"),
    ("CWE-798 python hardcoded AWS key", "CWE-798"),
    ("CWE-732 docker no-new-privileges", "CWE-732"),
    ("CWE-522 session cookie httponly secure", "CWE-522"),
    ("CWE-1357 github actions mutable tag", "CWE-1357"),
    ("CWE-319 node http.createServer", "CWE-319"),
]


def main():
    passed = 0
    for query, expected_cwe in QUERIES:
        results = retrieve(query, k=2, min_score=0.0)
        if not results:
            print(f"[FAIL] {query!r}: no results")
            continue
        top_cwe = results[0][1]["cwe"]
        score = results[0][0]
        status = "[ OK ]" if top_cwe == expected_cwe else "[FAIL]"
        print(f"{status} {query!r} → {top_cwe} (score {score:.3f})")
        if top_cwe == expected_cwe:
            passed += 1
    print(f"\n{passed}/{len(QUERIES)} passed")


if __name__ == "__main__":
    main()