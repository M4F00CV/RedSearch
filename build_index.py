#!/usr/bin/env python3
"""Legacy wrapper. Delegates to src.rag.index.

Deprecated: use `python -m src.rag.index` in new code.
"""

from src.rag.index import build_index

if __name__ == "__main__":
    build_index()