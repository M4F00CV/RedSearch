"""RAG corpus tool: search CWEs and fixes."""

from src.rag.retrieve import retrieve


def search_corpus_tool(query: str, k: int = 2) -> str:
    """Search the RAG corpus for CWEs, vulnerable patterns, and fixes.

    Args:
        query: Natural language or keywords (e.g. 'SQL injection python f-string').
        k: Number of top results to return.

    Returns:
        Formatted results with CWE, vulnerable pattern, and recommended fix.
    """
    results = retrieve(query, k=k, min_score=0.50)
    if not results:
        return f"Sin resultados relevantes en el corpus para: {query}"

    out = []
    for score, r in results:
        out.append(
            f"[{r['cwe']} {r['name']}] (score {score:.2f})\n"
            f"  Patrón vulnerable: {r['vulnerable']}\n"
            f"  Fix recomendado: {r['fix']}"
        )
    return "\n\n".join(out)