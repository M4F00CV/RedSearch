"""Tool registry: schemas and dispatch map.

Centralizes the OpenAI function-calling schemas and the runtime
dispatch map. Adding a new tool = add function + add schema + add
entry to TOOL_MAP.
"""

from src.tools.corpus import search_corpus_tool
from src.tools.dirsearch import dirsearch_tool
from src.tools.files import read_file_tool, write_report_tool
from src.tools.gitleaks import gitleaks_tool
from src.tools.semgrep import run_semgrep_tool

# Set by CLI entry point (scripts/agent.py) before run_agent.
ALLOW_NETWORK = False


def _dirsearch_with_config(target_url: str, wordlist: str = "quick",
                           extensions: str = "", max_entries: int = 200) -> str:
    """Wrapper that injects the global ALLOW_NETWORK flag into dirsearch_tool."""
    return dirsearch_tool(
        target_url, wordlist, extensions, max_entries,
        allow_network=ALLOW_NETWORK,
    )


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_semgrep_tool",
            "description": "Escanea un archivo o directorio con Semgrep.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Ruta a escanear."}
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file_tool",
            "description": "Lee líneas de un archivo de código.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Ruta del archivo."},
                    "start_line": {"type": "integer"},
                    "num_lines": {"type": "integer"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "gitleaks_tool",
            "description": "Detecta secretos hardcodeados (API keys, passwords, tokens) con gitleaks.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Ruta a escanear."}
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_corpus_tool",
            "description": "Consulta el corpus RAG de CWEs para obtener patrones vulnerables y fixes concretos.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Descripción del problema (ej. 'SQL injection python f-string')."},
                    "k": {"type": "integer", "description": "Número de resultados (default 2)."},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_report_tool",
            "description": "Guarda un reporte en formato Markdown en reports/.",
            "parameters": {
                "type": "object",
                "properties": {
                    "content": {"type": "string", "description": "Contenido del reporte en Markdown."},
                    "filename": {"type": "string", "description": "Nombre del archivo (default agent_report.md)."},
                },
                "required": ["content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dirsearch_tool",
            "description": (
                "Escanea rutas y directorios web con dirsearch. "
                "Devuelve solo metadatos (status, path, length, content_type, redirect), "
                "NO el cuerpo de la respuesta. Requiere --allow-network."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "URL base, ej. https://example.com"},
                    "wordlist": {
                        "type": "string",
                        "description": "Preset: quick, api, admin, backups; ruta a archivo; o lista separada por comas. Default quick.",
                    },
                    "extensions": {"type": "string", "description": "Extensiones separadas por coma, ej. php,html,js"},
                    "max_entries": {"type": "integer", "description": "Máximo de rutas a probar (default 200, cap 2000)."},
                },
                "required": ["target_url"],
            },
        },
    },
]


TOOL_MAP = {
    "run_semgrep_tool": run_semgrep_tool,
    "read_file_tool": read_file_tool,
    "gitleaks_tool": gitleaks_tool,
    "search_corpus_tool": search_corpus_tool,
    "write_report_tool": write_report_tool,
    "dirsearch_tool": _dirsearch_with_config,
}