"""File I/O tools: read fragments and write reports."""

from pathlib import Path


def read_file_tool(path: str, start_line: int = 1, num_lines: int = 30) -> str:
    """Read a fragment of a file.

    Args:
        path: File path.
        start_line: 1-based line to start reading from.
        num_lines: Number of lines to read.

    Returns:
        Formatted lines with line numbers, or error message.
    """
    p = Path(path)
    if not p.exists():
        return f"Archivo no encontrado: {path}"
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(0, start_line - 1)
    end = min(len(lines), start + num_lines)
    return "\n".join(f"{i+1:4d} | {lines[i]}" for i in range(start, end))


def write_report_tool(content: str, filename: str = "agent_report.md") -> str:
    """Write a report to reports/<filename>.

    Args:
        content: Markdown content.
        filename: Filename inside reports/.

    Returns:
        Confirmation with byte count.
    """
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    out = reports_dir / filename
    out.write_text(content, encoding="utf-8")
    return f"Reporte escrito en {out} ({len(content)} bytes)."