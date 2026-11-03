"""dirsearch integration: web path discovery.

Uses the dirsearch Python API (FuzzerConfig + DirsearchFuzzer) instead
of the CLI. Returns metadata only (status, path, length, redirect)
to avoid prompt injection from HTTP response bodies.
"""

import signal
from pathlib import Path

# Compact fallback list for when the builtin preset exceeds max_entries.
COMMON_PATHS = [
    "admin", "admin/", "administrator", "login", "logout", "signin", "signup",
    "register", "api", "api/v1", "api/v2", "api/health", "api/status",
    "robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt",
    ".git/config", ".git/HEAD", ".env", ".env.example", ".htaccess",
    "config", "config.json", "config.php", "backup", "backups", "backup.zip",
    "db", "database", "sql", "dump.sql", "test", "tests", "dev", "staging",
    "dashboard", "panel", "cpanel", "wp-admin", "wp-login.php",
    "uploads", "files", "static", "assets", "js", "css", "images",
    "index.php", "phpinfo.php", "info.php", "server-status",
    "README.md", "CHANGELOG.md", "LICENSE", "package.json",
    "Dockerfile", "docker-compose.yml",
]


class ScanTimeout(Exception):
    """Raised when dirsearch exceeds the hard timeout."""


def _timeout_handler(signum, frame):
    raise ScanTimeout()


def dirsearch_tool(
    target_url: str,
    wordlist: str = "quick",
    extensions: str = "",
    max_entries: int = 200,
    allow_network: bool = False,
) -> str:
    """Scan web paths with dirsearch.

    Args:
        target_url: Base URL, must start with http:// or https://.
        wordlist: Preset (quick, api, admin, backups), file path,
            or comma-separated list.
        extensions: Comma-separated extensions (e.g. 'php,html,js').
        max_entries: Hard cap on entries to test (1-2000).
        allow_network: If False, returns a refusal message without
            making any HTTP requests. Caller must set explicitly.

    Returns:
        Summary of paths found (status, length, path, redirect) or error.
    """
    if not allow_network:
        return "Escaneo de red deshabilitado. Ejecuta con --allow-network para permitir dirsearch."

    if not target_url.startswith(("http://", "https://")):
        return "target_url debe empezar con http:// o https://"

    try:
        from dirsearch import (
            DirsearchFuzzer, FuzzerConfig, Wordlist,
            WordlistTemplate, WordlistLimitError,
        )
    except ImportError:
        return "dirsearch no está instalado en este Python. Activa el venv: source .venv/bin/activate"

    max_entries = min(max(1, int(max_entries)), 2000)
    hard_timeout = 120

    try:
        if Path(wordlist).exists():
            wl = Wordlist.from_file(wordlist)
        elif "," in wordlist:
            wl = Wordlist([p.strip() for p in wordlist.split(",") if p.strip()])
        else:
            preset = (wordlist or "quick").lower()
            try:
                if preset == "api":
                    tmpl = WordlistTemplate.from_builtin("api")
                elif preset == "admin":
                    tmpl = WordlistTemplate.from_builtin("admin")
                elif preset == "backups":
                    tmpl = WordlistTemplate([
                        "%CATEGORY:backups%", "%CATEGORY:db%",
                        "%CATEGORY:logs%", "%CATEGORY:keys%", "%CATEGORY:vcs%",
                    ])
                else:
                    tmpl = WordlistTemplate(["%CATEGORY:common%", "%CATEGORY:web%"])
                wl = Wordlist.from_template(tmpl, max_entries=max_entries)
            except WordlistLimitError:
                wl = Wordlist(COMMON_PATHS[:max_entries])
    except Exception as e:
        return f"Error construyendo wordlist: {e}"

    ext_tuple = tuple(e.strip() for e in extensions.split(",") if e.strip()) if extensions else ()

    config = FuzzerConfig(
        url=target_url,
        wordlist=wl,
        extensions=ext_tuple,
        timeout=3.0,
        follow_redirects=False,
        verify_tls=False,
        include_status_codes={200, 204, 301, 302, 401, 403},
        exclude_status_codes={404},
        user_agent="ollama-agente/1.0",
    )

    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(hard_timeout)
    try:
        results = DirsearchFuzzer(config).run()
    except ScanTimeout:
        return f"dirsearch alcanzó el límite de {hard_timeout}s. Usa menos entradas o un timeout menor."
    except Exception as e:
        return f"Error ejecutando dirsearch: {e}"
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

    if not results:
        return f"dirsearch no encontró rutas en {target_url} (wordlist={wordlist}, max_entries={max_entries})."

    results.sort(key=lambda r: (r.status != 200, -r.length))
    lines = []
    for r in results[:25]:
        redir = f" -> {r.redirect}" if r.redirect else ""
        lines.append(f"{r.status} {r.length:>7}B {r.path}{redir}")
    more = f"\n... y {len(results) - 25} más" if len(results) > 25 else ""
    return f"dirsearch encontró {len(results)} rutas en {target_url}:\n" + "\n".join(lines) + more