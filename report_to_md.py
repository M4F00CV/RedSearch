#!/usr/bin/env python3
"""Legacy wrapper. Delegates to src.orchestrator.report_md.

Deprecated: use `python -m src.orchestrator.report_md` in new code.
"""

from src.orchestrator.report_md import main_cli

if __name__ == "__main__":
    main_cli()