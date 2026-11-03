#!/usr/bin/env python3
"""Legacy entry point. Delegates to src.agent.cli.

Deprecated: use `python -m src.agent.cli ...` or the scripts/
wrapper added in the next refactor commit. Kept for backward
compatibility with existing commands and the planner subprocess call.
"""

from src.agent.cli import main_cli

if __name__ == "__main__":
    main_cli()