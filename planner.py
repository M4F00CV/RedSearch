#!/usr/bin/env python3
"""Legacy wrapper. Delegates to src.planner.planner.

Deprecated: use `python -m src.planner.planner` in new code.
"""

from src.planner.planner import main_cli

if __name__ == "__main__":
    main_cli()