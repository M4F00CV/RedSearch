#!/usr/bin/env python3
"""Legacy wrapper. Delegates to src.orchestrator.pipeline.

Deprecated: use `python -m src.orchestrator.pipeline` in new code.
Kept for backward compatibility with existing scripts and docs.
"""

from src.orchestrator.pipeline import main

if __name__ == "__main__":
    main()