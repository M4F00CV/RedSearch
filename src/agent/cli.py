"""CLI entry point for the agent."""

import argparse

from src.agent.react_loop import run_agent
from src.tools import registry

MAX_ITERATIONS = 6


def main_cli():
    """Parse CLI args and run the agent."""
    parser = argparse.ArgumentParser()
    parser.add_argument("goal")
    parser.add_argument("--max-iter", type=int, default=MAX_ITERATIONS)
    parser.add_argument(
        "--allow-network",
        action="store_true",
        help="Permite herramientas que hacen peticiones de red (dirsearch).",
    )
    args = parser.parse_args()

    # Inject network flag into registry (read by _dirsearch_with_config)
    registry.ALLOW_NETWORK = args.allow_network
    run_agent(args.goal, max_iter=args.max_iter)