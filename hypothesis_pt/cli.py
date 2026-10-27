"""Command line interface for synthetic assessment runs."""
from __future__ import annotations

import argparse
import json
import os

from .core import run_assessment
from .storage import RunStore


def main() -> None:
    parser = argparse.ArgumentParser(prog="hypothesis-pt")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="Run a synthetic scenario without network access")
    demo.add_argument("scenario", choices=["secure", "vulnerable"])
    server = commands.add_parser("serve", help="Run local dashboard")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if args.command == "demo":
        result = run_assessment(args.scenario)
        RunStore(os.getenv("HYPOTHESIS_DB", "./data/hypothesis.sqlite3")).save(result)
        print(json.dumps({"id": result["id"], "summary": result["summary"]}, indent=2))
    else:
        import uvicorn
        uvicorn.run("hypothesis_pt.web:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
