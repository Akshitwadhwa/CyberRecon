#!/usr/bin/env python3
"""CyberRecon entrypoint.

  python main.py ingest
  python main.py demo case-b
  python main.py demo case-b --failure-demo
  python main.py investigate case-b
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberRecon")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("ingest", help="Load JSON incidents and intel into SQLite")

    demo = sub.add_parser("demo", help="Print ticket + tool results (no LLM)")
    demo.add_argument("incident_id", nargs="?", default="case-b")
    demo.add_argument("--failure-demo", action="store_true")

    inv = sub.add_parser("investigate", help="Run the CrewAI crew (needs OPENAI_API_KEY)")
    inv.add_argument("incident_id", nargs="?", default="case-b")

    args = parser.parse_args()

    if args.cmd == "ingest":
        from cyberrecon.ingest import run

        print("Ingested:", ", ".join(run()))
        return

    if args.cmd == "demo":
        from cyberrecon.demo import demo_tool_failure, print_case

        print_case(args.incident_id)
        if args.failure_demo:
            print()
            demo_tool_failure()
        return

    if args.cmd == "investigate":
        from cyberrecon.crew import investigate

        text, folder = investigate(args.incident_id)
        print(text)
        print(f"\nSaved run: {folder}")


if __name__ == "__main__":
    main()
