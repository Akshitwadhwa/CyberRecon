"""Run and measure the existing CyberRecon investigation."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from cyberrecon.evaluation import evaluate_case  # noqa: E402


if __name__ == "__main__":
    incident_id = sys.argv[1] if len(sys.argv) > 1 else "case-b"
    path = asyncio.run(evaluate_case(incident_id))
    print(f"Saved evaluation: {path}")
