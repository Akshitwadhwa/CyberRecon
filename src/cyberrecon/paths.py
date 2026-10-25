from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
INCIDENTS_DIR = DATA_DIR / "incidents"
INTEL_PATH = DATA_DIR / "intel" / "iocs.json"
KNOWLEDGE_DIR = DATA_DIR / "knowledge"
SCHEMA_PATH = ROOT / "db" / "schema.sql"
DB_PATH = ROOT / "db" / "cyberrecon.db"
GOLD_PATH = ROOT / "eval" / "gold.json"
