# CyberRecon

Multi-agent investigation copilot for CSE3101. Analysts get an evidence-backed report: what happened, which event IDs support it, where sources conflict, most likely explanation, recommended human response.

Evidence is **synthetic labeled cases** in SQLite. There is no live SOC, no attacker lab, and no offensive tooling.

## Setup

```bash
cd "/Users/Lenovo/Desktop/sem-7/Agentic Ai/Project"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # paste OPENAI_API_KEY for the crew only
```

You can also copy the existing key from `../.env`.

## Run (no LLM)

```bash
python main.py ingest
python main.py demo case-a
python main.py demo case-b --failure-demo
python main.py demo case-c
```

## Run agents (needs API key)

```bash
python main.py investigate case-b
```

## Cases

| ID | What to demo |
|---|---|
| `case-a` | Benign: identity, endpoint, network agree |
| `case-b` | Conflict: suspicious host + outbound IP, login looks normal |
| `case-c` | Identity-led impossible travel; workstation quiet |
| `case-d` | Noisy but benign: corporate updater to an allowlisted host |
| `case-e` | One unlisted destination, no intel hit, browser only. Stay uncertain |

Gold labels for evaluation live in `eval/gold.json`. Agents cannot read that file.

## Layout

- `data/incidents/` JSON evidence packs
- `data/intel/` local IOC snapshot
- `data/knowledge/` RAG notes (next)
- `src/cyberrecon/tools.py` CrewAI tools over SQLite
- `src/cyberrecon/crew.py` coordinator + specialists + reconcile + report
