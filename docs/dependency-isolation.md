# Dependency isolation

The CrewAI and Google ADK profiles are intentionally separated because the
currently selected framework versions require incompatible OpenTelemetry
versions.

Create one environment per execution path:

```powershell
python -m venv .venv-crewai
.\.venv-crewai\Scripts\Activate.ps1
python -m pip install -r requirements-crewai.txt
```

For the ADK path, use a separate shell and environment:

```powershell
python -m venv .venv-adk
.\.venv-adk\Scripts\Activate.ps1
python -m pip install -r requirements-adk.txt
```

Do not install both profile files into one environment. The combined
`requirements.txt` remains for compatibility with the original prototype;
the profile files are the supported way to run either framework reliably.

## Local A2A development

Start the CrewAI service from the CrewAI environment in one PowerShell window:

```powershell
.\.venv-crewai\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\src"
python -m cyberrecon.crewai_a2a
```

In a second PowerShell window, run the ADK path with the service URL:

```powershell
.\.venv-adk\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\src;$PWD"
$env:CREWAI_A2A_URL = "http://127.0.0.1:8765"
python main.py adk case-b
```

The ADK runner only contacts the CrewAI service when `CREWAI_A2A_URL` is set;
without it, the existing standalone ADK path remains available.
