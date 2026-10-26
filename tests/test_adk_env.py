from __future__ import annotations

import os
import tempfile
from pathlib import Path

from adk_app.agent import _load_project_environment


def test_project_env_overrides_process_openai_key_without_mapping_google_key(monkeypatch) -> None:
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
        project_root = Path(temp_dir) / "project"
        project_root.mkdir()
        (project_root / ".env").write_text(
            "OPENAI_API_KEY=file-openai-key\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("OPENAI_API_KEY", "process-google-shaped-key")
        monkeypatch.setenv("GOOGLE_API_KEY", "process-google-key")

        values = _load_project_environment(project_root)

        assert values["OPENAI_API_KEY"] == "file-openai-key"
        assert os.environ["OPENAI_API_KEY"] == "file-openai-key"
        assert os.environ["GOOGLE_API_KEY"] == "process-google-key"
