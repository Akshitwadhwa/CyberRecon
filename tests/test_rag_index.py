from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import chromadb
import pytest

from cyberrecon.rag.index import (
    DEFAULT_COLLECTION_NAME,
    IndexManifest,
    build_mitre_index,
    dataset_sha256,
)


@pytest.fixture
def workspace_tmp() -> Path:
    path = Path(tempfile.mkdtemp(prefix="cyberrecon-index-", dir=Path.cwd()))
    try:
        yield path
    finally:
        shutil.rmtree(path)


class FakeEncoder:
    def encode(self, texts, **kwargs):
        return [[float(index + 1), float(len(text) % 17), 1.0] for index, text in enumerate(texts)]


def test_index_persists_all_documents_and_manifest(workspace_tmp: Path) -> None:
    index_path = workspace_tmp / "chroma"
    manifest_path = workspace_tmp / "manifest.json"
    manifest = build_mitre_index(
        index_path=index_path,
        manifest_path=manifest_path,
        encoder=FakeEncoder(),
        batch_size=100,
    )
    assert manifest.document_count == 718
    assert manifest.embedding_dimensions == 3
    assert manifest.attack_version == "20.1"
    assert manifest.dataset_sha256 == dataset_sha256()

    client = chromadb.PersistentClient(path=str(index_path))
    collection = client.get_collection(DEFAULT_COLLECTION_NAME)
    assert collection.count() == 718
    assert collection.get(ids=["attack-pattern:T1059.001"])["ids"] == ["attack-pattern:T1059.001"]
    client.close()
    assert IndexManifest.load(manifest_path) == manifest


def test_reopening_preserves_text_and_metadata(workspace_tmp: Path) -> None:
    index_path = workspace_tmp / "chroma"
    build_mitre_index(index_path=index_path, manifest_path=workspace_tmp / "manifest.json", encoder=FakeEncoder())
    reopened = chromadb.PersistentClient(path=str(index_path))
    result = reopened.get_collection(DEFAULT_COLLECTION_NAME).get(ids=["attack-pattern:T1059"])
    assert result["documents"][0].startswith("ATT&CK technique: Command and Scripting Interpreter")
    assert result["metadatas"][0]["technique_id"] == "T1059"
    reopened.close()


def test_rebuilding_uses_upsert_without_duplicates(workspace_tmp: Path) -> None:
    index_path = workspace_tmp / "chroma"
    manifest_path = workspace_tmp / "manifest.json"
    first = build_mitre_index(index_path=index_path, manifest_path=manifest_path, encoder=FakeEncoder())
    second = build_mitre_index(index_path=index_path, manifest_path=manifest_path, encoder=FakeEncoder())
    client = chromadb.PersistentClient(path=str(index_path))
    collection = client.get_collection(DEFAULT_COLLECTION_NAME)
    assert collection.count() == 718
    assert second == first
    client.close()


def test_manifest_validation_rejects_invalid_data(workspace_tmp: Path) -> None:
    path = workspace_tmp / "bad-manifest.json"
    path.write_text(json.dumps({"document_count": 718}), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid"):
        IndexManifest.load(path)


def test_manifest_validation_rejects_bad_hash() -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        IndexManifest("not-a-hash", "20.1", "model", 384, 718, "1", "collection")

