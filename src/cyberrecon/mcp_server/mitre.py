"""Cached loader for the local MITRE ATT&CK Enterprise STIX bundle."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from cyberrecon.paths import ROOT

MITRE_DATA_PATH = ROOT / "data" / "mitre" / "enterprise-attack.json"
_ATTACK_ID_RE = re.compile(r"^(?:T|TA|M)\d{4}(?:\.\d{3})?$")


class MitreDataError(RuntimeError):
    """Raised when the local ATT&CK bundle is missing or malformed."""


def _attack_id(obj: dict[str, Any]) -> str | None:
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            value = reference.get("external_id")
            if isinstance(value, str) and _ATTACK_ID_RE.fullmatch(value):
                return value
    return None


def _description(obj: dict[str, Any]) -> str:
    value = obj.get("description", "")
    return value.strip() if isinstance(value, str) else ""


def _references(obj: dict[str, Any]) -> list[str]:
    return [
        ref["url"]
        for ref in obj.get("external_references", [])
        if isinstance(ref.get("url"), str)
    ]


def _active(obj: dict[str, Any]) -> bool:
    return not obj.get("revoked", False) and not obj.get("deprecated", False)


@dataclass(frozen=True)
class MitreCatalog:
    """Normalized, read-only ATT&CK indexes used by the MCP tools."""

    techniques: dict[str, dict[str, Any]]
    tactics: dict[str, dict[str, Any]]
    mitigations: dict[str, dict[str, Any]]
    mitigation_ids_by_technique: dict[str, tuple[str, ...]]
    dataset_path: Path

    def get_technique(self, attack_id: str) -> dict[str, Any] | None:
        return self.techniques.get(attack_id.upper())

    def search_techniques(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        needle = query.casefold().strip()
        matches = [
            technique
            for technique in self.techniques.values()
            if needle in technique["attack_id"].casefold()
            or needle in technique["name"].casefold()
            or needle in technique["description"].casefold()
        ]
        return sorted(
            matches,
            key=lambda item: (
                0 if needle in item["name"].casefold() else 1,
                item["name"].casefold(),
                item["attack_id"],
            ),
        )[:limit]


def _build_catalog(bundle: dict[str, Any], path: Path) -> MitreCatalog:
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise MitreDataError("ATT&CK dataset does not contain an objects list")

    live = [obj for obj in objects if isinstance(obj, dict) and _active(obj)]
    tactics_by_stix: dict[str, dict[str, Any]] = {}
    tactics_by_name: dict[str, dict[str, Any]] = {}
    for obj in live:
        if obj.get("type") != "x-mitre-tactic":
            continue
        attack_id = _attack_id(obj)
        if not attack_id:
            continue
        item = {
            "attack_id": attack_id,
            "name": obj.get("name", ""),
            "description": _description(obj),
            "technique_ids": [],
            "references": _references(obj),
        }
        tactics_by_stix[obj.get("id", "")] = item
        tactics_by_name[item["name"].casefold()] = item

    techniques: dict[str, dict[str, Any]] = {}
    for obj in live:
        if obj.get("type") != "attack-pattern":
            continue
        attack_id = _attack_id(obj)
        if not attack_id:
            continue
        tactic_items = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            tactic = tactics_by_name.get(str(phase.get("phase_name", "")).casefold())
            if tactic and tactic not in tactic_items:
                tactic_items.append(tactic)
        parent_id = attack_id.split(".", 1)[0] if "." in attack_id else None
        techniques[attack_id] = {
            "attack_id": attack_id,
            "name": obj.get("name", ""),
            "description": _description(obj),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", "." in attack_id)),
            "parent_id": parent_id,
            "tactic_ids": [item["attack_id"] for item in tactic_items],
            "tactics": [item["name"] for item in tactic_items],
            "references": _references(obj),
            "stix_id": obj.get("id", ""),
        }
        for tactic in tactic_items:
            tactic["technique_ids"].append(attack_id)

    mitigations: dict[str, dict[str, Any]] = {}
    for obj in live:
        if obj.get("type") != "course-of-action":
            continue
        attack_id = _attack_id(obj)
        if attack_id:
            mitigations[attack_id] = {
                "attack_id": attack_id,
                "name": obj.get("name", ""),
                "description": _description(obj),
                "references": _references(obj),
                "stix_id": obj.get("id", ""),
            }

    mitigation_ids: dict[str, list[str]] = {attack_id: [] for attack_id in techniques}
    techniques_by_stix = {item["stix_id"]: item for item in techniques.values()}
    mitigations_by_stix = {item["stix_id"]: item for item in mitigations.values()}
    for obj in live:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "mitigates":
            continue
        source = mitigations_by_stix.get(obj.get("source_ref", ""))
        target = techniques_by_stix.get(obj.get("target_ref", ""))
        if source and target:
            ids = mitigation_ids[target["attack_id"]]
            if source["attack_id"] not in ids:
                ids.append(source["attack_id"])

    for technique in techniques.values():
        technique["mitigation_ids"] = mitigation_ids[technique["attack_id"]]

    return MitreCatalog(
        techniques=techniques,
        tactics={item["attack_id"]: item for item in tactics_by_stix.values()},
        mitigations=mitigations,
        mitigation_ids_by_technique={key: tuple(value) for key, value in mitigation_ids.items()},
        dataset_path=path,
    )


@lru_cache(maxsize=1)
def load_catalog(path: str | Path = MITRE_DATA_PATH) -> MitreCatalog:
    """Load and normalize ATT&CK once per process."""
    dataset_path = Path(path)
    try:
        bundle = json.loads(dataset_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MitreDataError("Local ATT&CK dataset is unavailable") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise MitreDataError("Local ATT&CK dataset could not be read") from exc
    if not isinstance(bundle, dict):
        raise MitreDataError("Local ATT&CK dataset must be a JSON object")
    return _build_catalog(bundle, dataset_path)
