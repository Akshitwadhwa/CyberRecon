from __future__ import annotations

import re

from cyberrecon.schemas import AttackTechniqueMapping
from cyberrecon.mcp_server.mitre import MitreDataError, load_catalog
from cyberrecon.store import connect, get_events

_ID_RE = re.compile(r"\b((?:id|ep|net|al)-\d+)\b", re.IGNORECASE)
_MAPPING_LINE_RE = re.compile(
    r"^-\s*\[?(T\d{4}(?:\.\d{3})?)\]?\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*"
    r"(candidate|supported|confirmed)\s*\|\s*(.+?)\s*$",
    re.IGNORECASE,
)
_MAPPING_HEADING = "### ATT&CK candidate mappings"
_MAPPING_HEADING_RE = re.compile(r"(?im)^###\s*ATT&CK candidate mappings\s*$")


def cited_event_ids(text: str) -> list[str]:
    return sorted({m.group(1).lower() for m in _ID_RE.finditer(text)})


def ensure_attack_mapping_section(text: str) -> str:
    """Ensure specialist output has the required ATT&CK mapping section.

    This only adds protocol structure. It never creates a mapping or an event
    reference; malformed mapping content remains subject to the normal parser.
    """
    if _MAPPING_HEADING_RE.search(text):
        return text

    lines = text.splitlines()
    for index, line in enumerate(lines):
        if _MAPPING_LINE_RE.match(line.strip().replace("**", "")):
            lines.insert(index, _MAPPING_HEADING)
            return "\n".join(lines)

    suffix = f"{_MAPPING_HEADING}\n[]"
    return f"{text.rstrip()}\n\n{suffix}" if text.strip() else suffix


def _event_id_indexes(
    incident_id: str, rows: list[dict] | None = None
) -> tuple[dict[str, dict], dict[str, set[str]]]:
    if rows is None:
        conn = connect()
        try:
            rows = get_events(conn, incident_id)
        finally:
            conn.close()

    canonical = {row["id"].lower(): row for row in rows}
    aliases: dict[str, set[str]] = {}
    for row in rows:
        payload = row.get("payload")
        if not isinstance(payload, dict):
            continue
        for key, value in payload.items():
            if not key.startswith("_original_event_id") or not isinstance(value, str):
                continue
            alias = value.strip().lower()
            if alias:
                aliases.setdefault(alias, set()).add(row["id"].lower())
    return canonical, aliases


def resolve_event_ids(
    incident_id: str, event_ids: list[str], rows: list[dict] | None = None
) -> list[str]:
    """Resolve report IDs to canonical IDs for this incident only.

    Canonical IDs take precedence. Original submitted IDs are accepted only when
    they map to exactly one event in the current incident.
    """
    canonical, aliases = _event_id_indexes(incident_id, rows)
    resolved: list[str] = []
    for event_id in event_ids:
        value = event_id.strip().lower()
        if value in canonical:
            resolved.append(canonical[value]["id"])
            continue
        matches = aliases.get(value, set())
        if len(matches) > 1:
            raise ValueError(f"Ambiguous event id alias: {event_id}")
        if not matches:
            raise ValueError(f"unknown event id: {event_id}")
        resolved.append(next(iter(matches)))
    return resolved


def unknown_citations(incident_id: str, text: str) -> list[str]:
    canonical, aliases = _event_id_indexes(incident_id)
    unknown: list[str] = []
    for event_id in cited_event_ids(text):
        value = event_id.lower()
        if value in canonical or len(aliases.get(value, set())) == 1:
            continue
        unknown.append(event_id)
    return unknown


def assert_grounded(incident_id: str, text: str) -> str:
    try:
        resolve_event_ids(incident_id, cited_event_ids(text))
    except ValueError as exc:
        raise ValueError(f"Report cited invalid event ids for {incident_id}: {exc}") from exc
    return text


def parse_attack_mappings(incident_id: str, text: str) -> list[AttackTechniqueMapping]:
    """Parse and validate the required specialist ATT&CK mapping section.

    Expected line format:
    ``- T1059.001 | PowerShell | ep-11, ep-12 | candidate | rationale``
    Square brackets around the technique ID are also accepted for common
    Markdown output such as ``- [T1059.001] | ...``.
    ``[]`` is the explicit no-mapping result.
    """
    heading = re.search(r"(?im)^#+\s*ATT&CK candidate mappings\s*:?\s*$", text)
    if not heading:
        raise ValueError("Specialist output is missing the ATT&CK candidate mappings section")
    section = text[heading.end() :]
    next_heading = re.search(r"(?m)^#+\s+", section)
    if next_heading:
        section = section[: next_heading.start()]
    if not section.strip() or section.strip() == "[]":
        return []

    mappings: list[AttackTechniqueMapping] = []
    for line in section.splitlines():
        if not line.strip():
            continue
        normalized_line = line.strip().replace("**", "")
        if not normalized_line.startswith("-"):
            # Models may wrap a rationale or add a short explanatory sentence
            # inside the section; only mapping bullets are contract data.
            continue
        if re.fullmatch(r"-\s*\[(?:none available|no mappings?)\]", normalized_line, re.IGNORECASE):
            continue
        match = _MAPPING_LINE_RE.match(normalized_line)
        if not match:
            raise ValueError("Invalid ATT&CK mapping line; use the documented pipe-delimited format")
        raw_event_ids = match.group(3).strip()
        if raw_event_ids.lower() in {"[no events]", "no events", "none"}:
            continue
        event_ids = [item.strip().lower() for item in raw_event_ids.split(",") if item.strip()]
        if not event_ids:
            continue
        mapping = AttackTechniqueMapping(
            technique_id=match.group(1).upper(),
            technique_name=match.group(2).strip(),
            supporting_event_ids=event_ids,
            status=match.group(4).lower(),
            rationale=match.group(5).strip(),
        )
        mappings.append(mapping)

    conn = connect()
    try:
        known_rows = get_events(conn, incident_id)
    finally:
        conn.close()
    for index, mapping in enumerate(mappings):
        try:
            known_technique = load_catalog().get_technique(mapping.technique_id)
        except MitreDataError as exc:
            raise ValueError("ATT&CK catalog is unavailable for mapping validation") from exc
        if known_technique is None:
            raise ValueError(f"Unknown ATT&CK technique id: {mapping.technique_id}")
        try:
            canonical_event_ids = resolve_event_ids(
                incident_id, mapping.supporting_event_ids, rows=known_rows
            )
        except ValueError as exc:
            raise ValueError(
                f"ATT&CK mapping {mapping.technique_id} cited unknown event ids or an ambiguous alias: {exc}"
            ) from exc
        mapping = mapping.model_copy(update={"supporting_event_ids": canonical_event_ids})
        mappings[index] = mapping
        if mapping.status == "confirmed" and any(
            row["id"].lower() in set(mapping.supporting_event_ids)
            and row["verification_status"] != "verified"
            for row in known_rows
        ):
            raise ValueError(
                f"Confirmed ATT&CK mapping {mapping.technique_id} requires verified supporting evidence"
            )
        if mapping.status == "confirmed" and len(set(mapping.supporting_event_ids)) < 2:
            raise ValueError(
                f"Confirmed ATT&CK mapping {mapping.technique_id} requires at least two supporting event ids"
            )
    return mappings
