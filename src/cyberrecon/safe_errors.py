"""Redacted exception metadata for operational diagnostics."""

from __future__ import annotations

import re
from typing import Any

_SAFE_VALUE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def exception_metadata(error: BaseException) -> dict[str, Any]:
    """Return typed transport metadata without serializing exception text."""
    types: list[str] = []
    status_code: int | None = None
    provider_code: str | None = None
    request_id: str | None = None
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen and len(types) < 8:
        seen.add(id(current))
        types.append(type(current).__name__)
        if status_code is None:
            for attribute in ("status_code", "code", "status"):
                value = getattr(current, attribute, None)
                if isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599:
                    status_code = value
                    break
        if provider_code is None:
            value = getattr(current, "code", None)
            if isinstance(value, str) and _SAFE_VALUE.fullmatch(value):
                provider_code = value
        if request_id is None:
            value = getattr(current, "request_id", None)
            if isinstance(value, str) and _SAFE_VALUE.fullmatch(value):
                request_id = value
        current = current.__cause__ or current.__context__

    return {
        "exception_types": ">".join(types),
        "http_status": status_code if status_code is not None else "none",
        "provider_error_code": provider_code or "none",
        "request_id": request_id or "none",
    }


def redacted_exception_line(error: BaseException, *, stage: str) -> str:
    """Format only safe exception metadata for a process boundary log."""
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", stage):
        stage = "unknown"
    fields = exception_metadata(error)
    return " ".join(
        [f"stage={stage}"] + [f"{key}={value}" for key, value in fields.items()]
    )
