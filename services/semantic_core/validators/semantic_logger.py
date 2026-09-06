# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def append_jsonl(log_path: str | Path, payload: dict[str, Any]) -> None:
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def build_log_entry(
    *,
    phrase: str,
    normalized: str,
    detected_primitives: list[str],
    blocked_terms: list[str],
    status: str,
    reason: str,
    contamination: list[str],
    source: str = "manual",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "phrase": phrase,
        "normalized": normalized,
        "detected_primitives": detected_primitives,
        "blocked_terms": blocked_terms,
        "status": status,
        "reason": reason,
        "contamination": contamination,
        "metadata": metadata or {},
    }
