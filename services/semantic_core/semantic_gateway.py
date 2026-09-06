# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from validators.semantic_logger import append_jsonl
from validators.semantic_validator import SemanticValidator


class SemanticGateway:
    def __init__(self, base_path: str | Path) -> None:
        self.base_path = Path(base_path)
        self.validator = SemanticValidator(self.base_path)
        self.gateway_log_file = self.base_path / "reports" / "semantic_gateway_log.jsonl"

        self.policy_map = {
            "valida": {
                "decision": "allow",
                "reason": "texto compatible con el nucleo semantico"
            },
            "frontera": {
                "decision": "review",
                "reason": "texto con riesgo semantico; requiere revision"
            },
            "invalida": {
                "decision": "block",
                "reason": "texto incompatible con las reglas semanticas"
            },
            "contaminada": {
                "decision": "block",
                "reason": "texto contaminado por valor, poder, permiso o fusion prohibida"
            }
        }

    def evaluate(
        self,
        text: str,
        direction: str = "input",
        source: str = "gateway",
        metadata: dict[str, Any] | None = None,
        write_log: bool = True,
    ) -> dict[str, Any]:
        semantic_result = self.validator.classify(
            text,
            write_log=write_log,
            source=f"{source}:{direction}:semantic_validator",
            metadata={
                "layer": "semantic_validator",
                "direction": direction,
                **(metadata or {})
            }
        )

        semantic_status = semantic_result["status"]
        policy = self.policy_map.get(
            semantic_status,
            {
                "decision": "review",
                "reason": "estado no reconocido; requiere revision"
            }
        )

        result = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "direction": direction,
            "source": source,
            "text": text,
            "semantic_status": semantic_status,
            "gateway_decision": policy["decision"],
            "gateway_reason": policy["reason"],
            "semantic_result": semantic_result,
            "metadata": metadata or {}
        }

        if write_log:
            append_jsonl(self.gateway_log_file, result)

        return result
