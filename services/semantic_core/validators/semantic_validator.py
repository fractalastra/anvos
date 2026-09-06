# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Any

from validators.semantic_logger import append_jsonl, build_log_entry
from validators.relation_parser import RelationParser


class SemanticValidator:
    def __init__(self, base_path: str | Path) -> None:
        self.base_path = Path(base_path)
        self.data_path = self.base_path / "data"
        self.reports_path = self.base_path / "reports"
        self.log_file = self.reports_path / "semantic_validation_log.jsonl"

        self.primitives = self._load_json("primitives.json")
        self.matrix = self._load_json("compatibility_matrix.json")
        self.grammar = self._load_json("grammar_rules.json")
        self.examples = self._load_json("examples.json")
        self.relation_parser = RelationParser(self.matrix)


        self.aliases = {
            "vida": "VIDA",
            "sistema": "SISTEMA",
            "impacto": "IMPACTO",
            "reversibilidad": "REVERSIBILIDAD",
            "irreversibilidad": "IRREVERSIBILIDAD",
            "reversible": "REVERSIBILIDAD",
            "irreversible": "IRREVERSIBILIDAD",
        }

        self.blocked_terms = {
            self.normalize(term)
            for term in self.grammar.get("blocked_terms", [])
        }

        self.blocked_verbs = {
            self.normalize(verb)
            for verb in self.grammar.get("blocked_verbs", [])
        }

        self.blocked_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.grammar.get("blocked_patterns", [])
        ]

        self.examples_by_status = {
            "valid": {
                self.normalize(text)
                for text in self.examples.get("valid", [])
            },
            "invalid": {
                self.normalize(text)
                for text in self.examples.get("invalid", [])
            },
            "frontier": {
                self.normalize(text)
                for text in self.examples.get("frontier", [])
            },
            "contaminated": {
                self.normalize(text)
                for text in self.examples.get("contaminated", [])
            },
        }

    def _load_json(self, filename: str) -> dict[str, Any]:
        file_path = self.data_path / filename
        with file_path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def normalize(self, text: str) -> str:
        text = text.strip().lower()
        text = unicodedata.normalize("NFD", text)
        text = "".join(
            ch for ch in text
            if unicodedata.category(ch) != "Mn"
        )
        text = re.sub(r"[^\w\s]", "", text)
        text = re.sub(r"_", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def detect_primitives(self, phrase: str) -> list[str]:
        normalized = self.normalize(phrase)
        found: set[str] = set()

        for alias, canonical in self.aliases.items():
            pattern = rf"\b{re.escape(alias)}\b"
            if re.search(pattern, normalized):
                found.add(canonical)

        return sorted(found)

    def detect_blocked_terms(self, phrase: str) -> list[str]:
        normalized = self.normalize(phrase)
        found: set[str] = set()

        tokens = re.findall(r"\b\w+\b", normalized)

        for token in tokens:
            if token in self.blocked_terms or token in self.blocked_verbs:
                found.add(token)

        for pattern in self.blocked_patterns:
            for match in pattern.finditer(normalized):
                found.add(match.group(0))

        return sorted(found)

    def classify(
        self,
        phrase: str,
        write_log: bool = False,
        source: str = "manual",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized = self.normalize(phrase)
        primitives = self.detect_primitives(phrase)
        blocked = self.detect_blocked_terms(phrase)
        pair_analysis = self.relation_parser.validate_pairs(primitives)
        forbidden_fusions = self.relation_parser.detect_forbidden_fusions(normalized)


        status = "valida"
        reason = "frase descriptiva compatible con el nucleo semantico"
        contamination: list[str] = []

        if normalized in self.examples_by_status["contaminated"]:
            status = "contaminada"
            reason = "frase con mezcla de semantica y valor, poder o preferencia"
            contamination.append("contaminacion_semantica")

        elif normalized in self.examples_by_status["invalid"]:
            status = "invalida"
            reason = "frase incluida en el banco de ejemplos invalidos"
            contamination.append("banco_invalido")

        elif blocked:
            status = "invalida"
            reason = "se detectaron terminos normativos, valorativos o de agencia"
            contamination.append("normativa/agencia")

        elif normalized in self.examples_by_status["frontier"]:
            status = "frontera"
            reason = "frase descriptiva con riesgo de deslizamiento semantico"

        elif not primitives:
            status = "frontera"
            reason = "no se detectaron primitivas del nucleo semantico"
        if forbidden_fusions:
            status = "contaminada"
            reason = "se detectaron fusiones semanticas prohibidas"
            contamination.append("fusion_prohibida")

        elif pair_analysis["unknown_pairs_detected"]:
            status = "frontera"
            reason = "se detectaron pares semanticos no registrados en la matriz"

        result = {
            "phrase": phrase,
            "normalized": normalized,
            "detected_primitives": primitives,
            "blocked_terms": blocked,
            "status": status,
            "reason": reason,
            "contamination": sorted(set(contamination)),
            "pair_analysis": pair_analysis,
            "forbidden_fusions": forbidden_fusions,
        }

        if write_log:
            log_entry = build_log_entry(
                phrase=phrase,
                normalized=normalized,
                detected_primitives=result["detected_primitives"],
                blocked_terms=result["blocked_terms"],
                status=result["status"],
                reason=result["reason"],
                contamination=result["contamination"],
                source=source,
                metadata=metadata,
            )
            append_jsonl(self.log_file, log_entry)

        return result
