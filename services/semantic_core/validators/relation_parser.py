# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
from __future__ import annotations

import re
from itertools import combinations
from typing import Any


class RelationParser:
    def __init__(self, matrix: dict[str, Any]) -> None:
        self.matrix = matrix

        self.allowed_pairs = {
            tuple(sorted(pair))
            for pair in self.matrix.get("allowed_pairs", [])
        }

        self.restricted_pairs = {
            tuple(sorted(item["pair"])): item["rule"]
            for item in self.matrix.get("restricted_pairs", [])
        }

        self.forbidden_fusions = self.matrix.get("forbidden_fusions", [])

    def extract_pairs(self, primitives: list[str]) -> list[tuple[str, str]]:
        if len(primitives) < 2:
            return []

        pairs = [
            tuple(sorted(pair))
            for pair in combinations(sorted(set(primitives)), 2)
        ]
        return pairs

    def validate_pairs(self, primitives: list[str]) -> dict[str, Any]:
        detected_pairs = self.extract_pairs(primitives)

        allowed: list[list[str]] = []
        restricted: list[dict[str, str]] = []
        unknown: list[list[str]] = []

        for pair in detected_pairs:
            if pair in self.allowed_pairs:
                if pair in self.restricted_pairs:
                    restricted.append({
                        "pair": f"{pair[0]}<->{pair[1]}",
                        "rule": self.restricted_pairs[pair]
                    })
                else:
                    allowed.append([pair[0], pair[1]])
            else:
                unknown.append([pair[0], pair[1]])

        return {
            "detected_pairs": [[a, b] for a, b in detected_pairs],
            "allowed_pairs_detected": allowed,
            "restricted_pairs_detected": restricted,
            "unknown_pairs_detected": unknown,
        }

    # Nexo copulativo o atributivo: lo que convierte dos conceptos en una FUSION.
    # No basta con que dos palabras aparezcan; hace falta que una se predique de la otra.
    # Ojo con las contracciones: «emana del sistema» es «emana de» + «l sistema», sin espacio
    # entre la preposición y el artículo. Escribir `emana de\s+` deja escapar justo la forma
    # más natural en castellano. Por eso las preposiciones llevan la contracción opcional.
    _NEXO = r"(?:\s+(?:es|son|era|eran|ser[ií]a|equivale al?|significa|consiste en|se reduce al?|" \
            r"act[uú]a como|funciona como|ejerce(?:\s+(?:del?|como))?|encarna|constituye|representa|" \
            r"tiene|ostenta|posee|detenta|asume|concentra|reside en|radica en|emana del?|" \
            r"pertenece al?|corresponde al?|proviene del?|nace del?)\s*)"
    # «lo» incluido: la forma neutra —«lo reversible es lo permitido»— es la que usa el axioma.
    _ART = r"(?:el|la|lo|los|las|un|una|unos|unas|su|sus|toda|todo)?\s*"

    def _fusion(self, a: str, b: str) -> list[str]:
        """Patrones en los dos sentidos: «a <nexo> b» y «b <nexo> a»."""
        return [rf"\b{a}\b{self._NEXO}{self._ART}\b{b}\b",
                rf"\b{b}\b{self._NEXO}{self._ART}\b{a}\b"]

    def detect_forbidden_fusions(self, phrase: str) -> list[str]:
        """Detecta que dos conceptos se PREDIQUEN uno del otro, no que coincidan en el texto.

        DEFECTO MEDIDO Y SUBSANADO (1-ago-2026). La versión anterior buscaba `a.*b` sobre el
        texto COMPLETO, de modo que cualquier documento que nombrase «sistema» en una frase y
        «autoridad» doce frases después quedaba marcado como fusión prohibida. No detectaba una
        fusión: detectaba **coincidencia a cualquier distancia**, y además dependía del orden —
        se le escapaba «la autoridad es externa; el sistema no la contiene», que dice lo
        contrario de lo que se le imputaba al texto legítimo.

        Consecuencia medida: bloqueó de forma sistemática los hechos de ingeniería del propio
        ecosistema, cuyo vocabulario habla a diario de fichero de autoridad, cadena de autoridad
        y autoridad de firma. Se creyó durante días que el vocabulario chocaba con los axiomas
        del núcleo. **No chocaba: el axioma es correcto y el vocabulario también; el instrumento
        que los enfrentaba estaba mal escrito.**

        Lo revelador es que en este mismo diccionario `VIDA=SISTEMA` ya estaba escrito bien,
        exigiendo la construcción copulativa. El modelo correcto llevaba aquí desde el principio.

        Dos correcciones, y ninguna toca el axioma:
          1. Se evalúa **frase a frase**, no sobre el documento entero.
          2. Dentro de la frase se exige un **nexo copulativo o atributivo** — ser, equivaler,
             ejercer, encarnar, residir en— que es lo que convierte dos conceptos en una fusión.

        El resultado es MÁS fiel al axioma que la versión anterior, no menos: ahora también caza
        «la autoridad reside en el sistema», que antes pasaba por estar en orden inverso.
        """
        normalized = re.sub(r"\s+", " ", phrase.lower())
        # Frase a frase: una fusión se afirma dentro de una oración, no a lo largo de un texto.
        oraciones = [o for o in re.split(r"[.;:!?\n]+", normalized) if o.strip()]

        patterns = {
            "VIDA=VALOR": self._fusion("vida", "valor(?:es)?"),
            "SISTEMA=AUTORIDAD": self._fusion("sistema", "autoridad(?:es)?") + [
                # el sistema como sujeto que manda: eso sí es la fusión que el axioma veda
                r"\bsistema\b\s+(?:lo\s+|la\s+|le\s+|les\s+|nos\s+|me\s+)?"
                r"(?:controla|gobierna|domina|manda|dirige|somete|impone)\b",
            ],
            "IMPACTO=DANO": self._fusion("impacto", "da[nñ]o"),
            "REVERSIBILIDAD=PERMISO": self._fusion("reversibilidad", "permiso")
            + self._fusion("reversible", "permitid[oa]")
            + self._fusion("reversible", "aceptable")
            + self._fusion("reversible", "l[ií]cit[oa]"),
            "IRREVERSIBILIDAD=PROHIBICION": self._fusion("irreversibilidad", "prohibici[oó]n")
            + self._fusion("irreversible", "prohibid[oa]")
            + self._fusion("irreversible", "inaceptable")
            + self._fusion("irreversible", "il[ií]cit[oa]")
            + [r"\birreversible\b\s+debe impedirse\b"],
            "VIDA=SISTEMA": self._fusion("vida", "sistema"),
        }

        fusion_hits: list[str] = []
        for fusion, fusion_patterns in patterns.items():
            for pattern in fusion_patterns:
                if any(re.search(pattern, o, re.IGNORECASE) for o in oraciones):
                    fusion_hits.append(fusion)
                    break

        return sorted(set(fusion_hits))
