#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""
ASTRANOVA — AXIOM INTEGRITY CHECKER
Phase: Local IA · Foundational Integrity

ENGLISH:
This process verifies the integrity of the foundational axioms.
It does not enforce immutability.
It only detects and records divergence.

ESPAÑOL:
Este proceso verifica la integridad de los axiomas fundacionales.
No impone inmutabilidad.
Solo detecta y registra divergencias.

ITV-062 (2026-08-07): la primera copia desplegada a los nodos iba SIN firma, fuera del
manifiesto, y layerd —fail-closed— nunca la ejecutó, dejando además MAIN en estado no
verificado. Esta es la MISMA lógica que revisor-b probó en ambos nodos (detecta 'intact' y
'modified'), colocada en la fuente canónica de la capa para que viaje firmada y anotada
en el manifiesto, que es lo que le faltaba para correr.
"""

from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json

# Las rutas dejan de estar fijas para que este mismo verificador pueda correr en un nodo soberano,
# donde el arbol de cognicion no vive en esa ruta. Sin ANV_COGNITION, se usa el arbol del nodo si
# existe y, si no, el del equipo principal: el mismo fichero corre en las dos formas.
import os
_DEF_NODO = "/persist/anvos-data/cognition"
BASE_PATH = Path(os.environ.get("ANV_COGNITION") or _DEF_NODO)
AXIOMS_PATH = BASE_PATH / "axioms"
MEMORY_PATH = BASE_PATH / "memory"

AXIOM_FILE = AXIOMS_PATH / "INITIAL_AXIOMS.md"
HASH_FILE = AXIOMS_PATH / "INITIAL_AXIOMS.sha256"
INTEGRITY_LOG = MEMORY_PATH / "axiom_integrity_log.jsonl"


def calculate_hash(path: Path):
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha.update(chunk)
    return sha.hexdigest()


def load_expected_hash():
    if not HASH_FILE.exists():
        return None
    return HASH_FILE.read_text().split()[0]


def record_integrity(status: str, details: dict):
    entry = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "details": details
    }
    MEMORY_PATH.mkdir(parents=True, exist_ok=True)
    with open(INTEGRITY_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    # bajo layerd el stdout se anexa a la salida del manifiesto: el mismo hecho, visible ahi
    print(json.dumps({"svc": "axiom_integrity_checker", "base": str(BASE_PATH), **entry},
                     ensure_ascii=False))


if __name__ == "__main__":
    if not AXIOM_FILE.exists() or not HASH_FILE.exists():
        record_integrity(
            "missing",
            {"message": "Axiom file or hash file missing"}
        )
    else:
        current_hash = calculate_hash(AXIOM_FILE)
        expected_hash = load_expected_hash()

        if current_hash == expected_hash:
            record_integrity(
                "intact",
                {"hash": current_hash}
            )
        else:
            record_integrity(
                "modified",
                {
                    "expected": expected_hash,
                    "current": current_hash
                }
            )
