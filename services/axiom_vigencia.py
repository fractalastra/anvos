#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""axiom_vigencia — servicio de capa que da periodicidad a semantic_core/validators/axioma_vigente.

ITB-074 (2026-08-07): axioma_vigente.py estaba desplegado y PROBADO en ambos nodos (revisor-b,
2026-08-05) pero nadie lo invocaba dentro del nodo: en el master corre por temporizador diario y
en los nodos solo a mano. layerd únicamente lanza ficheros del manifiesto que viven en services/,
y el validador es un módulo de semantic_core: este envoltorio es la pieza que faltaba — lo importa,
lo ejecuta con las rutas del nodo y deja el informe donde el manifiesto diga.

No decide nada: informa (vigencia y correspondencia son del validador). Sale con 0 también cuando
el axioma no rige — eso es un hallazgo del informe, no un fallo del servicio. Solo sale con 1
cuando ni siquiera puede preguntar (sin primitivas operativas que leer)."""
import os
import sys
import json
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from semantic_core.validators.axioma_vigente import comprobar

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
AXIOMS = os.path.join(DATA, "axioms")
PRIMITIVAS = os.path.join(HERE, "semantic_core", "data", "primitives.json")
# la clave con la que ESTE nodo admite su indice de axiomas (no una que elija quien comprueba).
# El ancla NO va embebida en el fuente: la despliega el seed o se declara por entorno.
_STG = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
PUBS = [p for p in (os.path.join(DATA, ".an_service_embedded.pub"),
        os.path.join(_STG, "an_service.pub"),
        os.path.join(DATA, "keys", "an_service.pub"),
        os.environ.get("ANVOS_ANSERVICE_PUB", "")) if p]


def main():
    rec = {"svc": "axiom_vigencia", "ts": int(time.time())}
    try:
        ops = [x["name"] for x in json.load(open(PRIMITIVAS))["primitives"]]
    except Exception as e:
        rec["error"] = "sin primitivas operativas que leer: %s" % str(e)[:80]
        print(json.dumps(rec, ensure_ascii=False))
        return 1
    rec.update(comprobar(AXIOMS, ops, PUBS))
    print(json.dumps(rec, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
