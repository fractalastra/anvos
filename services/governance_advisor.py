#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""governance_advisor — PLANO DE RESPUESTA GRADUADA del nodo ANVOS (matriz item 2: gobernanza).

Capstone de la capa de autoconciencia: sensa (sentinel_core_audit) → predice (twin_forward) →
se autoprueba (asct_incident_sim) → recuerda (event_ledger) → **ACONSEJA** aquí. Sintetiza el
estado del nodo (salud + régimen + gobernanza + riesgo) y lo mapea a la RESPUESTA GRADUADA que
el AXIOMA de Autonomía-Mutación-Graduada permitiría (escala A0-A6), SIEMPRE en modo consejo.

INVARIANTE DURO (fail-closed): el nodo es OBSERVE_ONLY — este servicio NUNCA ejecuta ni firma.
Solo RECOMIENDA; la ejecución de cualquier acción es del operador/master bajo el autonomy-gate
(A5+llave física del operador). Prohibido-autónomo siempre: consenso / MAIN / claves / nodos / destrucción.
Distinto de cognition_guard (verifica AUTORIDAD legítima) y de asct_drift (detecta riesgo runtime):
aquí se DECIDE QUÉ RESPUESTA aconsejar dado el cuadro completo. Single-shot bajo layerd. stdlib."""
import os
import re
import json
import time

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
OUT = os.path.join(DATA, "governance", "advisor.jsonl")


def _last(rel, *fields):
    try:
        with open(os.path.join(DATA, rel)) as f:
            for ln in reversed(f.readlines()):
                ln = ln.strip()
                if ln:
                    d = json.loads(ln)
                    return {k: d.get(k) for k in fields} if fields else d
    except Exception:
        pass
    return {}


def _risk_num(v):
    m = re.search(r"(\d+)", str(v or ""))
    return int(m.group(1)) if m else 0


def advise():
    ca = _last("sentinel/core_audit.jsonl", "state", "core_health_score")
    cg = _last("governance/cognition_guard.jsonl", "verdict", "veredicto")
    tw = _last("twin/twin_forward.jsonl", "state")
    dr = _last("asct/drift.jsonl", "risk_level", "risk")

    health = ca.get("state") or "UNKNOWN"
    score = ca.get("core_health_score")
    gov = cg.get("verdict") or cg.get("veredicto") or "SIN_DATO"
    regime = tw.get("state") or "SIN_DATO"
    risk = _risk_num(dr.get("risk_level") or dr.get("risk"))

    # escala graduada del axioma (A0 observar … A5 escalar). Fail-closed hacia arriba.
    if gov == "SIN_GOBIERNO" or health == "CRITICAL":
        level = "A5_ESCALAR"
        rec = ("Gobernanza o integridad comprometida → ESCALAR al operador/master. "
               "Fail-closed: acción crítica exige aprobación humana (llave física/autonomy-gate). "
               "El nodo NO actúa por sí mismo.")
    elif health == "DEGRADED" or regime == "CAMBIO_REGIMEN" or risk >= 4:
        level = "A2_ADVERTIR"
        cause = ("integridad/salud" if health == "DEGRADED" else
                 "cambio de régimen (gemelo)" if regime == "CAMBIO_REGIMEN" else "riesgo alto (drift)")
        rec = ("Degradación detectada por %s. CONSEJO (no autónomo): aplicar corrección ACOTADA y "
               "REVERSIBLE bajo las 6 compuertas (reversible+rollback / acotada / firmada / simulada "
               "ASCT-GO / no-degrada / fail-closed). Ejecución = operador." % cause)
    elif health == "WATCH" or regime == "DIVERGENCIA_LEVE" or risk >= 2:
        level = "A1_VIGILAR"
        rec = "Señales de vigilancia (WATCH/divergencia leve/riesgo medio). Sin acción: monitorizar la próxima ventana."
    else:
        level = "A0_OBSERVAR"
        rec = "Nodo sano y GOBERNADO. Observar; sin acción recomendada."

    return {
        "svc": "governance_advisor", "ts": int(time.time()), "observe_only": True,
        "recommended_level": level, "recommendation": rec,
        "synthesis": {"health": health, "score": score, "governance": gov,
                      "regime": regime, "drift_risk": risk},
        "axiom_note": ("Advisory-only: el nodo es OBSERVE_ONLY; nunca ejecuta ni firma. Ejecución de "
                       "cualquier acción = operador/master bajo autonomy-gate (A5+llave física). "
                       "Prohibido-autónomo: consenso, MAIN, claves, nodos, destrucción."),
    }


def main():
    # print-only: bajo layerd el stdout se anexa al .jsonl del manifiesto (escribir aparte duplicaba)
    print(json.dumps(advise(), ensure_ascii=False))


if __name__ == "__main__":
    main()
