#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""asct_incident_sim — SIMULACRO de incidentes (fire-drill) del ASCT en la capa ANVOS (matriz item 10).

Completa asct_sim (pre-vuelo de código) y asct_drift (deriva en runtime) con lo que faltaba:
INCIDENT-SIM. Un detector que nunca se prueba puede estar roto en silencio. Este servicio inyecta
INCIDENTES SINTÉTICOS en un directorio SOMBRA y ejecuta el detector REAL (sentinel_core_audit,
importado apuntando su ANVOS_DATA a la sombra) para verificar que CLASIFICA cada incidente con la
severidad esperada. Si el detector no reacciona como debe → regresión del plano de seguridad.

TOTALMENTE AISLADO: solo escribe/lee bajo /persist/anvos-asct-shadow (NUNCA toca los datos reales del
nodo ni levanta incidentes reales). OBSERVE-only, determinista, solo stdlib. Single-shot bajo layerd."""
import os
import sys
import json
import time
import shutil

SHADOW = "/persist/anvos-asct-shadow"                      # dir sombra aislado (no es anvos-data)
STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
SVCDIR = os.path.join(STAGING, "services")
OUT = os.path.join(os.environ.get("ANVOS_DATA", "/persist/anvos-data"), "asct", "incident_sim.jsonl")


def _write(rel, obj):
    p = os.path.join(SHADOW, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def _scenario(name, *, sealed=True, gov="GOBERNADO", risk=0, findings=None):
    """Puebla la sombra con un estado sintético (los ledgers que lee core_audit)."""
    shutil.rmtree(SHADOW, ignore_errors=True)
    _write("integrity/self_integrity.jsonl",
           {"attestation": "SEALED" if sealed else "FAIL", "verified": 30 if sealed else 12, "total": 30})
    _write("governance/cognition_guard.jsonl", {"veredicto": gov})
    _write("asct/drift.jsonl", {"risk": risk, "drift_events": risk})
    _write("sentinel/immune.jsonl", {"immune_state": "CALM", "agents": []})
    _write("sentinel/sentinel.jsonl",
           {"immune_state": "ALERT" if findings else "CALM", "findings": findings or []})
    return name


# escenarios: (nombre, kwargs, estado esperado de core_audit)
SCENARIOS = [
    ("sano",            dict(),                                                    "HEALTHY"),
    ("integridad_rota", dict(sealed=False),                                        "CRITICAL"),
    ("drift_critico",   dict(risk=5),                                              "DEGRADED"),
    ("hallazgos_warn",  dict(findings=[{"sev": "warn", "code": "PORT_UNEXPECTED", "msg": "puerto 4444"},
                                       {"sev": "warn", "code": "DISK_HIGH", "msg": "92%"}]), "WATCH"),
    ("sin_gobierno",    dict(gov="SIN_GOBIERNO", sealed=True),                      "DEGRADED"),
]


def run():
    # apuntar el detector REAL a la sombra e importarlo (su DATA se resuelve al importar)
    os.environ["ANVOS_DATA"] = SHADOW
    sys.path.insert(0, SVCDIR)
    try:
        import sentinel_core_audit as core
    except Exception as e:
        return {"svc": "asct_incident_sim", "ts": int(time.time()), "ok": False,
                "error": "no se pudo importar el detector: %s" % str(e)[:80]}

    results = []
    passed = 0
    for name, kw, expected in SCENARIOS:
        _scenario(name, **kw)
        try:
            verdict = core.audit()
            got = verdict.get("state")
        except Exception as e:
            got = "ERROR:%s" % str(e)[:40]
        ok = (got == expected)
        passed += 1 if ok else 0
        results.append({"scenario": name, "expected": expected, "got": got, "detected": ok})

    shutil.rmtree(SHADOW, ignore_errors=True)               # limpiar la sombra
    total = len(SCENARIOS)
    return {"svc": "asct_incident_sim", "ts": int(time.time()), "observe_only": True,
            "detector": "sentinel_core_audit",
            "passed": passed, "total": total,
            "verdict": "DETECTOR_OK" if passed == total else "DETECTOR_REGRESION",
            "results": results}


def main():
    # print-only: bajo layerd el stdout se anexa al .jsonl del manifiesto (escribir aparte duplicaba)
    print(json.dumps(run(), ensure_ascii=False))


if __name__ == "__main__":
    main()
