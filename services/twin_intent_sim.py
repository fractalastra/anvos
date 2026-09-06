#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""twin_intent_sim — B.2 Fase B: SIMULACIÓN de una INTENCIÓN en el gemelo (what-if de AV/GM).

OBSERVE-ONLY, sin GPU, stdlib. Completa a asct_sim (pre-vuelo de CÓDIGO: sintaxis/firma/import/
rollback) con la proyección MÉTRICA: dada una intención propuesta como DELTAS sobre el vector
soberano de 5 factores (ΩV*, TN*, ΦA*, RA*, ΔI*) de un objetivo, proyecta el AV y el modo de
gobernanza GM (EQ-0011) resultantes ANTES de aplicar nada. Reusa las fórmulas exactas del
ecosistema (anv-fract-validator: AV = (ΩV*·TN*·ΦA*·(1-RA*)·(1-ΔI*))^(1/5); GM ladder EQ-0011);
NO reinventa. Es el paso 'simular en el gemelo' del bucle Fase B (intención→plan→SIM→GM gate→...).

Cada ciclo (todo local, sin tocar nada):
  1. Verifica FAIL-CLOSED su propia integridad la hace layerd; aquí solo lee intenciones firmables.
  2. Lee intenciones del buzón semantic/intent/*.json:
       {"desc":"endurece el master","target":"master",
        "baseline":{"ov_star":..,"tn_star":..,"phi_a":..,"ra_star":..,"di_star":..,"C0":1},
        "deltas":{"ra_star":-0.05,"ov_star":0.02}}
  3. Proyecta AV/GM ANTES vs DESPUÉS, dictamina MEJORA/NEUTRO/DEGRADA y qué GM permitiría el resultado.
  4. Registra el what-if en semantic/twin_intent_sim.jsonl y mueve la intención a processed/.

NUNCA aplica, muta, propone-vinculante ni firma. Solo proyecta y deja evidencia. La ACCIÓN es del
operador bajo el GM gate real; la IA no firma (invariante). Simular ≠ decidir.
"""
import os, sys, json, time, glob, math

DATA   = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
SEM    = os.path.join(DATA, "semantic")
INTENT = os.path.join(SEM, "intent")
DONE   = os.path.join(INTENT, "processed")
OUT    = os.path.join(SEM, "twin_intent_sim.jsonl")

FACTORS = ("ov_star", "tn_star", "phi_a", "ra_star", "di_star")


def _now(): return int(time.time())


def _emit(o):
    try: print(json.dumps(o, ensure_ascii=False))
    except Exception: pass


def _append(path, o):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    except Exception: pass


def _clamp(x): return max(0.0, min(1.0, x))


def _av(v):
    """AV soberano = (ΩV*·TN*·ΦA*·(1-RA*)·(1-ΔI*))^(1/5)."""
    p = (v["ov_star"] * v["tn_star"] * v["phi_a"] *
         (1.0 - v["ra_star"]) * (1.0 - v["di_star"]))
    p = max(0.0, p)
    return round(p ** 0.2, 4)


def _gm(v, c0):
    """GM (EQ-0011) — ladder EXACTO del validador."""
    tn, ra, ov = v["tn_star"], v["ra_star"], v["ov_star"]
    if c0 == 0:
        return "BLOCK"
    if tn >= 0.92 and ra < 0.25 and ov >= 0.90:
        return "FULL_APPLY"
    if tn >= 0.75 and ra < 0.45 and ov >= 0.75:
        return "LIMITED_APPLY"
    if tn >= 0.55 and ra < 0.75:
        return "DRY_RUN"
    return "BLOCK"


def _project(baseline, deltas):
    v = {k: _clamp(float(baseline.get(k, 0.0))) for k in FACTORS}
    after = dict(v)
    for k, d in (deltas or {}).items():
        if k in FACTORS:
            after[k] = _clamp(after[k] + float(d))
    return v, after


def _simulate(intent):
    base = intent.get("baseline", {})
    c0 = int(base.get("C0", 1))
    before, after = _project(base, intent.get("deltas", {}))
    av_b, av_a = _av(before), _av(after)
    gm_b, gm_a = _gm(before, c0), _gm(after, c0)
    if av_a > av_b + 1e-4:
        verdict = "MEJORA"
    elif av_a < av_b - 1e-4:
        verdict = "DEGRADA"
    else:
        verdict = "NEUTRO"
    return {
        "desc": intent.get("desc", "?"), "target": intent.get("target", "?"),
        "av_before": av_b, "av_after": av_a, "gm_before": gm_b, "gm_after": gm_a,
        "verdict": verdict,
        "gate": f"el resultado quedaria en GM={gm_a}",
        "factors_after": {k: round(after[k], 4) for k in FACTORS},
    }


def main():
    os.makedirs(DONE, exist_ok=True)
    processed = 0
    for f in sorted(glob.glob(os.path.join(INTENT, "*.json"))):
        try:
            intent = json.load(open(f, encoding="utf-8"))
            sim = _simulate(intent)
            _append(OUT, {"svc": "twin_intent_sim", "ts": _now(), "observe_only": True,
                          "applied": False, **sim})
            os.rename(f, os.path.join(DONE, os.path.basename(f)))
            processed += 1
        except Exception:
            continue

    self_test = None
    if processed == 0:
        # what-if testigo: 'endurecer' baja RA* (menos riesgo) y sube ΩV* -> ¿mejora AV/GM?
        demo = {"desc": "selftest: endurecer reduce riesgo", "target": "demo",
                "baseline": {"ov_star": 0.88, "tn_star": 0.90, "phi_a": 0.85,
                             "ra_star": 0.30, "di_star": 0.02, "C0": 1},
                "deltas": {"ra_star": -0.08, "ov_star": 0.03, "tn_star": 0.03}}
        self_test = _simulate(demo)

    _emit({"svc": "twin_intent_sim", "ts": _now(), "observe_only": True, "applied": False,
           "phase": "OS-FaseB-Paso1(B.2)", "authority": False,
           "intents_processed": processed, "self_test": self_test,
           "note": "proyeccion what-if de AV/GM de una intencion; sin aplicar/mutar/firmar (simular != decidir)"})


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        _emit({"svc": "twin_intent_sim", "ts": _now(), "observe_only": True, "fatal": str(e)[:140]})
