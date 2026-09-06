#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""twin_forward — GEMELO DIGITAL MULTI-MÉTRICA de proyección-adelante del nodo ANVOS (matriz item 11).

Complementa twin_intent_sim (what-if de una INTENCIÓN) con el gemelo tipo EQ-0015 del master.
v2 MULTI-MÉTRICA: ya no proyecta solo el Core Health Score — modela 5 métricas REALES del nodo,
cada una con su propio EWMA (α=0.3, igual que el gemelo del ecosistema) + tendencia, guarda la
predicción por métrica y en la siguiente pasada la compara con la realidad → DIVERGENCIA (IDG)
POR MÉTRICA. Divergencia alta en cualquiera = CAMBIO DE RÉGIMEN en ese eje (fallo, deriva,
ataque) — señal temprana localizada, no solo global.

Métricas (todas normalizadas 0-1; fuente = ledgers vivos del propio nodo):
  health = core_health_score (sentinel_core_audit; alto=bien)      | cpu  = load/ncpu (beacon)
  mem    = mem_pct/100 (beacon)   | disk = disk_pct/100 (beacon)   | risk = R0-R5/5 (asct_drift)

ESCENARIOS (what-if determinista de ESTRÉS, sin tocar nada): aplica deltas sintéticos sobre la
proyección (pico de carga / fuga de memoria / crecimiento de disco / degradación de salud) y
clasifica el resultado contra los umbrales del nodo (WARN80/CRIT90, coherentes con el
disk-space-guardian del ecosistema) → responde "qué estrés nos rompería primero y cuánto margen hay".

Compatibilidad: los campos de nivel superior (state/actual/projection_next/idg) conservan su
semántica sobre la métrica PRIMARIA (health) — event_ledger, governance_advisor y
node_status_server siguen leyendo lo mismo; el detalle nuevo va en "metrics"/"scenarios".

OBSERVE-only, determinista, sin red, solo stdlib. Single-shot bajo layerd (print-only: el stdout
es el ledger)."""
import os
import json
import time

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
STATE = os.path.join(DATA, "twin", "forward_state.json")   # predicciones previas (para comparar)
ALPHA = 0.3                                                # EWMA (idéntico al gemelo del ecosistema)
COHERENT_TH = 0.05                                         # |proj-real| < esto = coherente
REGIME_TH = 0.15                                           # ≥ esto = cambio de régimen
NCPU = os.cpu_count() or 1

# métrica: (ledger, extractor -> float 0-1 o None, sentido) — sentido 'high_bad'|'high_good'
def _x_health(d):
    s = d.get("core_health_score")
    return float(s) if isinstance(s, (int, float)) else None


def _x_cpu(d):
    s = d.get("cpu_load")
    return min(1.0, float(s) / NCPU) if isinstance(s, (int, float)) else None


def _x_mem(d):
    s = d.get("mem_pct")
    return min(1.0, float(s) / 100.0) if isinstance(s, (int, float)) else None


def _x_disk(d):
    s = d.get("disk_pct")
    return min(1.0, float(s) / 100.0) if isinstance(s, (int, float)) else None


def _x_risk(d):
    s = d.get("risk_level") or d.get("risk")
    if isinstance(s, str) and len(s) == 2 and s[0] == "R" and s[1].isdigit():
        return min(1.0, int(s[1]) / 5.0)
    if isinstance(s, (int, float)):
        return min(1.0, float(s) / 5.0)
    return None


METRICS = {
    "health": ("sentinel/core_audit.jsonl", _x_health, "high_good"),
    "cpu":    ("eco-telem/beacon.jsonl",    _x_cpu,    "high_bad"),
    "mem":    ("eco-telem/beacon.jsonl",    _x_mem,    "high_bad"),
    "disk":   ("eco-telem/beacon.jsonl",    _x_disk,   "high_bad"),
    "risk":   ("asct/drift.jsonl",          _x_risk,   "high_bad"),
}

# umbrales de clasificación por métrica (WARN/CRIT; health invertida)
THRESH = {
    "health": (0.70, 0.50),   # <0.70 WARN, <0.50 CRITICAL
    "cpu":    (0.80, 0.95),
    "mem":    (0.80, 0.90),   # coherente con disk-space-guardian WARN80/CRIT90
    "disk":   (0.80, 0.90),
    "risk":   (0.60, 0.80),   # R3=WARN, R4+=CRITICAL
}

# escenarios de estrés: deltas sintéticos sobre la PROYECCIÓN de una métrica
SCENARIOS = [
    ("pico_carga",        "cpu",    +0.50),
    ("fuga_memoria",      "mem",    +0.30),
    ("crecimiento_disco", "disk",   +0.20),
    ("degradacion_salud", "health", -0.20),
]

_RANK = {"CALIBRANDO": 0, "COHERENTE": 1, "DIVERGENCIA_LEVE": 2, "CAMBIO_REGIMEN": 3}


def _read_series(rel, extract, n=30):
    """Últimos n valores de una métrica desde su ledger (defensivo)."""
    vals = []
    try:
        with open(os.path.join(DATA, rel)) as f:
            for ln in f.readlines()[-n:]:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    v = extract(json.loads(ln))
                    if v is not None:
                        vals.append(v)
                except Exception:
                    pass
    except Exception:
        pass
    return vals


def _load_state():
    try:
        with open(STATE) as f:
            st = json.loads(f.read())
        if "metrics" not in st:                              # migración desde el estado v1 (solo health)
            st = {"metrics": {"health": {"ewma": st.get("ewma"), "projection": st.get("projection")}}}
        return st
    except Exception:
        return {"metrics": {}}


def _save_state(st):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + ".%d.tmp" % os.getpid()
    try:
        with open(tmp, "w") as f:
            f.write(json.dumps(st, ensure_ascii=False))
        os.replace(tmp, STATE)                              # atómico
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass


def _classify(metric, value):
    """Clasifica un valor contra los umbrales del nodo (GREEN/WARN/CRITICAL)."""
    warn, crit = THRESH[metric]
    if METRICS[metric][2] == "high_good":
        return "CRITICAL" if value < crit else ("WARN" if value < warn else "GREEN")
    return "CRITICAL" if value >= crit else ("WARN" if value >= warn else "GREEN")


def _margin_to_warn(metric, value):
    """Margen (en la escala 0-1) que queda hasta el umbral WARN."""
    warn = THRESH[metric][0]
    if METRICS[metric][2] == "high_good":
        return round(max(0.0, value - warn), 4)
    return round(max(0.0, warn - value), 4)


def _project_metric(name, series, prev):
    """EWMA+tendencia de una métrica; IDG vs la predicción previa; veredicto de régimen."""
    if len(series) < 3:
        return {"verdict": "CALIBRANDO", "samples": len(series)}, None
    actual = series[-1]
    prev_ewma = prev.get("ewma") if isinstance(prev.get("ewma"), (int, float)) else series[0]
    prev_proj = prev.get("projection")
    ewma = ALPHA * actual + (1 - ALPHA) * prev_ewma
    tail = series[-5:]
    slope = (tail[-1] - tail[0]) / max(1, len(tail) - 1)
    projection = round(max(0.0, min(1.0, ewma + slope)), 4)
    idg = round(abs(prev_proj - actual), 4) if isinstance(prev_proj, (int, float)) else None
    if idg is None:
        verdict = "CALIBRANDO"
    elif idg < COHERENT_TH:
        verdict = "COHERENTE"
    elif idg < REGIME_TH:
        verdict = "DIVERGENCIA_LEVE"
    else:
        verdict = "CAMBIO_REGIMEN"                           # el modelo no anticipó -> señal temprana
    rec = {"verdict": verdict, "actual": round(actual, 4), "projection_next": projection,
           "idg": idg, "level": _classify(name, actual),
           "margin_to_warn": _margin_to_warn(name, actual), "samples": len(series)}
    return rec, {"ewma": round(ewma, 4), "projection": projection}


def project():
    now = int(time.time())
    state = _load_state()
    new_state = {"metrics": {}, "ts": now}
    metrics = {}
    for name, (rel, extract, _sense) in METRICS.items():
        series = _read_series(rel, extract)
        rec, st = _project_metric(name, series, state["metrics"].get(name, {}))
        metrics[name] = rec
        if st:
            new_state["metrics"][name] = st
    _save_state(new_state)

    # régimen GLOBAL = la peor métrica (localiza el eje: no es lo mismo divergir en disco que en salud)
    scored = {n: m for n, m in metrics.items() if m["verdict"] != "CALIBRANDO"}
    if not scored:
        head = {"state": "WARMING_UP" if metrics["health"].get("samples", 0) < 3 else "CALIBRANDO"}
    else:
        worst = max(scored, key=lambda n: _RANK[scored[n]["verdict"]])
        head = {"state": scored[worst]["verdict"], "worst_metric": worst}

    # compatibilidad: los campos planos siguen siendo la métrica PRIMARIA (health)
    h = metrics["health"]
    head.update({"svc": "twin_forward", "ts": now,
                 "actual": h.get("actual"), "projection_next": h.get("projection_next"),
                 "idg": h.get("idg"),
                 "coherence_pct": (round((1 - h["idg"]) * 100, 1)
                                   if isinstance(h.get("idg"), (int, float)) else None)})

    # ESCENARIOS what-if: qué estrés rompería el nodo primero (sobre la proyección, determinista)
    scenarios = []
    for sname, metric, delta in SCENARIOS:
        base = metrics[metric].get("projection_next")
        if not isinstance(base, (int, float)):
            continue
        stressed = max(0.0, min(1.0, base + delta))
        scenarios.append({"scenario": sname, "metric": metric, "delta": delta,
                          "projected": round(stressed, 4), "result": _classify(metric, stressed)})
    breaks = [s["scenario"] for s in scenarios if s["result"] == "CRITICAL"]

    head.update({"metrics": metrics, "scenarios": scenarios,
                 "first_to_break": (breaks[0] if breaks else None),
                 "horizon": "~5min (siguiente ciclo core_audit)"})
    return head


def main():
    # print-only: bajo layerd el stdout se anexa al .jsonl del manifiesto (escribir aparte duplicaba)
    print(json.dumps(project(), ensure_ascii=False))


if __name__ == "__main__":
    main()
