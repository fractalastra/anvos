#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""asct_policy — PLANO DE POLÍTICA del ASCT en la capa ANVOS (matriz item 10, pieza final).

Completa el ASCT (asct_sim pre-vuelo, asct_drift deriva, asct_incident_sim fire-drill del
detector, asct_rollback_sim fire-drill de la recuperación) con la GOBERNANZA COMO DATOS:
la respuesta graduada del axioma vive en una POLÍTICA FIRMADA (`asct_policy.json` + .minisig
653C, empujada por el master como los vectores/catálogos), no hardcodeada en código.

Cada ciclo:
  1. CARGA la política FAIL-CLOSED: firma 653C verificada ANTES de usarla; sin firma/ inválida →
     política POR-DEFECTO embebida (conservadora). Una política firmada pero que viole el
     invariante duro del nodo (observe_only) se RECHAZA igualmente → por-defecto (el axioma
     del nodo está por encima de cualquier política).
  2. EVALÚA el estado vivo (core_audit + cognition_guard + gemelo + drift + honeypot) contra las
     reglas (primera-que-matchea, orden severa→leve) → DICTAMEN A0-A5 + regla + razón.
  3. CONFORMIDAD: compara el dictamen de la NORMA con lo que recomienda el plano de respuesta
     real (governance_advisor) → CONFORME / DESVIACION (una desviación = el advisor y la política
     divergen: o regresión del advisor o norma más rica — p.ej. la regla honeypot).
  4. AUTOPRUEBA: pasa escenarios sintéticos por el motor puro cada ciclo → POLICY_OK/REGRESION.

OBSERVE-only SIEMPRE: dictamina y compara, NUNCA ejecuta ni firma (techo ADVISORY inviolable).
Single-shot bajo layerd, solo stdlib, print-only (el stdout es el ledger)."""
import os
import re
import json
import time
import glob
import subprocess

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
POLICY = os.path.join(DATA, "asct", "asct_policy.json")
MS = os.path.join(STAGING, "pylayer-verify")
PUB = os.path.join(STAGING, "pylayer", "release.pub")   # clásica (caída de compatibilidad)
RELEASE_D = os.path.join(STAGING, "pylayer", "release.d")


# _release_pubs de F0 ELIMINADO tras el gate de gobernanza (higiene 15-ago): la firma
# de la política va por la partición A/B (verify_file en _sig_ok). Código muerto retirado.
HITS_WINDOW_S = 3600                                       # sondeos honeypot "recientes"

ORDEN = {"A0_OBSERVAR": 0, "A1_VIGILAR": 1, "A2_ADVERTIR": 2, "A5_ESCALAR": 5}

# política POR-DEFECTO embebida (conservadora, espejo del axioma) — se usa fail-closed
DEFAULT_POLICY = {
    "typ": "ANV-ASCT-POLICY-v1", "version": 0,
    "invariantes": {"observe_only": True, "max_autonomy": "ADVISORY"},
    "reglas": [
        {"id": "D-A5-GOBIERNO", "si": {"gov": "SIN_GOBIERNO"}, "respuesta": "A5_ESCALAR", "razon": "default"},
        {"id": "D-A5-CRITICO", "si": {"core_state": "CRITICAL"}, "respuesta": "A5_ESCALAR", "razon": "default"},
        {"id": "D-A2-DEGRADADO", "si": {"core_state": "DEGRADED"}, "respuesta": "A2_ADVERTIR", "razon": "default"},
        {"id": "D-A2-REGIMEN", "si": {"twin_state": "CAMBIO_REGIMEN"}, "respuesta": "A2_ADVERTIR", "razon": "default"},
        {"id": "D-A2-RIESGO", "si": {"risk_min": 4}, "respuesta": "A2_ADVERTIR", "razon": "default"},
        {"id": "D-A1-WATCH", "si": {"core_state": "WATCH"}, "respuesta": "A1_VIGILAR", "razon": "default"},
        {"id": "D-A1-DIVERGENCIA", "si": {"twin_state": "DIVERGENCIA_LEVE"}, "respuesta": "A1_VIGILAR", "razon": "default"},
        {"id": "D-A1-RIESGO", "si": {"risk_min": 2}, "respuesta": "A1_VIGILAR", "razon": "default"},
        {"id": "D-A1-HONEYPOT", "si": {"hits_min": 1}, "respuesta": "A1_VIGILAR", "razon": "default"},
        {"id": "D-A0", "si": {}, "respuesta": "A0_OBSERVAR", "razon": "default"},
    ],
}

# autoprueba del motor: escenarios sintéticos → dictamen esperado (con la política activa)
SCENARIOS = [
    ({"gov": "SIN_GOBIERNO", "core_state": "HEALTHY", "twin_state": "COHERENTE", "risk": 0, "hits": 0}, "A5_ESCALAR"),
    ({"gov": "GOBERNADO", "core_state": "CRITICAL", "twin_state": "COHERENTE", "risk": 0, "hits": 0}, "A5_ESCALAR"),
    ({"gov": "GOBERNADO", "core_state": "HEALTHY", "twin_state": "CAMBIO_REGIMEN", "risk": 0, "hits": 0}, "A2_ADVERTIR"),
    ({"gov": "GOBERNADO", "core_state": "HEALTHY", "twin_state": "COHERENTE", "risk": 4, "hits": 0}, "A2_ADVERTIR"),
    ({"gov": "GOBERNADO", "core_state": "HEALTHY", "twin_state": "COHERENTE", "risk": 0, "hits": 3}, "A1_VIGILAR"),
    ({"gov": "GOBERNADO", "core_state": "HEALTHY", "twin_state": "COHERENTE", "risk": 0, "hits": 0}, "A0_OBSERVAR"),
]


def _ap():
    """Carga el helper de partición A/B — pero PRIMERO lo verifica contra la 653C HORNEADA
    (authority_partition.py es Set B: si origo, que es root, lo intercambiara, colapsaría
    todo el gate). minisign INLINE, sin depender del propio helper que va a cargar; fail-
    closed: si el helper no ancla en la horneada, se levanta excepción (nada se verifica)."""
    import sys as _s, glob as _g, subprocess as _sp
    d = os.path.dirname(os.path.abspath(__file__))
    mod = os.path.join(d, "authority_partition.py")
    baked = "/opt/anvos-verify/release.pub"
    if os.environ.get("ANVOS_TWIN") == "1" and os.path.exists("/etc/anvos-twin"):
        baked = os.environ.get("ANVOS_BAKED_PUB", baked)
    ms = os.path.join(os.environ.get("ANVOS_STAGING", "/persist/anvos-staging"), "pylayer-verify")
    lds = _g.glob(os.path.join(ms, "ld-linux*.so.2"))
    ok = False
    if lds and all(os.path.exists(x) for x in (mod, mod + ".minisig", baked, os.path.join(ms, "minisign"))):
        try:
            ok = _sp.run([lds[0], "--library-path", ms, os.path.join(ms, "minisign"),
                          "-Vm", mod, "-p", baked, "-x", mod + ".minisig"],
                         capture_output=True, timeout=6).returncode == 0
        except Exception:
            ok = False
    if not ok:
        raise RuntimeError("authority_partition.py no verifica contra la clave horneada (fail-closed)")
    if d not in _s.path:
        _s.path.insert(0, d)
    import authority_partition
    return authority_partition


def _sig_ok(target):
    """Bajo PARTICIÓN A/B: la política (si es Set B) solo cuenta firmada por la horneada."""
    sig = target + ".minisig"
    if not (os.path.exists(os.path.join(MS, "minisign"))
            and os.path.isfile(target) and os.path.isfile(sig)):
        return False
    return _ap().verify_file(target, sig)


def load_policy():
    """Carga la política firmada; fail-closed a la por-defecto embebida. (policy, source, signed)."""
    if not _sig_ok(POLICY):
        return DEFAULT_POLICY, "default_embebida", False
    try:
        p = json.loads(open(POLICY).read())
    except Exception:
        return DEFAULT_POLICY, "default_embebida", False
    inv = p.get("invariantes", {})
    # el axioma del NODO está por encima de la política: una política (aunque firmada) que
    # pretenda relajar observe_only/ADVISORY se rechaza entera
    if inv.get("observe_only") is not True or inv.get("max_autonomy") != "ADVISORY":
        return DEFAULT_POLICY, "default_embebida_por_invariante_violado", False
    if not isinstance(p.get("reglas"), list) or not p["reglas"]:
        return DEFAULT_POLICY, "default_embebida", False
    return p, "firmada", True


def evaluate(policy, st):
    """Motor PURO primera-regla-que-matchea. st: gov/core_state/twin_state/risk/hits."""
    for r in policy.get("reglas", []):
        si = r.get("si", {})
        ok = True
        if "gov" in si and st.get("gov") != si["gov"]:
            ok = False
        if ok and "core_state" in si and st.get("core_state") != si["core_state"]:
            ok = False
        if ok and "twin_state" in si and st.get("twin_state") != si["twin_state"]:
            ok = False
        if ok and "risk_min" in si and int(st.get("risk", 0)) < int(si["risk_min"]):
            ok = False
        if ok and "hits_min" in si and int(st.get("hits", 0)) < int(si["hits_min"]):
            ok = False
        if ok:
            return {"respuesta": r.get("respuesta", "A5_ESCALAR"), "regla": r.get("id"),
                    "razon": r.get("razon")}
    return {"respuesta": "A5_ESCALAR", "regla": "SIN_REGLA", "razon": "fail-closed: ninguna regla matchea"}


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


def _recent_hits(now):
    """Sondeos del honeypot en la última ventana (lee deception/hits.jsonl, defensivo)."""
    n = 0
    try:
        with open(os.path.join(DATA, "deception", "hits.jsonl")) as f:
            for ln in f.readlines()[-200:]:
                ln = ln.strip()
                if ln:
                    try:
                        if now - int(json.loads(ln).get("ts", 0)) <= HITS_WINDOW_S:
                            n += 1
                    except Exception:
                        pass
    except Exception:
        pass
    return n


def read_state(now):
    ca = _last("sentinel/core_audit.jsonl", "state")
    cg = _last("governance/cognition_guard.jsonl", "verdict", "veredicto")
    tw = _last("twin/twin_forward.jsonl", "state")
    dr = _last("asct/drift.jsonl", "risk_level", "risk")
    return {"gov": cg.get("verdict") or cg.get("veredicto") or "SIN_DATO",
            "core_state": ca.get("state") or "SIN_DATO",
            "twin_state": tw.get("state") or "SIN_DATO",
            "risk": _risk_num(dr.get("risk_level") or dr.get("risk")),
            "hits": _recent_hits(now)}


def run():
    now = int(time.time())
    policy, source, signed = load_policy()
    st = read_state(now)
    dictamen = evaluate(policy, st)

    # conformidad NORMA (política) vs PLANO DE RESPUESTA real (advisor)
    adv = _last("governance/advisor.jsonl", "recommended_level").get("recommended_level")
    if adv is None:
        conf = "SIN_ADVISOR"
    elif adv == dictamen["respuesta"]:
        conf = "CONFORME"
    else:
        conf = "DESVIACION"

    # autoprueba del motor con la política ACTIVA (puro, determinista)
    passed = sum(1 for s, want in SCENARIOS if evaluate(policy, dict(s))["respuesta"] == want)
    drill = "POLICY_OK" if passed == len(SCENARIOS) else "POLICY_REGRESION"

    return {"svc": "asct_policy", "ts": now, "observe_only": True,
            "policy_source": source, "policy_signed": signed,
            "policy_version": policy.get("version"),
            "estado": st, "dictamen": dictamen,
            "advisor_level": adv, "conformidad": conf,
            "drill": drill, "drill_passed": "%d/%d" % (passed, len(SCENARIOS)),
            "techo": "ADVISORY: la política nunca autoriza ejecutar/firmar"}


def main():
    # print-only: bajo layerd el stdout se anexa al .jsonl del manifiesto
    print(json.dumps(run(), ensure_ascii=False))


if __name__ == "__main__":
    main()
