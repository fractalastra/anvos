#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""sentinel_core_audit — SÍNTESIS del Sentinel en la capa ANVOS (Sentinel completo, matriz item 4).

Porta el `sentinelctl core-audit` del ecosistema: no vuelve a escanear (eso lo hacen sentinel_observe
rápido y sentinel_immune profundo), sino que AGREGA todas las señales de seguridad del nodo en un
único veredicto — taxonomía + deduplicación + **Core Health Score** + máquina de estados. Es el
plano "meta" que un operador (o el master) mira de un vistazo.

Fuentes (lee los ledgers vivos del nodo; OBSERVE-only, no actúa, no firma):
  - sentinel_observe  -> findings [{sev,code,msg}] + immune_state rápido
  - sentinel_immune   -> immune_state global + agents [{agent,count,state}]
  - self_integrity    -> attestation SEALED / verified/total  (señal DURA)
  - asct_drift        -> riesgo R0-R5 / drift_events
  - cognition_guard   -> veredicto de gobernanza (GOBERNADO/…)

Estado = máquina {HEALTHY→WATCH→DEGRADED→CRITICAL}; integridad no-SEALED fuerza CRITICAL (fail-safe).
Solo stdlib. Single-shot bajo layerd."""
import os
import re
import json
import time

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
OUT = os.path.join(DATA, "sentinel", "core_audit.jsonl")

# categorías de la taxonomía por prefijo/palabra del code
_TAX = [
    ("integridad", ("INTEGRITY", "SEAL", "SIG", "CHAIN")),
    ("recursos",   ("DISK", "MEM", "PROC", "CPU", "BEACON")),
    ("red",        ("PORT", "NET", "LINK", "PEER", "HONEYPOT", "INTRUS")),
    ("capa",       ("LAYER", "SERVICE", "AGENT")),
    ("secretos",   ("SECRET", "TOKEN", "KEY", "LEAK")),
]
_SEV_W = {"crit": 0.40, "warn": 0.12, "watch": 0.05, "info": 0.0}


def _last(rel):
    """Última línea JSON NO vacía de un ledger del nodo (o {} defensivo)."""
    try:
        with open(os.path.join(DATA, rel)) as f:
            for ln in reversed(f.readlines()):
                ln = ln.strip()
                if ln:
                    return json.loads(ln)
    except Exception:
        pass
    return {}


def _category(code):
    c = str(code or "").upper()
    for name, keys in _TAX:
        if any(k in c for k in keys):
            return name
    return "otros"


def _risk_num(v):
    """riesgo puede venir 'R3', 3, '3' -> entero 0-5."""
    if isinstance(v, (int, float)):
        return int(v)
    m = re.search(r"(\d+)", str(v or ""))
    return int(m.group(1)) if m else 0


def audit():
    obs = _last("sentinel/sentinel.jsonl")
    imm = _last("sentinel/immune.jsonl")
    si = _last("integrity/self_integrity.jsonl")
    drift = _last("asct/drift.jsonl")
    cg = _last("governance/cognition_guard.jsonl")

    # 1) recolectar hallazgos de todas las fuentes
    findings = []
    for f in obs.get("findings", []):
        if isinstance(f, dict):
            findings.append({"src": "observe", "sev": f.get("sev", "watch"),
                             "code": f.get("code", "UNKNOWN"), "msg": f.get("msg", "")})
    for a in imm.get("agents", []):
        st = str(a.get("state", ""))
        if st and st.upper() not in ("CALM", "OBSERVE", "HEALTHY", "NORMAL"):
            findings.append({"src": "immune", "sev": "warn" if "ALERT" in st.upper() else "watch",
                             "code": "AGENT_" + str(a.get("agent", "?")).upper(),
                             "msg": "%s (count=%s)" % (st, a.get("count"))})

    # 2) deduplicar por (code, msg)
    seen, dedup = set(), []
    for f in findings:
        k = (f["code"], f["msg"])
        if k not in seen:
            seen.add(k)
            dedup.append(f)

    # 3) taxonomía (conteo por categoría)
    tax = {}
    for f in dedup:
        cat = _category(f["code"])
        tax[cat] = tax.get(cat, 0) + 1

    # 4) señales DURAS
    integrity_sealed = si.get("attestation") == "SEALED"
    gov = cg.get("veredicto") or cg.get("verdict")
    governed = gov in ("GOBERNADO", None)          # None = sin dato aún (no penaliza)
    risk = _risk_num(drift.get("risk") or drift.get("risk_level"))

    # 5) Core Health Score = 1 - penalizaciones acotadas
    penalty = sum(_SEV_W.get(f.get("sev"), 0.05) for f in dedup)
    if not integrity_sealed:
        penalty += 0.50
    if not governed:
        penalty += 0.20
    penalty += min(0.30, risk * 0.06)
    score = max(0.0, round(1.0 - penalty, 3))

    # 6) máquina de estados (fail-safe: integridad rota -> CRITICAL; gobernanza perdida -> DEGRADED).
    # La rama de gobernanza la destapó asct_incident_sim: perder el gobierno (SIN_GOBIERNO) solo
    # bajaba el score a 0.80 (=HEALTHY), sin reflejar la gravedad. Ahora es señal dura.
    if not integrity_sealed:
        state = "CRITICAL"
    elif not governed:
        state = "DEGRADED"
    elif score < 0.50 or risk >= 4:
        state = "DEGRADED"
    elif score < 0.80 or dedup:
        state = "WATCH"
    else:
        state = "HEALTHY"

    return {
        "svc": "sentinel_core_audit", "ts": int(time.time()), "observe_only": True,
        "core_health_score": score, "state": state,
        "taxonomy": tax, "findings_total": len(findings), "findings_dedup": len(dedup),
        "hard_signals": {"integrity_sealed": integrity_sealed,
                         "integrity": "%s/%s" % (si.get("verified", "?"), si.get("total", "?")),
                         "governance": gov, "drift_risk": risk,
                         "immune_state": imm.get("immune_state") or obs.get("immune_state")},
        "findings": dedup[:15],
    }


def main():
    # print-only: bajo layerd el stdout se anexa al .jsonl del manifiesto (escribir aparte duplicaba)
    print(json.dumps(audit(), ensure_ascii=False))


if __name__ == "__main__":
    main()
