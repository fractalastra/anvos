#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""asct_drift — plano de DERIVA + RIESGO en runtime del ASCT LIGERO (node-local). Completa a
asct_sim (pre-vuelo, NO_MUTATION) con el detector de DESVIACIÓN EN RUNTIME: compara el estado
OBSERVADO del nodo (la telemetría que los servicios YA emiten) contra la línea-base ESPERADA
(invariantes soberanos del nodo) y produce eventos de deriva -> nivel de riesgo R0-R5 con su
respuesta graduada. CONSUME el diseño probado del ecosistema (anv-asct-drift.sh + anv-asct-risk.sh:
current vs expected -> drift_events -> risk_score) mapeado a las fuentes del nodo; NO reinventa.
Solo stdlib, OBSERVE-only (nunca muta; solo registra y recomienda). Fail-safe: no lanza al supervisor.
Modos: run (por defecto, periódico) | status."""
import os
import sys
import json
import time
import glob

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
REC = os.path.join(DATA, "asct", "drift.jsonl")
LATEST_DRIFT = os.path.join(DATA, "asct", "latest_drift.json")
RISK_OUT = os.path.join(DATA, "asct", "risk_score.json")

# Fuentes de estado OBSERVADO (último registro que cada servicio ya emite bajo /persist/anvos-data)
SRC = {
    "layerd":      os.path.join(DATA, "layerd", "layerd.jsonl"),
    "governance":  os.path.join(DATA, "governance", "cognition_guard.jsonl"),
    "integrity":   os.path.join(DATA, "integrity", "self_integrity.jsonl"),
    "immune":      os.path.join(DATA, "sentinel", "immune.jsonl"),
}

# Línea-base ESPERADA (invariantes soberanos del nodo). El nodo debe ser autocontenido: los
# invariantes viven en el propio detector (firmado 653C). Un override firmado en asct/expected.json
# puede endurecerlos, pero nunca relajar el mínimo.
EXPECTED = {
    "min_services": 9,           # el daemon debe supervisar >= 9 servicios firmados
    "fail_closed_blocks": 0,     # 0 bloqueos = ninguna firma inválida intentó ejecutarse
    "all_signatures_ok": True,   # toda firma de servicio válida (sig_fail acumulado == 0)
    "heartbeat_max_age_s": 300,  # el latido del daemon no puede tener > 5 min (daemon vivo)
    "governance": "GOBERNADO",   # cognition_guard: constitución firmada + OBSERVE_ONLY
    "integrity_sealed": True,    # self_integrity: capa SELLADA (sin manipulación de ficheros)
    "observe_only": True,        # invariante inmune: t_killer inhibido
}

# Mapa severidad -> riesgo (idéntico al anv-asct-risk.sh del ecosistema)
SEV_TO_RISK = {"critical": ("R4", "CRITICAL"), "high": ("R3", "HIGH"),
               "medium": ("R2", "MEDIUM"), "low": ("R1", "LOW"), "info": ("R0", "INFO")}
RESPONSE = {0: "Registrar.", 1: "Reportar.", 2: "Analizar y proponer.",
            3: "Simular, bloquear ejecución directa.", 4: "Bloqueo, llave física/HSM.",
            5: "No mutación, intervención humana."}


# Umbral de fallo CRONICO (ITV-068). Se expresa como proporcion porque una cifra suelta no dice
# nada: 66 fallos sobre 100 ejecuciones es un servicio roto; sobre 36.000 es un 0,18%. Y se exige
# una muestra minima para no declarar «el 50% falla» cuando lo que hay es una ejecucion de dos.
UMBRAL_PROPORCION = 0.01     # 1%
MIN_MUESTRA = 200
# Y por SERVICIO: uno que falla mas de la mitad de las veces esta roto, aunque la media de
# la capa lo disimule. La muestra minima es menor porque aqui se mira un solo servicio.
UMBRAL_SERVICIO = 0.50
MIN_MUESTRA_SVC = 20
# Donde se recuerda la observacion anterior, para poder preguntar «cuantos fallos NUEVOS» en vez
# de «cuantos ha habido desde el principio».
PREVIO = os.path.join(os.environ.get("ANVOS_DATA", "/persist/anvos-data"), "asct", "drift_previo.json")


def _leer_previo():
    try:
        with open(PREVIO) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        # Sin observacion anterior no se puede hablar de fallos nuevos, y NO se inventa una: la
        # primera pasada solo mira la proporcion. Suponer un cero anterior haria que la primera
        # lectura tras un arranque declarase como nuevos todos los fallos historicos.
        return {}


def _guardar_previo(d):
    try:
        os.makedirs(os.path.dirname(PREVIO), exist_ok=True)
        with open(PREVIO, "w") as f:
            json.dump(d, f, ensure_ascii=False)
    except Exception:
        pass


def _last_json(path):
    """Último objeto JSON de un .jsonl (o None). Fail-safe."""
    obj = None
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        obj = json.loads(line)
                    except Exception:
                        pass
    except Exception:
        return None
    return obj


def observe():
    """Construye el estado OBSERVADO desde la telemetría viva del nodo."""
    st = {"sources_ok": {}}
    hb = _last_json(SRC["layerd"]) or {}
    st["sources_ok"]["layerd"] = bool(hb)
    svcs = hb.get("services", {}) if isinstance(hb, dict) else {}
    st["supervised"] = hb.get("supervised", len(svcs))
    st["fail_closed_blocks"] = hb.get("fail_closed_blocks", 0)
    st["hb_ts"] = hb.get("ts", 0)
    st["sig_fail_total"] = sum(int(v.get("sig_fail", 0)) for v in svcs.values() if isinstance(v, dict))
    st["fail_total"] = sum(int(v.get("fail", 0)) for v in svcs.values() if isinstance(v, dict))
    # El total de ejecuciones CORRECTAS hace falta para poder hablar de proporcion en vez de
    # cifras sueltas: 66 fallos no significan lo mismo sobre 100 ejecuciones que sobre 36.000.
    st["ok_total"] = sum(int(v.get("ok", 0)) for v in svcs.values() if isinstance(v, dict))
    # El desglose por servicio permite ver al que esta roto sin que la media lo tape.
    st["por_servicio"] = {k: {"ok": int(v.get("ok", 0)), "fail": int(v.get("fail", 0))}
                          for k, v in svcs.items() if isinstance(v, dict)}
    st["services_sig_bad"] = [k for k, v in svcs.items()
                              if isinstance(v, dict) and v.get("sig_ok") is False]

    gov = _last_json(SRC["governance"]) or {}
    st["sources_ok"]["governance"] = bool(gov)
    st["governance"] = gov.get("verdict") or gov.get("governance") or "DESCONOCIDO"

    integ = _last_json(SRC["integrity"]) or {}
    st["sources_ok"]["integrity"] = bool(integ)
    # self_integrity del nodo emite all_valid + total/verified (N/N); versiones previas 'state=SEALED'
    seal = integ.get("state") or integ.get("integrity") or ""
    st["integrity_sealed"] = (integ.get("all_valid") is True
                              or bool(integ.get("sealed"))
                              or "SEAL" in str(seal).upper())

    imm = _last_json(SRC["immune"]) or {}
    st["sources_ok"]["immune"] = bool(imm)
    st["immune_state"] = imm.get("immune_state")
    st["observe_only"] = imm.get("observe_only", True)
    st["immune_critical"] = int(imm.get("critical", 0) or 0)
    # inmune a oscuras: emite ok:False cuando su firma/carga falla (fail-closed) -> plano incompleto
    st["immune_ok"] = imm.get("ok")
    st["immune_error"] = imm.get("error")
    return st


def _add(drifts, field, expected_val, observed_val, dtype, severity):
    drifts.append({"type": dtype, "field": field, "expected": str(expected_val),
                   "observed": str(observed_val), "severity": severity,
                   "requires_action": severity in ("high", "critical")})


def detect(st):
    """Compara OBSERVADO vs ESPERADO y devuelve la lista de derivas reales."""
    d = []
    now = int(time.time())

    # D0 fuente ausente: si el propio latido del daemon no está, es alto (¿daemon caído?)
    if not st["sources_ok"].get("layerd"):
        _add(d, "layerd.heartbeat", "presente", "ausente", "D0_SOURCE", "high")
    else:
        age = now - int(st.get("hb_ts", 0) or 0)
        if age > EXPECTED["heartbeat_max_age_s"]:
            _add(d, "layerd.heartbeat_age_s", "<=%d" % EXPECTED["heartbeat_max_age_s"],
                 age, "D1_LIVENESS", "high")

    # D1 supervisión mínima
    if int(st.get("supervised", 0)) < EXPECTED["min_services"]:
        _add(d, "layerd.supervised", ">=%d" % EXPECTED["min_services"],
             st.get("supervised"), "D1_LIVENESS", "high")

    # D4 seguridad/manipulación: firmas inválidas o bloqueos fail-closed = CRÍTICO
    if int(st.get("fail_closed_blocks", 0)) != EXPECTED["fail_closed_blocks"]:
        _add(d, "layerd.fail_closed_blocks", EXPECTED["fail_closed_blocks"],
             st.get("fail_closed_blocks"), "D4_SECURITY", "critical")
    if int(st.get("sig_fail_total", 0)) > 0 or st.get("services_sig_bad"):
        _add(d, "layerd.signatures", "todas válidas",
             "sig_fail=%s bad=%s" % (st.get("sig_fail_total"), st.get("services_sig_bad")),
             "D4_SECURITY", "critical")

    # D5 gobernanza: constitución/OBSERVE_ONLY
    if st.get("governance") != EXPECTED["governance"]:
        sev = "critical" if str(st.get("governance")) in ("SIN_GOBIERNO", "DESCONOCIDO") else "high"
        _add(d, "governance.verdict", EXPECTED["governance"], st.get("governance"), "D5_GOV", sev)
    if st.get("observe_only") is not True:
        _add(d, "immune.observe_only", True, st.get("observe_only"), "D5_GOV", "critical")

    # D2 integridad de la capa firmada
    if st.get("integrity_sealed") is not True:
        _add(d, "integrity.sealed", True, st.get("integrity_sealed"), "D2_INTEGRITY", "high")

    # D3 salud operativa
    #
    # EL TRINQUETE QUE HABIA AQUI (ITV-068, medido el 2026-08-07)
    # ------------------------------------------------------------
    # Se comparaba `fail_total` —el ACUMULADO de fallos de la capa desde que arranco el supervisor—
    # contra un esperado de CERO ABSOLUTO. Ese contador nunca se reinicia, de modo que bastaba que
    # UN servicio fallara UNA vez para que el nodo no pudiera volver a su puntuacion maxima hasta
    # reiniciar el supervisor.
    #
    # Medido en el nodo soberano: 64 servicios, 36.092 ejecuciones correctas y 66 fallos, todos de
    # un unico servicio con 99,57% de acierto. El auditor declaraba CERO hallazgos, integridad
    # sellada 77/77 y gobernanza correcta, y aun asi la puntuacion se quedaba en 0.88 de forma
    # permanente: 0.12 exactos, que es lo que cuesta un riesgo R2.
    #
    # El defecto no es el umbral, es la PREGUNTA: «¿ha fallado algo alguna vez?» no distingue un
    # nodo sano de uno con un problema, porque en cuanto pasa el tiempo suficiente la respuesta es
    # que si en los dos. Lo que una puntuacion de salud tiene que responder es «¿esta fallando
    # AHORA?», y para eso hace falta comparar con la observacion anterior, no con el origen.
    #
    # Se miden dos cosas distintas, porque son dos preguntas distintas:
    #   · fallos NUEVOS desde la ultima pasada  -> algo esta fallando ahora
    #   · proporcion de fallos sobre el total   -> algo falla de forma cronica aunque no sea nuevo
    # Sin la segunda, un servicio que falla sin parar dejaria de verse en cuanto su ritmo fuera
    # constante; sin la primera, volveriamos al trinquete.
    _prev = _leer_previo()
    _fail = int(st.get("fail_total", 0))
    _ok = int(st.get("ok_total", 0))
    _fail_antes = _prev.get("fail_total")
    if isinstance(_fail_antes, int) and _fail > _fail_antes:
        _add(d, "services.fail_nuevos", 0, _fail - _fail_antes, "D3_HEALTH", "medium")
    # Un descenso significa que el supervisor se reinicio y los contadores volvieron a cero: no es
    # una deriva, es un origen nuevo. Se acepta en silencio y la proxima pasada compara desde ahi.
    _tot = _ok + _fail
    if _tot >= MIN_MUESTRA and (_fail / _tot) > UMBRAL_PROPORCION:
        _add(d, "services.fail_proporcion", "<=%.1f%%" % (UMBRAL_PROPORCION * 100),
             "%.2f%% (%d de %d)" % (100.0 * _fail / _tot, _fail, _tot), "D3_HEALTH", "medium")
    # POR SERVICIO, no solo en agregado. La proporcion de la capa entera DILUYE al servicio roto:
    # medido en el nodo de laboratorio, gpu_enable falla 749 de 749 —el cien por cien de sus propias
    # ejecuciones— y aun asi el conjunto sale al 0,99%, por debajo del umbral. Un servicio que no
    # acierta nunca no puede quedar tapado por la media de sus compañeros sanos.
    for _n, _v in sorted(st.get("por_servicio", {}).items()):
        _f, _o = int(_v.get("fail", 0)), int(_v.get("ok", 0))
        _t = _f + _o
        if _t >= MIN_MUESTRA_SVC and (_f / _t) > UMBRAL_SERVICIO:
            _add(d, "servicio.%s" % _n, "<=%.0f%% de fallo" % (UMBRAL_SERVICIO * 100),
                 "%.0f%% (%d de %d)" % (100.0 * _f / _t, _f, _t), "D3_HEALTH", "medium")
    _guardar_previo({"fail_total": _fail, "ok_total": _ok, "ts": int(time.time())})
    if int(st.get("immune_critical", 0)) > 0:
        _add(d, "immune.critical", 0, st.get("immune_critical"), "D3_HEALTH", "high")
    # plano inmune a oscuras (firma inválida/ausente o excepción): fail-closed correcto pero incompleto
    if st.get("immune_ok") is False:
        _add(d, "immune.plane", "activo",
             "error: %s" % (st.get("immune_error") or "?"), "D3_HEALTH", "medium")

    # solo derivas reales (expected != observed ya garantizado por construcción)
    return [x for x in d if x["expected"] != x["observed"]]


def score(drifts):
    """Deriva -> riesgo agregado R0-R5 (misma escala que el ecosistema)."""
    level, name = "R0", "INFO"
    events = []
    for x in drifts:
        rl, rn = SEV_TO_RISK.get(x["severity"], ("R0", "INFO"))
        events.append({"risk_level": rl, "risk_name": rn, "drift_type": x["type"],
                       "component": x["field"], "requires_action": x["requires_action"]})
        if rl > level:   # 'R4' > 'R3' lexicográfico == numérico para R0-R5
            level, name = rl, rn
    num = int(level[1])
    return {"risk_level": level, "risk_name": name, "risk_num": num,
            "response": RESPONSE.get(num, "Registrar."), "events": events}


def _write(path, obj):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(json.dumps(obj, ensure_ascii=False, indent=2))
    except Exception:
        pass


def _record(rec):
    try:
        os.makedirs(os.path.dirname(REC), exist_ok=True)
        with open(REC, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL asct_drift._record: %r" % (e,), file=sys.stderr, flush=True)


def cmd_run():
    ts = int(time.time())
    st = observe()
    drifts = detect(st)
    risk = score(drifts)
    crit = sum(1 for x in drifts if x["severity"] == "critical")
    high = sum(1 for x in drifts if x["severity"] == "high")
    summary = {"svc": "asct_drift", "ts": ts, "mode": "OBSERVE_ONLY",
               "drift_count": len(drifts), "critical": crit, "high": high,
               "risk_level": risk["risk_level"], "risk_name": risk["risk_name"],
               "response": risk["response"],
               "verdict": ("ESTABLE" if not drifts else "DERIVA"),
               "drifts": drifts}
    # ficheros para el cockpit / consumidores
    _write(LATEST_DRIFT, {"ts": ts, "drift_count": len(drifts),
                          "critical": crit, "high": high, "drifts": drifts})
    _write(RISK_OUT, {"ts": ts, **{k: risk[k] for k in ("risk_level", "risk_name",
                      "risk_num", "response", "events")}, "drift_count": len(drifts)})
    # registro compacto (sin el detalle largo) al jsonl y a stdout
    compact = {k: v for k, v in summary.items() if k != "drifts"}
    _record(compact)
    print(json.dumps(compact, ensure_ascii=False))
    return 0


def cmd_status():
    print(json.dumps(_last_json(REC) or {"svc": "asct_drift", "status": "sin ejecuciones"},
                     ensure_ascii=False))
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    try:
        if cmd == "run":
            return cmd_run()
        if cmd == "status":
            return cmd_status()
        print(json.dumps({"svc": "asct_drift", "error": "modo desconocido: %s" % cmd}))
        return 2
    except Exception as e:
        # OBSERVE-only + fail-safe: nunca romper el supervisor
        _record({"svc": "asct_drift", "ok": False, "fatal": str(e), "ts": int(time.time())})
        print(json.dumps({"svc": "asct_drift", "ok": False, "fatal": str(e)}, ensure_ascii=False))
        return 0


if __name__ == "__main__":
    sys.exit(main())
