#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""vigias_watch — META-VIGÍA del nodo ANVOS: vigila que la SUPERVISIÓN funcione (Fase 1 migración).

NO duplica layerd. layerd YA: lanza los servicios del manifest, respawnea los LONG_RUNNING que
mueren (backoff), mata los periódicos colgados (MAX_RUNTIME) y verifica su firma. Lo que layerd NO
hace —y es el hueco real— es vigilarse a SÍ MISMO ni comprobar que lo declarado produce resultado:

  - LAYERD_MUDO        : el latido de layerd (layerd.jsonl) está ESTANCADO -> layerd atascado/muerto
                         (no un cuelgue total de kernel, que cubre liveness_watchdog+watchdog HW,
                         sino layerd vivo pero sin ciclar; el supervisor 'while true' solo lo
                         reinicia si SALE, no si se cuelga).
  - SERVICIO_MUDO      : un servicio DECLARADO en el manifest lleva > N intervalos SIN escribir su
                         ledger de salida -> declarado pero no produce (roto en silencio). layerd lo
                         relanza pero nadie ALERTA de que su trabajo no aparece.
  - INTEGRIDAD_DEGRADADA: la última atestación de self_integrity NO es SEALED -> una firma se rompió;
                         layerd no vigila esto.

Es el "vigía de los vigías" del máster, adaptado al nodo y RECORTADO al hueco (sin re-implementar la
supervisión que layerd ya da). OBSERVE-only, ledger propio, periódico, solo stdlib."""
import os
import sys
import json
import time

PERSIST = os.environ.get("ANVOS_PERSIST", "/persist")
STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
MANIFEST = os.path.join(STAGING, "services", "manifest.txt")
LAYERD_HB = os.path.join(DATA, "layerd", "layerd.jsonl")
INTEGRITY = os.path.join(DATA, "integrity", "self_integrity.jsonl")
REC = os.path.join(DATA, "vigias", "vigias_watch.jsonl")
STATE = os.path.join(DATA, "vigias", "vigias_state.json")

LAYERD_STALE_S = int(os.environ.get("ANVOS_VW_LAYERD_STALE", "120"))  # layerd cicla seguido
SVC_STALE_MULT = int(os.environ.get("ANVOS_VW_SVC_MULT", "4"))        # > N intervalos sin salida
# Los LONG_RUNNING corren en CONTINUO (no escriben su ledger a intervalo): layerd ya los supervisa
# por respawn. Comprobar su "frescura de salida" contra el intervalo es un FALSO POSITIVO (cazado
# 2026-07-22 con cockpit-fb en origo, amplificado por su mtime de 2023). Se excluyen del check
# SERVICIO_MUDO; su salud la garantiza layerd, no este vigía (no duplicar).
LONG_RUNNING = {"anvos-cockpit-fb.py", "node_status_server.py", "deception_sensor.py",
                "ai_llama_server.py", "liveness_watchdog.py"}


def _now():
    return int(time.time())


def _mtime(path):
    try:
        return int(os.path.getmtime(path))
    except OSError:
        return 0


def _parse_manifest():
    """Devuelve [(fichero, intervalo_s, ruta_salida_abs)] de los servicios declarados."""
    svcs = []
    try:
        for line in open(MANIFEST):
            line = line.strip()
            if not line or line.startswith("#") or "|" not in line:
                continue
            parts = line.split("|")
            if len(parts) < 3:
                continue
            fichero, interval, out_rel = parts[0], parts[1], parts[2]
            try:
                iv = int(interval)
            except ValueError:
                continue
            svcs.append((fichero, iv, os.path.join(DATA, out_rel)))
    except Exception:
        pass
    return svcs


def _evaluar():
    now = _now()
    res = []

    # 1) latido de layerd fresco
    hb = _mtime(LAYERD_HB)
    if hb == 0:
        res.append(("vw:layerd", "OK", "sin latido de layerd todavía (¿arranque?)"))
    elif now - hb > LAYERD_STALE_S:
        res.append(("vw:layerd", "LAYERD_MUDO",
                    "layerd.jsonl estancado hace %ds (>%ds): layerd atascado o muerto" % (now - hb, LAYERD_STALE_S)))
    else:
        res.append(("vw:layerd", "OK", "layerd ciclando (latido hace %ds)" % (now - hb)))

    # 2) servicios declarados que no producen salida
    for fichero, iv, out in _parse_manifest():
        # servicios con intervalo 0 o LONG_RUNNING no escriben periódicamente -> los supervisa
        # layerd por respawn, no este vigía (evita falso positivo + no duplica).
        if iv <= 0 or fichero in LONG_RUNNING:
            continue
        m = _mtime(out)
        clave = "vw:svc:" + fichero.replace(".py", "")
        umbral = iv * SVC_STALE_MULT
        if m == 0:
            # aún no ha producido nada; solo alerta si lleva mucho desde el arranque (usa hb como ref)
            if hb and now - hb > umbral:
                res.append((clave, "SERVICIO_MUDO", "%s declarado pero SIN salida (%s)" % (fichero, out)))
            else:
                res.append((clave, "OK", "%s aún sin primera salida (tolerado)" % fichero))
        elif now - m > umbral:
            res.append((clave, "SERVICIO_MUDO",
                        "%s sin escribir su ledger hace %ds (>%dx intervalo=%ds)" % (fichero, now - m, SVC_STALE_MULT, umbral)))
        else:
            res.append((clave, "OK", "%s produce (hace %ds)" % (fichero, now - m)))

    # 3) integridad SEALED
    att = None
    try:
        with open(INTEGRITY) as f:
            last = None
            for line in f:
                if line.strip():
                    last = line
            if last:
                att = json.loads(last).get("attestation")
    except Exception:
        att = None
    if att is None:
        res.append(("vw:integrity", "OK", "sin atestación reciente para evaluar"))
    elif att != "SEALED":
        res.append(("vw:integrity", "INTEGRIDAD_DEGRADADA", "self_integrity NO SEALED (=%s): firma rota" % att))
    else:
        res.append(("vw:integrity", "OK", "self_integrity SEALED"))

    return res


def _sev(estado):
    return {"LAYERD_MUDO": "CRIT", "INTEGRIDAD_DEGRADADA": "CRIT",
            "SERVICIO_MUDO": "WARN"}.get(estado, "INFO")


def _load(path, d):
    try:
        return json.load(open(path))
    except Exception:
        return d


def _save(path, datos):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(datos, f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _append(path, entry):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def main():
    hall = _evaluar()
    previo = _load(STATE, {})
    nuevo, transiciones, malos = {}, [], 0
    for clave, estado, det in hall:
        nuevo[clave] = estado
        if estado != "OK":
            malos += 1
        if previo.get(clave, "OK") != estado:
            transiciones.append({"clave": clave, "de": previo.get(clave, "OK"), "a": estado, "detalle": det})
            _append(REC, {"ts": _now(), "clave": clave, "estado": estado, "detalle": det, "severity": _sev(estado)})
    _save(STATE, nuevo)
    out = {"svc": "vigias_watch", "ts": _now(), "comprobaciones": len(hall),
           "con_problema": malos, "transiciones": transiciones[:12],
           "verdict": "SUPERVISION_DEGRADADA" if malos else "SUPERVISION_OK"}
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(json.dumps({"svc": "vigias_watch", "error": str(e)[:200]}, ensure_ascii=False))
        sys.exit(1)
