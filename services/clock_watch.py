#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""clock_watch — VIGÍA DE RELOJ del nodo ANVOS (Fase 1 migración; primitiva de soberanía: tiempo).

Razón de ser (incidente origo 2026-07-22): un nodo ANVOS sin RTC/NTP puede arrancar con el reloj
MUY desviado (origo creía estar en enero 2023, ~3,5 años atrás) y NADIE lo cazaba — sus propios
ledgers también quedaban con 2023, así que un vigía auto-referencial no sirve. Los controles de
seguridad dependen del reloj (TTLs, firmas, correlación en la malla), y un reloj corrupto rompe la
validación de firmas de anillo (peers_cfg_signed=false) y aísla el nodo.

Adaptado al entorno del NODO (busybox: sin timedatectl/systemctl/NTP). Detecta con SOLO stdlib:
  - RELOJ_BAJO_SUELO : el reloj es ANTERIOR al SUELO horario baked-in (fecha de sellado del OS).
                       Es el caso origo: 2023 < 2026 -> corrupto seguro. El suelo NO puede ser
                       falsificado por el propio reloj del nodo (es una constante del build).
  - RELOJ_ATRASADO   : el reloj es anterior al mtime más reciente de su propio /persist (el reloj
                       retrocedió respecto a algo que el nodo ya escribió) — salto hacia atrás.
  - SKEW_VS_PEERS    : desfase grande frente al timestamp más reciente visto de PEERS en la malla
                       (beacons del anillo); un peer con reloj bueno delata al nodo desviado.
  - OK               : reloj coherente con el suelo, su propio estado y los peers.

OBSERVE-only: informa, no toca el reloj (corregirlo es acción del operador/ring). Ledger propio.
Periódico (rápido, <1s). Solo stdlib. Atestado por self_integrity al vivir en services/."""
import os
import sys
import json
import time
import glob

PERSIST = os.environ.get("ANVOS_PERSIST", "/persist")
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
REC = os.path.join(DATA, "clock", "clock_watch.jsonl")
STATE = os.path.join(DATA, "clock", "clock_state.json")

# SUELO horario: epoch por debajo del cual el reloj es CORRUPTO seguro. Constante del build,
# NO derivable del reloj del nodo (por eso caza el caso origo aunque sus ledgers digan 2023).
# 2026-06-01T00:00:00Z — anterior a cualquier sellado v18 real, posterior a 2023.
FLOOR_EPOCH = int(os.environ.get("ANVOS_CLOCK_FLOOR", "1748736000"))
SKEW_WARN_S = int(os.environ.get("ANVOS_CLOCK_SKEW_WARN", "300"))    # 5 min vs peers
SKEW_CRIT_S = int(os.environ.get("ANVOS_CLOCK_SKEW_CRIT", "86400"))  # 1 día vs peers
# fuentes de timestamps de PEERS (beacons del anillo empujados a este nodo)
PEER_BEACON_GLOBS = [
    os.path.join(DATA, "eco-telem", "peers", "*.json"),
    os.path.join(DATA, "ring", "peers", "*.json"),
    os.path.join(PERSIST, "anvos-ring-link", "peers", "*.json"),
]


def _now():
    return int(time.time())


def _newest_own_mtime():
    """mtime más reciente de ficheros de estado que el propio nodo escribe (salto-atrás)."""
    newest = 0
    for root in (DATA, os.path.join(PERSIST, "anvos-ring-link")):
        for dirpath, _dirs, files in os.walk(root):
            # no seguir dentro de este propio ledger (se acaba de escribir)
            if "clock" in dirpath:
                continue
            for fn in files:
                try:
                    m = os.path.getmtime(os.path.join(dirpath, fn))
                    if m > newest:
                        newest = m
                except OSError:
                    pass
    return int(newest)


def _newest_peer_ts():
    """timestamp más reciente declarado por un PEER en sus beacons (reloj externo de referencia)."""
    newest = 0
    for g in PEER_BEACON_GLOBS:
        for f in glob.glob(g):
            try:
                d = json.load(open(f))
            except Exception:
                continue
            for k in ("ts", "utc_epoch", "epoch", "clock", "now"):
                v = d.get(k)
                if isinstance(v, (int, float)) and v > newest:
                    newest = int(v)
    return newest


def _evaluar():
    now = _now()
    res = []
    # 1) suelo horario (el más fuerte; caza origo-2023)
    if now < FLOOR_EPOCH:
        res.append(("clock:floor", "RELOJ_BAJO_SUELO",
                    "reloj=%d < suelo=%d: el reloj es ANTERIOR a la fecha de sellado del OS "
                    "(corrupto seguro, p.ej. nodo sin RTC arrancó en el pasado)" % (now, FLOOR_EPOCH)))
    else:
        res.append(("clock:floor", "OK", "reloj por encima del suelo del build"))
    # 2) salto hacia atrás vs su propio estado
    own = _newest_own_mtime()
    if own and now < own - 5:
        res.append(("clock:backward", "RELOJ_ATRASADO",
                    "reloj=%d < mtime más reciente propio=%d: el reloj retrocedió %ds" % (now, own, own - now)))
    else:
        res.append(("clock:backward", "OK", "sin salto hacia atrás vs estado propio"))
    # 3) desfase vs peers (si hay beacons)
    peer = _newest_peer_ts()
    if peer:
        skew = abs(now - peer)
        if skew >= SKEW_CRIT_S:
            res.append(("clock:peers", "SKEW_VS_PEERS",
                        "desfase %ds vs peer más reciente (%d) >= %ds CRIT" % (skew, peer, SKEW_CRIT_S)))
        elif skew >= SKEW_WARN_S:
            res.append(("clock:peers", "SKEW_VS_PEERS",
                        "desfase %ds vs peers >= %ds WARN" % (skew, SKEW_WARN_S)))
        else:
            res.append(("clock:peers", "OK", "coherente con peers (desfase %ds)" % skew))
    else:
        res.append(("clock:peers", "OK", "sin beacons de peers para comparar (no bloqueante)"))
    return res


def _sev(estado):
    return {"RELOJ_BAJO_SUELO": "CRIT", "RELOJ_ATRASADO": "CRIT",
            "SKEW_VS_PEERS": "WARN"}.get(estado, "INFO")


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
            _append(REC, {"ts": _now(), "clave": clave, "estado": estado, "detalle": det,
                          "severity": _sev(estado)})
    _save(STATE, nuevo)
    out = {"svc": "clock_watch", "ts": _now(), "node_epoch": _now(),
           "comprobaciones": len(hall), "con_problema": malos,
           "transiciones": transiciones[:10],
           "verdict": "RELOJ_CORRUPTO" if any(h[1] in ("RELOJ_BAJO_SUELO", "RELOJ_ATRASADO") for h in hall)
                      else ("RELOJ_DESVIADO" if malos else "RELOJ_OK")}
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(json.dumps({"svc": "clock_watch", "error": str(e)[:200]}, ensure_ascii=False))
        sys.exit(1)
