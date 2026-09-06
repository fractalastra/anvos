#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""clock_sync — CORRECTOR de reloj del nodo ANVOS (Fase 1+, complemento de clock_watch).

Razón de ser (validado en producción 2026-07-22): un nodo ANVOS SIN RTC/NTP arranca con el reloj en
el pasado (origo derivó a enero 2023 en cada reboot). Eso ROMPE las firmas de anillo (ring_cfg no se
firma/valida), los TTLs y la correlación en la malla. clock_watch DETECTA pero NO corrige; este
servicio CORRIGE, de forma AUTÓNOMA (sin depender de la red) y opportunista con los peers cuando hay.

Estrategia (fail-safe, solo hacia ADELANTE):
  referencia = max(SUELO_del_build, mtime_más_reciente_propio, timestamp_más_reciente_de_peers)
  - SUELO: constante del build (2026-06). Nunca por debajo -> mata el caso 2023 sin red.
  - mtime propio: el fichero más nuevo de /persist es de justo antes del último apagado -> el reloj
    no debe ser anterior a la última actividad conocida del nodo (precisión de minutos, suficiente).
  - peers: si hay beacons con reloj bueno (nodo-c tenía hora correcta), refina a la hora real.
  Si el reloj actual < referencia - GRACIA -> lo SALTA HACIA ADELANTE (date -s). Nunca hacia atrás.

Corre PRONTO y frecuente (intervalo corto) para corregir dentro de un ciclo tras el boot, antes de
que ring_link firme con el reloj malo. OBSERVE del resultado en su ledger. Solo stdlib. Requiere root
(los servicios de capa corren como root). ANVOS_CLOCK_DRYRUN=1 -> reporta sin tocar el reloj (test)."""
import os
import sys
import json
import time
import glob
import subprocess

PERSIST = os.environ.get("ANVOS_PERSIST", "/persist")
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
REC = os.path.join(DATA, "clock", "clock_sync.jsonl")

FLOOR_EPOCH = int(os.environ.get("ANVOS_CLOCK_FLOOR", "1748736000"))  # 2026-06-01, igual que clock_watch
GRACE_S = int(os.environ.get("ANVOS_CLOCK_SYNC_GRACE", "60"))         # no corregir por <60s de desfase
DRYRUN = os.environ.get("ANVOS_CLOCK_DRYRUN", "0") == "1"
PEER_BEACON_GLOBS = [
    os.path.join(DATA, "eco-telem", "peers", "*.json"),
    os.path.join(DATA, "ring", "peers", "*.json"),
    os.path.join(PERSIST, "anvos-ring-link", "peers", "*.json"),
]


def _now():
    return int(time.time())


def _newest_own_mtime():
    newest = 0
    for root in (DATA, os.path.join(PERSIST, "anvos-ring-link"), os.path.join(PERSIST, "anvos-ring")):
        for dp, _d, files in os.walk(root):
            if "clock" in dp:   # no contar este propio ledger
                continue
            for fn in files:
                try:
                    m = os.path.getmtime(os.path.join(dp, fn))
                    if m > newest:
                        newest = m
                except OSError:
                    pass
    return int(newest)


def _newest_peer_ts():
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


def _rtc_leer():
    """Lee el reloj de HARDWARE por sysfs, sin depender de ninguna herramienta externa."""
    try:
        f = "/sys/class/rtc/rtc0/"
        return open(f + "date").read().strip() + " " + open(f + "time").read().strip()
    except Exception:
        return None


def _rtc_escribir():
    """Escribe el reloj del sistema en el reloj de HARDWARE. Devuelve (ok, detalle).

    POR QUE EXISTE (defecto medido el 1-ago-2026)
    ---------------------------------------------
    Este servicio ajustaba el reloj del SISTEMA y no lo escribia nunca en el de HARDWARE.
    Consecuencia: el nodo arrancaba con la fecha que tuviera el reloj de la placa —enero de
    2023— y la correccion de mas de tres años se aplicaba DESPUES del arranque. Todo lo que
    se registrara entre el arranque y esta correccion quedaba fechado en 2023, invisible a
    cualquier listado por fecha. Se llego a creer durante dias que la caja negra habia dejado
    de registrar: registraba, pero con fecha de hace tres años.

    Y era irreparable por si solo: por bien que se ajustara el reloj del sistema en cada
    arranque, el de la placa seguia igual, de modo que el defecto se reproducia entero en el
    arranque siguiente. Ajustar sin escribir de vuelta es arreglar el sintoma cada vez.

    NO enmascara una pila agotada: si la pila no retiene, el reloj volvera a 2023 tras un
    corte de corriente y la comparacion que se registra aqui lo dejara a la vista. Por eso se
    anota el valor del reloj de hardware ANTES y DESPUES: es la prueba de la pila, y se hace
    sola en cada ejecucion.
    """
    antes = _rtc_leer()
    for cmd in (["hwclock", "--systohc", "--utc"], ["hwclock", "-w", "-u"]):
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=15)
            if r.returncode == 0:
                return True, {"antes": antes, "despues": _rtc_leer(), "via": cmd[0]}
        except Exception:
            continue
    return False, {"antes": antes, "despues": _rtc_leer(), "via": None}


def _set_clock(epoch):
    """Fija el reloj del sistema con date -s (busybox) Y lo escribe en el de hardware.

    Devuelve True/False segun el reloj del SISTEMA, que es lo que gobierna al nodo. Que la
    escritura en hardware falle NO invalida el ajuste: se anota y se sigue. Es una degradacion
    declarada, no un fallo silencioso — el nodo funciona con la hora correcta aunque la placa
    no la conserve, que es exactamente la situacion de una pila agotada.
    """
    # formato UTC que entiende busybox date -s: "YYYY-MM-DD HH:MM:SS"
    txt = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(epoch))
    try:
        subprocess.run(["date", "-u", "-s", txt], capture_output=True, timeout=10)
    except Exception:
        return False
    ok_rtc, detalle = _rtc_escribir()
    _set_clock.rtc = {"escrito": ok_rtc, **detalle}
    return True


_set_clock.rtc = None


def _append(path, entry):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def main():
    now = _now()
    own = _newest_own_mtime()
    peer = _newest_peer_ts()
    fuentes = {"floor": FLOOR_EPOCH, "own_mtime": own, "peer": peer}
    referencia = max(FLOOR_EPOCH, own, peer)
    # de dónde vino la referencia (para trazabilidad)
    origen = "floor" if referencia == FLOOR_EPOCH else ("peer" if referencia == peer and peer else "own_mtime")

    accion, nuevo = "ninguna", now
    if now < referencia - GRACE_S:
        # el reloj está en el pasado -> saltar hacia adelante a la referencia
        if DRYRUN:
            accion = "DRYRUN_corregiria"
        elif _set_clock(referencia):
            accion = "CORREGIDO"
            nuevo = _now()
        else:
            accion = "FALLO_set"
    else:
        accion = "OK_sin_correccion"
        # Aunque el reloj del sistema este bien, el de HARDWARE puede seguir en el pasado: es
        # justo el caso que dejo el nodo fechando en 2023 durante semanas. Se escribe igual.
        if not DRYRUN:
            ok_rtc, det = _rtc_escribir()
            _set_clock.rtc = {"escrito": ok_rtc, **det}

    rtc = _set_clock.rtc or {"escrito": None, "antes": _rtc_leer(), "despues": None}
    # La comparacion entre el reloj del sistema y el de hardware AL ENTRAR es la prueba de la
    # pila, y se hace sola en cada ejecucion: si el nodo arranca con el hardware en el pasado
    # despues de haberlo escrito, la pila no retiene.
    rtc["coincidia_al_entrar"] = (str(rtc.get("antes") or "")[:4] ==
                                  time.strftime("%Y", time.gmtime(now)))

    rec = {"svc": "clock_sync", "ts": nuevo, "reloj_antes": now, "referencia": referencia,
           "rtc": rtc,
           "origen_referencia": origen, "fuentes": fuentes, "desfase_s": referencia - now,
           "accion": accion, "dryrun": DRYRUN,
           "verdict": ("RELOJ_CORREGIDO" if accion == "CORREGIDO" else
                       ("CORRECCION_PENDIENTE" if accion in ("DRYRUN_corregiria", "FALLO_set") else "RELOJ_OK"))}
    # Se registra tambien cuando el reloj de hardware NO coincidia al entrar, aunque el del
    # sistema estuviera bien: ese es el sintoma de la pila, y perderlo fue lo que hizo falta
    # tres dias para diagnosticar.
    if accion in ("CORREGIDO", "FALLO_set", "DRYRUN_corregiria") or rtc.get("coincidia_al_entrar") is False:
        _append(REC, rec)
    print(json.dumps(rec, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(json.dumps({"svc": "clock_sync", "error": str(e)[:200]}, ensure_ascii=False))
        sys.exit(1)
