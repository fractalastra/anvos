#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""anv-crit-escalator — canal CRIT que no se ahoga, y que falla cerrado.

El nodo detecta problemas CRIT, pero vigias_watch solo escribe el detalle en las
transiciones; una vez estabilizado en CRIT, el resumen periodico solo emite un
contador. La alerta queda ahogada 1:420 en su propio fichero.

Este servicio:
  - Lee vigias_state.json, vigias_watch.jsonl y layerd.jsonl.
  - Identifica CRIT persistentes y fuentes muertas.
  - Escribe en operator_queue.jsonl con identidad, antigüedad y contador.
  - Re-escala cada REESCALA_S mientras el CRIT persista, pero nunca deja de nombrarlo.
  - NO escala si la firma con an_service falla: la ausencia de firma es un estado
    estable con significado, no algo que se pueda tapar con una entrada sin firmar.
  - Trata como CRIT cualquier estado desconocido: lo no clasificado es peligroso.
  - Detecta cuando su propia fuente (vigias_state.json) falta o está corrupta.
  - Escribe heartbeat propio para que otro vigia pueda detectar si él muere.

Manifest: anv-crit-escalator.py|60|crit_escalator/crit_escalator.jsonl
"""
import os
import sys
import json
import time
import hashlib
import subprocess

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
VIGIAS_STATE = os.path.join(DATA, "vigias", "vigias_state.json")
VIGIAS_LOG = os.path.join(DATA, "vigias", "vigias_watch.jsonl")
LAYERD_HB = os.path.join(DATA, "layerd", "layerd.jsonl")
QUEUE = os.path.join(DATA, "queue", "operator_queue.jsonl")
ESC_DIR = os.path.join(DATA, "crit_escalator")
ESC_STATE = os.path.join(ESC_DIR, "escalator_state.json")
ESC_HB = os.path.join(ESC_DIR, "crit_escalator.jsonl")
# Firmante externo opcional: por configuracion (ANVOS_SIGN_AGENT). Vacio = sin firma diferida.
SIGN_AGENT = os.environ.get("ANVOS_SIGN_AGENT", "")
NODE_NAME = os.environ.get("ANVOS_NODE", "origo")

REESCALA_S = int(os.environ.get("ANVOS_CRIT_REESCALA_S", "900"))          # 15 min
LAYERD_STALE_S = int(os.environ.get("ANVOS_CRIT_LAYERD_STALE_S", "600"))  # 10 min
VIGIAS_STATE_STALE_S = int(os.environ.get("ANVOS_CRIT_VIGIAS_STATE_STALE_S", "300"))  # 5 min

# Estados explícitamente conocidos como no-críticos. TODO LO DEMÁS es CRIT.
WARN_ESTADOS = {"SERVICIO_MUDO"}


def _now():
    return int(time.time())


def _ts_iso(t=None):
    t = t or _now()
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def _load_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


def _save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _append_jsonl(path, entry):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


def _mtime(path):
    try:
        return int(os.path.getmtime(path))
    except OSError:
        return 0


def _last_line_json(path):
    """Última línea JSON válida de un fichero, o None."""
    if not os.path.isfile(path):
        return None
    try:
        with open(path, errors="replace") as f:
            try:
                f.seek(-min(65536, os.path.getsize(path)), os.SEEK_END)
            except OSError:
                pass
            for line in reversed(f.read().splitlines()):
                line = line.strip()
                if not line:
                    continue
                try:
                    return json.loads(line)
                except Exception:
                    continue
    except Exception:
        pass
    return None


def _incident_id(clave):
    """ID estable por clave. No cambia con el día, así que la reiteración es real."""
    short = hashlib.sha256(clave.encode()).hexdigest()[:6]
    return "INC-CRIT-%s" % short


def _last_event_for_key(clave):
    """Último evento de vigias_watch.jsonl para una clave dada."""
    if not os.path.isfile(VIGIAS_LOG):
        return None
    found = None
    try:
        with open(VIGIAS_LOG, errors="replace") as f:
            try:
                f.seek(-min(1048576, os.path.getsize(VIGIAS_LOG)), os.SEEK_END)
            except OSError:
                pass
            for line in f.read().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    if e.get("clave") == clave:
                        found = e
                except Exception:
                    continue
    except Exception:
        pass
    return found


def _check_vigias_source_dead():
    """Detecta si vigias_state.json no existe o no se actualiza."""
    m = _mtime(VIGIAS_STATE)
    now = _now()
    if m == 0:
        return {
            "clave": "vw:source",
            "estado": "FUENTE_VIGIAS_INALCANZABLE",
            "severity": "CRIT",
            "detalle": "%s no existe: el vigía de vigías no deja rastro" % VIGIAS_STATE,
            "ts_evento": 0,
            "antiguedad_s": None,
        }
    age = now - m
    if age > VIGIAS_STATE_STALE_S:
        return {
            "clave": "vw:source",
            "estado": "FUENTE_VIGIAS_ESTANCADA",
            "severity": "CRIT",
            "detalle": "%s estancado hace %ds (>%ds): vigias_watch no cicla" % (VIGIAS_STATE, age, VIGIAS_STATE_STALE_S),
            "ts_evento": m,
            "antiguedad_s": age,
        }
    return None


def _check_layerd_dead():
    """Detecta si layerd no cicla, independientemente de vigias_watch."""
    m = _mtime(LAYERD_HB)
    if m == 0:
        return {
            "clave": "vw:layerd",
            "estado": "LAYERD_MUDO",
            "severity": "CRIT",
            "detalle": "layerd.jsonl no existe: layerd nunca ha latido o la fuente está muerta",
            "ts_evento": 0,
            "antiguedad_s": None,
        }
    age = _now() - m
    if age > LAYERD_STALE_S:
        return {
            "clave": "vw:layerd",
            "estado": "LAYERD_MUDO",
            "severity": "CRIT",
            "detalle": "layerd.jsonl estancado hace %ds (>%ds): layerd atascado o muerto" % (age, LAYERD_STALE_S),
            "ts_evento": m,
            "antiguedad_s": age,
        }
    return None


def _severity(estado):
    """Fallo cerrado: solo los estados explícitamente conocidos como WARN lo son.
    Cualquier estado nuevo/desconocido se escala como CRIT."""
    return "WARN" if estado in WARN_ESTADOS else "CRIT"


def _crits_from_vigias():
    """Devuelve CRIT persistentes según vigias_state.json.

    Fallo cerrado: si el estado no se puede leer, se escala como CRIT de fuente.
    """
    state = _load_json(VIGIAS_STATE, None)
    if state is None:
        src = _check_vigias_source_dead()
        return [src] if src else []

    crits = []
    now = _now()
    # También comprobar si el fichero, aunque legible, está estancado.
    src = _check_vigias_source_dead()
    if src:
        crits.append(src)

    for clave, estado in state.items():
        if estado in ("OK",):
            continue
        ev = _last_event_for_key(clave)
        severity = _severity(estado)
        if severity != "CRIT":
            continue
        ts_evento = int(ev.get("ts", 0)) if ev else 0
        antiguedad = now - ts_evento if ts_evento else None
        detalle = ev.get("detalle", "sin detalle") if ev else "sin detalle previo"
        crits.append({
            "clave": clave,
            "estado": estado,
            "severity": severity,
            "detalle": detalle,
            "ts_evento": ts_evento,
            "antiguedad_s": antiguedad,
        })
    return crits


def _sign_queue():
    """Firma operator_queue.jsonl con an_service si está disponible."""
    if not os.path.isfile(QUEUE):
        return False
    if not os.path.isfile(SIGN_AGENT):
        return False
    try:
        r = subprocess.run([SIGN_AGENT, QUEUE], capture_output=True, timeout=30)
        return r.returncode == 0
    except Exception:
        return False


def _revert_last_entry(path, entry_json):
    """Elimina la última línea de path si coincide con entry_json. Usado cuando
    la firma falla para no dejar la cola sin firma."""
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "r+") as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell()
            if pos == 0:
                return False
            # Buscar el último '\n' desde el final.
            buf = b""
            while pos > 0:
                pos -= 1
                f.seek(pos)
                ch = f.read(1)
                if ch == b"\n":
                    break
                buf = ch + buf
            last_line = buf.decode("utf-8", errors="replace").strip()
            if not last_line:
                return False
            # Truncar justo después del '\n' anterior (o al inicio).
            truncate_at = pos if pos > 0 else 0
            f.seek(truncate_at)
            f.truncate()
            return True
    except Exception:
        return False


def _escalate(crit, state, now):
    """Escala un CRIT a operator_queue.jsonl si corresponde y SI se puede firmar.

    Fallo cerrado: si la firma no se produce, la entrada se revierte y no se
    considera escalada. La ausencia de firma no se tapa con una entrada sin firmar.
    """
    # 1. Verificar que tenemos firmador antes de tocar la cola.
    if not os.path.isfile(SIGN_AGENT) or not os.access(SIGN_AGENT, os.X_OK):
        return False, "sign_agent.sh no disponible"

    clave = crit["clave"]
    incident_id = _incident_id(clave)
    last = state.get(incident_id, {})
    last_ts = last.get("ts_ultima_escalada", 0)
    reiteracion = last.get("reiteracion", 0) + 1

    # Si ya escalamos recientemente, no repetir.
    if last_ts and (now - last_ts) < REESCALA_S:
        return False, "rate-limit"

    entry = {
        "ts": _ts_iso(now),
        "typ": "OPERATOR-REQUIRED",
        "incident_id": incident_id,
        "node": NODE_NAME,
        "severity": "CRITICAL",
        "type": "VIGIA_CRIT",
        "title": crit["estado"],
        "detail": crit["detalle"],
        "reason": "CRIT persistente detectado por el nodo y no resuelto",
        "acknowledged": False,
        "origen": "anv-crit-escalator",
        "reiteracion": reiteracion,
        "antiguedad_s": crit.get("antiguedad_s"),
    }
    entry_json = json.dumps(entry, ensure_ascii=False)

    # 2. Escribir entrada.
    _append_jsonl(QUEUE, entry)

    # 3. Firmar. Si falla, revertir la entrada.
    if _sign_queue():
        state[incident_id] = {
            "clave": clave,
            "ts_ultima_escalada": now,
            "reiteracion": reiteracion,
        }
        _save_json(ESC_STATE, state)
        return True, "escalado y firmado"

    # Firma fallida: revertir para no dejar la cola sin firma.
    reverted = _revert_last_entry(QUEUE, entry_json)
    return False, "firma fallida; entrada revertida" if reverted else "firma fallida; NO se pudo revertir"


def _heartbeat(now, escalados, total_crit, errores):
    estado = "ERROR" if errores else ("DEGRADADO" if total_crit else "OK")
    entry = {
        "svc": "anv-crit-escalator",
        "ts": now,
        "ts_iso": _ts_iso(now),
        "escalados": escalados,
        "crit_activos": total_crit,
        "errores": errores,
        "estado": estado,
    }
    _append_jsonl(ESC_HB, entry)


def main():
    os.makedirs(ESC_DIR, exist_ok=True)
    now = _now()
    state = _load_json(ESC_STATE, {})
    errores = []

    crits = _crits_from_vigias()
    layerd = _check_layerd_dead()
    if layerd:
        if not any(c["clave"] == "vw:layerd" for c in crits):
            crits.append(layerd)

    escalados = 0
    for crit in crits:
        ok, msg = _escalate(crit, state, now)
        if ok:
            escalados += 1
        else:
            errores.append("%s: %s" % (crit["clave"], msg))

    _heartbeat(now, escalados, len(crits), errores)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        entry = {
            "svc": "anv-crit-escalator",
            "ts": _now(),
            "ts_iso": _ts_iso(),
            "estado": "ERROR",
            "error": str(e)[:200],
        }
        _append_jsonl(ESC_HB, entry)
        sys.exit(1)
