#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""storage_watch — VIGÍA DE ALMACENAMIENTO del nodo ANVOS (Fase 1 migración).

Razón de ser: el rootfs de ANVOS vive en RAM; TODO el estado durable está en /persist (disco real).
Si /persist se LLENA, el nodo deja de poder escribir ledgers, sellar, o recuperarse — y hoy NADIE
lo vigila en el nodo (una auditoría hallo que el disco no tenia cobertura; se cazo un ledger
enorme por casualidad). Ademas un fichero/ledger que crece sin control (como un merkle
que re-serializa el arbol entero) llena el disco en silencio.

Adaptado al NODO (busybox: sin mdadm/smartctl/RAID; solo stdlib). NO duplica reboot_check (que ya
comprueba que /persist es disco real): storage_watch mira la OCUPACION y el CRECIMIENTO.

Detecta:
  - DISCO_LLENO   : /persist por encima del umbral (WARN 85% / CRIT 95%). Aviso temprano.
  - FICHERO_ENORME: un solo fichero de estado por encima del umbral (posible crecimiento sin
                    control, p.ej. un ledger que no rota o un merkle re-serializado).
  - INODOS_BAJOS  : inodos libres escasos (muchos ficheros pequeños agotan inodos antes que bytes).
  - OK            : espacio y crecimiento sanos.

OBSERVE-only: informa, no borra (podar es acción del operador/ring). Ledger propio. Periódico. Solo stdlib."""
import os
import sys
import json
import time

PERSIST = os.environ.get("ANVOS_PERSIST", "/persist")
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
REC = os.path.join(DATA, "storage", "storage_watch.jsonl")
STATE = os.path.join(DATA, "storage", "storage_state.json")

USO_WARN = int(os.environ.get("ANVOS_STO_WARN", "85"))   # % de uso
USO_CRIT = int(os.environ.get("ANVOS_STO_CRIT", "95"))
FICHERO_ENORME_MB = int(os.environ.get("ANVOS_STO_BIGFILE_MB", "500"))
INODOS_WARN_PCT = int(os.environ.get("ANVOS_STO_INODES_WARN", "90"))
# raíces cuyo crecimiento vigilar (estado vivo del nodo)
ROOTS = [DATA, os.path.join(PERSIST, "anvos-ring")]


def _now():
    return int(time.time())


def _df(path):
    """Uso de disco de la partición que contiene path: (uso_pct, inodos_uso_pct). stdlib (statvfs)."""
    try:
        s = os.statvfs(path)
    except OSError:
        return None, None
    total = s.f_blocks * s.f_frsize
    libre = s.f_bavail * s.f_frsize
    usado = total - libre
    uso_pct = int(round(100 * usado / total)) if total else 0
    it = s.f_files
    il = s.f_favail
    ino_uso = int(round(100 * (it - il) / it)) if it else 0
    return uso_pct, ino_uso


def _ficheros_enormes():
    """Ficheros de estado por encima del umbral (crecimiento sin control)."""
    lim = FICHERO_ENORME_MB * 1024 * 1024
    grandes = []
    for root in ROOTS:
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                p = os.path.join(dirpath, fn)
                try:
                    sz = os.path.getsize(p)
                except OSError:
                    continue
                if sz >= lim:
                    grandes.append((p, sz))
    grandes.sort(key=lambda x: -x[1])
    return grandes[:5]


def _evaluar():
    res = []
    uso, ino = _df(PERSIST)
    if uso is None:
        res.append(("sto:persist", "OK", "/persist no medible (¿aún no montado?)"))
    else:
        if uso >= USO_CRIT:
            res.append(("sto:persist", "DISCO_LLENO", "/persist al %d%% >= %d%% CRIT" % (uso, USO_CRIT)))
        elif uso >= USO_WARN:
            res.append(("sto:persist", "DISCO_LLENO", "/persist al %d%% >= %d%% WARN" % (uso, USO_WARN)))
        else:
            res.append(("sto:persist", "OK", "/persist al %d%%" % uso))
        if ino is not None and ino >= INODOS_WARN_PCT:
            res.append(("sto:inodos", "INODOS_BAJOS", "inodos de /persist al %d%% (muchos ficheros pequeños)" % ino))
        else:
            res.append(("sto:inodos", "OK", "inodos ok"))
    for p, sz in _ficheros_enormes():
        clave = "sto:big:" + os.path.basename(p)
        res.append((clave, "FICHERO_ENORME",
                    "%s = %d MB (>= %d MB; posible crecimiento sin control)" % (p, sz // 1048576, FICHERO_ENORME_MB)))
    return res


def _sev(estado):
    return {"DISCO_LLENO": "CRIT", "INODOS_BAJOS": "WARN", "FICHERO_ENORME": "WARN"}.get(estado, "INFO")


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
    out = {"svc": "storage_watch", "ts": _now(), "comprobaciones": len(hall),
           "con_problema": malos, "transiciones": transiciones[:10],
           "verdict": "ALMACENAMIENTO_EN_RIESGO" if malos else "ALMACENAMIENTO_OK"}
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(json.dumps({"svc": "storage_watch", "error": str(e)[:200]}, ensure_ascii=False))
        sys.exit(1)
