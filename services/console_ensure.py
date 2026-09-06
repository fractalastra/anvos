#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""console_ensure — asegura una CONSOLA LOCAL en la pantalla física (tty1, la VT visible por fbcon) del
nodo: un getty->login para que el nodo tenga TERMINAL PROPIA sin depender de ssh-desde-master. Es un
requisito de autosuficiencia del nodo soberano (el operador debe poder sentarse al portátil y tener shell).

Idempotente/ensure-corto: crea /dev/tty1 si falta (busybox/mdev no siempre) y mantiene UN getty vivo en
tty1 (lo relanza si murió). Detecta el getty REAL (excluye la cmdline del lanzador -> evita auto-match).
Solo stdlib. Uso: [cycle]."""
import os
import sys
import json
import time
import subprocess

TTY = "tty1"
OUT = "/persist/anvos-data/console/console_ensure.jsonl"


def _sh(cmd, t=10):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t).stdout or ""
    except Exception:
        return ""


def _getty_alive():
    for ln in _sh("ps w 2>/dev/null").splitlines():
        # getty REAL = "getty ... tty1 ..." SIN ser la cmdline del lanzador (sh -c / este servicio)
        if "getty" in ln and TTY in ln and "sh -c" not in ln and "console_ensure" not in ln:
            return True
    return False


def main():
    st = {"svc": "console_ensure", "ts": int(time.time())}
    if not os.path.exists("/dev/" + TTY):
        try:
            os.mknod("/dev/" + TTY, 0o600 | 0o020000, os.makedev(4, 1))   # S_IFCHR, major 4 minor 1
        except Exception:
            pass
    if _getty_alive():
        st["estado"] = "CONSOLA_VIVA"
    else:
        # busybox getty: BAUD TTY [TERMTYPE]. -L = local (sin carrier). Detached via setsid.
        _sh("setsid sh -c 'exec getty -L 115200 %s linux' </dev/null >/dev/null 2>&1 &" % TTY)
        time.sleep(1)
        st["estado"] = "CONSOLA_ARRANCADA" if _getty_alive() else "CONSOLA_FALLO"
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "a") as f:
            f.write(json.dumps(st, ensure_ascii=False) + "\n")
    except Exception:
        pass
    print(json.dumps(st, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
