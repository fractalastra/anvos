#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""boot_sanity — ¿arrancó este nodo con los parámetros que debía?

Hallado 2026-07-29 en origo: su `/proc/cmdline` son **25 bytes de basura binaria** (0 caracteres
imprimibles). Con Secure Boot desactivado, systemd-stub prefiere las `LoadOptions` del firmware
sobre la cmdline firmada del UKI, y una entrada UEFI con `optional_data` corrupta las estaba
pisando. El nodo llevaba días arrancando SIN sus parámetros previstos… y nadie se enteró, porque
la capa arranca por sus propios medios y nada comprobaba esto.

Dos consecuencias que sí importan:
  · el nodo corre sin su perfil/política de arranque previstos;
  · la ESCOTILLA DE RECUPERACIÓN del operador (`anvos.recovery` en la cmdline) queda INERTE:
    su emergencia dependía de que el firmware se portara bien. (El init ya acepta además
    `/persist/anvos-recovery.flag`, que no depende de nadie — aquí se comprueba que exista esa
    alternativa en el init vivo y se avisa si tampoco está.)

Observe-only: no toca el arranque ni la cmdline (no se puede desde el sistema en marcha). Solo
mide y reporta, para que la cola del operador lo levante. Solo stdlib.

Manifest: boot_sanity.py|3600|boot/boot_sanity.jsonl
"""
import os
import json
import time

# claves que la cmdline firmada del UKI debería traer (si falta todo, el arranque es degradado)
# claves REALES de la cmdline firmada del UKI (medidas en el nodo tras la ceremonia de Secure Boot:
# console=tty0 node=auto cycle=4000 enforce=1 profile=eco ...). "panic=" era una suposicion mia
# de un informe previo y no esta en la linea real: se corrige para no medir contra un espejismo.
ESPERADAS = ("node=", "profile=", "enforce=")


def _cmdline():
    try:
        with open("/proc/cmdline", "rb") as f:
            return f.read()
    except OSError:
        return b""


def main():
    out = {"svc": "boot_sanity", "ts": int(time.time())}
    raw = _cmdline()
    total = len(raw)
    imprimibles = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10))
    texto = raw.decode("utf-8", "replace").strip()

    out["cmdline_bytes"] = total
    out["cmdline_imprimibles"] = imprimibles
    # basura = hay contenido pero casi nada legible (una cmdline real es ASCII limpio)
    basura = total > 0 and imprimibles < max(1, total // 2)
    vacia = total == 0
    presentes = [k for k in ESPERADAS if k in texto] if not basura else []
    out["claves_presentes"] = presentes

    # ¿sobrevive la escotilla de recuperación si la cmdline no sirve?
    escotilla = os.path.exists("/persist/anvos-recovery.flag")
    init_soporta_flag = False
    for ruta in ("/core/init_v11.3.0.sh", "/core/init_v11.2.0.sh"):
        try:
            with open(ruta) as f:
                if "anvos-recovery.flag" in f.read():
                    init_soporta_flag = True
                    break
        except OSError:
            continue
    out["recovery_por_flag_soportado"] = init_soporta_flag
    out["recovery_flag_presente"] = escotilla

    if basura:
        # el nodo arrancó con parámetros ilegibles: degradado, y sin escotilla por cmdline
        out["verdict"] = ("ARRANQUE_DEGRADADO_SIN_ESCOTILLA" if not init_soporta_flag
                          else "ARRANQUE_DEGRADADO")
        out["detalle"] = ("cmdline ilegible (%d bytes, %d imprimibles): el firmware pisó la "
                          "cmdline firmada del UKI" % (total, imprimibles))
    elif vacia:
        out["verdict"] = "SIN_CMDLINE"
    elif not presentes:
        out["verdict"] = "CMDLINE_SIN_PARAMETROS"
        out["detalle"] = "cmdline legible pero sin ninguna clave esperada: %s" % texto[:80]
    else:
        out["verdict"] = "ARRANQUE_OK"
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()
