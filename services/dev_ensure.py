#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""dev_ensure — garantiza los nodos ESENCIALES de /dev en el nodo ANVOS (y con ellos la ENTROPÍA).

Hallazgo 2026-07-28 (lo encontró el propio codegen soberano de origo): en origo hay un **tmpfs
montado ENCIMA del devtmpfs** de /dev. El devtmpfs real (117 nodos) queda tapado y el tmpfs
aparece casi vacío -> cualquier redirección/`chmod` crea un FICHERO REGULAR donde debería haber
un nodo char. Consecuencia grave constatada: `/dev/urandom` era un fichero de 32 bytes FIJOS
(dos lecturas idénticas = **entropía muerta**); `/dev/null` y `/dev/console` ficheros regulares;
`zero`, `random`, `tty`, `full` inexistentes. Es también la causa raíz del bug recurrente del
device node USB de la YubiKey.

Este servicio restaura y VIGILA los nodos esenciales (mismo patrón que usb-nodes.sh: validar
tipo char + major:minor, no solo existencia) y comprueba que la entropía está VIVA. En un nodo
con /dev sano (nodo-c) es no-op: 0 reparados.

El arreglo de RAÍZ es no montar el tmpfs sobre devtmpfs en el arranque (init/initrd = lado
imagen); mientras tanto esto lo mantiene sano en caliente y sobrevive reboots.

Observe-and-repair (los "ensure" reparan por diseño), acotado a 7 nodos conocidos. Solo stdlib.

También recrea los NODOS DE BLOQUE que el kernel conoce (/proc/partitions) y /dev no muestra:
sin ellos, un despliegue puede escribir sobre el disco equivocado (hallado 2026-07-29 en origo,
donde faltaba el disco del sistema entero y el único bloque visible era el USB de respaldo).

Manifest: dev_ensure.py|300|dev/dev_ensure.jsonl
"""
import os
import json
import time
import stat

# nombre: (major, minor, permisos)
ESENCIALES = {
    "null": (1, 3, 0o666),
    "zero": (1, 5, 0o666),
    "full": (1, 7, 0o666),
    "random": (1, 8, 0o666),
    "urandom": (1, 9, 0o666),
    "tty": (5, 0, 0o666),
    "console": (5, 1, 0o600),
}


def _ok(path, maj, minr):
    """True si es un char device con EXACTAMENTE ese major:minor (no basta con que exista)."""
    try:
        st = os.stat(path)
    except OSError:
        return False
    return (stat.S_ISCHR(st.st_mode) and os.major(st.st_rdev) == maj
            and os.minor(st.st_rdev) == minr)


def _entropia_viva():
    """Dos lecturas de /dev/urandom deben diferir. Fichero regular estático -> idénticas."""
    try:
        with open("/dev/urandom", "rb") as f:
            a = f.read(16)
        with open("/dev/urandom", "rb") as f:
            b = f.read(16)
        return len(a) == 16 and a != b
    except Exception:
        return False


def _dev_tapado():
    """¿Hay un tmpfs montado sobre /dev tapando el devtmpfs? (la condición de fondo)"""
    try:
        tipos = [ln.split()[2] for ln in open("/proc/mounts")
                 if len(ln.split()) > 2 and ln.split()[1] == "/dev"]
    except Exception:
        return None
    return ("tmpfs" in tipos and "devtmpfs" in tipos) or None



# --- NODOS DE BLOQUE (2026-07-29) ----------------------------------------------------------
# Segundo acto del mismo defecto: con el tmpfs tapando el devtmpfs, en origo faltaban TAMBIÉN
# los nodos del DISCO DEL SISTEMA (/dev/nvme0n1, p1=ESP, p2=/persist). El kernel los conoce
# (/proc/partitions) pero /dev no los muestra: el único bloque visible era el USB de DR. Un
# script de despliegue con el ESP cableado a /dev/sda1 habría escrito el UKI SOBRE EL DISCO DE
# RESPALDO del nodo soberano — y no por casualidad, sino porque era el único que existía.
# Aquí se recrean desde /proc/partitions (misma fuente que usa el init), root-only (600).
def _nodos_bloque():
    creados, fallos, permisos = [], [], []
    try:
        lineas = open("/proc/partitions").read().splitlines()[2:]
    except OSError:
        return creados, fallos
    for ln in lineas:
        campos = ln.split()
        if len(campos) < 4:
            continue
        try:
            maj, minr, nombre = int(campos[0]), int(campos[1]), campos[3]
        except ValueError:
            continue
        if nombre.startswith(("loop", "ram", "zram")):
            continue                                   # pseudo-dispositivos: no interesan
        p = "/dev/" + nombre
        try:
            st = os.stat(p)
            if (stat.S_ISBLK(st.st_mode) and os.major(st.st_rdev) == maj
                    and os.minor(st.st_rdev) == minr):
                # el nodo es correcto, pero los PERMISOS también importan: un dispositivo de
                # bloque en 644 permite leer el disco EN CRUDO a cualquier uid del nodo, saltándose
                # los permisos del sistema de ficheros montado encima. Hallado 2026-07-29 en origo:
                # /dev/sda* (el disco de RESPALDO, con la copia del nodo y el modelo de IA) estaba
                # world-readable desde el 24-jul. Se normaliza a root-only, sin recrear el nodo.
                if (st.st_mode & 0o777) != 0o600:
                    try:
                        os.chmod(p, 0o600)
                        permisos.append(nombre)
                    except OSError as e:
                        fallos.append("%s perms: %s" % (nombre, str(e)[:40]))
                continue
            os.unlink(p)                               # fichero regular o nodo caducado
        except FileNotFoundError:
            pass
        except OSError as e:
            fallos.append("%s: %s" % (nombre, str(e)[:50]))
            continue
        try:
            os.mknod(p, stat.S_IFBLK | 0o600, os.makedev(maj, minr))
            creados.append(nombre)
        except OSError as e:
            fallos.append("%s: %s" % (nombre, str(e)[:50]))
    return creados, fallos, permisos


def main():
    out = {"svc": "dev_ensure", "ts": int(time.time())}
    reparados = []
    fallos = []
    for nombre, (maj, minr, perm) in ESENCIALES.items():
        p = "/dev/" + nombre
        if _ok(p, maj, minr):
            try:
                os.chmod(p, perm)
            except OSError:
                pass
            continue
        try:
            if os.path.lexists(p):
                os.unlink(p)                       # fichero regular o nodo caducado
            os.mknod(p, stat.S_IFCHR | perm, os.makedev(maj, minr))
            os.chmod(p, perm)
            reparados.append(nombre)
        except Exception as e:
            fallos.append("%s: %s" % (nombre, str(e)[:60]))

    bloques, fallos_bloque, perms_bloque = _nodos_bloque()
    fallos += fallos_bloque

    viva = _entropia_viva()
    tapado = _dev_tapado()
    out["reparados"] = reparados
    out["n_reparados"] = len(reparados)
    out["bloques_recreados"] = bloques
    out["n_bloques"] = len(bloques)
    if perms_bloque:
        out["bloques_endurecidos"] = perms_bloque     # estaban legibles por no-root
    out["entropia_viva"] = viva
    if tapado:
        out["dev_tapado"] = True                   # tmpfs sobre devtmpfs: arreglo de raíz en el arranque
    if fallos:
        out["fallos"] = fallos
    out["verdict"] = ("DEV_OK" if (viva and not fallos) else
                      "ENTROPIA_MUERTA" if not viva else "DEV_PROBLEMA")
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()
