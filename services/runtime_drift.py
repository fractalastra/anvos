#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""runtime_drift — comprueba que lo que se EJECUTA es lo que esta DESPLEGADO.

El ecosistema sella los ficheros en reposo (self_integrity), simula los candidatos antes de
promover (asct_sim) y vigila los cuelgues (liveness_watchdog). Ninguna de esas tres mira el eje
que falta: un servicio residente que sigue ejecutando codigo ANTERIOR mientras el fichero en
disco ya es el nuevo y su firma es correcta.

Caso que lo origina (nodo-d, 01-ago-2026): el servidor de estado llevaba 49.638 segundos con un
proceso reteniendo el puerto. Cada reinicio de la capa lanzaba una instancia que salia de
inmediato con "already-serving", de modo que el nodo respondia con codigo viejo mientras TODAS
las senales de despliegue decian que estaba al dia: fichero correcto, sha igual al del master,
firma valida, mismo entorno. Se tardo veinte minutos en verlo y solo aparecio al localizar el
proceso por el inodo de su socket.

Comprobar que el fichero desplegado es el correcto NO comprueba que sea el que se esta
ejecutando. Esa es la distincion que este servicio mide.

QUE MIDE

  1. DESFASE     el proceso arranco ANTES de la ultima modificacion del fichero que ejecuta
                 -> esta sirviendo una version anterior.
  2. RESPAWN     el pid de un servicio cambia entre dos muestras separadas -> algo lo mata o
                 sale solo; el sintoma clasico de un puerto retenido por otra instancia.
  3. HUERFANO    un puerto de la capa lo retiene un proceso que NO ejecuta el fichero desplegado
                 para ese puerto.

Observe-only: no mata procesos ni reinicia nada. Emite el desfase para que se decida. Un servicio
que reinicia procesos por su cuenta puede tumbar un nodo entero por una medida equivocada, y hoy
mismo se ha visto que las medidas equivocadas ocurren.

Fail-safe: cualquier fallo se registra y termina en 0. Solo stdlib.

Manifest: runtime_drift.py|900|runtime/runtime_drift.jsonl
Uso: runtime_drift.py [cycle]
"""
import os
import sys
import json
import time

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
SERVICES = os.path.join(STAGING, "services")
OUT = os.path.join(DATA, "runtime", "runtime_drift.jsonl")
MUESTRA_S = 6          # separacion entre las dos muestras para detectar respawn


def _emit(d):
    print(json.dumps(d, ensure_ascii=False), flush=True)
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "a") as f:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL runtime_drift._emit: %r" % (e,), file=sys.stderr, flush=True)


def _procesos():
    """{pid: (arranque_epoch, cmdline)} de todo lo vivo. Sin ps: busybox no da los argumentos."""
    out = {}
    try:
        for n in os.listdir("/proc"):
            if not n.isdigit():
                continue
            d = "/proc/" + n
            try:
                cmd = open(d + "/cmdline", "rb").read().replace(b"\0", b" ").decode("utf-8", "replace")
                out[int(n)] = (os.stat(d).st_mtime, cmd)
            except Exception:
                continue
    except Exception:
        pass
    return out


def _servicio_de(cmd):
    """Que ejecuta un proceso, si es algo de la capa. Devuelve (nombre, ruta).

    No basta con buscar .py: la capa tambien lanza binarios nativos a traves de su cargador.
    Falso positivo medido el 01-ago-2026 en nodo-d: el servidor del modelo local (llama-server,
    binario nativo bajo el staging, atado a loopback) quedaba marcado como puerto huerfano.

    Un detector que llama huerfano a lo que funciona se desactiva solo: nadie atiende avisos que
    suelen ser falsos, y entonces tampoco se atiende el que si importa.

    Regla: el primer argumento bajo el staging que no sea el cargador ni una lista de bibliotecas.
    """
    tramos = cmd.split()
    saltar_siguiente = False
    for t in tramos:
        if saltar_siguiente:
            saltar_siguiente = False
            continue
        if t == "--library-path":
            saltar_siguiente = True
            continue
        if not t.startswith(STAGING):
            continue
        base = os.path.basename(t)
        if base.startswith("ld-linux") or base.startswith("ld-musl") or "/lib" in t.rsplit("/", 1)[0][-4:]:
            continue
        return base, t
    return None, None


def _residentes(procs):
    """{servicio: [(pid, arranque, ruta)]} de los servicios de la capa que estan vivos."""
    r = {}
    for pid, (arr, cmd) in procs.items():
        nombre, ruta = _servicio_de(cmd)
        if nombre:
            r.setdefault(nombre, []).append((pid, arr, ruta))
    return r


def _puertos_escuchando():
    """{puerto: inodo} de los sockets TCP en escucha, leidos de /proc.

    Se lee /proc/net/tcp directamente: netstat -p no resuelve el proceso en busybox, y ahi
    estuvo el atasco del caso que origina este servicio.
    """
    out = {}
    try:
        with open("/proc/net/tcp") as f:
            next(f, None)
            for ln in f:
                c = ln.split()
                if len(c) < 10 or c[3] != "0A":       # 0A = LISTEN
                    continue
                try:
                    dir_hex, pto_hex = c[1].split(":")
                    # 0100007F = 127.0.0.1 en little-endian: un servicio en loopback no lo
                    # alcanza nadie desde fuera y no merece el mismo aviso que uno expuesto.
                    out[(int(pto_hex, 16), dir_hex.upper() == "0100007F")] = c[9]
                except Exception:
                    continue
    except Exception:
        pass
    return out


def _duenio_de_inodo(inodo):
    """pid que tiene abierto ese socket. Es la unica via fiable aqui para atribuir un puerto."""
    try:
        for n in os.listdir("/proc"):
            if not n.isdigit():
                continue
            fd = "/proc/%s/fd" % n
            try:
                for f in os.listdir(fd):
                    try:
                        if os.readlink(os.path.join(fd, f)) == "socket:[%s]" % inodo:
                            return int(n)
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception:
        pass
    return None


def cmd_cycle():
    ahora = time.time()
    hallazgos = []

    procs1 = _procesos()
    res1 = _residentes(procs1)

    # 1 · DESFASE: proceso anterior al fichero que ejecuta
    for nombre, lista in sorted(res1.items()):
        ruta_serv = os.path.join(SERVICES, nombre)
        if not os.path.isfile(ruta_serv):
            continue          # servicio fuera de services/: su fichero se compara donde vive
        try:
            mtime = os.path.getmtime(ruta_serv)
        except Exception:
            continue
        for pid, arranque, ruta in lista:
            # Margen de 60 s: el propio despliegue toca el fichero y relanza casi a la vez, y no
            # tendria sentido gritar por esa ventana.
            if arranque + 60 < mtime:
                hallazgos.append({
                    "tipo": "DESFASE", "servicio": nombre, "pid": pid,
                    "proceso_arrancado_hace_s": int(ahora - arranque),
                    "fichero_modificado_hace_s": int(ahora - mtime),
                    "detalle": ("el proceso arranco %d s antes de la ultima modificacion del fichero: "
                                "sirve una version anterior aunque el fichero en disco sea el nuevo"
                                % int(mtime - arranque))})

    # 2 · RESPAWN: el pid cambia entre dos muestras
    time.sleep(MUESTRA_S)
    res2 = _residentes(_procesos())
    for nombre, lista in sorted(res1.items()):
        pids1 = {p for p, _, _ in lista}
        pids2 = {p for p, _, _ in res2.get(nombre, [])}
        if pids1 and pids2 and not (pids1 & pids2):
            hallazgos.append({
                "tipo": "RESPAWN", "servicio": nombre,
                "pids_antes": sorted(pids1), "pids_despues": sorted(pids2),
                "detalle": ("ningun pid sobrevive %d s: el servicio se relanza en bucle. El caso "
                            "conocido es un puerto retenido por otra instancia, que hace salir a "
                            "las nuevas de inmediato" % MUESTRA_S)})

    # 3 · HUERFANO: quien retiene cada puerto de la capa
    puertos = {}
    for (puerto, local), inodo in sorted(_puertos_escuchando().items()):
        if puerto < 1024:
            continue
        duenio = _duenio_de_inodo(inodo)
        if duenio is None:
            continue
        arr, cmd = _procesos().get(duenio, (None, ""))
        nombre, _ = _servicio_de(cmd)
        puertos[puerto] = {"pid": duenio, "servicio": nombre, "solo_loopback": local,
                           "vive_hace_s": int(ahora - arr) if arr else None}
        if nombre is None and not local and arr and (ahora - arr) > 3600:
            hallazgos.append({
                "tipo": "HUERFANO", "puerto": puerto, "pid": duenio,
                "vive_hace_s": int(ahora - arr),
                "detalle": ("puerto EXPUESTO retenido por un proceso ajeno a la capa "
                            "(los de loopback no se senalan: no alcanzan a nadie de fuera)")})

    rec = {"svc": "runtime_drift", "ts": int(ahora),
           "residentes": {k: len(v) for k, v in sorted(res1.items())},
           "puertos": puertos,
           "hallazgos": hallazgos,
           "veredicto": "DESFASE" if hallazgos else "AL_DIA",
           "nota": ("comprueba que lo EJECUTADO coincide con lo DESPLEGADO; el sello de ficheros "
                    "no cubre este eje")}
    _emit(rec)
    return 0


def main():
    try:
        return cmd_cycle()
    except Exception as e:
        _emit({"svc": "runtime_drift", "ts": int(time.time()), "error": str(e)[:200]})
        return 0


if __name__ == "__main__":
    sys.exit(main())
