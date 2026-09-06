#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""ssh_guard — guarda del plano de administración (dropbear :22) bajo layerd.

BUCLE que cierra: el activador lanza dropbear UNA vez al boot (setsid, PPID=1); si el
listener muere o se atasca (visto en la prueba de reboot real de origo: proceso vivo
pero accept colgado -> "ssh caído"), nadie lo re-lanza y el nodo queda sin
administración remota hasta un power-cycle.

Diseño (lecciones del ecosistema):
  - La sonda es el SERVICIO REAL, no el proceso: conexión TCP a 127.0.0.1:22 + lectura
    del banner "SSH-" (un pgrep no distingue vivo de atascado; TCP sin ICMP).
  - Si la sonda falla: se localiza SOLO el/los pid con el socket LISTEN :22
    (/proc/net/tcp -> inode -> /proc/*/fd) y se mata ESO; las sesiones establecidas
    (hijos de dropbear) nunca se tocan.
  - Re-lanzado con doble-fork+setsid (huérfano de PPID=1, igual que el activador);
    el binario /opt/dropbear viene del initramfs del UKI FIRMADO (integridad anclada
    en el arranque verificado, no re-verificamos un fichero de un rootfs en RAM).
  - Fail-safe, idempotente, convergente bajo MAX_RUNTIME=30s de layerd; print-only
    (bajo layerd el stdout ES el ledger del servicio).
Solo stdlib."""
import os
import json
import time
import socket
import signal

DB = "/opt/dropbear"
LD = os.path.join(DB, "ld-linux-x86-64.so.2")
BIN = os.path.join(DB, "dropbear")
HOSTKEY = os.path.join(DB, "hostkey")
# -E hace que dropbear escriba sus mensajes en la SALIDA DE ERROR. Sin él los manda a syslog, y en
# este nodo no hay syslog: se pierden. Faltaba (ITV-059, 2026-08-05).
#
# EL FALLO ERA UNA SIMETRÍA, y por eso ninguno de los dos lados parecía roto
# ---------------------------------------------------------------------------
# Hay DOS sitios que lanzan este mismo demonio, y cada uno tenía la mitad que al otro le faltaba:
#
#   init (arranque)   -> SÍ pasaba -E, pero redirigía la salida de error a /dev/console, que no
#                        persiste: los fallos de autenticación se veían y se perdían.
#   ssh_guard (aquí)  -> SÍ redirigía a /persist/db.err (spawn() hace dup2(fd, 2), correcto), pero
#                        NO pasaba -E, así que por esa salida no iba nada.
#
# Resultado: la capa de seguridad Fibonacci del nodo, que cuenta los fallos leyendo /persist/db.err,
# llevaba inerte desde el principio —no desde una fecha concreta— con su contador de direcciones
# vigiladas en cero, mientras se declaraba "watching". Medido: tres fallos de autenticación reales
# contra el nodo de laboratorio dejaron el fichero en cero bytes; y el mismo servicio, alimentado
# con contenido real, cuenta correctamente y excluye malla y bucle local.
#
# Cada mitad, por separado, se lee como código correcto. Es la clase de defecto que no aparece
# revisando ninguno de los dos ficheros: solo aparece preguntando por el dato que debería fluir
# entre ellos y comprobando que no llega.
ARGS = ["-F", "-r", HOSTKEY, "-p", "22", "-s", "-g", "-j", "-k", "-E"]
ERRLOG = "/persist/db.err"
PORT = 22


def probe(timeout=5.0):
    """True si hay un SSH REAL respondiendo: conecta y lee el banner 'SSH-'."""
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(64).split(b"\r\n")[0].split(b"\n")[0]
        return banner.startswith(b"SSH-"), banner.decode("ascii", "replace").strip()
    except Exception as e:
        return False, "sin_respuesta: %s" % e


def _listen_inodes():
    """Inodes de sockets en LISTEN sobre :22 (tcp y tcp6)."""
    inodes = set()
    want = "%04X" % PORT
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f)
                for ln in f:
                    p = ln.split()
                    if len(p) > 9 and p[3] == "0A" and p[1].rsplit(":", 1)[-1] == want:
                        inodes.add(p[9])
        except Exception:
            pass
    return inodes


def listener_pids():
    """Pids que poseen el socket LISTEN :22 (solo el listener, nunca las sesiones)."""
    inodes = _listen_inodes()
    pids = []
    if not inodes:
        return pids
    targets = {"socket:[%s]" % i for i in inodes}
    for pid in os.listdir("/proc"):
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        fddir = "/proc/%s/fd" % pid
        try:
            for fd in os.listdir(fddir):
                try:
                    if os.readlink(os.path.join(fddir, fd)) in targets:
                        pids.append(int(pid))
                        break
                except Exception:
                    pass
        except Exception:
            pass
    return pids


def kill_stuck(pids):
    """SIGTERM al listener atascado; SIGKILL si sigue a los 2s."""
    for p in pids:
        try:
            os.kill(p, signal.SIGTERM)
        except Exception:
            pass
    time.sleep(2)
    for p in pids:
        try:
            os.kill(p, 0)
            os.kill(p, signal.SIGKILL)
        except Exception:
            pass


def spawn():
    """Re-lanza el listener huérfano (doble-fork+setsid), stderr al log del activador."""
    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            if os.fork() > 0:
                os._exit(0)
            fd = os.open(ERRLOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            os.dup2(os.open("/dev/null", os.O_RDONLY), 0)
            os.dup2(fd, 1)
            os.dup2(fd, 2)
            os.execv(LD, [LD, "--library-path", DB, BIN] + ARGS)
        except Exception:
            os._exit(1)
    os.waitpid(pid, 0)


def main():
    rec = {"svc": "ssh_guard", "ts": int(time.time()), "port": PORT}
    if not (os.path.exists(LD) and os.path.exists(BIN) and os.path.exists(HOSTKEY)):
        rec["state"] = "NO_BINARY"
        rec["note"] = "falta dropbear/ld/hostkey en /opt/dropbear (bundle del UKI)"
        print(json.dumps(rec, ensure_ascii=False))
        return
    ok, banner = probe()
    if ok:
        rec["state"] = "SSH_OK"
        rec["banner"] = banner
        rec["listener_pids"] = listener_pids()
        print(json.dumps(rec, ensure_ascii=False))
        return
    # caído o atascado: cirugía mínima + re-lanzado
    stuck = listener_pids()
    rec["probe_fail"] = banner
    rec["stuck_listener_pids"] = stuck
    if stuck:
        kill_stuck(stuck)
        rec["action"] = "kill_stuck+respawn"
    else:
        rec["action"] = "respawn"
    spawn()
    time.sleep(2)
    ok2, banner2 = probe()
    rec["state"] = "SSH_RECOVERED" if ok2 else "SSH_FAIL"
    rec["banner"] = banner2
    print(json.dumps(rec, ensure_ascii=False))


if __name__ == "__main__":
    main()
