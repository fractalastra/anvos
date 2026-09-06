#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""ring_transport — TRANSPORTE del anillo ANVOS (anvring0) para la replicación entre nodos.
Cierra el hueco del PASO 3 del tri-ring: hasta ahora el bundle MAIN viajaba por un transporte
externo (cat|ssh del master, USB); con ring_link (anvring0, subred del anillo) los nodos ANVOS ya
tienen enlace propio — este tool mueve el bundle POR EL ANILLO, de nodo a nodo, sin master.

Sigue el patrón envoltorio del ecosistema: el TRANSPORTE es commodity y NO otorga confianza;
la VERIFICACIÓN soberana fail-closed la hace ring_replicate (manifiesto+sha256+content_hash+
firmas 653C) antes de instalar nada. Este tool solo sirve/trae bytes y deposita en INBOX.

Modos (herramienta on-demand, como ring_promote/ring_replicate):
  serve [puerto]        sirve UNA VEZ el bundle MAIN propio (tar) en la IP del anillo;
                        SOLO acepta clientes del anillo declarado ANVOS_RING_NET (rechaza el resto y sigue esperando).
  fetch <ip> <origen>   trae el bundle desde <ip> del anillo al INBOX/<origen>, extrae de forma
                        segura (solo nombres planos) e invoca ring_replicate install <origen>
                        (fail-closed: si algo no verifica, NADA se instala).
Solo stdlib."""
import os
import re
import sys
import json
import time
import glob
import socket
import tarfile
import io
import subprocess

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
PERSIST = os.environ.get("ANVOS_PERSIST", "/persist")
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
SVCDIR = os.path.join(STAGING, "services")          # MAIN activo (lo que atesta ring_promote)
RING = os.path.join(PERSIST, "anvos-ring")
INBOX = os.path.join(RING, "inbox")
REC = os.path.join(DATA, "ring", "ring_transport.jsonl")
RING_NET = os.environ.get("ANVOS_RING_NET", "127.")  # prefijo del anillo: declarar en config (fail-closed a local)
PORT = 8473
SAFE_NAME = re.compile(r"^[A-Za-z0-9._+-]{1,128}$")   # solo nombres planos (sin rutas)


def _emit(d):
    os.makedirs(os.path.dirname(REC), exist_ok=True)
    with open(REC, "a") as f:
        f.write(json.dumps(d, ensure_ascii=False) + "\n")
    print(json.dumps(d, ensure_ascii=False))


def _ring_ip():
    """IP propia en el anillo (anvring0)."""
    r = subprocess.run(["ip", "-o", "addr", "show", "dev", "anvring0"],
                       capture_output=True, text=True)
    m = re.search(r"inet (10\.98\.\d+\.\d+)/", r.stdout or "")
    return m.group(1) if m else None


def _bundle_bytes():
    """Empaqueta el bundle MAIN en tar (en memoria): main_manifest + chain.head + ficheros+firmas."""
    names = ["main_manifest.json", "promotion.chain.head"]
    paths = [os.path.join(RING, n) for n in names]
    for f in sorted(glob.glob(os.path.join(SVCDIR, "*.py")) + [os.path.join(SVCDIR, "manifest.txt")]):
        paths.append(f)
        if os.path.isfile(f + ".minisig"):
            paths.append(f + ".minisig")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for p in paths:
            if os.path.isfile(p):
                t.add(p, arcname=os.path.basename(p))
    return buf.getvalue()


def cmd_serve(port):
    ip = _ring_ip()
    if not ip:
        _emit({"svc": "ring_transport", "action": "serve", "ok": False,
               "error": "sin IP en anvring0 (ring_link no enlazado)"})
        return 2
    data = _bundle_bytes()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))                      # SOLO la interfaz del anillo
    s.listen(1)
    s.settimeout(180)
    _emit({"svc": "ring_transport", "action": "serve", "bind": "%s:%d" % (ip, port),
           "bundle_bytes": len(data), "state": "esperando 1 peer del anillo (180s)"})
    try:
        while True:
            conn, addr = s.accept()
            if not addr[0].startswith(RING_NET):
                conn.close()                # fuera del anillo -> rechazado
                _emit({"svc": "ring_transport", "action": "serve", "rejected": addr[0]})
                continue
            with conn:
                conn.sendall(data)
            _emit({"svc": "ring_transport", "action": "serve", "ok": True,
                   "served_to": addr[0], "bytes": len(data)})
            return 0
    except socket.timeout:
        _emit({"svc": "ring_transport", "action": "serve", "ok": False, "error": "timeout sin peers"})
        return 1
    finally:
        s.close()


def cmd_fetch(ip, source):
    if not ip.startswith(RING_NET):
        _emit({"svc": "ring_transport", "action": "fetch", "ok": False,
               "error": "origen fuera del anillo declarado (%s*): %s" % (RING_NET, ip)})
        return 2
    try:
        with socket.create_connection((ip, PORT), timeout=30) as c:
            c.settimeout(60)
            chunks = []
            while True:
                b = c.recv(65536)
                if not b:
                    break
                chunks.append(b)
        raw = b"".join(chunks)
    except Exception as e:
        _emit({"svc": "ring_transport", "action": "fetch", "ok": False,
               "error": "transporte: %s" % str(e)[:80]})
        return 1
    # extracción SEGURA al inbox: solo miembros regulares con nombre plano permitido
    box = os.path.join(INBOX, source)
    os.makedirs(box, exist_ok=True)
    kept, skipped = 0, 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw)) as t:
            for m in t.getmembers():
                if m.isreg() and SAFE_NAME.match(m.name):
                    t.extract(m, path=box, filter="data")
                    kept += 1
                else:
                    skipped += 1
    except Exception as e:
        _emit({"svc": "ring_transport", "action": "fetch", "ok": False,
               "error": "tar ilegible: %s" % str(e)[:80], "bytes": len(raw)})
        return 1
    _emit({"svc": "ring_transport", "action": "fetch", "ok": True, "from": ip,
           "inbox": box, "bytes": len(raw), "files": kept, "skipped": skipped,
           "note": "transporte hecho; la confianza la decide ring_replicate"})
    # verificación + instalación SOBERANA (fail-closed) por ring_replicate, EN-PROCESO
    # (en busybox sys.executable no es ejecutable directo: el ELF python necesita su ld-linux)
    sys.path.insert(0, SVCDIR)
    import ring_replicate
    return ring_replicate.cmd_install(source)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd == "serve":
        port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
        return cmd_serve(port)
    if cmd == "fetch" and len(sys.argv) > 3:
        return cmd_fetch(sys.argv[2], sys.argv[3])
    print(json.dumps({"svc": "ring_transport",
                      "error": "uso: serve [puerto] | fetch <ip-anillo> <origen>"}))
    return 2


if __name__ == "__main__":
    sys.exit(main())
