#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""deception_sensor — HONEYPOT PASIVO del nodo ANVOS (matriz item 13: deception).

El motor de deception del ecosistema tuvo incidentes por su respuesta ACTIVA (blacklisteó el propio
anillo). Aquí, deliberadamente, la versión de la OS es PURAMENTE PASIVA: abre puertos-cebo (servicios
falsos que nadie legítimo usa), y CUALQUIER conexión a ellos es una señal de sondeo/intrusión que se
REGISTRA. NUNCA actúa: no bloquea, no hace DROP, no toca firewall — coherente con OBSERVE_ONLY y con
el axioma (DROP/blacklist son prohibido-autónomo; la respuesta la decide el operador).

Los hits alimentan la cadena de seguridad: quedan en deception/hits.jsonl (los puede leer sentinel/
core_audit como hallazgo de categoría 'red'). Servicio RESIDENTE (LONG_RUNNING). Solo stdlib."""
import os
import json
import time
import socket
import select

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
HITS = os.path.join(DATA, "deception", "hits.jsonl")
BAIT_PORTS = [int(p) for p in os.environ.get("ANVOS_BAIT_PORTS", "2323,8081,5555,9200").split(",")]
FAKE_BANNER = {2323: b"login: ", 8081: b"HTTP/1.0 401 Unauthorized\r\n\r\n",
               5555: b"", 9200: b'{"error":"unauthorized"}'}
HEARTBEAT_S = 120


def _emit(rec):
    print(json.dumps(rec, ensure_ascii=False), flush=True)


def _log_hit(rec):
    os.makedirs(os.path.dirname(HITS), exist_ok=True)
    with open(HITS, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _node_id():
    try:
        return open("/persist/anvos-node.id").read().strip()
    except Exception:
        return "unknown"


def main():
    listeners = {}
    for port in BAIT_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(8)
            s.setblocking(False)
            listeners[s] = port
        except Exception:
            pass   # puerto no disponible -> se omite (defensivo)

    node = _node_id()
    _emit({"svc": "deception_sensor", "ts": int(time.time()), "state": "listening",
           "bait_ports": list(listeners.values()), "observe_only": True,
           "note": "honeypot PASIVO: registra sondeos, NUNCA bloquea (respuesta = operador)"})

    if not listeners:
        return   # nada que escuchar

    hits_total = 0
    last_hb = time.time()
    while True:
        try:
            ready, _, _ = select.select(list(listeners.keys()), [], [], HEARTBEAT_S)
        except Exception:
            time.sleep(1)
            continue
        now = time.time()
        for s in ready:
            port = listeners[s]
            try:
                conn, addr = s.accept()
            except Exception:
                continue
            src_ip, src_port = (addr[0], addr[1]) if addr else ("?", 0)
            peek = ""
            try:
                conn.settimeout(0.8)
                # dar un banner falso (mantiene ocupado al escáner) y leer lo que envíe
                conn.sendall(FAKE_BANNER.get(port, b""))
                data = conn.recv(96)
                peek = data.decode("latin-1", "replace")[:80] if data else ""
            except Exception:
                pass
            finally:
                try:
                    conn.close()   # cerrar SIEMPRE — nunca se mantiene ni se actúa
                except Exception:
                    pass
            hits_total += 1
            hit = {"svc": "deception_sensor", "ts": int(now), "event": "HONEYPOT_HIT",
                   "node": node, "bait_port": port, "src_ip": src_ip, "src_port": src_port,
                   "peek": peek, "action": "SOLO_REGISTRADO"}
            _log_hit(hit)
            _emit(hit)
        # latido periódico
        if now - last_hb >= HEARTBEAT_S:
            last_hb = now
            _emit({"svc": "deception_sensor", "ts": int(now), "state": "listening",
                   "bait_ports": list(listeners.values()), "hits_total": hits_total})


if __name__ == "__main__":
    main()
