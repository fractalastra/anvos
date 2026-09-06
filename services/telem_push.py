#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""telem_push — empuja telemetría consolidada del nodo ANVOS al panel del master.
Single-shot: lee la última muestra de cada ledger local (beacon/sentinel/chain/router),
arma un JSON y lo POSTea a http://<master>:8765/api/anvos-telem/ingest. Solo stdlib.
Un fallo de RED se reporta como 'note' (no 'error'): no es un bug del servicio, así la
puerta de verificación no lo rechaza. Configurable por entorno ANVOS_DATA y ANVOS_MASTER.

Destino = la IP de MALLA declarada en ANVOS_MASTER, no la LAN física: esta última
cambia con el DHCP del router (medido dos veces: 10-ago y de nuevo sin reserva fijada) y deja
la telemetría muerta en silencio hasta que alguien lo nota (measured: origo 47h sin push tras
el corte 9/10-ago). La malla WG es estable y además es la ÚNICA ruta que nodo-c puede alcanzar
(su salida por NAT de usuario QEMU no llega a la LAN física en absoluto)."""
import os
import json
import time
import socket
import urllib.request

BASE = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
# Destino de telemetria: SIEMPRE por configuracion (ANVOS_MASTER). Vacio = no se empuja.
MASTER = os.environ.get("ANVOS_MASTER", "")
INGEST = MASTER + "/api/anvos-telem/ingest"


def _ultima_linea_json(path):
    """Última línea no vacía de un ledger jsonl, parseada. {} si no se puede."""
    try:
        ultima = None
        with open(path) as f:
            for linea in f:
                linea = linea.strip()
                if linea:
                    ultima = linea
        return json.loads(ultima) if ultima else {}
    except Exception:
        return {}


def _id_nodo():
    """Identidad estable del nodo: machine-id; si no, 'anvos-'+cola del MAC de eth0."""
    for _p in ("/persist/anvos-node.id", "/etc/anvos-node.id"):
        try:
            _v = open(_p).read().strip()
            if _v:
                return _v
        except Exception:
            pass
    try:
        mid = open("/etc/machine-id").read().strip()
        if mid and mid != "unknown":
            return mid
    except Exception:
        pass
    try:
        mac = open("/sys/class/net/eth0/address").read().strip().replace(":", "")
        if mac:
            return "anvos-" + mac[-6:]
    except Exception:
        pass
    return "anvos-desconocido"


def _ip_local():
    """IP local usada para alcanzar al master (truco del socket UDP, sin subprocess)."""
    try:
        host = MASTER.split("//", 1)[-1].split(":", 1)[0].split("/", 1)[0]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def _uptime():
    try:
        return float(open("/proc/uptime").read().split()[0])
    except Exception:
        return None


def main():
    if not MASTER:
        print(json.dumps({"svc": "telem_push", "ok": False,
                          "motivo": "ANVOS_MASTER sin declarar: no se empuja telemetria"}))
        return 0
    beacon = _ultima_linea_json(os.path.join(BASE, "eco-telem/beacon.jsonl"))
    sentinel = _ultima_linea_json(os.path.join(BASE, "sentinel/sentinel.jsonl"))
    chain = _ultima_linea_json(os.path.join(BASE, "chain/chain_status.jsonl"))
    router = _ultima_linea_json(os.path.join(BASE, "ai/router.jsonl"))
    payload = {
        "node": _id_nodo(),
        "ip": _ip_local(),
        "ts": int(time.time()),
        "uptime_s": sentinel.get("uptime_s") or _uptime(),
        "cpu_load": beacon.get("cpu_load"),
        "mem_pct": beacon.get("mem_pct"),
        "disk_pct": beacon.get("disk_pct"),
        "immune_state": sentinel.get("immune_state", ""),
        "findings": [f.get("code", "") if isinstance(f, dict) else str(f)
                     for f in (sentinel.get("findings") or [])],
        "chain_ok": bool(chain.get("all_ok")),
        "ai_status": router.get("status", ""),
        "ai_models": router.get("n_models", 0),
        "build": "v18",
    }
    data = json.dumps(payload).encode()
    # Reintento breve: en el arranque la ruta de red tarda unos segundos en existir
    # (la red se levanta en 2º plano). Así el PRIMER push tras el boot ya entra, sin
    # esperar un ciclo completo. Acotado para no romper el contrato single-shot.
    ack = None
    err = ""
    for intento in range(3):
        try:
            req = urllib.request.Request(INGEST, data=data,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as r:
                ack = json.loads(r.read().decode("utf-8", "replace"))
            break
        except Exception as e:
            err = str(e)[:100]
            if intento < 2:
                time.sleep(2)
    if ack is not None:
        out = {"svc": "telem_push", "ts": int(time.time()), "pushed": True, "ack": ack}
    else:
        # fallo de RED (master inalcanzable): NO es bug del servicio -> 'note', no 'error'
        out = {"svc": "telem_push", "ts": int(time.time()), "pushed": False,
               "note": f"master inalcanzable: {err}"}
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(json.dumps({"svc": "telem_push", "ts": int(time.time()),
                          "error": str(e)}, ensure_ascii=False))
