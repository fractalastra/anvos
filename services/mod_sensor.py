#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""mod_sensor — MÓDULO OPCIONAL de dominio (IoT) de la capa ANVOS.

Porta el colector de sensores del ecosistema a la capa: recibe lecturas por HTTP POST
(JSON) en :7790, valida umbrales y registra eventos/alertas en el ledger del nodo. Es un MÓDULO
opcional — solo corre si el PERFIL FIRMADO del nodo (/persist/anvos-modules/profile.json) lo habilita
(layerd gatea por la etiqueta del manifiesto). Se añade/retira sin tocar el núcleo.

Diferencias con el master (adaptación al nodo busybox):
  - Config en JSON (no yaml): /persist/anvos-modules/mod_sensor.config.json (o defaults embebidos).
  - Ledger bajo /persist/anvos-data/modules/ (almacenamiento del propio nodo). El nodo NO firma (identidad
    solo en el master); el hash-chain / firma de evidencia la hace el ecosistema aguas arriba.
  - MQTT eliminado (dependencia opcional ausente en el nodo). Solo HTTP, stdlib puro.
Servicio LONG-RUNNING bajo layerd: servidor residente con apagado limpio en SIGTERM. Fail-safe."""
import os
import sys
import json
import time
import signal
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
MODDIR = os.environ.get("ANVOS_MODULES", "/persist/anvos-modules")
OUTDIR = os.path.join(DATA, "modules")
EVENTS = os.path.join(OUTDIR, "sensor_events.jsonl")
REC = os.path.join(OUTDIR, "sensor.jsonl")               # latido del servicio (ledger)
CONFIG = os.path.join(MODDIR, "mod_sensor.config.json")
HOST = os.environ.get("ANV_SENSOR_HOST", "0.0.0.0")
PORT = int(os.environ.get("ANV_SENSOR_PORT", "7790"))

DEFAULT_CFG = {
    "thresholds": {"temperature_max": 85.0, "humidity_max": 95.0,
                   "voltage_min": 11.0, "pressure_max": 120.0},
    "alert_on_threshold": True,
}
_CFG = DEFAULT_CFG
_STATS = {"ingested": 0, "alerts": 0, "started": 0}


def _node_id():
    for p in ("/persist/anvos-node.id", "/etc/anvos-node.id"):
        try:
            v = open(p).read().strip()
            if v:
                return v
        except Exception:
            pass
    return socket.gethostname() or "anvos-node"


NODE = _node_id()


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _load_config():
    try:
        with open(CONFIG) as f:
            c = json.load(f)
        if isinstance(c, dict):
            cfg = dict(DEFAULT_CFG)
            cfg.update(c)
            cfg["thresholds"] = {**DEFAULT_CFG["thresholds"], **(c.get("thresholds") or {})}
            return cfg
    except Exception:
        pass
    return dict(DEFAULT_CFG)


def _check_thresholds(reading, cfg):
    alerts = []
    th = cfg.get("thresholds", {})
    # metric -> (clave_max, clave_min)
    checks = {"temperature": ("temperature_max", None), "humidity": ("humidity_max", None),
              "voltage": (None, "voltage_min"), "pressure": ("pressure_max", None)}
    for metric, (key_max, key_min) in checks.items():
        if metric not in reading:
            continue
        try:
            value = float(reading[metric])
        except (TypeError, ValueError):
            continue
        if key_max and key_max in th and value > th[key_max]:
            alerts.append({"metric": metric, "value": value, "threshold": th[key_max], "type": "OVER_MAX"})
        if key_min and key_min in th and value < th[key_min]:
            alerts.append({"metric": metric, "value": value, "threshold": th[key_min], "type": "UNDER_MIN"})
    return alerts


# ITB-079 clase B: fallos CONSECUTIVOS de registro. Este modulo quedo MUDO el 19-ago
# (las dos vias callaron con 49 s de diferencia) y siguio sirviendo HTTP >24 h. Un modulo
# expuesto que no puede dejar constancia no sigue escuchando: al decimo fallo seguido el
# bucle principal termina ordenadamente; layerd lo relanza y, si el fallo persiste, vuelve
# a salir (fail-closed por ejecucion). _append_event corre en el hilo del handler, asi que
# NO mata el proceso: cuenta, y el bucle principal (tick de 1 s) decide.
_REG_FALLOS = {"n": 0}
_REG_TOPE = 10


def _append_event(event):
    try:
        os.makedirs(OUTDIR, exist_ok=True)
        with open(EVENTS, "a") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        _REG_FALLOS["n"] = 0
    except Exception as e:
        _REG_FALLOS["n"] += 1
        print("REG_FAIL mod_sensor._append_event %d/%d: %r" % (_REG_FALLOS["n"], _REG_TOPE, e), file=sys.stderr, flush=True)


def _rec(rec):
    try:
        os.makedirs(OUTDIR, exist_ok=True)
        with open(REC, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        _REG_FALLOS["n"] = 0
    except Exception as e:
        _REG_FALLOS["n"] += 1
        print("REG_FAIL mod_sensor._rec %d/%d: %r" % (_REG_FALLOS["n"], _REG_TOPE, e), file=sys.stderr, flush=True)


class SensorHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n) if n else b"{}"
            reading = json.loads(raw.decode("utf-8", "replace"))
            if not isinstance(reading, dict):
                return self._send(400, {"ok": False, "error": "cuerpo no es objeto JSON"})
        except Exception as e:
            return self._send(400, {"ok": False, "error": "json inválido: %s" % e})
        alerts = _check_thresholds(reading, _CFG) if _CFG.get("alert_on_threshold", True) else []
        event = {"ts": _now(), "node": NODE, "module": "sensor",
                 "sensor_id": reading.get("sensor_id", "?"),
                 "sensor_type": reading.get("sensor_type", "?"),
                 "reading": reading, "alerts": alerts}
        _append_event(event)
        _STATS["ingested"] += 1
        _STATS["alerts"] += len(alerts)
        if alerts:
            print(json.dumps({"svc": "mod_sensor", "event": "ALERT", "node": NODE,
                              "sensor_id": event["sensor_id"], "alerts": alerts}, ensure_ascii=False), flush=True)
        self._send(200, {"ok": True, "alerts": len(alerts)})

    def do_GET(self):
        self._send(200, {"svc": "mod_sensor", "node": NODE, "status": "ok",
                         "ingested": _STATS["ingested"], "alerts": _STATS["alerts"],
                         "thresholds": _CFG.get("thresholds", {})})


def main():
    global _CFG
    try:
        _CFG = _load_config()
        _STATS["started"] = int(time.time())
        try:
            srv = HTTPServer((HOST, PORT), SensorHandler)
        except OSError as e:
            # puerto ocupado u otro: fail-safe, no propagar (layerd hará backoff)
            print(json.dumps({"svc": "mod_sensor", "ok": False, "fatal": "bind %s:%d: %s" % (HOST, PORT, e)},
                             ensure_ascii=False), flush=True)
            return 0
        t = Thread(target=srv.serve_forever, daemon=True)
        t.start()
        print(json.dumps({"svc": "mod_sensor", "node": NODE, "status": "listening",
                          "endpoint": "%s:%d" % (HOST, PORT), "mode": "module",
                          "thresholds": _CFG.get("thresholds", {}),
                          "note": "MÓDULO opcional (perfil); colector IoT HTTP /ingest"}, ensure_ascii=False), flush=True)
        _rec({"svc": "mod_sensor", "ts": int(time.time()), "node": NODE, "status": "listening", "port": PORT})

        stop = {"v": False}

        def _sig(*_):
            stop["v"] = True
            try:
                srv.shutdown()
            except Exception:
                pass
        signal.signal(signal.SIGTERM, _sig)
        signal.signal(signal.SIGINT, _sig)
        last_hb = 0
        while not stop["v"]:
            if _REG_FALLOS["n"] >= _REG_TOPE:
                # ITB-079 clase B: mudo persistente -> dejar de servir, ordenadamente.
                print(json.dumps({"svc": "mod_sensor", "ok": False,
                                  "fatal": "registro mudo %d veces seguidas — el modulo deja de servir (ITB-079)" % _REG_FALLOS["n"]},
                                 ensure_ascii=False), flush=True)
                try:
                    srv.shutdown()
                except Exception:
                    pass
                return 70
            time.sleep(1)
            now = int(time.time())
            if now - last_hb >= 60:
                _rec({"svc": "mod_sensor", "ts": now, "node": NODE, "status": "listening",
                      "ingested": _STATS["ingested"], "alerts": _STATS["alerts"]})
                last_hb = now
        print(json.dumps({"svc": "mod_sensor", "node": NODE, "status": "stopped"}, ensure_ascii=False), flush=True)
        return 0
    except Exception as e:
        print(json.dumps({"svc": "mod_sensor", "ok": False, "fatal": str(e)}, ensure_ascii=False), flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
