#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""mod_modbus — MÓDULO OPCIONAL de dominio (OT/industrial) de la capa ANVOS: POLLER Modbus TCP.

Lee registros de PLCs/RTUs por Modbus TCP, valida umbrales y registra eventos/alertas en el ledger del
nodo. **OBSERVE-ONLY POR DISEÑO**: implementa SOLO funciones de LECTURA (0x03 holding, 0x04 input); NO
tiene código de escritura (0x06/0x10) — físicamente NO puede actuar sobre el proceso. Es la doctrina de
seguridad OT ("nunca actuar sobre el proceso vivo sin firma humana") impuesta a nivel de PROTOCOLO.

Sólo corre si el PERFIL FIRMADO del nodo lo habilita (etiqueta 'modbus'; layerd gatea). Periódico bajo
layerd (una pasada de sondeo por ciclo). Solo stdlib (socket+struct). Fail-safe: PLC caído -> log y sigue.

Config: /persist/anvos-modules/mod_modbus.config.json
  {"targets":[{"host":"192.0.2.5","port":502,"unit":1,
               "registers":[{"name":"temp_reactor","addr":0,"type":"holding","scale":0.1,"max":85},
                            {"name":"nivel","addr":10,"type":"input","min":20}]}]}"""
import os
import sys
import json
import time
import socket
import struct

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
MODDIR = os.environ.get("ANVOS_MODULES", "/persist/anvos-modules")
OUTDIR = os.path.join(DATA, "modules")
EVENTS = os.path.join(OUTDIR, "modbus_events.jsonl")
REC = os.path.join(OUTDIR, "modbus.jsonl")
CONFIG = os.path.join(MODDIR, "mod_modbus.config.json")
CONNECT_TIMEOUT = 3.0
_txn = [0]

# Funciones Modbus permitidas: SOLO lectura. (Escritura deliberadamente NO implementada = observe-only.)
FC_READ_HOLDING = 0x03
FC_READ_INPUT = 0x04


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



# ITB-079 clase B: fallos CONSECUTIVOS de registro. Un modulo expuesto que no puede
# dejar constancia de lo que hace no sigue sirviendo (el 19-ago mod_sensor quedo mudo
# y siguio escuchando >24 h). Al decimo fallo seguido el modulo termina; layerd lo
# relanza y, si el fallo persiste, vuelve a salir: fail-closed por ejecucion.
_REG_FALLOS = {"n": 0}
_REG_TOPE = 10

def _rec(path, rec):
    try:
        os.makedirs(OUTDIR, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        _REG_FALLOS["n"] = 0
    except Exception as e:
        _REG_FALLOS["n"] += 1
        print("REG_FAIL mod_modbus._rec %d/%d: %r" % (_REG_FALLOS["n"], _REG_TOPE, e), file=sys.stderr, flush=True)
        if _REG_FALLOS["n"] >= _REG_TOPE:
            raise SystemExit(70)


def _load_config():
    try:
        c = json.load(open(CONFIG))
        if isinstance(c, dict) and isinstance(c.get("targets"), list):
            return c
    except Exception:
        pass
    return {"targets": []}


def _read_registers(host, port, unit, fc, addr, count):
    """Lee 'count' registros de 16 bits (SOLO 0x03/0x04). Devuelve lista de enteros o None si falla."""
    if fc not in (FC_READ_HOLDING, FC_READ_INPUT):
        return None                       # guarda: jamás otra función que no sea lectura
    _txn[0] = (_txn[0] + 1) & 0xFFFF
    pdu = struct.pack(">BHH", fc, addr, count)                    # función + dir + nº registros
    mbap = struct.pack(">HHHB", _txn[0], 0, len(pdu) + 1, unit)   # transacción, proto=0, long, unit
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as s:
            s.settimeout(CONNECT_TIMEOUT)
            s.sendall(mbap + pdu)
            head = s.recv(9)              # MBAP(7) + fc(1) + byte_count(1)
            if len(head) < 9:
                return None
            rfc = head[7]
            if rfc & 0x80:                # excepción Modbus
                return None
            bc = head[8]
            data = b""
            while len(data) < bc:
                chunk = s.recv(bc - len(data))
                if not chunk:
                    break
                data += chunk
            return [struct.unpack(">H", data[i:i + 2])[0] for i in range(0, len(data) - 1, 2)]
    except Exception:
        return None


def _check(reg, value):
    alerts = []
    if reg.get("max") is not None and value > reg["max"]:
        alerts.append({"metric": reg.get("name"), "value": value, "threshold": reg["max"], "type": "OVER_MAX"})
    if reg.get("min") is not None and value < reg["min"]:
        alerts.append({"metric": reg.get("name"), "value": value, "threshold": reg["min"], "type": "UNDER_MIN"})
    return alerts


def cmd_cycle():
    cfg = _load_config()
    polled = 0
    alerts_total = 0
    unreachable = 0
    for tgt in cfg.get("targets", []):
        host = tgt.get("host")
        port = int(tgt.get("port", 502))
        unit = int(tgt.get("unit", 1))
        for reg in tgt.get("registers", []):
            fc = FC_READ_INPUT if reg.get("type") == "input" else FC_READ_HOLDING
            regs = _read_registers(host, port, unit, fc, int(reg.get("addr", 0)), 1)
            if regs is None:
                unreachable += 1
                continue
            raw = regs[0]
            value = raw * float(reg.get("scale", 1)) if reg.get("scale") else raw
            polled += 1
            alerts = _check(reg, value)
            if alerts:
                alerts_total += len(alerts)
                ev = {"ts": _now(), "node": NODE, "module": "modbus", "target": "%s:%d/%d" % (host, port, unit),
                      "register": reg.get("name"), "addr": reg.get("addr"), "value": value, "alerts": alerts}
                _rec(EVENTS, ev)
                print(json.dumps({"svc": "mod_modbus", "event": "ALERT", "node": NODE,
                                  "register": reg.get("name"), "value": value, "alerts": alerts}, ensure_ascii=False), flush=True)
    rec = {"svc": "mod_modbus", "ts": int(time.time()), "node": NODE, "mode": "observe-read-only",
           "targets": len(cfg.get("targets", [])), "polled": polled, "alerts": alerts_total,
           "unreachable": unreachable, "note": "SOLO lectura Modbus (0x03/0x04); jamás escribe al proceso"}
    print(json.dumps(rec, ensure_ascii=False))
    _rec(REC, rec)
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "cycle"
    try:
        if cmd in ("cycle", "run", "probe"):
            return cmd_cycle()
        print(json.dumps({"svc": "mod_modbus", "error": "modo desconocido: %s" % cmd}))
        return 2
    except Exception as e:
        print(json.dumps({"svc": "mod_modbus", "ok": False, "fatal": str(e)}, ensure_ascii=False))
        return 0


if __name__ == "__main__":
    sys.exit(main())
