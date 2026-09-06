#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""mod_netflow — MÓDULO OPCIONAL de dominio (observabilidad de RED) de la capa ANVOS.

Observa las conexiones de red ACTIVAS del nodo (desde /proc/net/tcp[6]), rastrea los peers remotos,
detecta peers NUEVOS y marca los EXTERNOS a la malla soberana/LAN, y registra flujos/eventos en el
ledger del nodo. **OBSERVE-ONLY**: solo LEE /proc/net; NO abre/cierra/bloquea conexiones ni toca el
firewall (coherente con la doctrina del nodo: la respuesta la decide el operador).

Sólo corre si el PERFIL FIRMADO del nodo lo habilita (etiqueta 'netflow'; layerd gatea). Periódico bajo
layerd (una pasada por ciclo). Solo stdlib. Fail-safe."""
import os
import sys
import json
import time
import socket

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
OUTDIR = os.path.join(DATA, "modules", "netflow")
EVENTS = os.path.join(OUTDIR, "netflow_events.jsonl")     # peers nuevos / externos (señal)
REC = os.path.join(OUTDIR, "netflow.jsonl")               # latido/resumen del módulo
SEEN = os.path.join(OUTDIR, "seen_peers.txt")             # peers ya vistos (para detectar nuevos)

# Prefijos CONFIABLES (malla soberana / anillo / LAN de gestión / loopback): un peer fuera de aquí = EXTERNO.
# Prefijos de confianza: por configuracion (ANVOS_NETFLOW_TRUSTED, separados por comas).
# Por defecto solo local: todo lo demas se trata como externo y avisa (fail-closed).
TRUSTED_PREFIXES = tuple(p.strip() for p in os.environ.get("ANVOS_NETFLOW_TRUSTED", "127.,0.0.0.0").split(",") if p.strip())


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
        print("REG_FAIL mod_netflow._rec %d/%d: %r" % (_REG_FALLOS["n"], _REG_TOPE, e), file=sys.stderr, flush=True)
        if _REG_FALLOS["n"] >= _REG_TOPE:
            raise SystemExit(70)


def _ipv4(hexip):
    """'0100007F' -> '127.0.0.1' (little-endian)."""
    try:
        b = bytes.fromhex(hexip)
        return ".".join(str(x) for x in reversed(b))
    except Exception:
        return None


def _established_peers():
    """Conjunto de (ip, puerto) remotos de conexiones ESTABLECIDAS (st=01) en /proc/net/tcp[6]."""
    peers = set()
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f)
                for ln in f:
                    p = ln.split()
                    if len(p) < 4 or p[3] != "01":     # 01 = ESTABLISHED
                        continue
                    rem = p[2]                          # rem_address hex "IP:PORT"
                    if ":" not in rem:
                        continue
                    hip, hport = rem.rsplit(":", 1)
                    if path.endswith("tcp"):
                        ip = _ipv4(hip)
                    else:
                        ip = "ipv6"                     # IPv6: se cuenta pero no se decodifica en detalle
                    try:
                        port = int(hport, 16)
                    except Exception:
                        port = 0
                    if ip and ip != "0.0.0.0":
                        peers.add((ip, port))
        except Exception:
            pass
    return peers


def _trusted(ip):
    return any(ip.startswith(t) for t in TRUSTED_PREFIXES) or ip == "ipv6"


def _load_seen():
    try:
        return set(open(SEEN).read().split())
    except Exception:
        return set()


def _save_seen(s):
    try:
        os.makedirs(OUTDIR, exist_ok=True)
        tmp = SEEN + ".tmp"
        with open(tmp, "w") as f:
            f.write("\n".join(sorted(s)))
        os.replace(tmp, SEEN)
    except Exception:
        pass


def cmd_cycle():
    peers = _established_peers()
    seen = _load_seen()
    ips = set(ip for ip, _ in peers)
    external = sorted(ip for ip in ips if not _trusted(ip))
    new = sorted(ip for ip in ips if ip not in seen)
    for ip in new:
        ev = {"ts": _now(), "node": NODE, "module": "netflow", "event": "new_peer",
              "ip": ip, "external": not _trusted(ip)}
        _rec(EVENTS, ev)
        if not _trusted(ip):
            print(json.dumps({"svc": "mod_netflow", "event": "NEW_EXTERNAL_PEER", "node": NODE,
                              "ip": ip, "note": "peer externo NUEVO; observe-only (la respuesta la decide el operador)"},
                             ensure_ascii=False), flush=True)
    _save_seen(seen | ips)
    rec = {"svc": "mod_netflow", "ts": int(time.time()), "node": NODE, "mode": "observe-read-only",
           "established": len(peers), "unique_peers": len(ips), "external_peers": len(external),
           "new_peers": len(new), "note": "SOLO lee /proc/net; jamás toca la red ni el firewall"}
    print(json.dumps(rec, ensure_ascii=False))
    _rec(REC, rec)
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "cycle"
    try:
        if cmd in ("cycle", "run", "probe"):
            return cmd_cycle()
        print(json.dumps({"svc": "mod_netflow", "error": "modo desconocido: %s" % cmd}))
        return 2
    except Exception as e:
        print(json.dumps({"svc": "mod_netflow", "ok": False, "fatal": str(e)}, ensure_ascii=False))
        return 0


if __name__ == "__main__":
    sys.exit(main())
