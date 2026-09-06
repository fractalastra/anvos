#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""fib_guard — Capa Fibonacci Security del NODO, en modo OBSERVE+RECOMIENDA (axioma-conforme).

Porta la lógica anti-predicción del master (anv-security-fib.sh) a la capa ANVOS, PERO
respetando la doctrina OBSERVE-ONLY del nodo (axioma ASTRANOVA_VERSION_1_0 + deception_sensor:
"DROP/blacklist son prohibido-autónomo; la respuesta la decide el operador"):
  - CUENTA los fallos de autenticación SSH por IP (dropbear -> /persist/db.err).
  - Escala una duración de bloqueo RECOMENDADA en Fibonacci (0,0,0,30,60,60,120,180,300,…).
  - Registra estado + emite la RECOMENDACIÓN (señal de gobernanza / alerta a umbral 15).
  - NUNCA toca el firewall (ni iptables ni nft): la acción la decide el operador.
    == "IA propone, humano firma". El enforcement, si algún día se autoriza, iría gated aparte.

No cuenta a la malla soberana (10.99/10.98) ni loopback: lección de la brecha de whitelist de deception.
Solo stdlib. Fail-safe: nunca lanza excepción al supervisor (layerd). Print = ledger del servicio."""
import os
import re
import sys
import json
import time
import socket

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
SEC_DIR = os.path.join(DATA, "security")
STATE_FILE = os.path.join(SEC_DIR, "fib_state.json")
REC = os.path.join(SEC_DIR, "fib_guard.jsonl")          # latido/recomendaciones (ledger del svc)
ALERTS = os.path.join(SEC_DIR, "fib_alerts.jsonl")      # alertas a umbral (revisión operador)
DBERR = os.environ.get("ANVOS_DBERR", "/persist/db.err")  # stderr de dropbear (fallos SSH)

# Secuencia Fibonacci de bloqueo RECOMENDADO (índice = intento-1, valor = segundos). Idéntica en todo el ecosistema.
FIB_DELAYS = [0, 0, 0, 30, 60, 60, 120, 180, 300, 480, 780, 1260, 2040, 3300, 8640]
ALERT_THRESHOLD = 15   # desde aquí: alerta + bloqueo máximo recomendado + revisión manual

# No recomendar bloqueo sobre la malla soberana / anillo / loopback (amigos): prefijos por texto.
# Prefijos permitidos: por configuracion (ANVOS_FIB_WHITELIST, separados por comas).
WHITELIST_PREFIXES = tuple(p.strip() for p in os.environ.get("ANVOS_FIB_WHITELIST", "127.,::1").split(",") if p.strip())

# Líneas de dropbear que indican FALLO de autenticación (no conexiones legítimas).
_FAIL_MARKERS = ("bad password", "login attempt for nonexistent",
                 "exit before auth", "bad packet", "authentication failure",
                 "user 'root' has invalid", "no matching")
# ITV-059 (2026-08-06): dropbear escribe el origen ENTRE ANGULOS en su mensaje mas frecuente:
#
#   Exit before auth from <192.0.2.1:35440>: (user 'root', 0 fails): Exited normally
#   Bad password attempt for 'root' from 192.0.2.1:41234
#
# El patron anterior exigia un digito justo detras de "from ", de modo que la PRIMERA forma no
# casaba. El marcador de fallo si casaba —la comparacion se hace en minusculas— pero sin IP el
# codigo hace `if m:` y descarta la linea EN SILENCIO. Resultado medido tras reconectar la tuberia:
# tres fallos de autenticacion reales quedaron registrados por dropbear y el contador siguio en
# cero. Es el tercer eslabon roto de la misma cadena, y solo se veia con los otros dos ya arreglados:
# mientras el fichero estuvo vacio, este defecto era invisible.
#
# Los angulos son opcionales para que las dos formas casen con el mismo patron.
_IP_RE = re.compile(r"from <?(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?>?")


def _node_id():
    for p in ("/persist/anvos-node.id", "/etc/anvos-node.id"):
        try:
            v = open(p).read().strip()
            if v:
                return v
        except Exception:
            pass
    return socket.gethostname() or "anvos-node"


def _ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _whitelisted(ip):
    return any(ip.startswith(p) for p in WHITELIST_PREFIXES)


def fib_delay_for(count):
    idx = count - 1
    if idx < 0:
        idx = 0
    if idx >= len(FIB_DELAYS):
        idx = len(FIB_DELAYS) - 1
    return FIB_DELAYS[idx]


def _load_state():
    try:
        with open(STATE_FILE) as f:
            d = json.load(f)
        if isinstance(d, dict):
            d.setdefault("ssh", {})
            d.setdefault("offset", 0)
            d.setdefault("inode", 0)
            return d
    except Exception:
        pass
    return {"version": "1.0", "ssh": {}, "offset": 0, "inode": 0}


def _save_state(d):
    try:
        os.makedirs(SEC_DIR, exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f, indent=1)
        os.replace(tmp, STATE_FILE)
    except Exception:
        pass


def _append(path, rec):
    try:
        os.makedirs(SEC_DIR, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL fib_guard._append: %r" % (e,), file=sys.stderr, flush=True)


def _read_new_fail_ips(state):
    """Lee las líneas NUEVAS de db.err (por offset+inode) y devuelve lista de IPs con fallo."""
    ips = []
    try:
        st = os.stat(DBERR)
    except Exception:
        return ips, state
    inode = getattr(st, "st_ino", 0)
    offset = state.get("offset", 0)
    # rotación/truncado: si el inode cambió o el fichero encogió, empezar de 0.
    if inode != state.get("inode", 0) or st.st_size < offset:
        offset = 0
    try:
        with open(DBERR, "r", errors="replace") as f:
            f.seek(offset)
            for line in f:
                low = line.lower()
                if any(m in low for m in _FAIL_MARKERS):
                    # ITB-083: 'exit before auth ... exited normally' es una DESCONEXION LIMPIA,
                    # no un intento de fuerza bruta. Los fallos reales, si los hay, se cuentan por
                    # sus propias lineas ('bad password'/'authentication failure'/'exit before auth'
                    # ANORMAL sin 'exited normally'). Forensia medida: 13.289 'exit before auth' en
                    # origo, el 100% 'exited normally', 0 fallos reales. El discriminador fiable es
                    # 'exited normally' (aparece con y sin la clausula '(user, N fails)').
                    if "exit before auth" in low and "exited normally" in low:
                        continue
                    m = _IP_RE.search(line)
                    if m:
                        ip = m.group(1)
                        if not _whitelisted(ip):
                            ips.append(ip)
            offset = f.tell()
    except Exception:
        pass
    state["offset"] = offset
    state["inode"] = inode
    return ips, state


def _record_fail(state, ip, now, ts):
    e = state["ssh"].get(ip, {})
    count = int(e.get("count", 0)) + 1
    delay = fib_delay_for(count)
    until = now + delay
    e.update({
        "count": count,
        "recommended_block_secs": delay,     # RECOMENDADO, no aplicado
        "recommended_until_epoch": until,
        "recommended_until": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(until)),
        "first_seen": e.get("first_seen", ts),
        "last_seen": ts,
        "alert": count >= ALERT_THRESHOLD,
        "enforced": False,                    # invariante: el nodo NO aplica (observe-only)
    })
    state["ssh"][ip] = e
    return count, delay


def cmd_cycle():
    """Un ciclo bajo layerd: leer fallos nuevos, actualizar estado, emitir recomendaciones."""
    now = int(time.time())
    ts = _ts()
    state = _load_state()
    new_ips, state = _read_new_fail_ips(state)

    recs = []
    for ip in new_ips:
        count, delay = _record_fail(state, ip, now, ts)
        rec = {"svc": "fib_guard", "ts": now, "node": _node_id(), "mode": "observe",
               "event": "ssh_fail", "ip": ip, "count": count,
               "recommend_block_secs": delay, "enforced": False}
        _append(REC, rec)
        recs.append(rec)
        if count >= ALERT_THRESHOLD:
            alert = {"svc": "fib_guard", "ts": ts, "node": _node_id(),
                     "source": ip, "attack_type": "ssh_bruteforce", "attempt_count": count,
                     "recommend_block_secs": delay, "requires_manual_review": True}
            _append(ALERTS, alert)

    # barrido: marcar recomendaciones expiradas (solo estado, no hay nada que "desbloquear")
    active = 0
    for ip, e in state["ssh"].items():
        if e.get("recommended_until_epoch", 0) > now:
            active += 1
    state["updated_at"] = ts
    _save_state(state)

    summary = {"svc": "fib_guard", "ts": now, "node": _node_id(), "mode": "observe",
               "status": "watching", "new_fails": len(new_ips),
               "tracked_ips": len(state["ssh"]), "active_recommendations": active,
               "note": "OBSERVE+RECOMIENDA (no toca firewall; la accion la decide el operador)"}
    print(json.dumps(summary, ensure_ascii=False))
    _append(REC, summary)
    return 0


def cmd_status():
    state = _load_state()
    now = int(time.time())
    rows = []
    for ip, e in sorted(state["ssh"].items(), key=lambda x: -int(x[1].get("count", 0))):
        rem = max(0, int(e.get("recommended_until_epoch", 0)) - now)
        rows.append({"ip": ip, "count": e.get("count", 0),
                     "recommend_block_secs": e.get("recommended_block_secs", 0),
                     "recommend_remaining_s": rem, "alert": e.get("alert", False),
                     "enforced": False})
    print(json.dumps({"svc": "fib_guard", "node": _node_id(), "mode": "observe",
                      "tracked": len(rows), "sources": rows}, ensure_ascii=False))
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "cycle"
    try:
        if cmd in ("cycle", "probe", "run"):
            return cmd_cycle()
        if cmd == "status":
            return cmd_status()
        print(json.dumps({"svc": "fib_guard", "error": "modo desconocido: %s" % cmd}))
        return 2
    except Exception as e:
        # fail-safe: jamás propagar al supervisor
        print(json.dumps({"svc": "fib_guard", "ok": False, "fatal": str(e)}, ensure_ascii=False))
        return 0


if __name__ == "__main__":
    sys.exit(main())
