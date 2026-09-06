#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""event_ledger — MEMORIA EPISÓDICA encadenada del nodo ANVOS (matriz item 5: blockchain de memoria).

Complementa chain_integrity (que encadena la telemetría CRUDA del beacon) con la capa SEMÁNTICA:
registra los EVENTOS SIGNIFICATIVOS del nodo — transiciones de estado del core_audit (salud), del
gemelo twin_forward (régimen), de la malla ring_link, y de la integridad — en un ledger
HASH-ENCADENADO (tamper-evident: cada evento lleva prev_hash + hash=sha256(prev_hash+evento)).

Es la "memoria de qué le pasó" al nodo: un operador (o una sesión futura, o el master) lee la
historia episódica y ve la secuencia de cambios de régimen. El nodo NO firma (la clave privada no reside en el nodo, política de identidad), pero el hash-chain da tamper-evidence dentro del nodo.

OBSERVE-only: solo registra transiciones, no actúa. Single-shot bajo layerd. Solo stdlib."""
import os
import json
import time
import hashlib

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
MEMDIR = os.path.join(DATA, "memory")
LEDGER = os.path.join(MEMDIR, "events.jsonl")               # eventos encadenados (append-only)
HEAD = os.path.join(MEMDIR, "events.head.json")             # cabeza de cadena + últimos valores
GENESIS = "0" * 64

# fuentes vigiladas: (kind, fichero, campo a extraer)
SOURCES = [
    ("core_health", "sentinel/core_audit.jsonl", "state"),
    ("twin_regime", "twin/twin_forward.jsonl", "state"),
    ("mesh",        "ring/ring_link.jsonl", "state"),
    ("integrity",   "integrity/self_integrity.jsonl", "attestation"),
    ("governance",  "governance/cognition_guard.jsonl", "verdict"),
]


def _last_field(rel, field):
    """Último valor de <field> en la última línea JSON no vacía de un ledger."""
    try:
        with open(os.path.join(DATA, rel)) as f:
            for ln in reversed(f.readlines()):
                ln = ln.strip()
                if ln:
                    d = json.loads(ln)
                    return d.get(field)
    except Exception:
        pass
    return None


def _canon(d):
    return json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _load_head():
    try:
        with open(HEAD) as f:
            return json.loads(f.read())
    except Exception:
        return {"head": GENESIS, "seq": 0, "last": {}}


def _save_head(h):
    os.makedirs(MEMDIR, exist_ok=True)
    tmp = HEAD + ".%d.tmp" % os.getpid()
    try:
        with open(tmp, "w") as f:
            f.write(json.dumps(h, ensure_ascii=False))
        os.replace(tmp, HEAD)
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass


def _heal_ledger():
    """AUTO-CURADO anti-corrupción (lección power-cycle 2026-07-19): un corte de corriente a mitad
    de escritura deja bytes NUL en events.jsonl (ext4 delayed-alloc). Al arrancar: valida la cadena
    desde génesis (parse + hash + enlace prev_hash), TRUNCA en la primera línea corrupta/rota, y
    reescribe ledger+head ATÓMICAMENTE al último punto sano. Idempotente si ya está sano."""
    try:
        with open(LEDGER, "rb") as f:
            raw = f.read()
    except Exception:
        return  # sin ledger: nada que curar (main arranca de génesis)
    lines = raw.decode("utf-8", "replace").split("\n")
    good, prev, last = [], GENESIS, {}
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        # una línea con NUL o no-JSON = corrupción -> corta aquí (no confiar en lo que sigue)
        if "\x00" in ln:
            break
        try:
            e = json.loads(s)
        except Exception:
            break
        core = {"seq": e.get("seq"), "ts": e.get("ts"), "kind": e.get("kind"),
                "from": e.get("from"), "to": e.get("to")}
        if e.get("seq") != len(good) or e.get("prev_hash") != prev:
            break
        if hashlib.sha256((prev + _canon(core)).encode()).hexdigest() != e.get("hash"):
            break
        good.append(s)
        prev = e["hash"]
        if e.get("kind") is not None:
            last[e["kind"]] = e.get("to")
    # ¿coincide con lo que hay en disco? si no, reescribir sano (atómico) + reconciliar head
    cur_lines = [l for l in raw.decode("utf-8", "replace").splitlines() if l.strip()]
    if len(good) != len(cur_lines) or ("\x00" in raw.decode("utf-8", "replace")):
        tmp = LEDGER + ".heal.%d.tmp" % os.getpid()
        with open(tmp, "w") as f:
            for s in good:
                f.write(s + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, LEDGER)
        _save_head({"head": prev, "seq": len(good), "last": last, "ts": int(time.time()),
                    "healed": True, "dropped": len(cur_lines) - len(good)})


def main():
    os.makedirs(MEMDIR, exist_ok=True)
    _heal_ledger()
    h = _load_head()
    prev_hash = h.get("head", GENESIS)
    seq = h.get("seq", 0)
    last = dict(h.get("last", {}))
    now = int(time.time())

    new_events = []
    for kind, rel, field in SOURCES:
        cur = _last_field(rel, field)
        if cur is None:
            continue
        old = last.get(kind)
        if old != cur:
            core = {"seq": seq, "ts": now, "kind": kind, "from": old, "to": cur}
            hh = hashlib.sha256((prev_hash + _canon(core)).encode()).hexdigest()
            ev = dict(core, prev_hash=prev_hash, hash=hh)
            new_events.append(ev)
            prev_hash = hh
            seq += 1
            last[kind] = cur

    if new_events:
        with open(LEDGER, "a") as f:
            for ev in new_events:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())   # durabilidad: el evento en disco antes de actualizar el head
        _save_head({"head": prev_hash, "seq": seq, "last": last, "ts": now})

    # verificación rápida de la cadena (últimas N entradas encadenan bien)
    chain_ok = _verify_tail()

    rec = {"svc": "event_ledger", "ts": now, "observe_only": True,
           "new_events": len(new_events), "total_seq": seq, "head": prev_hash[:16],
           "chain_ok": chain_ok,
           "transitions": [{"kind": e["kind"], "from": e["from"], "to": e["to"]} for e in new_events],
           "current": last}
    print(json.dumps(rec, ensure_ascii=False))


def _verify_tail(n=50):
    """Re-encadena las últimas n entradas y verifica hash + enlace prev_hash."""
    try:
        with open(LEDGER) as f:
            lines = [l for l in f.read().splitlines() if l.strip()][-n:]
    except Exception:
        return True   # ledger vacío = trivialmente íntegro
    prev = None
    for ln in lines:
        try:
            e = json.loads(ln)
        except Exception:
            return False
        core = {"seq": e.get("seq"), "ts": e.get("ts"), "kind": e.get("kind"),
                "from": e.get("from"), "to": e.get("to")}
        want = hashlib.sha256((e.get("prev_hash", "") + _canon(core)).encode()).hexdigest()
        if want != e.get("hash"):
            return False
        if prev is not None and e.get("prev_hash") != prev:
            return False
        prev = e.get("hash")
    return True


if __name__ == "__main__":
    main()
