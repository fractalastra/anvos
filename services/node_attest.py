#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""node_attest — ATESTACIÓN SOBERANA del nodo (identidad hacia fuera, para federación/padre/master).

Un nodo soberano necesita poder PROBAR su estado a otros (colmena fractal: un hijo atesta a su padre, un
peer a la federación, cualquiera al master). Este servicio produce una ATESTACIÓN compacta y **ANCLADA a
la cadena de bloques merkle del nodo** (block_anchor): identidad de realm + integridad (self_integrity) +
gobernanza + aprendizaje + cabeza de la cadena verificada. Anclarla a `block_anchor.head` la ata a la
historia tamper-evident del nodo: quien la recibe puede pedir/verificar la cadena de bloques.

El nodo NO firma (doctrina): la atestación es una AGREGACIÓN read-only cuya confianza viene de (a) el
anclaje a la cadena merkle auto-verificada, (b) el sello self_integrity de la capa firmada. Un verificador
externo la contrasta con la cadena del nodo y con el juicio del master. Solo stdlib. Fail-safe. Periódico.

Se escribe en attest/attestation.json (lo sirve node_status_server en /attest)."""
import os
import sys
import json
import time
import socket

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
OUT = os.path.join(DATA, "attest", "attestation.json")
REC = os.path.join(DATA, "attest", "node_attest.jsonl")


def _node_id():
    for p in ("/persist/anvos-node.id", "/etc/anvos-node.id"):
        try:
            v = open(p).read().strip()
            if v:
                return v
        except Exception:
            pass
    return socket.gethostname() or "anvos-node"


REALM_DIR = os.environ.get("ANVOS_REALM", "/persist/anvos-realm")


def _registro_realm():
    """Registro de realm del nodo, leido de su fuente y no del resumen intermedio.

    Anadido 2026-07-31. La atestacion componia el bloque de soberania a partir de
    realm/realm.jsonl, que emite realm_activate y que NO arrastra dos campos que si estan
    en el registro: node_id y federation.

    Consecuencias medidas de esa perdida: la atestacion de origo publicaba node_id nulo, de
    modo que un par lo identificaba por nombre; y federation no viajaba en absoluto. Sin ese
    segundo campo, un par no puede saber si el otro cuelga de su mismo realm padre.

    Eso importa mas de lo que parece en este diseno: cada nodo ES su propio realm (origo esta
    en realm-origo y nodo-c en realm-nodo-c), asi que contrastar contra el registro local solo
    contesta "¿este soy yo?". Sin publicar la adhesion, cualquier par es ajeno por construccion
    y ningun conjunto de nodos soberanos llega a reconocerse.
    """
    try:
        with open(os.path.join(REALM_DIR, "node_registry.json")) as f:
            return json.load(f)
    except Exception:
        return {}


def _node_id_de(reg):
    """node_id segun el registro: es la CLAVE del nodo en el mapa, no un campo suelto."""
    nodos = reg.get("nodes") or {}
    if isinstance(nodos, dict):
        for k, v in nodos.items():
            if isinstance(v, dict):
                return v.get("node_id") or k
            return k
    return None


def _last(rel):
    p = os.path.join(DATA, rel)
    try:
        with open(p, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 65536))
            tail = f.read().splitlines()
        for ln in reversed(tail):
            ln = ln.strip()
            if ln:
                return json.loads(ln)
    except Exception:
        pass
    return {}


def build_attestation():
    node = _node_id()
    ba = _last("chain/block_anchor.jsonl")
    si = _last("integrity/self_integrity.jsonl")
    gv = _last("governance/cognition_guard.jsonl")
    realm = _last("realm/realm.jsonl")
    reg = _registro_realm()
    el = _last("learning/event_learn.jsonl")
    beacon = _last("eco-telem/beacon.jsonl")
    _lsrc = ("from_episodic", "from_metrics", "from_fib", "from_deception",
             "from_netflow", "from_modbus", "from_merkle")
    senses = sum(1 for k in _lsrc if (el.get(k, 0) or 0) > 0)
    up = 0
    try:
        up = int(float(open("/proc/uptime").read().split()[0]))
    except Exception:
        pass
    mods = []
    try:
        mods = json.loads(open("/persist/anvos-modules/profile.json").read()).get("enabled_modules") or []
    except Exception:
        mods = []
    # head COMPLETO (blocks.head lo guarda entero; block_anchor.jsonl lo trunca a 16 para display).
    # El anclaje DEBE ser el hash completo para que attest_verify lo case con la cadena.
    head = None
    try:
        head = json.loads(open(os.path.join(DATA, "chain", "blocks.head")).read()).get("hash")
    except Exception:
        pass
    if not head:
        head = ba.get("head")
    att = {
        "svc": "node_attest",
        "ts": int(time.time()),
        "node": node,
        # El registro es la fuente; realm.jsonl es un resumen que pierde node_id y federation.
        "soberania": {"estado": realm.get("estado") or "-", "soberano": bool(realm.get("soberano")),
                      "realm": realm.get("realm_id") or reg.get("realm_id"),
                      "node_id": realm.get("node_id") or _node_id_de(reg) or node,
                      "federation": reg.get("federation")},
        "cadena_bloques": {"altura": ba.get("height"), "cabeza": head, "verificada": ba.get("verified"),
                           "bloques": ba.get("blocks")},
        "integridad": {"attestation": si.get("attestation"), "verified": si.get("verified"),
                       "total": si.get("total"), "all_valid": si.get("all_valid")},
        "gobernanza": gv.get("veredicto") or gv.get("verdict"),
        "aprendizaje_sentidos": "%d/7" % senses,
        "modulos": mods,
        "uptime_s": up,
        "salud": {"cpu_load": beacon.get("cpu_load"), "mem_pct": beacon.get("mem_pct"),
                  "disk_pct": beacon.get("disk_pct")},
        # ANCLAJE: la atestación está atada a la cabeza de la cadena merkle auto-verificada del nodo.
        "anclada_al_bloque": head,
        "modo": "observe-attest (el nodo no firma; confianza = anclaje a cadena + self_integrity)",
    }
    return att


def cmd_cycle():
    att = build_attestation()
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        tmp = OUT + ".tmp"
        with open(tmp, "w") as f:
            json.dump(att, f, ensure_ascii=False, indent=2)
        os.replace(tmp, OUT)
    except Exception:
        pass
    rec = {"svc": "node_attest", "ts": att["ts"], "node": att["node"],
           "soberano": att["soberania"]["soberano"], "altura_bloque": att["cadena_bloques"]["altura"],
           "verificada": att["cadena_bloques"]["verificada"], "sellado": "%s/%s" % (
               att["integridad"]["verified"], att["integridad"]["total"]),
           "anclada_al_bloque": (att["anclada_al_bloque"] or "")[:16],
           "note": "atestación soberana emitida (anclada a la cadena merkle del nodo)"}
    print(json.dumps(rec, ensure_ascii=False))
    try:
        os.makedirs(os.path.dirname(REC), exist_ok=True)
        with open(REC, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass
    return 0


def cmd_show():
    print(json.dumps(build_attestation(), ensure_ascii=False, indent=2))
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "cycle"
    try:
        if cmd in ("cycle", "run", "probe"):
            return cmd_cycle()
        if cmd == "show":
            return cmd_show()
        print(json.dumps({"svc": "node_attest", "error": "modo desconocido: %s" % cmd}))
        return 2
    except Exception as e:
        print(json.dumps({"svc": "node_attest", "ok": False, "fatal": str(e)}, ensure_ascii=False))
        return 0


if __name__ == "__main__":
    sys.exit(main())
