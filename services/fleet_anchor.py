#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""fleet_anchor — FEDERACIÓN NIVEL 3 (colmena fractal con MEMORIA del tiempo). N1 (fleet_attest) verifica
a un par AHORA; N2 (fleet_consensus) exige QUÓRUM de pares AHORA. Ambos son instantáneos: no ven si un
nodo REESCRIBIÓ o RETROCEDIÓ su propia historia entre dos instantes. N3 lo cierra: cada nodo ANCLA el
`head` (altura + hash) de sus pares en un registro local y, en cada pasada, comprueba contra esa memoria:

  - ROLLBACK        : la altura del par es MENOR que la ya anclada -> la cadena retrocedio (nunca debe).
  - REESCRITA       : una altura ya anclada ahora tiene un hash DISTINTO -> la historia fue reescrita/forkeada.
  - PODADA          : una altura anclada ya no esta en la cadena servida (poda legitima) -> se avisa, no alarma.
  - COHERENTE       : crecimiento monotono y los hashes historicos coinciden -> integridad en el tiempo.

Detección BIZANTINA sin master ni firma: para forjar la historia de un nodo habria que engañar la memoria
de TODOS los pares que lo anclaron. Reusa attest_verify (_block_hash + verify_chain). Observe/detect-only:
emite alertas (ROLLBACK/REESCRITA = severidad MÁXIMA) para que el operador decida; NUNCA actúa. Solo stdlib.
Uso: fleet_anchor.py [http://host:8088 ...]"""
import os
import sys
import json
import time
import hashlib
import urllib.request


def _sha(s):
    return hashlib.sha256(s.encode() if isinstance(s, str) else s).hexdigest()


def _block_hash(block):
    # MISMO algoritmo que block_anchor/attest_verify (sha256 del JSON canonico del bloque sin 'hash').
    b = {k: v for k, v in block.items() if k != "hash"}
    return _sha(json.dumps(b, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
ANCHOR_DIR = os.path.join(DATA, "fleet", "anchors")
ALERTS = os.path.join(DATA, "fleet", "anchor_alerts.jsonl")
# Pares de anclaje: por configuracion (ANVOS_ANCHOR_PEERS, URLs separadas por comas).
DEFAULT_PEERS = [p.strip() for p in os.environ.get("ANVOS_ANCHOR_PEERS", "").split(",") if p.strip()]
TIMEOUT = 8


def _now():
    return int(time.time())


def _get(url):
    try:
        return urllib.request.urlopen(url, timeout=TIMEOUT).read()
    except Exception as e:
        return b"__ERR__" + str(e).encode()


def _ensure():
    try:
        os.makedirs(ANCHOR_DIR, exist_ok=True)
    except Exception:
        pass


def _chain_map(text):
    """{altura: hash_bloque} + (altura_max, head_hash) desde el texto ndjson de /blocks."""
    hmap = {}
    maxh = -1
    head = None
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            b = json.loads(ln)
        except Exception:
            continue
        h = b.get("height")
        if h is None:
            continue
        bh = _block_hash(b)
        hmap[int(h)] = bh
        if int(h) >= maxh:
            maxh = int(h)
            head = bh
    return hmap, maxh, head


def _load_anchors(node):
    p = os.path.join(ANCHOR_DIR, "%s.jsonl" % node)
    out = []
    try:
        for ln in open(p):
            ln = ln.strip()
            if ln:
                out.append(json.loads(ln))
    except Exception:
        pass
    return out


def _append_anchor(node, rec):
    _ensure()
    try:
        with open(os.path.join(ANCHOR_DIR, "%s.jsonl" % node), "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL fleet_anchor._append_anchor: %r" % (e,), file=sys.stderr, flush=True)


def _alert(ev):
    _ensure()
    try:
        with open(ALERTS, "a") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    except Exception:
        pass


def check_peer(base):
    base = base.rstrip("/")
    att = _get(base + "/attest")
    if att.startswith(b"__ERR__"):
        return {"peer": base, "veredicto": "SIN_RESPUESTA"}
    try:
        node = json.loads(att).get("node")
    except Exception:
        node = None
    blocks = _get(base + "/blocks")
    if blocks.startswith(b"__ERR__") or not node:
        return {"peer": base, "node": node, "veredicto": "SIN_CADENA"}
    hmap, maxh, head = _chain_map(blocks.decode("utf-8", "replace"))
    if maxh < 0:
        return {"peer": base, "node": node, "veredicto": "CADENA_VACIA"}

    anchors = _load_anchors(node)
    veredicto = "NUEVO"
    detalle = {}
    if anchors:
        last = anchors[-1]
        oldh = int(last.get("height", -1))
        oldhash = last.get("head")
        if maxh < oldh:
            veredicto = "ROLLBACK"
            detalle = {"altura_anclada": oldh, "altura_ahora": maxh}
        elif oldh in hmap and hmap[oldh] != oldhash:
            veredicto = "REESCRITA"
            detalle = {"altura": oldh, "hash_anclado": (oldhash or "")[:16],
                       "hash_ahora": (hmap[oldh] or "")[:16]}
        elif oldh not in hmap:
            veredicto = "PODADA"
            detalle = {"altura_anclada_ausente": oldh, "min_en_cadena": min(hmap) if hmap else None}
        else:
            veredicto = "COHERENTE"
            detalle = {"desde_altura": oldh, "hasta_altura": maxh}

    # anclar la observacion actual (memoria colectiva del tiempo)
    _append_anchor(node, {"ts": _now(), "height": maxh, "head": head})

    res = {"peer": base, "node": node, "veredicto": veredicto, "altura": maxh,
           "head": (head or "")[:16], "detalle": detalle, "observaciones": len(anchors) + 1}
    if veredicto in ("ROLLBACK", "REESCRITA"):
        ev = {"svc": "fleet_anchor", "ts": _now(), "severidad": "MAXIMA", "evento": veredicto,
              "node": node, "detalle": detalle,
              "note": "integridad TEMPORAL de la flota rota (rollback/reescritura de la historia) -> posible nodo comprometido/bizantino; escalar al operador"}
        _alert(ev)
        res["ALERTA"] = ev["evento"]
    return res


def main():
    peers = sys.argv[1:]
    if not peers:
        env = os.environ.get("ANV_FLEET_PEERS")
        if env:
            peers = env.split(",")
        else:
            # servicio en el nodo: usa los peers de malla de fleet/peers.txt (el mismo que /fleet)
            try:
                peers = [l.strip() for l in open(os.path.join(DATA, "fleet", "peers.txt"))
                         if l.strip() and not l.startswith("#")]
            except Exception:
                peers = []
            if not peers:
                peers = DEFAULT_PEERS
    peers = [p.strip() for p in peers if p.strip()]
    results = [check_peer(p) for p in peers]
    coherentes = sum(1 for r in results if r.get("veredicto") in ("COHERENTE", "NUEVO"))
    alarmas = [r for r in results if r.get("ALERTA")]
    print(json.dumps({"svc": "fleet_anchor", "nivel": 3, "peers": len(peers),
                      "coherentes": coherentes, "alarmas": len(alarmas), "flota": results},
                     ensure_ascii=False, indent=2))
    print("\n== FEDERACIÓN N3 — integridad en el TIEMPO (memoria colectiva; sin master) ==", file=sys.stderr)
    for r in results:
        print("  %-14s %-12s altura=%-4s obs=%s %s" % (
            r.get("node", "?"), r.get("veredicto", "?"), r.get("altura", "-"),
            r.get("observaciones", "-"),
            ("<== " + r["ALERTA"] if r.get("ALERTA") else "")), file=sys.stderr)
    return 0 if not alarmas else 1


if __name__ == "__main__":
    sys.exit(main())
