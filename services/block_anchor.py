#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""block_anchor — CAPACIDAD CORE portada a la capa ANVOS: cadena de bloques MERKLE del PROPIO nodo.

El master ya mina bloques merkle del ecosistema (anv-merkle.py + anv-consensus.sh). Esta es la versión
NODE-LOCAL para la visión de colmena fractal: cada nodo soberano ancla SU PROPIA historia en bloques
merkle ENCADENADOS y VERIFICABLES, sin depender del master para ser tamper-evident. Un bloque compromete
(a) las cabezas de estado del nodo (event_ledger, cadenas beacon/sentinel, self_integrity, gobernanza,
malla) y (b) la MERKLE de los eventos NUEVOS desde el bloque anterior — así el bloque atestigua la
historia real, no solo un instante. La cadena (prev_hash) hace la manipulación detectable; el merkle_root
hace cada bloque verificable de forma independiente. Estos bloques pueden luego ANCLARSE al master/consenso.

Convención merkle IDÉNTICA al master (anv-merkle.py): sha256_pair(l,r)=sha256((l+r)); nodo impar se
duplica. OBSERVE-ONLY: la IA/el nodo no firma (doctrina del nodo); la integridad viene del hash-chain +
merkle. Solo stdlib. Fail-safe: nunca lanza al supervisor. Periódico bajo layerd.

Modos: cycle (mina 1 bloque con el estado actual) · verify (revalida toda la cadena) · status."""
import os
import sys
import json
import time
import hashlib
import socket

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
CHAIN_DIR = os.path.join(DATA, "chain")
BLOCKS = os.path.join(CHAIN_DIR, "blocks.jsonl")          # cadena de bloques merkle del nodo (append-only)
HEAD = os.path.join(CHAIN_DIR, "blocks.head")             # {height, hash, committed_seq}
REC = os.path.join(CHAIN_DIR, "block_anchor.jsonl")       # latido/registro del servicio (para GUI)
EVENT_LEDGER = os.path.join(DATA, "memory", "event_ledger.jsonl")
CHAIN_STATUS = os.path.join(DATA, "chain", "chain_status.jsonl")
INTEGRITY = os.path.join(DATA, "integrity", "self_integrity.jsonl")
GOV = os.path.join(DATA, "governance", "cognition_guard.jsonl")
RING = os.path.join(DATA, "mesh", "ring_link.jsonl")
MAX_NEW_LINES = 4000   # cota por bloque de eventos nuevos comprometidos (evita árboles enormes)


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


def _sha(s):
    return hashlib.sha256(s.encode() if isinstance(s, str) else s).hexdigest()


def _pair(l, r):
    return hashlib.sha256((l + r).encode()).hexdigest()


def _merkle_root(hashes):
    """Raíz merkle de una lista de hashes (hex). Convención del master: nodo impar se duplica.
    Lista vacía -> sha256('EMPTY_TREE')."""
    if not hashes:
        return hashlib.sha256(b"EMPTY_TREE").hexdigest()
    cur = list(hashes)
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i + 1] if i + 1 < len(cur) else cur[i]
            nxt.append(_pair(left, right))
        cur = nxt
    return cur[0]


def _last(path):
    try:
        with open(path, "rb") as f:
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


def _rec(path, rec):
    try:
        os.makedirs(CHAIN_DIR, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL block_anchor._rec: %r" % (e,), file=sys.stderr, flush=True)


def _load_head():
    try:
        return json.loads(open(HEAD).read())
    except Exception:
        return {"height": 0, "hash": _sha("ANVOS_BLOCK_GENESIS:" + NODE), "committed_seq": 0}


def _save_head(h):
    try:
        os.makedirs(CHAIN_DIR, exist_ok=True)
        tmp = HEAD + ".tmp"
        with open(tmp, "w") as f:
            json.dump(h, f)
        os.replace(tmp, HEAD)
    except Exception:
        pass


def _new_history_root(since_seq):
    """Merkle de las líneas del event_ledger con seq > since_seq (la historia NUEVA que este bloque
    compromete). Devuelve (root, max_seq_comprometido, n_lineas). Acota a MAX_NEW_LINES."""
    hashes = []
    max_seq = since_seq
    n = 0
    try:
        with open(EVENT_LEDGER) as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    d = json.loads(ln)
                except Exception:
                    continue
                seq = int(d.get("total_seq", d.get("seq", 0)) or 0)
                if seq <= since_seq:
                    continue
                hashes.append(_sha(ln))
                if seq > max_seq:
                    max_seq = seq
                n += 1
                if n >= MAX_NEW_LINES:
                    break
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return _merkle_root(hashes), max_seq, n


def _collect_leaves():
    """Hojas del bloque = huellas del ESTADO soberano del nodo (label, hash). Deterministas (sin ts)."""
    el = _last(EVENT_LEDGER)
    cs = _last(CHAIN_STATUS)
    si = _last(INTEGRITY)
    gv = _last(GOV)
    rg = _last(RING)
    heads = {c.get("ledger"): c.get("head") for c in (cs.get("chains") or [])}
    leaves = [
        ("node", _sha(NODE)),
        ("event_ledger_head", str(el.get("head") or _sha("NONE"))),
        ("event_ledger_seq", _sha(str(el.get("total_seq", 0) or 0))),
        ("beacon_head", str(heads.get("beacon") or _sha("NONE"))),
        ("sentinel_head", str(heads.get("sentinel") or _sha("NONE"))),
        ("self_integrity", _sha("%s|%s/%s" % (si.get("attestation"), si.get("verified"), si.get("total")))),
        ("governance", _sha(str(gv.get("veredicto") or gv.get("verdict") or "-"))),
        ("mesh", _sha(str(rg.get("state") or "-"))),
    ]
    return leaves, el, si, gv


def _block_hash(block):
    """Hash canónico del bloque SIN su campo 'hash' (claves ordenadas)."""
    b = {k: v for k, v in block.items() if k != "hash"}
    return _sha(json.dumps(b, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


def cmd_cycle():
    head = _load_head()
    leaves, el, si, gv = _collect_leaves()
    hist_root, new_seq, n_new = _new_history_root(int(head.get("committed_seq", 0)))
    leaves.append(("new_history_root", hist_root))
    merkle_root = _merkle_root([h for _, h in leaves])
    block = {
        "height": int(head.get("height", 0)) + 1,
        "node": NODE,
        "ts": int(time.time()),
        "prev": head.get("hash"),
        "merkle_root": merkle_root,
        "leaf_count": len(leaves),
        "leaves": [{"label": l, "hash": h} for l, h in leaves],
        "committed_seq": new_seq,
        "new_events": n_new,
        "sealed": "%s/%s" % (si.get("verified", "?"), si.get("total", "?")),
        "gov": str(gv.get("veredicto") or gv.get("verdict") or "-"),
    }
    block["hash"] = _block_hash(block)
    try:
        os.makedirs(CHAIN_DIR, exist_ok=True)
        with open(BLOCKS, "a") as f:
            f.write(json.dumps(block, ensure_ascii=False) + "\n")
    except Exception as e:
        print(json.dumps({"svc": "block_anchor", "ok": False, "error": "append: %s" % e}, ensure_ascii=False))
        return 0
    _save_head({"height": block["height"], "hash": block["hash"], "committed_seq": new_seq})
    # auto-verificación de la cadena COMPLETA tras minar (tamper-evidence continua)
    verified, vheight, vblocks, _vhead, vbad = _verify_chain()
    rec = {"svc": "block_anchor", "ts": block["ts"], "node": NODE, "mode": "observe-anchor",
           "height": block["height"], "head": block["hash"][:16], "merkle_root": merkle_root[:16],
           "new_events": n_new, "sealed": block["sealed"], "verified": verified,
           "blocks": vblocks, "first_bad": vbad,
           "note": "bloque merkle node-local encadenado + cadena verificada; observe-only (el nodo no firma)"}
    print(json.dumps(rec, ensure_ascii=False))
    _rec(REC, rec)
    return 0


def _verify_chain():
    """Revalida TODA la cadena: enlace prev + merkle_root reconstruido desde hojas + hash de bloque.
    Devuelve (verified, height, blocks, head_hash, first_bad)."""
    prev = _sha("ANVOS_BLOCK_GENESIS:" + NODE)
    height = 0
    bad = None
    n = 0
    try:
        with open(BLOCKS) as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    b = json.loads(ln)
                except Exception:
                    bad = {"height": height + 1, "why": "json_ilegible"}
                    break
                n += 1
                if b.get("prev") != prev:
                    bad = {"height": b.get("height"), "why": "prev_roto"}
                    break
                if _merkle_root([lf.get("hash") for lf in (b.get("leaves") or [])]) != b.get("merkle_root"):
                    bad = {"height": b.get("height"), "why": "merkle_root_no_casa"}
                    break
                if _block_hash(b) != b.get("hash"):
                    bad = {"height": b.get("height"), "why": "hash_bloque_no_casa"}
                    break
                prev = b.get("hash")
                height = b.get("height", height + 1)
    except FileNotFoundError:
        pass
    except Exception as e:
        bad = {"why": "excepcion: %s" % e}
    return (bad is None), height, n, prev, bad


def cmd_verify():
    verified, height, n, head, bad = _verify_chain()
    out = {"svc": "block_anchor", "action": "verify", "node": NODE, "blocks": n,
           "height": height, "head": head[:16], "verified": verified, "first_bad": bad,
           "note": "cadena merkle node-local VERIFICADA" if verified else "cadena con anomalia"}
    print(json.dumps(out, ensure_ascii=False))
    _rec(REC, {k: out[k] for k in ("svc", "action", "node", "blocks", "height", "verified", "first_bad")})
    return 0 if verified else 1


def cmd_status():
    head = _load_head()
    print(json.dumps({"svc": "block_anchor", "node": NODE, "height": head.get("height", 0),
                      "head": str(head.get("hash", ""))[:16], "committed_seq": head.get("committed_seq", 0),
                      "mode": "observe-anchor"}, ensure_ascii=False))
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "cycle"
    try:
        if cmd in ("cycle", "run", "probe"):
            return cmd_cycle()
        if cmd == "verify":
            return cmd_verify()
        if cmd == "status":
            return cmd_status()
        print(json.dumps({"svc": "block_anchor", "error": "modo desconocido: %s" % cmd}))
        return 2
    except Exception as e:
        print(json.dumps({"svc": "block_anchor", "ok": False, "fatal": str(e)}, ensure_ascii=False))
        return 0


if __name__ == "__main__":
    sys.exit(main())
