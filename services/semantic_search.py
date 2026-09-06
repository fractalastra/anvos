#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""semantic_search — B.1 Fase B: BÚSQUEDA SEMÁNTICA en el borde (vectores al borde).

OBSERVE/READ-ONLY, sin GPU. El master (autoridad de embeddings) pre-calcula y FIRMA un
índice de vectores (knowledge_vectors.json, 653C) y lo empuja al nodo. Este servicio:
  1. Verifica FAIL-CLOSED la firma 653C del índice con el minisign embebido. Si no valida, no usa el índice.
  2. Carga el índice y hace BÚSQUEDA POR COSENO local (Python puro, sin numpy, sin GPU, sin Ollama).
  3. Auto-latido: ejecuta las 'probes' pre-embebidas del índice (consultas de ejemplo) y reporta el top-K,
     probando que el borde BUSCA por significado sin depender de alcanzar la GPU del master.
  4. Buzón de consultas: procesa vectores de consulta que el master empuja a semantic/query/*.json
     ({"q":"...","vec":[...]}) -> top-K -> semantic/search_result.jsonl.

NUNCA: embebe localmente (no hay GPU), escribe en el índice firmado, decide/actúa/firma. Solo lee y busca.
El direccionamiento por significado (Fase B) se apoya en esto; la ACCIÓN sigue siendo del operador.
"""
import os, sys, json, time, glob, math, subprocess

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
DATA    = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
MS  = os.path.join(STAGING, "pylayer-verify")
PUB = os.path.join(STAGING, "pylayer", "release.pub")

SEM_DIR = os.path.join(DATA, "semantic")
INDEX   = os.path.join(SEM_DIR, "knowledge_vectors.json")   # índice firmado empujado por el master
QUERY   = os.path.join(SEM_DIR, "query")                    # buzón de vectores de consulta del master
DONE    = os.path.join(QUERY, "processed")
OUT     = os.path.join(SEM_DIR, "search_result.jsonl")
TOPK    = 3


def _now(): return int(time.time())


def _find_ld():
    for c in glob.glob(os.path.join(MS, "ld-linux*.so.2")):
        return c
    return None


def _verify(ld, target):
    sig = target + ".minisig"
    if not (ld and os.path.isfile(target) and os.path.isfile(sig)):
        return False
    try:
        r = subprocess.run([ld, "--library-path", MS, os.path.join(MS, "minisign"),
                            "-Vm", target, "-p", PUB, "-x", sig], capture_output=True, timeout=8)
        return r.returncode == 0
    except Exception:
        return False


def _emit(o):
    try: print(json.dumps(o, ensure_ascii=False))
    except Exception: pass


def _append(path, o):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    except Exception: pass


def _cosine(a, b):
    if not a or not b or len(a) != len(b):
        return -1.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)); nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else -1.0


def _search(items, qvec, k=TOPK):
    scored = [(round(_cosine(it.get("vec", []), qvec), 4), it["id"], it["text"]) for it in items]
    scored.sort(reverse=True)
    return [{"id": i, "text": t, "score": s} for s, i, t in scored[:k]]


def main():
    ts = _now()
    ld = _find_ld()
    verifier_ok = bool(ld) and os.path.exists(os.path.join(MS, "minisign")) and os.path.exists(PUB)
    if not verifier_ok:
        _emit({"svc": "semantic_search", "ts": ts, "observe_only": True,
               "verifier_ok": False, "note": "verificador embebido no disponible"})
        return
    if not _verify(ld, INDEX):
        _emit({"svc": "semantic_search", "ts": ts, "observe_only": True,
               "index_verified": False, "note": "FAIL-CLOSED: índice sin firma válida o ausente; no se usa"})
        return
    try:
        idx = json.load(open(INDEX, encoding="utf-8"))
        items = idx.get("items", [])
    except Exception as e:
        _emit({"svc": "semantic_search", "ts": ts, "observe_only": True,
               "index_verified": True, "load_ok": False, "error": str(e)[:140]})
        return

    # buzón de consultas (vectores empujados por el master)
    os.makedirs(DONE, exist_ok=True)
    processed = 0
    for qf in sorted(glob.glob(os.path.join(QUERY, "*.json"))):
        try:
            q = json.load(open(qf, encoding="utf-8"))
            res = _search(items, q.get("vec", []))
            _append(OUT, {"svc": "semantic_search", "ts": _now(), "observe_only": True,
                          "q": q.get("q", "?"), "top": res})
            os.rename(qf, os.path.join(DONE, os.path.basename(qf)))
            processed += 1
        except Exception:
            continue

    # auto-latido: probes pre-embebidas del índice (prueba de búsqueda al borde sin GPU)
    probe_top = []
    for p in idx.get("probes", []):
        top = _search(items, p.get("vec", []), k=1)
        if top:
            probe_top.append({"q": p.get("q", "?"), "best": top[0]["id"], "score": top[0]["score"]})

    _emit({"svc": "semantic_search", "ts": _now(), "observe_only": True,
           "index_verified": True, "model": idx.get("model"), "dim": idx.get("dim"),
           "items": len(items), "queries_processed": processed, "probes": probe_top,
           "phase": "OS-FaseB-Paso1(B.1)", "authority": False,
           "note": "busqueda semantica por coseno en el borde; sin GPU, sin embeber local, observe-only"})


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        _emit({"svc": "semantic_search", "ts": _now(), "observe_only": True, "fatal": str(e)[:140]})
