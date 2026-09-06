#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""codegen_audit — vigía de capa: constatación CONTINUA del codegen soberano del nodo.

Tras el hito code-on-origo (2026-07-27: AstraNova Code crea código EN la OS, firmado por el
9c del nodo), este servicio vuelve PERMANENTE la constatación que antes era puntual:
(1) hash-chain del codegen_ledger.jsonl íntegra (recomputo desde contenido),
(2) cada artefacto de applied/ coincide (sha256) con el candidate_sha256 que el gate aprobó
    y el 9c firmó,
(3) todo evento codegen lleva su firma 9c (presencia+forma; la verificación CRIPTO corre
    master-side en anv-codegen-verify.py — el nodo busybox no trae openssl),
(4) sin huérfanos en applied/ (fichero sin evento = puerta de atrás).

Observe-only, NO bloquea nada (regla del operador). Nodo sin codegen (nodo-c) = no-op
fail-safe (SIN_CODEGEN). Deriva → AUDIT_FALLA en el jsonl, que vigias_watch/event_learn
pueden consumir. Solo stdlib.

Manifest: codegen_audit.py|3600|codegen/codegen_audit.jsonl
"""
import os
import json
import time
import hashlib

ROOT = "/persist/anvos-data/astra-code"
STRIP = {"hash", "sig9c", "sig9c_slot", "sig9c_alg", "sig9c_over"}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def recompute(d):
    base = {k: v for k, v in d.items() if k not in STRIP}
    canon = json.dumps(base, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode()
    return hashlib.sha256(base["prev"].encode() + canon).hexdigest()


def audit():
    ledger = os.path.join(ROOT, "codegen_ledger.jsonl")
    applied = os.path.join(ROOT, "applied")
    fallos = []
    eventos = 0
    esperados = {}                      # filename -> candidate_sha256 (el último manda)

    prev = "GENESIS"
    for i, ln in enumerate(open(ledger)):
        ln = ln.strip()
        if not ln:
            continue
        try:
            d = json.loads(ln)
        except ValueError:
            fallos.append("linea %d: JSON invalido" % i)
            break
        if d.get("prev") != prev:
            fallos.append("linea %d: cadena rota" % i)
            break
        if d.get("event") == "codegen":
            eventos += 1
            if recompute(d) != d.get("hash"):
                fallos.append("linea %d: hash no recomputa (contenido alterado)" % i)
            if not d.get("sig9c") or d.get("sig9c_slot") != "9c":
                fallos.append("linea %d: evento codegen SIN firma 9c" % i)
            if d.get("filename"):
                esperados[d["filename"]] = d.get("candidate_sha256", "")
        prev = d.get("hash", prev)

    aplicados = sorted(os.listdir(applied)) if os.path.isdir(applied) else []
    for fn in aplicados:
        if fn not in esperados:
            fallos.append("applied/%s: HUERFANO (sin evento en el ledger)" % fn)
        elif sha256_file(os.path.join(applied, fn)) != esperados[fn]:
            fallos.append("applied/%s: sha256 NO coincide con lo firmado" % fn)
    for fn in esperados:
        if fn not in aplicados:
            fallos.append("falta applied/%s (el ledger lo da por aplicado)" % fn)

    return {"eventos": eventos, "aplicados": len(aplicados), "fallos": fallos,
            "veredicto": "AUDIT_OK" if not fallos else "AUDIT_FALLA"}


def main():
    out = {"svc": "codegen_audit", "ts": int(time.time())}
    if not os.path.exists(os.path.join(ROOT, "codegen_ledger.jsonl")):
        out["estado"] = "SIN_CODEGEN"          # nodo sin astra-code (p.ej. nodo-c): no-op
        print(json.dumps(out, ensure_ascii=False))
        return
    try:
        out.update(audit())
        out["estado"] = out.pop("veredicto")
    except Exception as e:                     # observe-only: nunca tirar la capa
        out["estado"] = "AUDIT_ERROR"
        out["error"] = str(e)[:200]
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()
