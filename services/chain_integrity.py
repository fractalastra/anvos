#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""chain_integrity — extiende el blockchain-de-memoria al PROPIO nodo ANVOS.
Single-shot: encadena las líneas del ledger de telemetría del nodo (beacon.jsonl) con
hash rodante hash_n = sha256(hash_{n-1} + linea) y persiste la cabeza firmable en
/persist/anvos-data/chain/. Detecta manipulación (append-only roto) y emite estado JSON.
Solo stdlib, sin red, defensivo."""
import os, json, time, hashlib

GEN = "0" * 64
# Base de datos del nodo; overridable por entorno para que la puerta de verificación
# pueda ejecutar el servicio contra un ledger sembrado (datos representativos).
BASE = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
CHAIN_DIR = os.path.join(BASE, "chain")
LEDGERS = [
    (os.path.join(BASE, "eco-telem/beacon.jsonl"), "beacon"),
    (os.path.join(BASE, "sentinel/sentinel.jsonl"), "sentinel"),
]

def _machine_id():
    try:
        with open('/etc/machine-id') as f:
            return f.read().strip() or 'unknown'
    except OSError:
        return 'unknown'

def _chain_ledger(path, name):
    """Reconstruye la cadena de un ledger append-only y compara con la cabeza previa.
    Devuelve (lines, head, verified). verified=False si la cadena previa no es prefijo
    o si el ledger retrocedió (líneas borradas)."""
    headf = os.path.join(CHAIN_DIR, name + ".head")
    prev_head = None
    prev_lines = 0
    if os.path.exists(headf):
        try:
            with open(headf) as f:
                raw = f.read().strip()
            # Formato: <head_hex> [<lines>]. Soporta headfiles antiguos sin conteo.
            parts = raw.split()
            if parts and len(parts[0]) == 64:
                prev_head = parts[0]
                if len(parts) > 1:
                    try:
                        prev_lines = int(parts[1])
                    except ValueError:
                        prev_lines = 0
        except OSError:
            prev_head = None
            prev_lines = 0
    h = GEN  # hex str; se codifica a bytes al hashear (evita mezclar str+bytes)
    n = 0
    # FIX v2: hash de la cadena EXACTAMENTE en el punto donde quedó la cabeza previa.
    # Es lo que hay que comparar: la cabeza previa selló prev_lines líneas, no las de ahora.
    h_at_prev = None
    try:
        with open(path, 'rb') as f:
            for raw in f:
                line = raw.rstrip(b'\n')
                if not line:
                    continue
                h = hashlib.sha256(h.encode() + b'\n' + line).hexdigest()
                n += 1
                if prev_lines and n == prev_lines:
                    h_at_prev = h
    except OSError:
        return (0, None, None)

    # Determinar veredicto. Sin baseline => None (primera vez).
    #
    # FIX v2 (regresión detectada 25-ago-2026 en origo, ledger de esta corrección):
    # la v1 comparaba `h` (cabeza de TODAS las líneas de AHORA) contra `prev_head`
    # (cabeza sellada en la pasada ANTERIOR, con menos líneas). En un ledger
    # append-only que CRECE esos dos valores no pueden coincidir nunca, así que
    # `verified` salía False en cuanto se añadía una sola línea; y como la cabeza
    # solo se persiste si la verificación no falla, quedaba congelada => fallo
    # permanente. Medido en origo: beacon y sentinel en FALLO 18 s después de
    # desplegar la v1, con los ledgers intactos. Era un FALSO POSITIVO, no tamper.
    #
    # Lo correcto es comparar por PREFIJO: recomputar hasta prev_lines y comprobar
    # que ese tramo sigue dando la cabeza sellada. Eso sí detecta reescritura
    # in-place del tramo ya sellado, que era el objetivo del hallazgo original.
    verified = None
    if prev_head is not None:
        if n < prev_lines:
            # El ledger retrocedió: líneas desaparecieron (append-only roto).
            verified = False
        elif not prev_lines:
            # Cabecera antigua (solo hash, sin conteo): no hay punto de comparación
            # fiable. NO se declara fallo — se re-baselina al formato con conteo.
            verified = None
        elif h_at_prev is None:
            # No se alcanzó prev_lines pese a n >= prev_lines: líneas vacías/saltadas
            # cambiaron el conteo efectivo. Sin punto comparable => re-baselinar.
            verified = None
        elif h_at_prev != prev_head:
            # El tramo YA SELLADO no reproduce su cabeza: reescritura in-place.
            verified = False
        else:
            # Prefijo intacto y crecimiento append-only sano.
            verified = True

    try:
        os.makedirs(CHAIN_DIR, exist_ok=True)
        # Solo persistimos la nueva cabeza si la verificación no falló.
        # Si falló, conservamos la cabeza previa como evidencia del último estado conocido.
        if verified is not False:
            tmp = headf + ".tmp"
            with open(tmp, 'w') as f:
                f.write("%s %d\n" % (h, n))
            os.replace(tmp, headf)
    except OSError:
        pass
    return (n, h, verified)

def main():
    chains = []
    for path, name in LEDGERS:
        lines, head, verified = _chain_ledger(path, name)
        if head is None and lines == 0 and not os.path.exists(path):
            continue  # ledger aún no existe; nada que encadenar
        chains.append({
            "ledger": name,
            "lines": lines,
            "head": head[:16] if head else None,
            "verified": verified,
        })
    rec = {
        "svc": "chain_integrity",
        "ts": int(time.time()),
        "node": _machine_id(),
        "chains": chains,
        "all_ok": all(c["verified"] is not False for c in chains),
    }
    print(json.dumps(rec, ensure_ascii=False))

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(json.dumps({"svc": "chain_integrity", "ts": int(time.time()),
                          "error": str(e)}, ensure_ascii=False))
