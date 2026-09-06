#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""cognition_guard — LATIDO DE GOBERNANZA del nodo ANVOS.
Distinto de self_integrity (que verifica la INTEGRIDAD de los ficheros de la capa): este
guarda verifica que el nodo sigue operando bajo AUTORIDAD LEGÍTIMA e invariantes de gobierno.
Cada ciclo comprueba, fail-closed en el VEREDICTO (nunca lanza):
  1. Constitución del nodo presente y FIRMADA por anvos_release.pub (autoridad de release del OS).
  2. Invariante de modo: la constitución declara OBSERVE_ONLY y el nodo lo respeta (sentinel observe_only).
  3. Autoridad presente: anvos_release.pub (gobierna al OS) y release.pub 653C (firma la capa).
  4. Identidad propia presente y estable (la deriva se ve en la cadena de latidos).
  5. Afiliación: estado dinámico (membership.json); se reporta y se marca cambio (evento de gobierno).
Veredicto: GOBERNADO / DEGRADADO / SIN_GOBIERNO. Firma su propio estado (self_sha256), como
exige el principio constitucional 'cada ciclo firma su estado'. Solo stdlib. Observe-only puro
(no muta nada del sistema). Overridable por ANVOS_STAGING para ejercitarlo desde la puerta."""
import os
import json
import time
import glob
import hashlib
import subprocess

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
ECO = os.environ.get("ANVOS_ECO", "/opt/anvos/ecosystem")
MS = os.path.join(STAGING, "pylayer-verify")               # minisign embebido + ld + libs
CONSTITUTION = os.path.join(ECO, "constitution.json")
ANVOS_PUB = os.path.join(ECO, "anvos_release.pub")          # autoridad del OS (gobierna el nodo)
LAYER_PUB = os.path.join(STAGING, "pylayer", "release.pub")  # clásica (caída de compatibilidad)
RELEASE_D = os.path.join(STAGING, "pylayer", "release.d")


_BAKED_PUB = "/opt/anvos-verify/release.pub"   # ancla de autoridad de capa (653C horneada)


def _release_pubs():
    """Conjunto de claves de autoridad de CAPA (ITAUTH-ORIGO F0): release.d/*.pub;
    sin set, cae a la clásica; sin ninguna, lista vacía (autoridad AUSENTE)."""
    pubs = sorted(glob.glob(os.path.join(RELEASE_D, "*.pub"))) if os.path.isdir(RELEASE_D) else []
    if not pubs and os.path.isfile(LAYER_PUB):
        pubs = [LAYER_PUB]
    return pubs
IDENTITY_FILES = ("/persist/anvos-data/varlib/node/identity",
                  "/persist/anvos-node.id")
MEMBERSHIP = "/var/lib/astranova/node/membership.json"


def _machine_id():
    try:
        with open('/etc/machine-id') as f:
            return f.read().strip() or 'unknown'
    except OSError:
        return 'unknown'


def _find_ld():
    for c in glob.glob(os.path.join(MS, "ld-linux*.so.2")):
        return c
    return None


def _verify(ld, target, pub, sig):
    """Verifica firma con el minisign embebido. True si válida."""
    try:
        r = subprocess.run(
            [ld, "--library-path", MS, os.path.join(MS, "minisign"),
             "-Vm", target, "-p", pub, "-x", sig],
            capture_output=True, timeout=6)
        return r.returncode == 0
    except Exception:
        return False


def _keyid(pubpath):
    """Extrae el keyid del comentario de una clave pública minisign."""
    try:
        with open(pubpath) as f:
            first = f.readline()
        # 'untrusted comment: minisign public key <KEYID>'
        if "public key" in first:
            return first.strip().split()[-1]
    except Exception:
        pass
    return None


def _read(path, limit=4096):
    try:
        with open(path) as f:
            return f.read(limit)
    except Exception:
        return None


def _identity():
    for p in IDENTITY_FILES:
        v = _read(p, 256)
        if v and v.strip():
            return v.strip()
    return None


def main():
    ld = _find_ld()
    verifier_ok = bool(ld) and os.path.exists(os.path.join(MS, "minisign"))
    invariants = {}
    drift = []

    # ── 1) constitución presente + firmada por la autoridad del OS ──
    const_present = os.path.isfile(CONSTITUTION) and os.path.isfile(CONSTITUTION + ".minisig")
    authority_present = os.path.isfile(ANVOS_PUB)
    const_sig_ok = False
    const = {}
    if const_present:
        try:
            const = json.loads(_read(CONSTITUTION) or "{}")
        except Exception:
            const = {}
        if verifier_ok and authority_present:
            const_sig_ok = _verify(ld, CONSTITUTION, ANVOS_PUB, CONSTITUTION + ".minisig")
    invariants["constitucion_presente"] = const_present
    invariants["constitucion_firmada"] = const_sig_ok
    invariants["autoridad_os_presente"] = authority_present
    # La autoridad de capa REAL es la 653C horneada (ancla Set-B, inmutable), no lo que
    # haya en release.d (que tras la partición son solo claves rutinarias Set-A).
    invariants["autoridad_capa_presente"] = os.path.isfile(_BAKED_PUB) or bool(_release_pubs())

    # ── 2) invariante de modo (la constitución manda) ──
    declared_mode = const.get("mode")
    invariants["modo_declarado"] = declared_mode
    invariants["modo_observe_only"] = (declared_mode == "OBSERVE_ONLY")

    # ── 3) identidad propia presente (deriva visible en la cadena de latidos) ──
    ident = _identity()
    invariants["identidad_presente"] = bool(ident)

    # ── 4) afiliación: estado dinámico (constitución = baseline sellado) ──
    const_affil = const.get("affiliation", "none")
    membership = None
    if os.path.isfile(MEMBERSHIP):
        try:
            membership = json.loads(_read(MEMBERSHIP) or "{}")
        except Exception:
            membership = {}
    cur_affil = (membership or {}).get("affiliation", const_affil)
    invariants["afiliacion_constitucion"] = const_affil
    invariants["afiliacion_actual"] = cur_affil
    if cur_affil != const_affil:
        # cambio de afiliación = acto de gobierno; se registra para que el master lo correlacione
        drift.append("afiliacion cambiada %s->%s (verificar admisión soberana)" % (const_affil, cur_affil))

    # ── veredicto fail-closed sobre la GOBERNANZA ──
    # SIN_GOBIERNO: se rompe el ancla de autoridad (constitución ausente/no firmada o sin clave OS)
    breach = (not const_present) or (not authority_present) or (verifier_ok and not const_sig_ok)
    # DEGRADADO: invariante blando roto (identidad ausente, modo inesperado, deriva de afiliación)
    soft = (not ident) or (declared_mode not in (None, "OBSERVE_ONLY")) or bool(drift)
    if breach:
        verdict = "SIN_GOBIERNO"
    elif not verifier_ok:
        # sin verificador embebido (p.ej. ejercitado desde la puerta del master): no es brecha
        verdict = "GOBERNADO_SIN_VERIFICADOR" if const_present and authority_present else "SIN_GOBIERNO"
    elif soft:
        verdict = "DEGRADADO"
    else:
        verdict = "GOBERNADO"

    rec = {
        "svc": "cognition_guard",
        "ts": int(time.time()),
        "node": _machine_id(),
        "node_id": ident,
        "verifier_ok": verifier_ok,
        "authority_os_keyid": _keyid(ANVOS_PUB),
        # retrocompatible: el campo clásico sigue siendo UN keyid (el primero del set);
        # el plural expone el conjunto completo sin romper a consumidores del latido
        # keyid de la autoridad de capa = la horneada (ancla Set-B); el plural añade las
        # claves rutinarias Set-A presentes en release.d (informativo).
        "authority_layer_keyid": (_keyid(_BAKED_PUB) if os.path.isfile(_BAKED_PUB)
                                  else (_keyid(_release_pubs()[0]) if _release_pubs() else None)),
        "authority_layer_keyids": ([_keyid(_BAKED_PUB)] if os.path.isfile(_BAKED_PUB) else [])
                                  + [_keyid(p) for p in _release_pubs()],
        "constitution_typ": const.get("typ"),
        "mode": declared_mode,
        "invariants": invariants,
        "drift": drift,
        "governed": verdict in ("GOBERNADO", "GOBERNADO_SIN_VERIFICADOR"),
        "verdict": verdict,
    }
    # firma del propio estado (self_sha256), como manda la constitución
    rec["self_sha256"] = hashlib.sha256(
        json.dumps(rec, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()
    print(json.dumps(rec, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # nunca romper el supervisor
        print(json.dumps({"svc": "cognition_guard", "ts": int(time.time()),
                          "verdict": "ERROR", "governed": False, "error": str(e)},
                         ensure_ascii=False))
