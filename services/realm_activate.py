#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""realm_activate — LADO-NODO de la soberanía (Vía A): activa el nodo como su propio REALM.

Cierra el ciclo instalación→soberanía en el nodo. El instalador deja el nodo en
`clean-node-pending-genesis` con la capa firmada. Tras la ceremonia de provisión en la autoridad,
ésta COPIA un PACK público/verificable a `/persist/anvos-realm/`:
  realm-root.cert · <node>.cert · realm_root.pub · node_registry.json · escrow_ref.json ·
  provision_manifest.json (lista+sha256, firmado con la clave de servicio)
La RAÍZ PRIVADA nunca se provisiona al nodo: queda bajo custodia externa de la autoridad.

Este servicio, por ciclo:
  - si el nodo ya es `sovereign-realm` -> emite estado del realm (no-op).
  - si está `clean-node-pending-genesis` y hay PACK -> VERIFICA fail-closed (todos los ficheros del
    manifiesto casan su sha256; firma del manifiesto si es verificable en el nodo; linaje presente
    realm-root+node cert+realm_root.pub) -> ACTIVA: fija la identidad del realm, transiciona el estado a
    `sovereign-realm`, y expone el realm (realm/realm.jsonl para GUI).
  - si está pending y NO hay pack -> sigue esperando (pending).
FAIL-CLOSED: cualquier fallo de integridad -> NO activa (el nodo no reclama soberanía en falso).
Observe/verify-only: el nodo NO firma; sólo consume y verifica lo que el master (autoridad) provisionó.
Solo stdlib. Fail-safe."""
import os
import sys
import json
import time
import hashlib
import glob
import subprocess
import socket

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
PERSIST = os.environ.get("ANVOS_PERSIST", "/persist")
STATE_FILE = os.path.join(PERSIST, "anvos-node.state")
REALM_DIR = os.path.join(PERSIST, "anvos-realm")
MANIFEST = os.path.join(REALM_DIR, "provision_manifest.json")
OUT = os.path.join(DATA, "realm", "realm.jsonl")             # estado del realm (para dashboard/cockpit)
STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
_MS = os.path.join(STAGING, "pylayer-verify")               # verificador minisign embebido del nodo
# pub de la clave de servicio (firma el manifiesto de provisión). El ancla de confianza NO va
# embebida en el fuente publicado: la despliega el seed en las rutas de abajo, o se declara por
# entorno (ANVOS_ANSERVICE_PUB). Sin ancla verificable, el nodo NO se activa (fail-closed).
_ANSERVICE_PUBS = [p for p in (os.path.join(STAGING, "an_service.pub"),
                   os.path.join(DATA, "keys", "an_service.pub"),
                   os.environ.get("ANVOS_ANSERVICE_PUB", "")) if p]

STATE_PENDING = "clean-node-pending-genesis"
STATE_SOVEREIGN = "sovereign-realm"


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _read_state():
    try:
        return open(STATE_FILE).read().strip()
    except Exception:
        return ""


def _write_state(s):
    try:
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            f.write(s + "\n")
        os.replace(tmp, STATE_FILE)
        return True
    except Exception:
        return False


def _sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _emit(rec):
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL realm_activate._emit: %r" % (e,), file=sys.stderr, flush=True)
    print(json.dumps(rec, ensure_ascii=False))


def _minisign_verify(target, pub):
    """Verifica target contra pub con el minisign embebido del nodo (pylayer-verify). True/False."""
    ld = None
    for c in glob.glob(os.path.join(_MS, "ld-linux*.so.2")):
        ld = c
    sig = target + ".minisig"
    if not (ld and os.path.exists(os.path.join(_MS, "minisign")) and os.path.isfile(pub)
            and os.path.isfile(target) and os.path.isfile(sig)):
        return None            # material insuficiente para verificar (no es fallo duro)
    try:
        r = subprocess.run([ld, "--library-path", _MS, os.path.join(_MS, "minisign"),
                            "-Vm", target, "-p", pub, "-x", sig], capture_output=True, timeout=8)
        return r.returncode == 0
    except Exception:
        return None


def _minisign_verify_any(target, pub):
    """Verifica con el minisign embebido del nodo (pylayer-verify) o, si no está, con un `minisign` del PATH."""
    v = _minisign_verify(target, pub)
    if v is not None:
        return v
    sig = target + ".minisig"
    if not (os.path.isfile(pub) and os.path.isfile(sig)):
        return None
    try:
        r = subprocess.run(["minisign", "-Vm", target, "-p", pub, "-x", sig], capture_output=True, timeout=8)
        return r.returncode == 0
    except Exception:
        return None


def _parse_manifest(path):
    """Parsea el manifiesto REAL (formato sha256sum + cabecera '# ...'/'clave=valor').
    Devuelve [(sha256, basename), ...] de los ficheros del pack (excluye el propio manifiesto y su firma)."""
    entries = []
    try:
        for ln in open(path):
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            parts = ln.split(None, 1)
            if len(parts) != 2:
                continue
            h, name = parts[0].lower(), os.path.basename(parts[1].strip())   # ruta con prefijo realm/ -> basename
            if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
                continue                                                     # línea de cabecera clave=valor
            if name in ("provision_manifest.json", "provision_manifest.json.minisig"):
                continue                                                     # auto-inclusión: no verificable desde sí mismo
            entries.append((h, name))
    except Exception:
        pass
    return entries


def _verify_pack():
    """Verifica el PACK fail-closed. Devuelve (ok, info, motivo_si_falla)."""
    if not os.path.isfile(MANIFEST):
        return False, {}, "sin provision_manifest.json"
    entries = _parse_manifest(MANIFEST)
    if not entries:
        return False, {}, "manifiesto sin ficheros verificables (formato)"
    checked = 0
    for want, name in entries:
        got = _sha256(os.path.join(REALM_DIR, name))
        if got is None:
            return False, {}, "falta fichero del pack: %s" % name
        if got.lower() != want:
            return False, {}, "sha256 no casa: %s" % name
        checked += 1
    # firma del manifiesto (an_service): OBLIGATORIA y fail-closed. Grieta hallada en red-team interno:
    # antes, si FALTABA el .minisig pero los sha256 casaban, el nodo se activaba (fail-OPEN). Ahora la firma
    # es requisito: sin .minisig, o si NINGUNA pub de confianza la verifica, NO se activa (fail-closed).
    if not os.path.isfile(MANIFEST + ".minisig"):
        return False, {}, "provision_manifest SIN FIRMA (.minisig ausente) -> fail-closed (firma obligatoria)"
    pubs = list(_ANSERVICE_PUBS)
    sig_status = None
    for pub in pubs:
        v = _minisign_verify_any(MANIFEST, pub)
        if v is True:
            sig_status = "an_service-VERIFICADA"
            break
        if v is False:
            return False, {}, "firma del manifiesto INVÁLIDA (an_service)"
    if sig_status != "an_service-VERIFICADA":
        # ni verificada ni invalida = no se pudo verificar con ninguna pub de confianza (o falta el verificador)
        return False, {}, "firma del manifiesto NO VERIFICABLE con pub de confianza -> fail-closed"
    # linaje presente (los certs + la pública de raíz)
    have_root = bool(glob.glob(os.path.join(REALM_DIR, "realm-root.cert")))
    have_rootpub = bool(glob.glob(os.path.join(REALM_DIR, "realm_root.pub")))
    node_certs = [c for c in glob.glob(os.path.join(REALM_DIR, "*.cert"))
                  if os.path.basename(c) != "realm-root.cert"]
    if not (have_root and have_rootpub and node_certs):
        return False, {}, "linaje incompleto (falta realm-root.cert/realm_root.pub/node.cert)"
    # identidad best-effort desde node_registry.json
    realm_id = node_id = None
    try:
        reg = json.loads(open(os.path.join(REALM_DIR, "node_registry.json")).read())
        realm_id = reg.get("realm") or reg.get("realm_id") or (reg.get("realm_anchor") or {}).get("id")
        node_id = reg.get("node") or reg.get("node_id")
        nodes = reg.get("nodes")
        if node_id is None and isinstance(nodes, dict) and nodes:
            node_id = next(iter(nodes))
    except Exception:
        pass
    info = {"realm_id": realm_id, "node_id": node_id, "node_cert": os.path.basename(node_certs[0]),
            "files_verificados": checked, "firma_manifiesto": sig_status,
            "escrow_ref": os.path.isfile(os.path.join(REALM_DIR, "escrow_ref.json"))}
    return True, info, None


def cmd_cycle():
    state = _read_state()
    node = None
    for p in ("/persist/anvos-node.id", "/etc/anvos-node.id"):
        try:
            node = open(p).read().strip() or None
        except Exception:
            pass
        if node:
            break
    node = node or (socket.gethostname() or "anvos-node")

    if state == STATE_SOVEREIGN:
        # ya soberano: emite estado del realm (leer del pack para el GUI)
        realm_id = node_id = None
        try:
            reg = json.loads(open(os.path.join(REALM_DIR, "node_registry.json")).read())
            realm_id = reg.get("realm") or reg.get("realm_id")
            node_id = reg.get("node") or reg.get("node_id")
        except Exception:
            pass
        _emit({"svc": "realm_activate", "ts": int(time.time()), "node": node, "estado": STATE_SOVEREIGN,
               "realm_id": realm_id, "node_id": node_id, "soberano": True,
               "note": "nodo activo como su propio realm (autoridad = quórum 2-de-2, raíz no residente)"})
        return 0

    if state != STATE_PENDING:
        # no instalado o estado desconocido: nada que activar
        _emit({"svc": "realm_activate", "ts": int(time.time()), "node": node, "estado": state or "-",
               "soberano": False, "note": "sin estado pending-genesis; nada que activar"})
        return 0

    # pending: ¿hay pack provisionado?
    if not os.path.isdir(REALM_DIR) or not os.path.isfile(MANIFEST):
        _emit({"svc": "realm_activate", "ts": int(time.time()), "node": node, "estado": STATE_PENDING,
               "soberano": False, "pack": False,
               "note": "esperando provisión del realm por la autoridad (Vía A)"})
        return 0

    ok, info, why = _verify_pack()
    if not ok:
        # FAIL-CLOSED: no activa; el nodo sigue pending (no reclama soberanía en falso)
        _emit({"svc": "realm_activate", "ts": int(time.time()), "node": node, "estado": STATE_PENDING,
               "soberano": False, "pack": True, "verificado": False, "motivo": why,
               "note": "PACK presente pero NO verifica -> fail-closed, sigue pending"})
        return 1

    # #3 (red-team interno): BIND al nodo LOCAL. Un pack firmado VÁLIDO pero para OTRO nodo (replay/misdirigido)
    # no debe activar soberanía aquí -> el node_id del pack debe coincidir con la identidad local.
    pack_node = info.get("node_id")
    if pack_node and node and pack_node != node:
        _emit({"svc": "realm_activate", "ts": int(time.time()), "node": node, "estado": STATE_PENDING,
               "soberano": False, "pack": True, "verificado": True,
               "motivo": "pack de OTRO nodo (node_id=%s != local=%s)" % (pack_node, node),
               "note": "PACK verificado pero NO es de este nodo -> fail-closed (anti-replay/misdireccion)"})
        return 1

    # ACTIVAR: transición a soberano
    if not _write_state(STATE_SOVEREIGN):
        _emit({"svc": "realm_activate", "ts": int(time.time()), "node": node, "estado": STATE_PENDING,
               "soberano": False, "note": "verificado OK pero no pude escribir el estado"})
        return 1
    rec = {"svc": "realm_activate", "ts": int(time.time()), "node": node, "estado": STATE_SOVEREIGN,
           "soberano": True, "activado": True, "realm_id": info.get("realm_id"),
           "node_id": info.get("node_id"), "node_cert": info.get("node_cert"),
           "firma_manifiesto": info.get("firma_manifiesto"), "escrow_ref": info.get("escrow_ref"),
           "files_verificados": info.get("files_verificados"),
           "note": "GENESIS consumida: nodo ACTIVADO como su propio realm soberano (verificado fail-closed)"}
    _emit(rec)
    return 0


def cmd_status():
    print(json.dumps({"svc": "realm_activate", "estado_nodo": _read_state() or "-",
                      "pack_presente": os.path.isfile(MANIFEST)}, ensure_ascii=False))
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "cycle"
    try:
        if cmd in ("cycle", "run", "probe"):
            return cmd_cycle()
        if cmd == "status":
            return cmd_status()
        print(json.dumps({"svc": "realm_activate", "error": "modo desconocido: %s" % cmd}))
        return 2
    except Exception as e:
        print(json.dumps({"svc": "realm_activate", "ok": False, "fatal": str(e)}, ensure_ascii=False))
        return 0


if __name__ == "__main__":
    sys.exit(main())
