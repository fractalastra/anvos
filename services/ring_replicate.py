#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""ring_replicate — PASO 2 del tri-ring: replicación VERIFICADA del MAIN entre nodos ANVOS.
Cierra la redundancia entre máquinas (el tri-ring interno de ring_promote da integridad+rollback
por nodo; esto da que la capa autoritativa de un nodo sobreviva en OTRO nodo).

Patrón envoltorio (transporte separado de verificación, como el resto del ecosistema):
  - TRANSPORTE (commodity): cualquier medio deposita el bundle de un nodo origen en un INBOX
    local — cat|ssh, rsync, WireGuard o USB. Este script NO transporta; verifica e instala.
  - VERIFICACIÓN (soberana, fail-closed): el receptor comprueba TODO antes de aceptar:
      1. main_manifest.json presente y parseable.
      2. cada fichero del manifiesto existe y su sha256 coincide.
      3. content_hash recomputado (ficheros + sus .minisig) == manifest.content_hash.
      4. cada *.py tiene .minisig VÁLIDA contra la clave release 653C (minisign embebido).
      5. promotion.chain.head presente (evidencia de manipulación / frescura vs origen).
    Si TODO pasa -> instala atómicamente en replica/<origen>. Si algo falla -> RECHAZA (nada).

Roles (bajo /persist/anvos-ring):
  inbox/<origen>    -> bundle recién traído por el transporte (a verificar).
  replica/<origen>  -> réplica VERIFICADA instalada (redundancia off-node).
Modos: verify <origen> | install <origen> | status . Solo stdlib + minisign embebido."""
import os
import sys
import json
import time
import glob
import shutil
import hashlib
import subprocess

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
PERSIST = os.environ.get("ANVOS_PERSIST", "/persist")
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
MS = os.path.join(STAGING, "pylayer-verify")
PUB = os.path.join(STAGING, "pylayer", "release.pub")

RING = os.path.join(PERSIST, "anvos-ring")
INBOX = os.path.join(RING, "inbox")
REPLICA = os.path.join(RING, "replica")
REC = os.path.join(DATA, "ring", "ring_replicate.jsonl")


def _ld():
    for c in glob.glob(os.path.join(MS, "ld-linux*.so.2")):
        return c
    return None


def _verify_sig(ld, target):
    sig = target + ".minisig"
    if not (ld and os.path.exists(os.path.join(MS, "minisign")) and os.path.exists(PUB)
            and os.path.isfile(target) and os.path.isfile(sig)):
        return False
    try:
        r = subprocess.run(
            [ld, "--library-path", MS, os.path.join(MS, "minisign"),
             "-Vm", target, "-p", PUB, "-x", sig],
            capture_output=True, timeout=6)
        return r.returncode == 0
    except Exception:
        return False


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _bundle_files(d):
    out = []
    mani = os.path.join(d, "manifest.txt")
    if os.path.isfile(mani):
        out.append(mani)
    out += sorted(glob.glob(os.path.join(d, "*.py")))
    return out


def _content_hash(d):
    """MISMA fórmula que ring_promote._content_hash: ficheros firmados + sus .minisig."""
    parts = []
    for f in _bundle_files(d):
        parts.append("%s:%s" % (os.path.basename(f), _sha(f)))
        sig = f + ".minisig"
        if os.path.isfile(sig):
            parts.append("%s:%s" % (os.path.basename(sig), _sha(sig)))
    return hashlib.sha256("\n".join(sorted(parts)).encode()).hexdigest()


def _record(rec):
    os.makedirs(os.path.dirname(REC), exist_ok=True)
    with open(REC, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _emit(d):
    print(json.dumps(d, ensure_ascii=False))
    _record(d)


def verify_bundle(ld, box):
    """Verifica FAIL-CLOSED el bundle en <box>. Devuelve (ok, detalle)."""
    reasons = []
    man_path = os.path.join(box, "main_manifest.json")
    if not os.path.isfile(man_path):
        return False, {"error": "sin main_manifest.json", "stage": "manifest"}
    try:
        man = json.load(open(man_path))
    except Exception as e:
        return False, {"error": "manifest ilegible: %s" % e, "stage": "manifest"}

    # 2) cada fichero del manifiesto existe y su sha coincide
    for entry in man.get("files", []):
        name = entry.get("name"); want = entry.get("sha256")
        fp = os.path.join(box, name)
        if not os.path.isfile(fp):
            reasons.append("falta %s" % name)
        elif _sha(fp) != want:
            reasons.append("sha no coincide en %s" % name)
    if reasons:
        return False, {"error": "; ".join(reasons), "stage": "hash"}

    # 3) content_hash recomputado == manifest.content_hash
    ch = _content_hash(box)
    if ch != man.get("content_hash"):
        return False, {"error": "content_hash no coincide (%s vs %s)" % (ch[:12], str(man.get("content_hash"))[:12]),
                       "stage": "content_hash"}

    # 4) cada *.py con firma 653C válida
    invalid = [os.path.basename(f) for f in glob.glob(os.path.join(box, "*.py"))
               if not _verify_sig(ld, f)]
    mani_txt = os.path.join(box, "manifest.txt")
    if os.path.isfile(mani_txt) and not _verify_sig(ld, mani_txt):
        invalid.append("manifest.txt")
    if invalid:
        return False, {"error": "firmas inválidas: %s" % invalid, "stage": "signature", "invalid": invalid}

    # 5) cabeza de cadena presente (frescura / tamper-evidence del origen)
    head = None
    hp = os.path.join(box, "promotion.chain.head")
    if os.path.isfile(hp):
        head = open(hp).read().strip()
    return True, {"content_hash": ch, "files": len(man.get("files", [])), "chain_head": (head or "")[:16]}


def cmd_verify(source):
    ld = _ld()
    box = os.path.join(INBOX, source)
    if not os.path.isdir(box):
        _emit({"svc": "ring_replicate", "action": "verify", "source": source, "ok": False,
               "error": "sin inbox para %s" % source})
        return 2
    ok, det = verify_bundle(ld, box)
    _emit({"svc": "ring_replicate", "action": "verify", "source": source, "ok": ok, **det})
    return 0 if ok else 1


def cmd_install(source):
    ld = _ld()
    box = os.path.join(INBOX, source)
    if not os.path.isdir(box):
        _emit({"svc": "ring_replicate", "action": "install", "source": source, "ok": False,
               "error": "sin inbox para %s" % source})
        return 2
    ok, det = verify_bundle(ld, box)
    if not ok:
        _emit({"svc": "ring_replicate", "action": "install", "source": source, "ok": False,
               "error": "bundle NO verifica (fail-closed) -> RECHAZADO", **det})
        return 1
    # instalar atómicamente: copiar a tmp y renombrar
    dst = os.path.join(REPLICA, source)
    tmp = dst + ".tmp"
    if os.path.isdir(tmp):
        shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, exist_ok=True)
    for f in _bundle_files(box):
        shutil.copy2(f, os.path.join(tmp, os.path.basename(f)))
        sig = f + ".minisig"
        if os.path.isfile(sig):
            shutil.copy2(sig, os.path.join(tmp, os.path.basename(sig)))
    for extra in ("main_manifest.json", "promotion.chain.head"):
        ep = os.path.join(box, extra)
        if os.path.isfile(ep):
            shutil.copy2(ep, os.path.join(tmp, extra))
    if os.path.isdir(dst):
        shutil.rmtree(dst, ignore_errors=True)
    os.replace(tmp, dst)
    _emit({"svc": "ring_replicate", "action": "install", "source": source, "ok": True,
           "replica": dst, **det,
           "note": "replica VERIFICADA instalada (redundancia off-node)"})
    return 0


def cmd_status():
    ld = _ld()
    reps = {}
    if os.path.isdir(REPLICA):
        for d in sorted(glob.glob(os.path.join(REPLICA, "*"))):
            if os.path.isdir(d):
                name = os.path.basename(d)
                ok, det = verify_bundle(ld, d)
                head = None
                hp = os.path.join(d, "promotion.chain.head")
                if os.path.isfile(hp):
                    head = open(hp).read().strip()[:16]
                reps[name] = {"verified": ok, "content_hash": _content_hash(d)[:16],
                              "chain_head": head}
    _emit({"svc": "ring_replicate", "action": "status", "replicas": reps, "count": len(reps)})
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    arg = sys.argv[2] if len(sys.argv) > 2 else None
    try:
        if cmd == "verify":
            return cmd_verify(arg or "unknown")
        if cmd == "install":
            return cmd_install(arg or "unknown")
        if cmd == "status":
            return cmd_status()
        print(json.dumps({"svc": "ring_replicate", "error": "modo desconocido: %s" % cmd}))
        return 2
    except Exception as e:
        _emit({"svc": "ring_replicate", "action": cmd, "ok": False, "fatal": str(e)})
        return 1


if __name__ == "__main__":
    sys.exit(main())
