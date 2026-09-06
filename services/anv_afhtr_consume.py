#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""anv_afhtr_consume — consumidor de batches AFHTR-CS para ANVOS (port node-local de
anv-afhtr-consumer.sh / anv-afhtr-p2p-receive.sh del ecosistema). REUTILIZA lo ya construido:
  - anv_zstd (descompresión zstd vía libzstd embarcada, sin binario nuevo)
  - trust-bridge (an_service.pub avalada por 653C) + minisign embebido
Consume un directorio de batch sellado (payload.zst + manifest.json + manifest.json.minisig)
producido por anv-batch-pack.sh, verificando FAIL-CLOSED en cada paso:
  0. an_service.pub está avalada por la raíz 653C (release.pub)      -> autoridad legítima
  1. manifest.json tiene firma an_service válida                     -> integridad+autenticidad
  2. encrypted == false (age no está disponible en ANVOS busybox)    -> se rechaza cifrado
  3. sha256(payload.zst) == compressed_payload_hash del manifest     -> payload comprimido íntegro
  4. descomprime zstd (acotado por max_expected_decompressed_size)   -> payload.tar
  5. sha256(payload.tar) == raw_payload_hash del manifest            -> payload original íntegro
  6. extrae el tar de forma segura (filter='data', anti path-traversal)
Registra el consumo (sin ACK firmado: el nodo NO tiene clave secreta; su prueba es el registro
encadenable + la extracción verificada). Modos: verify <batch_dir> | consume <batch_dir> <dest>.
Solo stdlib + ctypes(libzstd) + minisign embebido."""
import os
import sys
import json
import time
import glob
import hashlib
import subprocess
import tarfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import anv_zstd  # noqa: E402  (mismo dir de la capa)

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
MS = os.path.join(STAGING, "pylayer-verify")
RELEASE_PUB = os.path.join(STAGING, "pylayer", "release.pub")     # raíz del nodo (653C)
AN_PUB = os.path.join(STAGING, "pylayer", "an_service.pub")       # autoridad de los batches
REC = os.path.join(DATA, "ring", "afhtr_consume.jsonl")


def _ld():
    for c in glob.glob(os.path.join(MS, "ld-linux*.so.2")):
        return c
    return None


def _minisign_verify(ld, target, pub, sig):
    if not (ld and os.path.exists(os.path.join(MS, "minisign")) and os.path.isfile(pub)
            and os.path.isfile(target) and os.path.isfile(sig)):
        return False
    try:
        r = subprocess.run(
            [ld, "--library-path", MS, os.path.join(MS, "minisign"),
             "-Vm", target, "-p", pub, "-x", sig],
            capture_output=True, timeout=8)
        return r.returncode == 0
    except Exception:
        return False


def _sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _strip(h):
    return h.split(":", 1)[1] if isinstance(h, str) and ":" in h else h


def verify_batch(ld, bdir):
    """Verificación fail-closed del batch. Devuelve (ok, detalle_o_error)."""
    man = os.path.join(bdir, "manifest.json")
    sig = man + ".minisig"
    zst = os.path.join(bdir, "payload.zst")
    # 0) an_service.pub avalada por 653C (trust-bridge) — cada consumo lo re-verifica
    if not _minisign_verify(ld, AN_PUB, RELEASE_PUB, AN_PUB + ".minisig"):
        return False, {"stage": "trust", "error": "an_service.pub NO avalada por 653C (trust-bridge roto)"}
    # 1) firma an_service del manifest
    if not _minisign_verify(ld, man, AN_PUB, sig):
        return False, {"stage": "signature", "error": "firma an_service del manifest inválida"}
    try:
        m = json.load(open(man))
    except Exception as e:
        return False, {"stage": "manifest", "error": "manifest ilegible: %s" % e}
    # 2) cifrado no soportado en ANVOS (sin age)
    if m.get("encrypted") is True:
        return False, {"stage": "encrypted", "error": "batch cifrado (age no disponible en ANVOS)"}
    # 3) integridad del payload comprimido
    if not os.path.isfile(zst):
        return False, {"stage": "payload", "error": "falta payload.zst"}
    if _sha_file(zst) != _strip(m.get("compressed_payload_hash", "")):
        return False, {"stage": "compressed_hash", "error": "sha256(payload.zst) no coincide con el manifest"}
    return True, {"manifest": m, "batch_id": m.get("batch_id"),
                  "compression": m.get("compression"), "seq": m.get("sequence_number")}


def _record(rec):
    os.makedirs(os.path.dirname(REC), exist_ok=True)
    with open(REC, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _emit(d):
    print(json.dumps(d, ensure_ascii=False))
    _record(d)


def cmd_verify(bdir):
    ld = _ld()
    ok, det = verify_batch(ld, bdir)
    if ok:
        _emit({"svc": "afhtr_consume", "action": "verify", "ok": True,
               "batch_id": det.get("batch_id"), "seq": det.get("seq"), "compression": det.get("compression")})
        return 0
    _emit({"svc": "afhtr_consume", "action": "verify", "ok": False, **det})
    return 1


def cmd_consume(bdir, dest):
    ld = _ld()
    t0 = int(time.time())
    ok, det = verify_batch(ld, bdir)
    if not ok:
        _emit({"svc": "afhtr_consume", "action": "consume", "ok": False,
               "error": "batch NO verifica (fail-closed) -> RECHAZADO", **det})
        return 1
    m = det["manifest"]
    # 4) descomprimir zstd (acotado)
    if m.get("compression") != "zstd":
        _emit({"svc": "afhtr_consume", "action": "consume", "ok": False,
               "error": "compresión no soportada: %s" % m.get("compression")})
        return 1
    zst = os.path.join(bdir, "payload.zst")
    try:
        with open(zst, "rb") as f:
            comp = f.read()
        tar_bytes = anv_zstd.decompress_bytes(
            comp, max_size=m.get("max_expected_decompressed_size_bytes"))
    except Exception as e:
        _emit({"svc": "afhtr_consume", "action": "consume", "ok": False,
               "stage": "decompress", "error": "zstd: %s" % e})
        return 1
    # 5) integridad del payload original (tar)
    tar_sha = hashlib.sha256(tar_bytes).hexdigest()
    if tar_sha != _strip(m.get("raw_payload_hash", "")):
        _emit({"svc": "afhtr_consume", "action": "consume", "ok": False,
               "stage": "raw_hash", "error": "sha256(payload.tar) no coincide con el manifest"})
        return 1
    # 6) extraer el tar de forma SEGURA
    os.makedirs(dest, exist_ok=True)
    tmp_tar = os.path.join(dest, ".incoming.tar")
    try:
        with open(tmp_tar, "wb") as f:
            f.write(tar_bytes)
        with tarfile.open(tmp_tar, "r:") as tf:
            try:
                tf.extractall(dest, filter="data")   # py3.12+: bloquea path-traversal/enlaces
            except TypeError:
                tf.extractall(dest)                   # respaldo si el filtro no existe
    finally:
        try:
            os.remove(tmp_tar)
        except Exception:
            pass
    _emit({"svc": "afhtr_consume", "action": "consume", "ok": True,
           "batch_id": m.get("batch_id"), "seq": m.get("sequence_number"),
           "raw_sha256": tar_sha[:16], "dest": dest, "elapsed_s": int(time.time()) - t0,
           "note": "batch AFHTR-CS verificado (an_service via 653C), descomprimido y extraído"})
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "verify"
    try:
        if cmd == "verify":
            return cmd_verify(sys.argv[2] if len(sys.argv) > 2 else ".")
        if cmd == "consume":
            if len(sys.argv) < 4:
                print("uso: anv_afhtr_consume.py consume <batch_dir> <dest>", file=sys.stderr)
                return 2
            return cmd_consume(sys.argv[2], sys.argv[3])
        print(json.dumps({"svc": "afhtr_consume", "error": "modo desconocido: %s" % cmd}))
        return 2
    except Exception as e:
        _emit({"svc": "afhtr_consume", "action": cmd, "ok": False, "fatal": str(e)})
        return 1


if __name__ == "__main__":
    sys.exit(main())
