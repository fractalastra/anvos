#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""dr_sync — COPIA DR/mirror del nodo al disco externo (2o disco fisico) que monta dr_ext_mount. Replica
los artefactos CRITICOS del nodo (capa MAIN firmada, cadena de bloques, certs de realm, politica de
caducidades) a <dr_root>/<node>/current, con un manifiesto sha256 + snapshots diarios rotados. Cada .py
va con su .minisig (integridad ya firmada 653C); el manifiesto DR es un indice auto-verificable.

FAIL-SAFE y NO destructivo: si el disco DR no esta montado -> NO-OP. NUNCA toca el workspace de IA del
disco (models/datasets/training/core/logs) ni borra nada fuera de la rotacion de snapshots propios.
Observe/act-minimo; cualquier fallo -> se registra y termina en 0 (no bloquea el ecosistema/OS).
Solo stdlib. Uso: dr_sync.py [cycle]."""
import os
import sys
import json
import time
import glob
import hashlib
import shutil

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
CFG = os.path.join(DATA, "dr", "dr_disk.json")
OUT = os.path.join(DATA, "dr", "dr_sync.jsonl")
NODE_ID_FILE = "/persist/anvos-node.id"
KEEP_SNAPSHOTS = 7
SNAP_MIN_INTERVAL = 20 * 3600      # un snapshot como mucho ~cada 20h


def _emit(d):
    print(json.dumps(d, ensure_ascii=False), flush=True)
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "a") as f:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL dr_sync._emit: %r" % (e,), file=sys.stderr, flush=True)


def _mounted(mp):
    try:
        with open("/proc/mounts") as f:
            return any(mp == ln.split()[1] for ln in f if len(ln.split()) > 1)
    except Exception:
        return False


def _node():
    try:
        return open(NODE_ID_FILE).read().strip() or "unknown"
    except Exception:
        return "unknown"


def _sha(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _copy_layer(origen, dst):
    """Copia la capa ENTERA a dst preservando subdirectorios, y ARCHIVA lo que ya no exista.

    DOS DEFECTOS CORREGIDOS (ITV-071, medidos el 2026-08-07)
    ---------------------------------------------------------
    1) LA COPIA ERA PLANA. Se respaldaba `services/*.py` con un glob sin recursion, de modo que el
       arbol semantic_core —cinco ficheros, entre ellos el validador que gobierna que entra en la
       memoria del ecosistema— NO ESTABA EN LA COPIA DE SEGURIDAD. Medido en el nodo soberano: 76
       ficheros respaldados frente a 81 vivos.

       Y no podia detectarse desde dentro: el manifiesto del DR se construye a partir de lo copiado,
       asi que listaba 76 y los 76 estaban. Un manifiesto que solo enumera lo que se copio jamas
       revela lo que no se copio. El ensayo de restauracion daba correcto sobre una copia incompleta.

    2) NO SE PODABA. Un fichero retirado de la capa viva permanecia en la copia para siempre:
       axiom_integrity_checker.py seguia ahi dos dias despues de haber sido retirado de ambos nodos,
       sin firma, haciendo fallar el veredicto de restauracion de forma permanente.

    La poda ARCHIVA, no borra: la regla de la casa es no destruir registros. Lo retirado se mueve a
    .archive/<fecha>/ dentro del propio DR, donde sigue disponible y deja de contaminar el veredicto.
    """
    n = 0
    try:
        os.makedirs(dst, exist_ok=True)
    except Exception:
        return 0

    vivos = set()
    for raiz, _dirs, fich in os.walk(origen):
        if "__pycache__" in raiz:
            continue
        for fn in sorted(fich):
            if not fn.endswith((".py", ".pyz", ".sh", ".yaml", ".minisig", ".mldsa", ".txt")):
                continue
            src = os.path.join(raiz, fn)
            rel = os.path.relpath(src, origen)
            vivos.add(rel)
            destino = os.path.join(dst, rel)
            try:
                os.makedirs(os.path.dirname(destino), exist_ok=True)
                shutil.copy2(src, destino)
                n += 1
            except Exception:
                pass

    # PODA ARCHIVADA: lo que esta en la copia y ya no en el origen
    try:
        arch = os.path.join(os.path.dirname(dst), ".archive",
                            time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
        for raiz, _dirs, fich in os.walk(dst):
            if ".archive" in raiz or "__pycache__" in raiz:
                continue
            for fn in fich:
                rel = os.path.relpath(os.path.join(raiz, fn), dst)
                if rel not in vivos:
                    viejo = os.path.join(raiz, fn)
                    guardado = os.path.join(arch, rel)
                    os.makedirs(os.path.dirname(guardado), exist_ok=True)
                    shutil.move(viejo, guardado)
    except Exception:
        pass
    return n


def _copy_set(srcs, dst):
    """Copia una lista de ficheros a dst (plano). Devuelve nº copiados."""
    n = 0
    try:
        os.makedirs(dst, exist_ok=True)
    except Exception:
        return 0
    for s in srcs:
        if os.path.isfile(s):
            try:
                shutil.copy2(s, os.path.join(dst, os.path.basename(s)))
                n += 1
            except Exception:
                pass
    return n


def _copytree(src, dst):
    n = 0
    if not os.path.isdir(src):
        return 0
    for root, _dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        d = os.path.join(dst, rel) if rel != "." else dst
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            continue
        for fn in files:
            try:
                shutil.copy2(os.path.join(root, fn), os.path.join(d, fn))
                n += 1
            except Exception:
                pass
    return n


def _manifest(root):
    files = []
    _meta = ("dr_manifest.json", "dr_manifest.json.minisig", "dr_last_sync.json")  # volatiles: excluir
    for r, _d, fs in os.walk(root):
        for fn in fs:
            if fn in _meta:
                continue
            p = os.path.join(r, fn)
            files.append({"rel": os.path.relpath(p, root), "sha256": _sha(p),
                          "size": (os.path.getsize(p) if os.path.isfile(p) else None)})
    return files


def _rotate_snapshot(nodedir, current, now):
    """Snapshot diario del current, con retencion KEEP_SNAPSHOTS. Best-effort."""
    snaps = os.path.join(nodedir, "snapshots")
    try:
        os.makedirs(snaps, exist_ok=True)
        existing = sorted(glob.glob(os.path.join(snaps, "20*")))
        # no repetir si el ultimo snapshot es muy reciente
        if existing:
            last = existing[-1]
            try:
                if now - os.path.getmtime(last) < SNAP_MIN_INTERVAL:
                    return None
            except Exception:
                pass
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
        dst = os.path.join(snaps, stamp)
        shutil.copytree(current, dst)
        # retencion GFS-lite NUNCA-BORRAR (regla del ecosistema + diseno P2 de revisor-b): los snapshots que
        # salen de la ventana reciente se ARCHIVAN (move a .archive), jamas se hace rmtree.
        allsnaps = sorted(glob.glob(os.path.join(snaps, "20*")))
        arch = os.path.join(snaps, ".archive")
        for old in allsnaps[:-KEEP_SNAPSHOTS]:
            try:
                os.makedirs(arch, exist_ok=True)
                shutil.move(old, os.path.join(arch, os.path.basename(old)))
            except Exception:
                pass
        return stamp
    except Exception:
        return None


def cmd_cycle():
    try:
        cfg = json.load(open(CFG))
    except Exception:
        _emit({"svc": "dr_sync", "state": "SIN_CONFIG", "note": "nodo sin disco DR (no-op)"})
        return 0
    dr_root = cfg.get("dr_root") or os.path.join(cfg.get("mount", "/mnt/anvos-dr-ext"), "anvos-node-dr")
    mp = cfg.get("mount") or "/mnt/anvos-dr-ext"
    if not _mounted(mp):
        _emit({"svc": "dr_sync", "state": "DR_NO_MONTADO", "note": "dr_ext_mount aun no monto el disco (no-op)"})
        return 0
    # GUARDA de no-pisar (diseno P2 de revisor-b): confirmar que el disco montado es el DR CORRECTO antes de
    # escribir. Senal = marca anvos-dr O el workspace de IA (models/training) presente. Si NADA coincide ->
    # NO escribir (podria ser otro disco montado por error en ese punto). Nunca formatea, nunca pisa la IA.
    marker = os.path.join(dr_root, ".anvos_dr")
    ia_present = os.path.isdir(os.path.join(mp, "models")) or os.path.isdir(os.path.join(mp, "training"))
    if not (os.path.exists(marker) or ia_present):
        _emit({"svc": "dr_sync", "state": "GUARDA_DISCO_NO_RECONOCIDO", "mount": mp,
               "note": "el disco montado no tiene marca anvos-dr ni workspace de IA -> NO se escribe (guarda de seguridad)"})
        return 0
    now = int(time.time())
    node = _node()
    nodedir = os.path.join(dr_root, node)
    current = os.path.join(nodedir, "current")
    counts = {}
    # 1) capa MAIN firmada (servicios + minisigs + manifiesto)
    counts["layer"] = _copy_layer(os.path.join(STAGING, "services"),
                                  os.path.join(current, "layer"))
    # 2) cadena de bloques (tamper-evident)
    counts["chain"] = _copy_set(
        [os.path.join(DATA, "chain", f) for f in
         ("blocks.jsonl", "blocks.head", "block_anchor.jsonl", "beacon.head", "sentinel.head")],
        os.path.join(current, "chain"))
    # 3) certs de realm (soberania del nodo) — pack completo si existe
    counts["realm"] = _copytree("/persist/anvos-realm", os.path.join(current, "realm"))
    # 4) politica de caducidades firmada + id/perfil del nodo
    counts["caducidades"] = _copy_set(
        glob.glob(os.path.join(DATA, "caducidades", "calendario.json*")),
        os.path.join(current, "caducidades"))
    counts["node"] = _copy_set(
        [NODE_ID_FILE, os.path.join("/persist", "anvos-modules", "profile.json"),
         os.path.join("/persist", "anvos-modules", "profile.json.minisig")],
        os.path.join(current, "node"))
    # manifiesto DETERMINISTA (SIN ts volatil): solo cambia su sha si cambia el CONTENIDO del DR -> la
    # firma master-side permanece VALIDA hasta que el contenido cambie de verdad (evita
    # el falso-tamper al restaurar). El instante del sync va aparte, informativo, en dr_last_sync.json.
    files = _manifest(current)
    man = {"typ": "ANVOS-NODE-DR-MANIFEST-v1",
           "node": node, "counts": counts, "n_files": len(files),
           "files": sorted(files, key=lambda x: x.get("rel", "")),
           "note": "copia DR del nodo; cada .py conserva su firma de release; NO incluye el workspace de IA; manifiesto determinista firmado master-side (clave de servicio)"}
    try:
        os.makedirs(current, exist_ok=True)
        # escritura canonica y estable (sort_keys) -> mismo contenido = mismo sha = misma firma
        with open(os.path.join(current, "dr_manifest.json"), "w") as f:
            json.dump(man, f, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        json.dump({"node": node, "synced_at": now,
                   "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))},
                  open(os.path.join(current, "dr_last_sync.json"), "w"), ensure_ascii=False)
    except Exception:
        pass
    snap = _rotate_snapshot(nodedir, current, now)
    # espacio del disco DR
    free_gb = None
    try:
        st = os.statvfs(mp)
        free_gb = round(st.f_bavail * st.f_frsize / (1024 ** 3), 1)
    except Exception:
        pass
    _emit({"svc": "dr_sync", "state": "SINCRONIZADO", "node": node, "dr_root": dr_root,
           "counts": counts, "n_files": len(files), "snapshot": snap, "libre_gb": free_gb,
           "note": "workspace de IA (models/datasets/training) INTACTO; copia DR actualizada"})
    return 0


def main():
    try:
        return cmd_cycle()
    except Exception as e:
        _emit({"svc": "dr_sync", "ok": False, "fatal": str(e)})
        return 0


if __name__ == "__main__":
    sys.exit(main())
