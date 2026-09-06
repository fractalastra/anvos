#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""reboot_check — VERIFICADOR DE PREPARACIÓN PARA REINICIO del nodo ANVOS (matriz item 1: núcleo).

El rootfs de ANVOS vive en RAM: TODO lo que debe sobrevivir un reinicio tiene que residir en
/persist (disco real) y el arranque protegido debe poder re-ensamblarlo. Un reinicio a ciegas
tras una sesión de cambios puede descubrir tarde que algo quedó solo en RAM. Esta herramienta lo
verifica ANTES, sin reiniciar: la prueba de que la migración de esta sesión es durable.

Comprueba, fail-closed:
  1. /persist es un montaje de DISCO real (no tmpfs) — si fuese RAM, nada persiste.
  2. Identidad del nodo (/persist/anvos-node.id) presente.
  3. Activador firmado (anvos-activate.sh + .minisig) — lo que el init verifica y lanza.
  4. Manifiesto + TODOS los servicios .py con su .minisig en MAIN (la capa que layerd arranca).
  5. self_integrity SEALED (la capa activa verifica su propia firma AHORA).
  6. Bundles nativos presentes (los que habilitan red/GPU/IA al arranque).
  7. Caché de shaders en /persist (para que el primer token tras el boot no recompile).
  8. Tri-ring consistente: MAIN == MIRROR (main_eq_mirror) — el estado autoritativo tiene espejo.
Veredicto: REBOOT_READY (todo durable) / NOT_READY + faltas. OBSERVE-only, no muta, no reinicia.
Solo stdlib. Modo único: run. Herramienta on-demand (no va en el manifiesto; atestada por
self_integrity al vivir en services/)."""
import os
import sys
import json
import time
import glob
import subprocess

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
PERSIST = os.environ.get("ANVOS_PERSIST", "/persist")
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
MAIN = os.path.join(STAGING, "services")
BUNDLES = ("pylayer", "pylayer-verify", "wg-native", "i915-native", "vulkan-native", "llama-native")
PY = os.environ.get("ANVOS_PY", "/usr/bin/anvos-python3")


def _persist_is_disk():
    """/persist debe ser un montaje real (ext4/nvme), no tmpfs/rootfs."""
    try:
        with open("/proc/mounts") as f:
            for ln in f:
                parts = ln.split()
                if len(parts) >= 3 and parts[1] == PERSIST:
                    return parts[2] not in ("tmpfs", "rootfs", "ramfs"), parts[2]
    except Exception:
        pass
    return False, "no-montado"


def _signed_pair(path):
    return os.path.isfile(path) and os.path.isfile(path + ".minisig")


def _self_integrity():
    si = os.path.join(MAIN, "self_integrity.py")
    if not os.path.isfile(si):
        return None, "self_integrity.py ausente"
    try:
        r = subprocess.run([PY, si], capture_output=True, timeout=30, text=True)
        d = json.loads(r.stdout.strip().splitlines()[-1])
        return d.get("attestation"), "%s/%s" % (d.get("verified"), d.get("total"))
    except Exception as e:
        return None, str(e)[:60]


def _ring_synced():
    rp = os.path.join(MAIN, "ring_promote.py")
    if not os.path.isfile(rp):
        return None
    try:
        r = subprocess.run([PY, rp, "status"], capture_output=True, timeout=30, text=True)
        for ln in reversed((r.stdout or "").splitlines()):
            ln = ln.strip()
            if ln.startswith("{"):
                return json.loads(ln).get("main_eq_mirror")
    except Exception:
        pass
    return None


def run():
    checks = []

    def add(name, ok, detail=""):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    disk_ok, fstype = _persist_is_disk()
    add("persist_es_disco", disk_ok, "fstype=%s" % fstype)

    add("identidad", os.path.isfile(os.path.join(PERSIST, "anvos-node.id")),
        os.path.isfile(os.path.join(PERSIST, "anvos-node.id")) and
        open(os.path.join(PERSIST, "anvos-node.id")).read().strip() or "")

    add("activador_firmado", _signed_pair(os.path.join(STAGING, "anvos-activate.sh")))

    svcs = sorted(glob.glob(os.path.join(MAIN, "*.py")))
    unsigned = [os.path.basename(p) for p in svcs if not os.path.isfile(p + ".minisig")]
    add("servicios_firmados", len(svcs) > 0 and not unsigned,
        "%d servicios, %d sin firma" % (len(svcs), len(unsigned)))
    add("manifiesto_firmado", _signed_pair(os.path.join(MAIN, "manifest.txt")))

    att, sidet = _self_integrity()
    add("self_integrity_sealed", att == "SEALED", "%s %s" % (att, sidet))

    missing_b = [b for b in BUNDLES if not os.path.isdir(os.path.join(STAGING, b))]
    add("bundles_presentes", not missing_b,
        "faltan: %s" % ",".join(missing_b) if missing_b else "%d bundles" % len(BUNDLES))

    shcache = os.path.join(PERSIST, "anvos-cache", "mesa")
    ncache = len(glob.glob(os.path.join(shcache, "**", "*"), recursive=True)) if os.path.isdir(shcache) else 0
    add("cache_shaders_persistente", ncache > 0, "%d ficheros" % ncache)

    synced = _ring_synced()
    add("tri_ring_main_eq_mirror", synced is True, "main_eq_mirror=%s" % synced)

    ok_all = all(c["ok"] for c in checks)
    return {"svc": "reboot_check", "ts": int(time.time()), "observe_only": True,
            "verdict": "REBOOT_READY" if ok_all else "NOT_READY",
            "passed": sum(1 for c in checks if c["ok"]), "total": len(checks),
            "no_listos": [c["check"] for c in checks if not c["ok"]],
            "checks": checks,
            "nota": "rootfs en RAM; solo /persist sobrevive. Este check NO reinicia."}


def main():
    r = run()
    print(json.dumps(r, ensure_ascii=False))
    return 0 if r["verdict"] == "REBOOT_READY" else 1


if __name__ == "__main__":
    sys.exit(main())
