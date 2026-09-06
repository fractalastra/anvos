#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""gpu_enable — habilita la iGPU Intel Arc (Meteor Lake, 8086:7d55) del portátil en ANVOS.
FASE 1 (render node): carga la cadena i915 FIRMADA (bundle i915-native, patrón wg-native) + el
firmware Meteor Lake FIRMADO (mtl_guc/huc/gsc/dmc), apuntando el firmware loader del kernel a una
ruta de /persist (no toca /lib). Objetivo: que aparezca /dev/dri/renderD128 (GPU accesible).

FAIL-CLOSED: cada .ko y cada .bin se verifica con el minisign de release embebido ANTES de cargar/exponer;
firma ausente/ inválida -> ese componente NO se usa. Idempotente y convergente bajo el MAX_RUNTIME
de layerd (los módulos ya cargados persisten; la siguiente pasada continúa).

NO hace inferencia: eso es la FASE 2 (runtime de cómputo Level Zero/oneAPI, pesado, aparte).
Este servicio solo EXPONE la GPU. Solo stdlib."""
import os
import json
import time
import glob
import subprocess

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
PERSIST = os.environ.get("ANVOS_PERSIST", "/persist")
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
MS = os.path.join(STAGING, "pylayer-verify")
PUB = os.path.join(STAGING, "pylayer", "release.pub")
BUNDLE = os.path.join(STAGING, "i915-native")
MODDIR = os.path.join(BUNDLE, "modules")
FWSRC = os.path.join(BUNDLE, "firmware")            # .../firmware/i915/*.bin
FWDST = os.path.join(PERSIST, "anvos-gpu", "firmware")   # ruta que verá el firmware loader
FW_PATH_PARAM = "/sys/module/firmware_class/parameters/path"
REC = os.path.join(DATA, "gpu", "gpu_enable.jsonl")
IGPU_PCI = "0000:00:02.0"
IGPU_IDS = ("0x8086", "0x7d55")   # vendor/device de la iGPU que este servicio habilita


def _run(cmd, timeout=30):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None


def _ld():
    return next(iter(glob.glob(os.path.join(MS, "ld-linux*.so.2"))), None)


def _verify_sig(target):
    ld = _ld()
    sig = target + ".minisig"
    if not (ld and os.path.exists(os.path.join(MS, "minisign")) and os.path.exists(PUB)
            and os.path.isfile(target) and os.path.isfile(sig)):
        return False
    r = _run([ld, "--library-path", MS, os.path.join(MS, "minisign"),
              "-Vm", target, "-p", PUB, "-x", sig], timeout=8)
    return bool(r) and r.returncode == 0


def _mod_loaded(name):
    return os.path.isdir("/sys/module/" + name.replace("-", "_"))


def place_firmware():
    """Copia el firmware FIRMADO a /persist y apunta el loader del kernel ahí (no toca /lib)."""
    dst_i915 = os.path.join(FWDST, "i915")
    os.makedirs(dst_i915, exist_ok=True)
    placed, blocked = [], []
    for bin_ in sorted(glob.glob(os.path.join(FWSRC, "i915", "*.bin"))):
        if not _verify_sig(bin_):
            blocked.append(os.path.basename(bin_))
            continue
        dst = os.path.join(dst_i915, os.path.basename(bin_))
        if not os.path.isfile(dst):
            with open(bin_, "rb") as s, open(dst, "wb") as d:
                d.write(s.read())
        placed.append(os.path.basename(bin_))
    # registrar la ruta en el firmware loader (append si ya hay otras)
    try:
        cur = open(FW_PATH_PARAM).read().strip()
        if FWDST not in cur:
            open(FW_PATH_PARAM, "w").write(FWDST)
    except Exception:
        pass
    return placed, blocked


def load_chain():
    """Carga la cadena i915 FIRMADA en orden. Devuelve (cargados, bloqueados)."""
    loaded, blocked = [], []
    for ko in sorted(glob.glob(os.path.join(MODDIR, "*.ko"))):
        name = os.path.basename(ko).split("_", 1)[1][:-3]
        if _mod_loaded(name):
            continue
        if not _verify_sig(ko):
            blocked.append(name)
            continue
        r = _run(["insmod", ko])
        (loaded if (r and r.returncode == 0 and _mod_loaded(name)) else blocked).append(name)
    return loaded, blocked


def make_dri_nodes():
    """Crea /dev/dri/{card*,renderD*} desde sysfs (ANVOS no corre udev: hay que mknod).
    Idempotente. Devuelve la lista de nodos creados o ya presentes."""
    os.makedirs("/dev/dri", exist_ok=True)
    made = []
    for devf in glob.glob("/sys/class/drm/*/dev"):
        node = os.path.basename(os.path.dirname(devf))
        if not (node.startswith("card") or node.startswith("renderD")):
            continue
        try:
            maj, minr = open(devf).read().strip().split(":")
        except Exception:
            continue
        path = "/dev/dri/" + node
        if not os.path.exists(path):
            r = _run(["mknod", path, "c", maj, minr])
            if r and r.returncode == 0:
                os.chmod(path, 0o666 if node.startswith("renderD") else 0o660)
        if os.path.exists(path):
            made.append(path)
    return sorted(made)


def dri_nodes():
    return sorted(glob.glob("/dev/dri/*"))


def gpu_bound():
    """¿i915 enlazó la iGPU? (driver symlink en el device PCI)."""
    drv = os.path.join("/sys/bus/pci/devices", IGPU_PCI, "driver")
    tgt = os.path.realpath(drv) if os.path.islink(drv) else ""
    return os.path.basename(tgt) if tgt else None


def igpu_presente():
    """¿Existe en ESTE equipo la iGPU que el servicio habilita? Se mide en sysfs, no se supone.

    ITV-063 (2026-08-07): en nodo-c (VM sin GPU) este servicio fallaba TODAS las pasadas
    (944/944 medidas) por diseño: no había nada que habilitar. Un servicio que falla siempre
    por diseño enseña a ignorar la columna de fallos. Sin el hardware el resultado correcto
    es NO_APLICABLE con éxito, no un fallo. Devuelve (presente, ids_leidos)."""
    base = os.path.join("/sys/bus/pci/devices", IGPU_PCI)
    try:
        vend = open(os.path.join(base, "vendor")).read().strip().lower()
        dev = open(os.path.join(base, "device")).read().strip().lower()
    except Exception:
        return False, None
    return (vend, dev) == IGPU_IDS, "%s:%s" % (vend, dev)


def main():
    rec = {"svc": "gpu_enable", "ts": int(time.time()), "phase": "1-render-node"}
    presente, ids = igpu_presente()
    if not presente:
        rec.update({"state": "NO_APLICABLE", "pci": IGPU_PCI, "pci_ids": ids,
                    "motivo": "este equipo no tiene la iGPU %s:%s: nada que habilitar"
                              % (IGPU_IDS[0][2:], IGPU_IDS[1][2:])})
        _emit(rec)
        return 0
    if not os.path.isdir(MODDIR):
        rec.update({"state": "NO_BUNDLE"})
        _emit(rec)
        return 1
    placed, fw_blocked = place_firmware()
    loaded, mod_blocked = load_chain()
    # ANVOS no corre udev -> crear los nodos /dev/dri desde sysfs si i915 enlazó
    if _mod_loaded("i915"):
        make_dri_nodes()
    nodes = dri_nodes()
    rec.update({
        "firmware_placed": placed, "firmware_blocked": fw_blocked,
        "modules_loaded_now": loaded, "modules_blocked": mod_blocked,
        "i915_loaded": _mod_loaded("i915"), "gpu_driver": gpu_bound(),
        "dri_nodes": nodes,
        "state": ("RENDER_READY" if nodes else
                  "DRIVER_BOUND_NO_NODE" if gpu_bound() == "i915" else
                  "I915_LOADED" if _mod_loaded("i915") else
                  "BLOCKED_SIG" if (mod_blocked or fw_blocked) else "LOADING"),
    })
    _emit(rec)
    return 0 if rec["state"] in ("RENDER_READY", "DRIVER_BOUND_NO_NODE") else 1


def _emit(rec):
    os.makedirs(os.path.dirname(REC), exist_ok=True)
    with open(REC, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(json.dumps(rec, ensure_ascii=False))


if __name__ == "__main__":
    raise SystemExit(main())
