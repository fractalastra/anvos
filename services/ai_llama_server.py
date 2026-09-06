#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""ai_llama_server — cerebro local RESIDENTE del nodo (llama.cpp server en la iGPU).

Cierra el pendiente-taller de item6: la vía llama-cli pagaba POR PETICIÓN el arranque del
proceso + carga del modelo (fría 4s / caliente 2s solo de preámbulo). El server mantiene el
modelo cargado en la iGPU (Vulkan) y atiende por HTTP local: /health al instante y
/completion sin recarga; ai_rag lo usa como PRIMERA vía de generación local.

FAIL-CLOSED: antes de ejecutar se verifican las firmas 653C del binario llama-server, del
backend libggml-vulkan y del VERSION del bundle; sin firma válida NO se arranca (el ciclo
de layerd re-verifica además este .py por-ejecución). SOLO escucha en 127.0.0.1 (plano
local del nodo; nada se expone a la red). LONG_RUNNING bajo layerd: respawn si muere.

Lección 954MB: el server corre con -lv 0 (silencio) y su stderr va a un log propio truncado
en cada arranque — el stdout de ESTE wrapper (1 línea JSON) es el ledger del servicio.
Solo stdlib."""
import os
import json
import time
import glob
import subprocess

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
MS = os.path.join(STAGING, "pylayer-verify")
PUB = os.path.join(STAGING, "pylayer", "release.pub")
LLAMA = os.path.join(STAGING, "llama-native")
VULKAN = os.path.join(STAGING, "vulkan-native")
HOST = "127.0.0.1"
PORT = int(os.environ.get("ANVOS_LLAMA_PORT", "8090"))
ERRLOG = os.path.join(DATA, "ai", "llama_server.err")


def _verify_sig(target):
    ld = next(iter(glob.glob(os.path.join(MS, "ld-linux*.so.2"))), None)
    sig = target + ".minisig"
    if not (ld and os.path.exists(os.path.join(MS, "minisign")) and os.path.exists(PUB)
            and os.path.isfile(target) and os.path.isfile(sig)):
        return False
    try:
        r = subprocess.run([ld, "--library-path", MS, os.path.join(MS, "minisign"),
                            "-Vm", target, "-p", PUB, "-x", sig],
                           capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def main():
    rec = {"svc": "ai_llama_server", "ts": int(time.time()), "port": PORT}
    srv = os.path.join(LLAMA, "bin", "llama-server")
    vk = os.path.join(LLAMA, "lib", "libggml-vulkan.so.0")
    ver = os.path.join(LLAMA, "VERSION")
    ld = next(iter(glob.glob(os.path.join(VULKAN, "lib", "ld-linux*.so.2"))), None)
    icd = os.path.join(VULKAN, "icd", "intel_icd.json")
    models = glob.glob(os.path.join(LLAMA, "model", "*.gguf"))
    # usar el modelo MÁS GRANDE disponible (mejor calidad): 8b si está, si no el que haya (0.5b)
    # SEGURIDAD (hueco hallado por red-team 26-ago): el MODELO se verifica 653C igual que el motor.
    # Un modelo sin firma valida determina lo que la IA DICE y NO debe ejecutarse. Se elige el
    # modelo mas grande (mejor calidad) DE ENTRE LOS FIRMADOS; el mas grande sin firma cae al
    # siguiente firmado; si NINGUNO esta firmado -> fail-closed. Reutiliza _verify_sig (653C).
    firmados = [m for m in sorted(models, key=lambda p: os.path.getsize(p), reverse=True)
                if _verify_sig(m)] if models else []
    if models and not firmados:
        rec["state"] = "MODELO_SIN_FIRMA_BLOQUEADO"
        print(json.dumps(rec, ensure_ascii=False), flush=True)
        return
    models = firmados[:1]
    if not (ld and models and os.path.isfile(srv)):
        rec["state"] = "SIN_BUNDLE"
        print(json.dumps(rec, ensure_ascii=False), flush=True)
        return
    if not (_verify_sig(srv) and _verify_sig(vk) and _verify_sig(ver)):
        rec["state"] = "FIRMA_INVALIDA_BLOQUEADO"
        print(json.dumps(rec, ensure_ascii=False), flush=True)
        return
    rec["state"] = "ARRANCANDO"
    rec["model"] = os.path.basename(models[0])
    rec["version"] = open(ver).read().strip()[:120]
    print(json.dumps(rec, ensure_ascii=False), flush=True)

    env = dict(os.environ)
    env["VK_DRIVER_FILES"] = icd
    env["VK_ICD_FILENAMES"] = icd
    cache = "/persist/anvos-cache/mesa"
    os.makedirs(cache, exist_ok=True)
    env["MESA_SHADER_CACHE_DIR"] = cache
    env["XDG_CACHE_HOME"] = "/persist/anvos-cache"

    # stderr/stdout del server a log propio TRUNCADO por arranque (nunca al ledger del svc)
    os.makedirs(os.path.dirname(ERRLOG), exist_ok=True)
    fd = os.open(ERRLOG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    # Aceleración: por defecto CPU (robusto en CUALQUIER nodo — el modelo es ~0.5B, CPU basta y
    # es fiable; nodo-c no tiene GPU y el Vulkan de origo se colgaba al init, dejando el server sin
    # servir el puerto). GPU (Vulkan) queda OPT-IN con ANVOS_LLAMA_GPU=1 para nodos donde la iGPU
    # esté verificada. (Fix IA-en-espera 2026-07-22: Vulkan hang -> CPU por defecto.)
    # GPU per-nodo: opt-in por env O por MARCADOR de fichero (origo tiene la iGPU verificada; nodo-c no).
    use_gpu = (os.environ.get("ANVOS_LLAMA_GPU", "0") == "1"
               or os.path.exists(os.path.join(LLAMA, "USE_GPU")))
    if use_gpu:
        accel = ["-ngl", "99", "--device", "Vulkan0"]
        rec["accel"] = "vulkan-igpu"
    else:
        accel = ["-ngl", "0"]
        rec["accel"] = "cpu"
    # -c 2048: contexto acotado para que un modelo grande (8b) QUEPA en la iGPU (con -c 4096 la
    # auto-fit lo mandaba a CPU por memoria). 2048 sobra para lecciones/consultas del nodo.
    ctx = ["-c", "2048"]
    # exec: este proceso PASA A SER el server -> layerd lo supervisa/mata directamente
    os.execve(ld, [ld, "--library-path",
                   os.path.join(LLAMA, "lib") + ":" + os.path.join(VULKAN, "lib"),
                   srv, "-m", models[0], "--host", HOST, "--port", str(PORT)]
                  + accel + ctx + ["--no-warmup", "-lv", "0"], env)


if __name__ == "__main__":
    main()
