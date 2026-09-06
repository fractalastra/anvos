#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""sentinel_immune — capa inmune COMPLETA del Sentinel en la capa ANVOS (OBSERVE-only).
Porta el módulo Sentinel del ecosistema (stdlib) al nodo: orquesta los
analyzers bajo la taxonomía de glóbulos blancos (neutrophil, etc.), clasifica hallazgos y
RECOMIENDA un estado inmune global. NUNCA actúa (t_killer inhibido, bridge ADVISORY).
Complementa sentinel_observe (rápido) con el análisis inmune profundo (secrets/permisos/
duplicados/clasificación) sobre la capa firmada. Solo stdlib (config_loader cae a parser YAML
propio si no hay PyYAML). Emite un registro compacto para el master/cockpit. Fail-safe."""
import os
import sys
import io
import json
import time
import glob
import socket
import subprocess
import contextlib

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
SVCDIR = os.path.join(STAGING, "services")
PYZ = os.path.join(SVCDIR, "sentinel.pyz")
CFG = os.path.join(SVCDIR, "sentinel-anvos.yaml")
MS = os.path.join(STAGING, "pylayer-verify")
PUB = os.path.join(STAGING, "pylayer", "release.pub")


def _verify_sig(target):
    """FAIL-CLOSED: verifica la firma minisign 653C de <target> con el verificador embebido.
    El pyz es código que se importa -> debe estar firmado y válido antes de cargarlo."""
    ld = None
    for c in glob.glob(os.path.join(MS, "ld-linux*.so.2")):
        ld = c
        break
    sig = target + ".minisig"
    if not (ld and os.path.exists(os.path.join(MS, "minisign")) and os.path.exists(PUB)
            and os.path.isfile(target) and os.path.isfile(sig)):
        return False
    try:
        r = subprocess.run([ld, "--library-path", MS, os.path.join(MS, "minisign"),
                            "-Vm", target, "-p", PUB, "-x", sig], capture_output=True, timeout=8)
        return r.returncode == 0
    except Exception:
        return False
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
REC = os.path.join(DATA, "sentinel", "immune.jsonl")
# rutas a auditar: los DATOS OPERATIVOS/mutables del nodo (donde aparecerían anomalías/secretos
# reales). La INTEGRIDAD de los ficheros firmados de la capa ya la atesta self_integrity; aquí el
# inmune vigila lo mutable. NO se escanea el modelo ollama de 2GB ni el tooling firmado (pyz).
SCAN_PATHS = ["/persist/anvos-quarantine"]

# Bundle de herramientas externas del Sentinel (gitleaks/shellcheck) firmadas 653C. Los adapters
# del pyz (gitleaks_adapter.py, shellcheck.py) las localizan por shutil.which -> PATH. Se exponen
# al PATH SOLO si su firma valida (fail-closed: tool no firmada = no expuesta = adapter degrada).
TOOLS_DIR = os.path.join(STAGING, "sentinel-tools")
TOOLS_BIN = os.path.join(TOOLS_DIR, "bin")
# ficheros cuya firma se exige antes de exponer cada herramienta (wrapper + binario real + lib)
TOOL_SIGSET = {
    "gitleaks":   [os.path.join(TOOLS_BIN, "gitleaks"),
                   os.path.join(TOOLS_BIN, "gitleaks.real")],
    "shellcheck": [os.path.join(TOOLS_BIN, "shellcheck"),
                   os.path.join(TOOLS_BIN, "shellcheck.real"),
                   os.path.join(TOOLS_DIR, "lib", "libgmp.so.10")],
}


def _expose_tools():
    """Verifica la firma 653C de cada herramienta del bundle y, si TODOS sus componentes validan,
    antepone el bin del bundle al PATH para que los adapters del Sentinel la encuentren. Devuelve
    la lista de herramientas expuestas. FAIL-CLOSED: firma inválida/ausente -> herramienta NO expuesta."""
    exposed = []
    if not os.path.isdir(TOOLS_BIN):
        return exposed
    for tool, comps in TOOL_SIGSET.items():
        if all(os.path.isfile(c) and _verify_sig(c) for c in comps):
            exposed.append(tool)
    if exposed:
        os.environ["PATH"] = TOOLS_BIN + os.pathsep + os.environ.get("PATH", "")
    return exposed


def _emit(rec):
    try:
        os.makedirs(os.path.dirname(REC), exist_ok=True)
        with open(REC, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL sentinel_immune._emit: %r" % (e,), file=sys.stderr, flush=True)
    print(json.dumps(rec, ensure_ascii=False))


def main():
    node = socket.gethostname() or "anvos-node"
    if not (os.path.isfile(PYZ) and os.path.isfile(CFG)):
        _emit({"svc": "sentinel_immune", "ts": int(time.time()), "node": node,
               "verifier_ok": False, "note": "sentinel.pyz/config no presentes (capa incompleta)"})
        return 0
    # FAIL-CLOSED: no importar el pyz ni usar la config si su firma 653C no valida
    if not (_verify_sig(PYZ) and _verify_sig(CFG)):
        _emit({"svc": "sentinel_immune", "ts": int(time.time()), "node": node,
               "ok": False, "error": "firma de sentinel.pyz/config INVÁLIDA -> no se carga (fail-closed)"})
        return 0
    # exponer gitleaks/shellcheck firmadas al PATH (fail-closed) ANTES de importar/correr el pyz,
    # para que sus adapters (shutil.which) las activen; sin firma válida -> degradan como hasta ahora
    tools = _expose_tools()
    try:
        sys.path.insert(0, PYZ)
        from pathlib import Path
        from sentinel.config_loader import load_config
        from sentinel.immune import run
        cfg = load_config(CFG)
        # acotar a la capa firmada (evita escanear el modelo de IA de 2GB)
        cfg.paths = [Path(p) for p in SCAN_PATHS if os.path.isdir(p)] or cfg.paths
        # el orquestador imprime progreso a stdout -> lo silenciamos para emitir solo nuestro JSON
        with contextlib.redirect_stdout(io.StringIO()):
            rep = run(cfg=cfg)
        t = rep.get("totals", {})
        gs = rep.get("governance_signal", {})
        rec = {
            "svc": "sentinel_immune", "ts": int(time.time()), "node": node,
            "immune_state": rep.get("recommended_global_state"),
            "asset_count": rep.get("asset_count"),
            "findings": t.get("findings", 0),
            "critical": t.get("critical", 0), "high": t.get("high", 0),
            "escalation": t.get("escalation"),
            "agents": [{"agent": a.get("agent"), "count": a.get("count"),
                        "state": a.get("recommended_state")} for a in rep.get("agents", [])],
            "chain_ok": rep.get("chain_ok"),
            "gm_recommendation": gs.get("gm_recommendation"),
            "gm_ceiling": gs.get("gm_ceiling"),
            "observe_only": True, "t_killer": "INHIBIDO", "bridge": "ADVISORY",
            "tools_active": tools,  # gitleaks/shellcheck firmadas y expuestas (o [] si degradadas)
            "run_id": rep.get("run_id"),
        }
        _emit(rec)
        return 0
    except Exception as e:
        _emit({"svc": "sentinel_immune", "ts": int(time.time()), "node": node,
               "error": str(e)})
        return 0  # nunca romper el supervisor


if __name__ == "__main__":
    sys.exit(main())
