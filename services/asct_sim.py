#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""asct_sim — ASCT LIGERO en la capa ANVOS: plano de simulación NO_MUTATION que evalúa un cambio
CANDIDATO (en DEV) ANTES de promoverlo por el tri-ring (DEV→MIRROR→MAIN). Réplica node-local del
plano de simulación del ecosistema (anv-asct-sim.sh: dry-run + impacto + rollback, sin mutación).
Para cada servicio candidato .py comprueba, sin tocar nada:
  1. SINTAXIS  (compile) — ¿parsea?
  2. FIRMA     (minisign 653C embebido) — ¿está firmado y válido?
  3. IMPORT    (smoke-test en subproceso: exec_module top-level; NO ejecuta main() -> seguro) —
               ¿carga sin errores de import/top-level?
  4. ROLLBACK  — ¿hay respaldo del MAIN actual para revertir? (predicción de reversibilidad)
Veredicto por candidato: GO / NO_GO + razones + riesgo. Agregado del bundle DEV: GO solo si TODOS
pasan -> apto para ring_promote. Solo stdlib. Modos: sim <file> | sim-dev [dir] | status."""
import os
import sys
import json
import time
import glob
import subprocess

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
PERSIST = os.environ.get("ANVOS_PERSIST", "/persist")
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
MS = os.path.join(STAGING, "pylayer-verify")
PUB = os.path.join(STAGING, "pylayer", "release.pub")
PY = os.environ.get("ANVOS_PY", "/usr/bin/anvos-python3")
DEV = os.path.join(PERSIST, "anvos-ring", "dev")
BACKUPS = os.path.join(PERSIST, "anvos-ring", "backups")
REC = os.path.join(DATA, "asct", "sim.jsonl")

# smoke-test de import: carga el módulo (top-level) SIN correr su main() -> seguro, detecta imports rotos
_SMOKE = ("import importlib.util,sys;"
          "s=importlib.util.spec_from_file_location('cand',sys.argv[1]);"
          "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)")


def _ld():
    for c in glob.glob(os.path.join(MS, "ld-linux*.so.2")):
        return c
    return None


def _sig_ok(target):
    ld = _ld(); sig = target + ".minisig"
    if not (ld and os.path.exists(os.path.join(MS, "minisign")) and os.path.exists(PUB)
            and os.path.isfile(target) and os.path.isfile(sig)):
        return False
    try:
        r = subprocess.run([ld, "--library-path", MS, os.path.join(MS, "minisign"),
                            "-Vm", target, "-p", PUB, "-x", sig], capture_output=True, timeout=6)
        return r.returncode == 0
    except Exception:
        return False


def _syntax_ok(path):
    try:
        with open(path) as f:
            compile(f.read(), path, "exec")
        return True, None
    except SyntaxError as e:
        return False, "sintaxis L%s: %s" % (e.lineno, e.msg)
    except Exception as e:
        return False, str(e)


def _import_ok(path):
    try:
        r = subprocess.run([PY, "-c", _SMOKE, path], capture_output=True, timeout=30,
                           text=True, stdin=subprocess.DEVNULL)
        if r.returncode == 0:
            return True, None
        err = (r.stderr or "").strip().splitlines()
        return False, err[-1] if err else "import fallo rc=%d" % r.returncode
    except subprocess.TimeoutExpired:
        return False, "import timeout (>30s)"
    except Exception as e:
        return False, str(e)


def _rollback_ok():
    """Predicción de reversibilidad: ¿hay al menos un respaldo del MAIN para revertir?"""
    return bool(glob.glob(os.path.join(BACKUPS, "main_*")))


def simulate_one(path):
    name = os.path.basename(path)
    reasons = []
    syn_ok, syn_e = _syntax_ok(path)
    if not syn_ok:
        reasons.append("sintaxis: " + str(syn_e))
    sig_ok = _sig_ok(path)
    if not sig_ok:
        reasons.append("firma 653C inválida/ausente")
    imp_ok, imp_e = (_import_ok(path) if syn_ok else (False, "no evaluado (sintaxis)"))
    if not imp_ok:
        reasons.append("import: " + str(imp_e))
    verdict = "GO" if (syn_ok and sig_ok and imp_ok) else "NO_GO"
    # riesgo: firma es la más crítica; sintaxis/import bloquean
    risk = "none" if verdict == "GO" else ("high" if not sig_ok else "medium")
    return {"candidate": name, "verdict": verdict, "risk": risk,
            "syntax_ok": syn_ok, "signature_ok": sig_ok, "import_ok": imp_ok,
            "reasons": reasons}


def _record(rec):
    try:
        os.makedirs(os.path.dirname(REC), exist_ok=True)
        with open(REC, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL asct_sim._record: %r" % (e,), file=sys.stderr, flush=True)


def _emit(d):
    print(json.dumps(d, ensure_ascii=False))
    _record(d)


def cmd_sim(path):
    if not os.path.isfile(path):
        _emit({"svc": "asct_sim", "action": "sim", "ok": False, "error": "no existe %s" % path})
        return 2
    res = simulate_one(path)
    _emit({"svc": "asct_sim", "action": "sim", "ts": int(time.time()),
           "mode": "NO_MUTATION", **res})
    return 0 if res["verdict"] == "GO" else 1


def cmd_sim_dev(devdir):
    devdir = devdir or DEV
    cands = sorted(glob.glob(os.path.join(devdir, "*.py")))
    results = [simulate_one(p) for p in cands]
    go = all(r["verdict"] == "GO" for r in results) and len(results) > 0
    rollback = _rollback_ok()
    rec = {"svc": "asct_sim", "action": "sim-dev", "ts": int(time.time()), "mode": "NO_MUTATION",
           "dev": devdir, "candidates": len(results),
           "global_verdict": ("GO" if go else "NO_GO"),
           "rollback_available": rollback,
           "no_go": [r["candidate"] for r in results if r["verdict"] != "GO"],
           "detail": results,
           "note": ("apto para ring_promote" if go and rollback else
                    "NO promover: revisar candidatos" if not go else
                    "GO pero SIN respaldo de rollback (init primero)")}
    _emit({k: v for k, v in rec.items() if k != "detail"})
    _record(rec)
    return 0 if go else 1


def cmd_status():
    last = None
    try:
        with open(REC) as f:
            for l in f:
                l = l.strip()
                if l:
                    last = json.loads(l)
    except Exception:
        pass
    print(json.dumps(last or {"svc": "asct_sim", "status": "sin simulaciones"}, ensure_ascii=False))
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    try:
        if cmd == "sim":
            return cmd_sim(sys.argv[2] if len(sys.argv) > 2 else "")
        if cmd == "sim-dev":
            return cmd_sim_dev(sys.argv[2] if len(sys.argv) > 2 else None)
        if cmd == "status":
            return cmd_status()
        print(json.dumps({"svc": "asct_sim", "error": "modo desconocido: %s" % cmd}))
        return 2
    except Exception as e:
        _emit({"svc": "asct_sim", "ok": False, "fatal": str(e)})
        return 1


if __name__ == "__main__":
    sys.exit(main())
