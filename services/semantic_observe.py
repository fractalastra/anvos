#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""semantic_observe — Paso 1 de la Fase B Semántica en AstraNovaOS.

OBSERVE-ONLY. Embarca el `semantic_core` SELLADO (primitivas 2B) en el nodo y CLASIFICA
texto contra el núcleo semántico descriptivo, SIN decidir, actuar, bloquear-de-verdad ni
firmar nada. Es la BARRERA/observador semántico, no un compilador de intención: respeta el
techo inmutable 2F (inteligencia NO es autoridad) y el invariante OBSERVE_ONLY del nodo.

Qué hace cada ciclo (todo stdlib, sin GPU):
  1. Verifica FAIL-CLOSED la firma de release del bundle semantic_core con el minisign embebido.
     Si el bundle no valida -> NO importa nada, reporta y sale (no degrada, no ejecuta código no firmado).
  2. Clasifica los textos del buzón /persist/anvos-data/semantic/inbox/*.txt
     (el operador/sistema deposita ahí conocimiento/intención a observar).
     Cada texto -> {valida|frontera|invalida|contaminada} + decisión informativa {allow|review|block}.
  3. Registra el veredicto (append) en semantic/semantic_observe.jsonl y mueve el texto a inbox/processed/.
  4. Auto-latido de vida: si el buzón está vacío, clasifica una frase-testigo del propio bundle
     para probar que el observador vive, y emite un resumen con conteos por estado.

NUNCA: escribe dentro del bundle firmado (usa write_log=False), bloquea acciones reales,
propone/aplica cambios, ni firma. Solo observa y deja evidencia.
"""
import os
import sys
import json
import time
import glob
import shutil
import hashlib
import subprocess

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
DATA    = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
BUNDLE  = os.path.join(STAGING, "services", "semantic_core")
MS  = os.path.join(STAGING, "pylayer-verify")            # minisign embebido + ld + libs
PUB = os.path.join(STAGING, "pylayer", "release.pub")    # clave release

SEM_DIR   = os.path.join(DATA, "semantic")
INBOX     = os.path.join(SEM_DIR, "inbox")
PROCESSED = os.path.join(INBOX, "processed")
OUT       = os.path.join(SEM_DIR, "semantic_observe.jsonl")

# ficheros del bundle que deben tener firma de release válida (fail-closed):
# el código Y los datos sellados (primitivas 2B) — si algo se alteró, no se ejecuta.
BUNDLE_SIGNED = [
    "semantic_gateway.py",
    "validators/semantic_validator.py",
    "validators/relation_parser.py",
    "validators/semantic_logger.py",
    "data/primitives.json",
    "data/compatibility_matrix.json",
    "data/grammar_rules.json",
    "data/examples.json",
]


def _now():
    return int(time.time())


def _find_ld():
    for c in glob.glob(os.path.join(MS, "ld-linux*.so.2")):
        return c
    return None


def _verify(ld, target):
    """Verifica firma minisign de <target> con el verificador embebido. True si válida."""
    sig = target + ".minisig"
    if not (ld and os.path.isfile(target) and os.path.isfile(sig)):
        return False
    try:
        r = subprocess.run(
            [ld, "--library-path", MS, os.path.join(MS, "minisign"),
             "-Vm", target, "-p", PUB, "-x", sig],
            capture_output=True, timeout=6)
        return r.returncode == 0
    except Exception:
        return False


def _emit(obj):
    """Latido a stdout (lo captura layerd)."""
    try:
        print(json.dumps(obj, ensure_ascii=False))
    except Exception:
        pass


def _append(path, obj):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL semantic_observe._append: %r" % (e,), file=sys.stderr, flush=True)


def main():
    ts = _now()
    ld = _find_ld()
    verifier_ok = bool(ld) and os.path.exists(os.path.join(MS, "minisign")) and os.path.exists(PUB)

    # 1) FAIL-CLOSED: verificar la firma de release del bundle antes de importar nada
    if not verifier_ok:
        # sin verificador embebido (p.ej. ejercitado en el master): reportar, no es fallo
        _emit({"svc": "semantic_observe", "ts": ts, "observe_only": True,
               "verifier_ok": False, "note": "verificador embebido no disponible; no se importa el bundle"})
        return
    unverified = [rel for rel in BUNDLE_SIGNED if not _verify(ld, os.path.join(BUNDLE, rel))]
    if unverified:
        _emit({"svc": "semantic_observe", "ts": ts, "observe_only": True,
               "bundle_verified": False, "unverified": unverified,
               "note": "FAIL-CLOSED: bundle semantic_core sin firma valida; no se ejecuta"})
        return

    # 2) importar el gateway sellado (ya verificado)
    if BUNDLE not in sys.path:
        sys.path.insert(0, BUNDLE)
    try:
        from semantic_gateway import SemanticGateway
        gw = SemanticGateway(BUNDLE)
    except Exception as e:
        _emit({"svc": "semantic_observe", "ts": ts, "observe_only": True,
               "bundle_verified": True, "import_ok": False, "error": str(e)[:160]})
        return

    os.makedirs(PROCESSED, exist_ok=True)
    counts = {"valida": 0, "frontera": 0, "invalida": 0, "contaminada": 0}
    processed = 0

    # 3) observar el buzón: cada texto -> veredicto (write_log=False: NO tocar el bundle firmado)
    for path in sorted(glob.glob(os.path.join(INBOX, "*.txt"))):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read().strip()
            if not text:
                continue
            r = gw.evaluate(text, direction="input", source="semantic_observe", write_log=False)
            st = r.get("semantic_status", "?")
            counts[st] = counts.get(st, 0) + 1
            _append(OUT, {
                "svc": "semantic_observe", "ts": _now(), "observe_only": True,
                "src_file": os.path.basename(path),
                "sha16": hashlib.sha256(text.encode()).hexdigest()[:16],
                "semantic_status": st,
                "gateway_decision": r.get("gateway_decision"),
                "gateway_reason": r.get("gateway_reason"),
                "detected_primitives": r.get("semantic_result", {}).get("detected_primitives", []),
            })
            shutil.move(path, os.path.join(PROCESSED, os.path.basename(path)))
            processed += 1
        except Exception:
            continue

    # 4) auto-latido de vida si el buzón estaba vacío (prueba que el observador clasifica)
    self_test = None
    if processed == 0:
        try:
            probe = gw.evaluate("un sistema vivo con elementos que coexisten y se afectan",
                                source="semantic_observe:selftest", write_log=False)
            self_test = {"status": probe.get("semantic_status"),
                         "decision": probe.get("gateway_decision")}
        except Exception:
            self_test = {"status": "error"}

    _emit({
        "svc": "semantic_observe", "ts": _now(), "observe_only": True,
        "bundle_verified": True, "import_ok": True,
        "phase": "OS-FaseB-Paso1", "ceiling": "2F", "authority": False,
        "inbox_processed": processed, "counts": counts,
        "self_test": self_test,
        "note": "clasificacion semantica descriptiva; sin decidir/actuar/firmar (observe-only)",
    })


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # defensivo: nunca tumbar la capa
        _emit({"svc": "semantic_observe", "ts": _now(), "observe_only": True,
               "fatal": str(e)[:160]})
