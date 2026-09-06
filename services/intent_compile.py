#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""intent_compile — B.3 Fase B: COMPILADOR DE INTENCIÓN (texto libre -> plan/deltas), draft-only.

Cierra el bucle Fase B SIN que la IA sea autoridad ni firme. Diseño que respeta el techo 2F:
el compilador NO INVENTA los deltas; los toma de un CATÁLOGO FIRMADO POR EL OPERADOR
(intent_catalog.json: intención->deltas->qué toca) y MATCHEA el texto de forma determinista y
explicable. Produce un BORRADOR que encadena al gemelo (B.2, twin_intent_sim) para proyectar el
efecto. El operador revisa y decide bajo el GM gate real. La IA no firma (invariante).

Cada ciclo (stdlib, sin GPU, observe/draft-only):
  1. Verifica FAIL-CLOSED la firma 653C del catálogo y del snapshot de vectores (minisign embebido).
  2. Lee texto de intención del buzón semantic/intent_text/*.txt.
  3. CLASIFICA con el guardarraíl semántico (semantic_core sellado): si invalida/contaminada -> RECHAZA
     (no compila texto normativo/de-poder; respeta 2F). Deja constancia del rechazo.
  4. MATCHEA a una plantilla del catálogo por patrones (determinista, explicable). Sin match -> no compila.
  5. Toma el BASELINE del target desde el snapshot firmado y EMITE un intent JSON para B.2
     (semantic/intent/*.json) + registra el BORRADOR con procedencia en semantic/intent_compile.jsonl.

NUNCA aplica, muta, propone-vinculante ni firma. Compilar = preparar un what-if trazable; decidir es del operador.
"""
import os, sys, json, time, glob, re, subprocess

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
DATA    = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
BUNDLE  = os.path.join(STAGING, "services", "semantic_core")
MS  = os.path.join(STAGING, "pylayer-verify")
PUB = os.path.join(STAGING, "pylayer", "release.pub")

SEM     = os.path.join(DATA, "semantic")
CATALOG = os.path.join(SEM, "intent_catalog.json")
SNAP    = os.path.join(SEM, "current_vectors.json")
TEXTBOX = os.path.join(SEM, "intent_text")           # buzón de texto libre del operador
DONE    = os.path.join(TEXTBOX, "processed")
INTENT  = os.path.join(SEM, "intent")                # salida -> la consume B.2 (twin_intent_sim)
OUT     = os.path.join(SEM, "intent_compile.jsonl")

# Sujetos conocidos: el propio nodo y el master; mas los declarados (ANVOS_KNOWN_TARGETS, coma).
KNOWN_TARGETS = ("master", "origo") + tuple(t.strip() for t in os.environ.get("ANVOS_KNOWN_TARGETS", "").split(",") if t.strip())


def _now(): return int(time.time())


def _find_ld():
    for c in glob.glob(os.path.join(MS, "ld-linux*.so.2")):
        return c
    return None


def _verify(ld, target):
    sig = target + ".minisig"
    if not (ld and os.path.isfile(target) and os.path.isfile(sig)):
        return False
    try:
        r = subprocess.run([ld, "--library-path", MS, os.path.join(MS, "minisign"),
                            "-Vm", target, "-p", PUB, "-x", sig], capture_output=True, timeout=8)
        return r.returncode == 0
    except Exception:
        return False


def _emit(o):
    try: print(json.dumps(o, ensure_ascii=False))
    except Exception: pass


def _append(path, o):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    except Exception: pass


def _classify(text):
    """Guardarraíl semántico sellado (2B). Devuelve semantic_status o None si no disponible."""
    try:
        if BUNDLE not in sys.path:
            sys.path.insert(0, BUNDLE)
        from semantic_gateway import SemanticGateway
        gw = SemanticGateway(BUNDLE)
        return gw.evaluate(text, source="intent_compile", write_log=False).get("semantic_status")
    except Exception:
        return None


def _match_template(text, catalog):
    """Match determinista por patrones. Devuelve (plantilla, patrones_acertados) o (None, [])."""
    low = text.lower()
    best, best_hits = None, []
    for t in catalog.get("templates", []):
        hits = [p for p in t.get("patterns", []) if p.lower() in low]
        if len(hits) > len(best_hits):
            best, best_hits = t, hits
    return best, best_hits


def _target(text, snap):
    low = text.lower()
    for tg in KNOWN_TARGETS:
        if re.search(r"\b" + re.escape(tg) + r"\b", low):
            return tg
    return "master"


def main():
    ts = _now()
    ld = _find_ld()
    verifier_ok = bool(ld) and os.path.exists(os.path.join(MS, "minisign")) and os.path.exists(PUB)
    if not verifier_ok:
        _emit({"svc": "intent_compile", "ts": ts, "draft_only": True,
               "verifier_ok": False, "note": "verificador embebido no disponible"})
        return
    if not (_verify(ld, CATALOG) and _verify(ld, SNAP)):
        _emit({"svc": "intent_compile", "ts": ts, "draft_only": True,
               "inputs_verified": False, "note": "FAIL-CLOSED: catálogo o snapshot sin firma válida; no compila"})
        return
    try:
        catalog = json.load(open(CATALOG, encoding="utf-8"))
        snap = json.load(open(SNAP, encoding="utf-8"))
    except Exception as e:
        _emit({"svc": "intent_compile", "ts": ts, "draft_only": True, "load_ok": False, "error": str(e)[:120]})
        return

    os.makedirs(DONE, exist_ok=True)
    os.makedirs(INTENT, exist_ok=True)
    compiled, rejected, unmatched = 0, 0, 0

    for f in sorted(glob.glob(os.path.join(TEXTBOX, "*.txt"))):
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                text = fh.read().strip()
            if not text:
                os.rename(f, os.path.join(DONE, os.path.basename(f)))
                continue
            status = _classify(text)
            # 2F FAIL-CLOSED: solo se compila si el guardarraíl semántico lo clasifica valida/frontera.
            # invalida/contaminada -> rechazo por techo 2F; None (guardarraíl no disponible) -> NO compilar.
            if status not in ("valida", "frontera"):
                reason = ("texto incompatible con nucleo semantico (2F)"
                          if status in ("invalida", "contaminada")
                          else "guardarrail semantico no disponible; fail-closed, no se compila")
                _append(OUT, {"svc": "intent_compile", "ts": _now(), "draft_only": True,
                              "text": text[:120], "semantic_status": status,
                              "result": "RECHAZADA", "reason": reason})
                rejected += 1
                os.rename(f, os.path.join(DONE, os.path.basename(f)))
                continue
            tpl, hits = _match_template(text, catalog)
            if not tpl:
                _append(OUT, {"svc": "intent_compile", "ts": _now(), "draft_only": True,
                              "text": text[:120], "semantic_status": status,
                              "result": "SIN_PLANTILLA", "reason": "ninguna plantilla del catálogo coincide (añadir plantilla firmada)"})
                unmatched += 1
                os.rename(f, os.path.join(DONE, os.path.basename(f)))
                continue
            target = _target(text, snap)
            baseline = dict(snap.get("targets", {}).get(target, {}))
            intent = {"desc": text[:120], "target": target,
                      "baseline": baseline, "deltas": tpl.get("deltas", {}),
                      "compiled": {"template": tpl["id"], "patterns_hit": hits,
                                   "touches": tpl.get("touches", []), "semantic_status": status,
                                   "authored_by": catalog.get("authored_by")}}
            # emitir intent para B.2 (twin_intent_sim lo simula en el próximo ciclo)
            base = os.path.splitext(os.path.basename(f))[0]
            with open(os.path.join(INTENT, base + ".json"), "w", encoding="utf-8") as out:
                json.dump(intent, out, ensure_ascii=False)
            _append(OUT, {"svc": "intent_compile", "ts": _now(), "draft_only": True,
                          "text": text[:120], "semantic_status": status, "result": "COMPILADA",
                          "target": target, "template": tpl["id"], "patterns_hit": hits,
                          "deltas": tpl.get("deltas", {}), "touches": tpl.get("touches", []),
                          "next": "twin_intent_sim proyectara AV/GM (B.2); operador decide"})
            compiled += 1
            os.rename(f, os.path.join(DONE, os.path.basename(f)))
        except Exception:
            continue

    _emit({"svc": "intent_compile", "ts": _now(), "draft_only": True,
           "inputs_verified": True, "phase": "OS-FaseB-Paso1(B.3)", "authority": False, "signs": False,
           "compiled": compiled, "rejected": rejected, "unmatched": unmatched,
           "templates": len(catalog.get("templates", [])),
           "note": "texto->plantilla firmada->intent para el gemelo; borrador trazable, la IA no firma ni aplica"})


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        _emit({"svc": "intent_compile", "ts": _now(), "draft_only": True, "fatal": str(e)[:140]})
