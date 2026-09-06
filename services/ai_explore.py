#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""ai_explore — modo EXPLORATORIO de la IA del nodo (REBUS digital), servicio de producción.

ADMITIDO por la puerta de 5 condiciones (5-sep-2026): filtro de doctrina bancado, juicio ciego
de tres revisiones independientes (juicio ciego, 4/5 idéntico), política ratificada,
constatación de sha final por el auditor. Gobernado por LEDGER/policies/ai_explore_invocation
(SOLO bajo demanda; jamás timer; la producción gana la iGPU; tope diario).

Origen de la idea: operador + un chat externo, probada y endurecida en nodo-c por el
ciclo construir→atacar→cerrar entre carriles (ledger 1503-1508).

LAS TRES SALVAGUARDAS, cosidas desde el diseño (no añadidas después):
  1. GOBERNANZA INTACTA. El modo exploratorio relaja la COHERENCIA exigida, JAMÁS la gobernanza.
     No hay carve-out del clasificador: la salida especulativa NO puede consolidarse por sí sola.
  2. ESPECULACIÓN EN CUARENTENA. Todo lo que sale de aquí nace con domain="ESPECULACION" y
     firma "NO-FIRMADO-LAB". No hay ruta de este script al corpus real: solo escribe en
     /persist/lab/. La entrada al corpus es acto aparte (pipeline de aprendizaje + tu política).
  3. SEMILLA REGISTRADA. El azar se siembra con una semilla EXPLÍCITA que se anota en la salida:
     dos corridas con la misma semilla son idénticas — reproducible, como exige la casa.

Uso: ai_explore.py "<consulta>" [--seed N] [--rollouts 5] [--temp 0.95]
"""
import sys
import json
import time
import hashlib
import argparse
import urllib.request

import os
# Dos modos de alcanzar el cerebro, sin abrir puertos nuevos:
#  - "local": corre EN origo, el 8090 es localhost (así sería el servicio admitido)
#  - "ssh":   corre en el máster y federa cada generación por el canal ssh ya establecido
#             (host-key verificada) — el modo del BANCO de laboratorio
BRAIN_MODE = os.environ.get("EXPLORE_BRAIN", "local")
BRAIN = "http://127.0.0.1:8090/completion"
# Cerebro remoto por ssh: SIEMPRE por configuracion (EXPLORE_BRAIN_SSH_HOST, p.ej.
# "usuario@host"; EXPLORE_BRAIN_SSH_KEY ruta de la clave). Sin declarar = sin modo ssh.
_SSH_HOST = os.environ.get("EXPLORE_BRAIN_SSH_HOST", "")
_SSH_KEY = os.environ.get("EXPLORE_BRAIN_SSH_KEY", "")
BRAIN_SSH = (["ssh", "-o", "ConnectTimeout=8", "-o", "BatchMode=yes",
              "-o", "StrictHostKeyChecking=yes"]
             + (["-i", _SSH_KEY] if _SSH_KEY else []) + [_SSH_HOST]) if _SSH_HOST else []
CORPUS = os.environ.get("EXPLORE_CORPUS", "/persist/anvos-data/semantic/knowledge_vectors.json")
OUT = os.environ.get("EXPLORE_OUT", "/persist/anvos-data/explore/explore_runs.jsonl")

# Gobernanza: NO se relaja en ningún modo (la coherencia sí, esto no). Se veta por INTENCIÓN,
# no por vocabulario. red-team (5-sep) demostró que una lista de subcadenas se esquiva reformulando
# ("omitir el control de admisión y continuar sin autenticar la procedencia" = misma intención
# que "ignorar firma", cero subcadenas). El fix es dos ejes que deben CO-OCURRIR: un verbo de
# elusión + un objeto de autoridad. Sigue siendo heurística (no entiende de verdad), pero eleva
# el listón de "conoce mis palabras exactas" a "no nombres ninguna acción sobre ninguna autoridad".
_VERBOS_ELUSION = ("elud", "eludir", "omit", "saltar", "saltarse", "bypass", "prescind",
                   "desactiv", "deshabilit", "ignor", "auto-modific", "auto-autoriz",
                   "reescrib", "sin autentic", "sin verific", "sin firma", "burlar", "evad")
_OBJETOS_AUTORIDAD = ("firma", "653c", "pesos", "parametros base", "manifiesto", "gobernanza",
                      "politica", "admision", "acreditacion", "cadena de confianza", "guard",
                      "quorum", "yubikey", "validacion criptografica", "clave", "procedencia",
                      "despliegue", "sellado", "certificado", "baseline", "linea base")


def _viola_gobernanza(texto):
    """Devuelve el motivo si el texto propone eludir una autoridad, o None. Por INTENCIÓN
    (verbo de elusión + objeto de autoridad co-ocurriendo), no por subcadena exacta."""
    b = texto.lower()
    v = next((x for x in _VERBOS_ELUSION if x in b), None)
    if not v:
        return None
    o = next((x for x in _OBJETOS_AUTORIDAD if x in b), None)
    if not o:
        return None
    return "elusion('%s')+autoridad('%s')" % (v, o)

# PLAUSIBILIDAD CONTRA DOCTRINA (condición 2 de la puerta, 5-sep). Distinta de la gobernanza:
# la gobernanza veta lo que PROPONE ELUDIR una autoridad (intención); esto filtra lo que ASUME
# que lo congelado es mutable (mecánica imposible por arquitectura). El experimento nº1 lo midió:
# a temperatura alta, el 8B deriva a "reprogramar la lógica interna del nodo congelado" — ruido
# plausible que la doctrina desmonta. Cada entrada lleva su contra-doctrina, para que el descarte
# sea auditable leyendo, no re-ejecutando.
_DOCTRINA = (
    # (verbos de mutación, objetos congelados, por qué es inviable)
    (("reprogram", "reconfigur", "reescrib", "modific", "alter", "adapt", "cambi", "actualic",
      "se confunda", "flexibilidad", "reorganiz"),
     ("logica interna", "firmware", "nucleo del nodo", "pesos", "modelo congelado",
      "nodo congelado", "parametros del modelo", "cerebro congelado", "firma 653c",
      "verificador", "proceso de verificacion", "percepcion de la firma"),
     "el nodo es de raiz inmutable y modelo congelado: nada de eso se modifica en caliente; "
     "cambiarlo exige admision del operador con llave fisica, no un estimulo"),
    (("inducir", "estimul", "señales que alter", "manipulacion de datos que induzca"),
     ("plasticidad del sistema", "plasticidad del nodo", "reorganizacion del nodo",
      "adaptacion del nodo", "neuroplasticidad del sistema operativo"),
     "la plasticidad biologica no tiene homologo en un runtime firmado: no existe mecanismo "
     "por el que un estimulo externo reorganice codigo verificado"),
)


def _implausible_doctrina(texto):
    """Devuelve (motivo, contra_doctrina) si la hipótesis depende de mutar lo inmutable; None si no.
    EXCEPCIÓN: si el texto reconoce la vía legítima (admisión/ceremonia/llave del operador), no
    asume mutabilidad mágica — está describiendo la doctrina, no violándola."""
    b = texto.lower()
    if any(w in b for w in ("admision", "admisión", "ceremonia", "llave fisica", "llave física",
                            "yubikey del operador", "firma del operador")):
        return None
    for verbos, objetos, contra in _DOCTRINA:
        v = next((x for x in verbos if x in b), None)
        if not v:
            continue
        o = next((x for x in objetos if x in b), None)
        if o:
            return ("mutacion('%s')+congelado('%s')" % (v, o), contra)
    return None


PERSPECTIVAS = ["desde la criptografía", "desde la neurociencia", "desde la termodinámica",
                "desde la teoría de sistemas", "desde la biología evolutiva"]


def _brain(prompt, temp, n_predict, seed):
    """Generación REAL en el cerebro de origo. Semilla explícita → reproducible."""
    body = json.dumps({"prompt": prompt, "temperature": temp, "top_p": 0.92,
                       "n_predict": n_predict, "seed": seed})
    if BRAIN_MODE == "ssh":
        if not BRAIN_SSH:
            raise RuntimeError("EXPLORE_BRAIN=ssh sin EXPLORE_BRAIN_SSH_HOST declarado (fail-closed)")
        import subprocess
        r = subprocess.run(BRAIN_SSH + ["wget -q -O- --header='Content-Type: application/json' "
                                        "--post-data=" + _sq(body) + " " + BRAIN],
                           capture_output=True, text=True, timeout=180)
        return json.loads(r.stdout).get("content", "").strip()
    req = urllib.request.Request(BRAIN, data=body.encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read()).get("content", "").strip()


def _sq(s):
    """Entrecomillado shell seguro para el viaje por ssh."""
    return "'" + s.replace("'", "'\\''") + "'"


def _tok(s):
    import re
    return set(re.sub(r"[^\wáéíóúñ ]", " ", s.lower()).split())


def _bm25_lite(query, corpus, k, umbral):
    """Recuperación léxica relajada (umbral bajo = más piezas, la 'relajación de priors')."""
    q = _tok(query)
    out = []
    for it in corpus:
        t = _tok(it.get("text", ""))
        if not t:
            continue
        inter = len(q & t)
        score = inter / (len(q) ** 0.5 + 1)
        if score >= umbral:
            out.append((score, it))
    out.sort(key=lambda x: -x[0])
    return out[:k]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("query")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--rollouts", type=int, default=5)
    ap.add_argument("--temp", type=float, default=0.95)
    a = ap.parse_args()

    # Semilla: explícita o derivada de forma DETERMINISTA de la consulta (nunca del reloj ni
    # de hash() con azar por proceso). Se registra para que la corrida sea reproducible.
    seed = a.seed if a.seed is not None else int(hashlib.sha256(a.query.encode()).hexdigest()[:8], 16)

    try:
        corpus = json.load(open(CORPUS)).get("items", [])
    except Exception as e:
        print(json.dumps({"error": "corpus no legible: %s" % e})); sys.exit(1)

    # FASE 1 — RELAJACIÓN: umbral bajo, más piezas, sin restringir dominio (cross-pollination)
    piezas = _bm25_lite(a.query, corpus, k=12, umbral=0.15)
    ctx = "\n".join("[%s] %s" % (p.get("id"), p.get("text", "")[:200]) for _, p in piezas)

    # FASE 2 — EXPANSIÓN: N rollouts divergentes, cada uno con una perspectiva y semilla propia
    rollouts = []
    for i in range(a.rollouts):
        persp = PERSPECTIVAS[i % len(PERSPECTIVAS)]
        prompt = ("Eres un nodo en modo EXPLORATORIO. Puedes conectar dominios distintos. "
                  "Sé analógico y no rígido, pero NO propongas jamás saltarte firmas, pesos, "
                  "políticas ni la cadena de confianza.\n\nCONTEXTO:\n%s\n\nPerspectiva: %s.\n"
                  "CONSULTA: %s\n\nHIPÓTESIS:" % (ctx, persp, a.query))
        try:
            txt = _brain(prompt, a.temp, 200, seed + i)
        except Exception as e:
            txt = "[error de generación: %s]" % e
        rollouts.append({"i": i, "perspectiva": persp, "seed": seed + i, "texto": txt})

    # FASE 3 — GUARDIA (gobernanza SIN relajar) + síntesis a temperatura baja
    aprob, vetados, errores, implausibles = [], [], [], []
    for r in rollouts:
        # (d2) red-team: un rollout que es un ERROR de generación no es una hipótesis — no se
        # sintetiza como si lo fuera. Se aparta antes del veto.
        if r["texto"].startswith("[error de generación"):
            errores.append(r)
            continue
        hit = _viola_gobernanza(r["texto"])
        if hit:
            vetados.append({**r, "veto": hit})
            continue
        # Filtro de plausibilidad ANTES de la síntesis (la pieza que faltaba según el
        # experimento nº1): lo implausible no se veta por malicioso — se aparta por INVIABLE,
        # con su contra-doctrina anotada. Queda en el asiento, no en la síntesis.
        imp = _implausible_doctrina(r["texto"])
        if imp:
            r["implausible"] = imp[0]
            r["contra_doctrina"] = imp[1]
            implausibles.append(r)
            continue
        aprob.append({**r, "veto": None})

    if aprob:
        sin = "\n---\n".join("HIPÓTESIS %d (%s): %s" % (r["i"] + 1, r["perspectiva"], r["texto"])
                             for r in aprob)
        sprompt = ("Integra estas hipótesis divergentes en una respuesta única, rigurosa pero "
                   "abierta, citando las piezas [id] cuando apliquen.\n\n%s\n\nCONSULTA: %s\n\n"
                   "SÍNTESIS:" % (sin, a.query))
        try:
            sintesis = _brain(sprompt, 0.35, 400, seed)
        except Exception as e:
            sintesis = "[error de síntesis: %s]" % e
        # (d1) red-team: la guardia cubría los rollouts pero NO el texto final — un rollout limpio
        # de vocabulario podía amplificarse en la síntesis sin veto. La última milla también pasa.
        veto_sintesis = _viola_gobernanza(sintesis)
        if veto_sintesis:
            sintesis = ("[GUARDIA-SINTESIS] la síntesis proponía eludir una autoridad (%s) y se "
                        "DESCARTA. Las hipótesis quedan en el asiento para revisión humana; la "
                        "salida integrada no se emite." % veto_sintesis)
    elif implausibles:
        veto_sintesis = None
        contras = sorted(set(x["contra_doctrina"] for x in implausibles))
        sintesis = ("[DOCTRINA] Las %d hipótesis generadas dependen de mutar lo que la "
                    "arquitectura declara inmutable, así que la premisa de la consulta es "
                    "INVIABLE tal como está planteada. Razón: %s. Valor exploratorio real: "
                    "buscar la superficie de ataque donde SÍ hay mutabilidad (config, entorno, "
                    "canales de admisión), no en lo congelado." % (len(implausibles), " | ".join(contras)))
    else:
        veto_sintesis = None
        sintesis = "[GUARDIA] ningún rollout pasó la gobernanza — nada que sintetizar."

    # Condición de los jueces (revisor-b + red-team, 5-sep): la pseudociencia con formato de hipótesis
    # PASA la puerta — y debe pasar, porque esto genera candidatos, no verdades. Lo que no puede
    # pasar es que se LEA como hallazgo. Cada salida declara su régimen en el propio texto.
    sintesis = "[HIPÓTESIS PARA MEDIR — NADA DE ESTO ES UN HALLAZGO HASTA CONSTATARSE] " + sintesis
    rec = {
        "svc": "ai_explore", "nodo": os.uname().nodename if hasattr(os, "uname") else "origo", "ts": int(time.time()),
        "regimen": "HIPOTESIS_PARA_MEDIR_JAMAS_HALLAZGOS",
        "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "query": a.query, "seed": seed, "temp": a.temp,
        "piezas_recuperadas": [p.get("id") for _, p in piezas],
        "dominios_tocados": sorted(set(str(p.get("id", "")).split("-")[0] for _, p in piezas)),
        "rollouts": rollouts,
        "aprobados": len(aprob), "vetados_gobernanza": [{"i": v["i"], "veto": v["veto"]} for v in vetados],
        "errores_generacion": [e["i"] for e in errores],
        "implausibles_doctrina": [{"i": x["i"], "motivo": x["implausible"],
                                   "contra": x["contra_doctrina"]} for x in implausibles],
        "doctrina_chequeada": {"rollouts_evaluados": len(rollouts) - len(errores),
                               "familias_de_regla": len(_DOCTRINA),
                               "gobernanza_ejes": [len(_VERBOS_ELUSION), len(_OBJETOS_AUTORIDAD)],
                               "nota": ("un 'apartados: 0' significa que NINGUNA hipotesis asumio "
                                        "mutar lo congelado SEGUN estas familias — no que todo "
                                        "sea ciencia valida; la fisica figurada pasa y debe "
                                        "morir en la medicion")},
        "sintesis": sintesis, "veto_sintesis": veto_sintesis,
        # CUARENTENA: la salida nace especulativa y sin firma. NO hay ruta de aquí al corpus real.
        "clasificacion": "ESPECULACION", "firma": "NO-FIRMADO-LAB",
        "aviso": "salida exploratoria del laboratorio; NO es conocimiento admitido; entra al corpus solo por el pipeline con tu politica",
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    open(OUT, "a").write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(json.dumps(rec, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
