#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""ai_rag — RAG LOCAL de la capa ANVOS (recuperación aumentada, sin GPU en el nodo).

Cierra el 'falta RAG' del salto de IA local. El nodo NO puede generar con LLM en local
(sin habilitación de la iGPU: no hay /dev/dri ni firmware; inferencia CPU tumba el nodo,
lección seq=71) — así que la RECUPERACIÓN es local y la GENERACIÓN es FEDERADA:

  1. RECUPERACIÓN (local, sin GPU, sin red): BM25 léxico sobre el corpus del índice FIRMADO
     knowledge_vectors.json (id+text+vec, 653C, verificado fail-closed). Si el master empuja
     un vector de consulta, además rerankea por COSENO (híbrido léxico+semántico).
  2. FUNDAMENTACIÓN (local, determinista): compone una respuesta EXTRACTIVA citada con el top-K
     (sin alucinación, siempre disponible aunque no haya cerebro alcanzable).
  3. GENERACIÓN (federada, opcional): si ai_router resuelve un endpoint Ollama (anillo/master),
     construye un prompt RAG (contexto recuperado + pregunta) y delega la generación allí (donde
     SÍ hay GPU). Timeout acotado; si falla o no hay endpoint -> se queda en la respuesta extractiva.

Modos: (periódico, por defecto) procesa el buzón semantic/rag_query/*.txt -> recuperación+extractiva
        (rápido, <30s, NUNCA genera en el ciclo para no exceder MAX_RUNTIME de layerd);
        ask <pregunta> [--gen]  interactivo: recuperación + (con --gen) generación federada acotada.
FAIL-CLOSED en el índice firmado. Solo stdlib."""
import os
import re
import sys
import json
import time
import glob
import math
import subprocess

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
SVCDIR = os.path.join(STAGING, "services")
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
MS = os.path.join(STAGING, "pylayer-verify")
PUB = os.path.join(STAGING, "pylayer", "release.pub")

SEM_DIR = os.path.join(DATA, "semantic")
INDEX = os.path.join(SEM_DIR, "knowledge_vectors.json")
INBOX = os.path.join(SEM_DIR, "rag_query")           # buzón de preguntas en texto plano
DONE = os.path.join(INBOX, "processed")
OUT = os.path.join(DATA, "ai", "rag.jsonl")
TOPK = 3
GEN_TIMEOUT = 20                                     # federada: acotado
# --- generación LOCAL en la iGPU (llama.cpp Vulkan) ---
LLAMA = os.path.join(STAGING, "llama-native")        # bundle firmado llama-cli+libs+modelo
VULKAN = os.path.join(STAGING, "vulkan-native")      # loader Vulkan + ICD Intel + ld-linux
GEN_LOCAL_TIMEOUT = 150                              # 1.er uso compila shaders SPIR-V (lento)
_WORD = re.compile(r"[0-9a-záéíóúñ]+", re.IGNORECASE)


def _now():
    return int(time.time())


def _find_ld():
    return next(iter(glob.glob(os.path.join(MS, "ld-linux*.so.2"))), None)


def _verify_sig(target):
    """FAIL-CLOSED: firma 653C del índice con el minisign embebido del nodo."""
    ld = _find_ld()
    sig = target + ".minisig"
    if not (ld and os.path.exists(os.path.join(MS, "minisign")) and os.path.exists(PUB)
            and os.path.isfile(target) and os.path.isfile(sig)):
        return False
    try:
        r = subprocess.run([ld, "--library-path", MS, os.path.join(MS, "minisign"),
                            "-Vm", target, "-p", PUB, "-x", sig],
                           capture_output=True, timeout=6)
        return r.returncode == 0
    except Exception:
        return False


def _tok(s):
    return [w.lower() for w in _WORD.findall(s or "")]


def load_corpus():
    """Carga el índice FIRMADO. Devuelve (items, dim) o (None, motivo) fail-closed."""
    if not _verify_sig(INDEX):
        return None, "indice sin firma valida (fail-closed)"
    try:
        d = json.load(open(INDEX))
    except Exception as e:
        return None, "indice ilegible: %s" % e
    items = d.get("items", [])
    for it in items:
        it["_tok"] = _tok(it.get("text", ""))
    return items, d.get("dim")


class BM25:
    """BM25 léxico (Robertson) sobre el corpus. stdlib, determinista, sin GPU."""
    def __init__(self, docs, k1=1.5, b=0.75):
        self.docs = docs
        self.k1, self.b = k1, b
        self.N = len(docs) or 1
        self.avgdl = (sum(len(d["_tok"]) for d in docs) / self.N) if docs else 0.0
        self.df = {}
        for d in docs:
            for t in set(d["_tok"]):
                self.df[t] = self.df.get(t, 0) + 1

    def _idf(self, t):
        n = self.df.get(t, 0)
        return math.log(1 + (self.N - n + 0.5) / (n + 0.5))

    def score(self, q_tok, d):
        dl = len(d["_tok"]) or 1
        tf = {}
        for t in d["_tok"]:
            tf[t] = tf.get(t, 0) + 1
        s = 0.0
        for t in q_tok:
            if t not in tf:
                continue
            f = tf[t]
            s += self._idf(t) * (f * (self.k1 + 1)) / (f + self.k1 * (1 - self.b + self.b * dl / self.avgdl))
        return s


def _cosine(a, b):
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return dot / (na * nb)


def retrieve(items, question, qvec=None, topk=TOPK):
    """Recuperación híbrida: BM25 léxico (siempre) + coseno (si hay qvec del master).
    Normaliza cada señal a [0,1] y las combina; sin qvec => solo léxico."""
    bm = BM25(items)
    qtok = _tok(question)
    lex = [bm.score(qtok, d) for d in items]
    lmax = max(lex) or 1.0
    cos = [_cosine(qvec, d.get("vec")) for d in items] if qvec else [0.0] * len(items)
    cmax = max(cos) or 1.0
    scored = []
    for i, it in enumerate(items):
        ln = lex[i] / lmax
        cn = cos[i] / cmax if qvec else 0.0
        combined = (0.5 * ln + 0.5 * cn) if qvec else ln
        scored.append((combined, ln, cn, it))
    scored.sort(key=lambda x: x[0], reverse=True)
    hits = []
    for combined, ln, cn, it in scored[:topk]:
        if combined <= 0:
            continue
        hits.append({"id": it.get("id"), "text": it.get("text"),
                     "score": round(combined, 4), "lex": round(ln, 4),
                     "cos": round(cn, 4) if qvec else None})
    return hits


def extractive_answer(question, hits):
    """Respuesta EXTRACTIVA fundamentada (determinista, sin generación, sin alucinar)."""
    if not hits:
        return "Sin base de conocimiento relevante para: %s" % question
    top = hits[0]
    cites = ", ".join(h["id"] for h in hits)
    return ("Según el conocimiento firmado del nodo, lo más relevante es %s: «%s». "
            "Fuentes: %s." % (top["id"], top["text"], cites))


RAG_MARK = "<<ANV_RESP>>"                            # marcador único: aísla la generación del eco del prompt


def _rag_prompt(question, hits):
    ctx = "\n".join("- [%s] %s" % (h["id"], h["text"]) for h in hits)
    return ("Responde SOLO con el siguiente contexto soberano; si no basta, dilo. "
            "No inventes.\n\nContexto:\n%s\n\nPregunta: %s\n%s" % (ctx, question, RAG_MARK))


LLAMA_SRV = "http://127.0.0.1:%s" % os.environ.get("ANVOS_LLAMA_PORT", "8090")


def server_generate(question, hits):
    """Generación en el CEREBRO RESIDENTE del nodo (ai_llama_server: llama.cpp server en la
    iGPU, modelo SIEMPRE cargado — sin pagar arranque+carga por petición). None si el server
    no está vivo o no responde -> cae a la vía llama-cli."""
    import urllib.request
    try:
        req = urllib.request.Request(
            LLAMA_SRV + "/completion",
            data=json.dumps({"prompt": _rag_prompt(question, hits),
                             "n_predict": 80, "temperature": 0}).encode(),
            headers={"Content-Type": "application/json"})
        d = json.loads(urllib.request.urlopen(req, timeout=GEN_LOCAL_TIMEOUT).read())
        text = (d.get("content") or "")
        text = text.rsplit(RAG_MARK, 1)[-1] if RAG_MARK in text else text
        text = " ".join(text.split()).strip()
        if not text:
            return None
        return {"answer": text, "backend": "local-igpu-server",
                "model": os.path.basename(str(d.get("model") or "llama-native"))}
    except Exception:
        return None


def local_generate(question, hits):
    """Generación LOCAL en la iGPU del portátil vía llama.cpp Vulkan (bundle llama-native).
    FAIL-CLOSED: verifica la firma 653C del binario + libggml-vulkan antes de ejecutar; sin firma
    válida -> None (cae a federación). Corre en la GPU (-ngl 99). Devuelve dict o None."""
    cli = os.path.join(LLAMA, "bin", "llama-cli")
    ld = next(iter(glob.glob(os.path.join(VULKAN, "lib", "ld-linux*.so.2"))), None)
    models = glob.glob(os.path.join(LLAMA, "model", "*.gguf"))
    vulkan_lib = os.path.join(LLAMA, "lib", "libggml-vulkan.so.0")
    icd = os.path.join(VULKAN, "icd", "intel_icd.json")
    if not (ld and models and os.path.isfile(cli)):
        return None
    # fail-closed: binario + backend Vulkan deben estar firmados 653C
    if not (_verify_sig(cli) and _verify_sig(vulkan_lib)):
        return None
    libpath = os.path.join(LLAMA, "lib") + ":" + os.path.join(VULKAN, "lib")
    env = dict(os.environ)
    env["VK_DRIVER_FILES"] = icd
    env["VK_ICD_FILENAMES"] = icd
    # caché de shaders Mesa PERSISTENTE: el rootfs de ANVOS vive en RAM, así que la caché por
    # defecto (~/.cache) muere en cada arranque y el primer token tras cada boot pagaba la
    # compilación SPIR-V completa (~min). En /persist sobrevive reinicios.
    cache = "/persist/anvos-cache/mesa"
    try:
        os.makedirs(cache, exist_ok=True)
        env["MESA_SHADER_CACHE_DIR"] = cache
        env["XDG_CACHE_HOME"] = "/persist/anvos-cache"
    except Exception:
        pass
    # --simple-io es CLAVE: sin él, este build no emite nada por la vía ld-linux del nodo.
    cmd = [ld, "--library-path", libpath, cli, "-m", models[0],
           "-p", _rag_prompt(question, hits), "-n", "80", "-ngl", "99",
           "-no-cnv", "-st", "--temp", "0", "--no-warmup", "--simple-io"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=GEN_LOCAL_TIMEOUT)
    except Exception:
        return None
    out = r.stdout or ""
    # la generación va tras el marcador único RAG_MARK (fin del prompt) y antes del footer '[ Prompt:'.
    body = out.split("[ Prompt:")[0]
    text = body.rsplit(RAG_MARK, 1)[-1] if RAG_MARK in body else body
    text = " ".join(l for l in text.splitlines() if l.strip() and not l.strip().startswith(">")).strip()
    if not text:
        return None
    return {"answer": text, "backend": "local-igpu", "model": os.path.basename(models[0])}


def federated_generate(question, hits):
    """Generación FEDERADA (Ollama del anillo/master) con contexto RAG. Acotada; None si falla."""
    try:
        sys.path.insert(0, SVCDIR)
        import ai_router
    except Exception:
        return None
    kind, base, models = ai_router.resolve_endpoint()
    if not kind:
        return None
    model = ai_router._pick_model("general", models)
    resp = ai_router._http_json(base + "/api/generate",
                                {"model": model, "prompt": _rag_prompt(question, hits),
                                 "stream": False}, timeout=GEN_TIMEOUT)
    if isinstance(resp, dict) and resp.get("response"):
        return {"answer": resp["response"].strip(), "backend": "federated:" + kind, "model": model}
    return None


def answer(question, qvec=None, allow_gen=False):
    items, dim = load_corpus()
    if items is None:
        return {"svc": "ai_rag", "ts": _now(), "ok": False, "error": dim}
    hits = retrieve(items, question, qvec)
    rec = {"svc": "ai_rag", "ts": _now(), "ok": True, "question": question[:200],
           "n_corpus": len(items), "hits": hits, "mode": "hibrido" if qvec else "lexico",
           "grounded": extractive_answer(question, hits)}
    if allow_gen:
        # 1.º cerebro RESIDENTE (server iGPU); 2.º llama-cli iGPU; 3.º FEDERADA; 4.º extractiva
        gen = (server_generate(question, hits) or local_generate(question, hits)
               or federated_generate(question, hits))
        if gen:
            rec.update({"generated": gen["answer"], "gen_backend": gen["backend"],
                        "gen_model": gen.get("model")})
        else:
            rec["gen_note"] = "ni iGPU local ni cerebro federado -> respuesta extractiva"
    return rec


def _emit(rec):
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(json.dumps(rec, ensure_ascii=False))


def cmd_periodic():
    """Procesa el buzón de preguntas: recuperación + extractiva (NUNCA genera aquí)."""
    os.makedirs(DONE, exist_ok=True)
    processed = 0
    for q in sorted(glob.glob(os.path.join(INBOX, "*.txt"))):
        try:
            question = open(q).read().strip()
        except Exception:
            continue
        # ¿el master empujó el vector de la consulta junto al .txt?
        qvec = None
        vp = q[:-4] + ".vec.json"
        if os.path.isfile(vp):
            try:
                qvec = json.load(open(vp)).get("vec")
            except Exception:
                qvec = None
        rec = answer(question, qvec=qvec, allow_gen=False)
        # print-only en el ciclo periódico: layerd anexa el stdout al .jsonl (escribir aparte duplicaba)
        print(json.dumps(rec, ensure_ascii=False))
        os.rename(q, os.path.join(DONE, os.path.basename(q)))
        processed += 1
    if processed == 0:
        # auto-latido: prueba de vida con una consulta de ejemplo (recuperación local)
        items, dim = load_corpus()
        probe = ("indice no verificado" if items is None
                 else retrieve(items, "estabilidad del vault soberano")[:1])
        print(json.dumps({"svc": "ai_rag", "ts": _now(), "heartbeat": True,
                          "index_verified": items is not None,
                          "n_corpus": (len(items) if items else 0), "probe": probe},
                         ensure_ascii=False))
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "ask":
        allow_gen = "--gen" in sys.argv[2:]
        q = " ".join(a for a in sys.argv[2:] if a != "--gen") or "¿qué es AstraNova?"
        _emit(answer(q, allow_gen=allow_gen))
        return 0
    return cmd_periodic()


if __name__ == "__main__":
    sys.exit(main())
