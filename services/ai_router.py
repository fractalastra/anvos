#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""ai_router — IA LOCAL de la capa ANVOS (router real con resolución de motor SOBERANA).
Solo stdlib (urllib). Da capacidad de IA al nodo probando motores por PRIORIDAD:
  1) LOCAL  llama-server nativo  http://127.0.0.1:8090   (API OpenAI /v1 — motor desplegado)
  2) LOCAL  Ollama               http://127.0.0.1:11434  (API Ollama, si existe)
  3) ANILLO Ollama del master    (URL declarada en ANVOS_OLLAMA_RING; federación por WireGuard)
El primero con >=1 modelo gana. Degradación grácil: si ninguno -> 'en-espera' (no falla).
Clasifica el contexto -> cerebro y consulta con la API correcta de cada motor.
Modos:
  probe            (por defecto, periódico): estado + endpoint + modelos -> router.jsonl (latido)
  classify <texto> : imprime el cerebro elegido para ese texto
  ask <prompt> [--task T] : clasifica, consulta el motor y devuelve la respuesta
Registra en /persist/anvos-data/ai/router.jsonl. Fail-safe: nunca lanza excepción al supervisor."""
import os
import sys
import json
import time
import socket
import urllib.request

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
REC = os.path.join(DATA, "ai", "router.jsonl")

# Motores por prioridad: (tipo, base_url, api).  api = "openai" (llama.cpp/llama-server) | "ollama".
ENDPOINTS = [
    ("local",       os.environ.get("ANVOS_LLAMA_LOCAL",  "http://127.0.0.1:8090"),  "openai"),
    ("local-ollama", os.environ.get("ANVOS_OLLAMA_LOCAL", "http://127.0.0.1:11434"), "ollama"),
    ("ring",        os.environ.get("ANVOS_OLLAMA_RING",   ""), "ollama"),
]
# Un endpoint sin URL declarada queda fuera (el federado exige declaracion explicita).
ENDPOINTS = [e for e in ENDPOINTS if e[1]]

# Mapa contexto -> cerebro (para motores Ollama; el llama-server usa su modelo cargado).
MODELS = {
    "fast": "llama3.2:3b", "balanced": "qwen3:8b",
    "code": "qwen2.5-coder:7b", "code_alt": "deepseek-coder:6.7b",
    "fallback": "llama3:latest", "embed": "bge-m3",
}
_CODE_HINTS = ("script", "bash", "python", "funcion", "función", "codigo", "código",
               "compil", "refactor", "sintaxis", "json", "yaml", "regex", "shell")
_ANALYSIS_HINTS = ("analiza", "analizar", "diagnos", "incidente", "log", "auditor",
                   "riesgo", "por qué", "porque", "explica")


def _node_id():
    node = socket.gethostname() or "anvos-node"
    for _p in ("/persist/anvos-node.id", "/etc/anvos-node.id"):
        try:
            _v = open(_p).read().strip()
            if _v:
                return _v
        except Exception:
            pass
    return node


def _record(rec):
    try:
        os.makedirs(os.path.dirname(REC), exist_ok=True)
        with open(REC, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL ai_router._record: %r" % (e,), file=sys.stderr, flush=True)


def _http_json(url, payload=None, timeout=8):
    try:
        if payload is None:
            req = urllib.request.Request(url)
        else:
            req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def _discover(base, api):
    """Lista de modelos del motor, o None si no responde."""
    if api == "openai":
        d = _http_json(base + "/v1/models", timeout=5)
        items = (d or {}).get("models") or (d or {}).get("data") or []
        models = [(m.get("name") or m.get("id")) for m in items if (m.get("name") or m.get("id"))]
        return models or None
    d = _http_json(base + "/api/tags", timeout=5)
    if isinstance(d, dict) and "models" in d:
        return [m.get("name") for m in d.get("models", []) if m.get("name")]
    return None


def resolve_endpoint():
    """(tipo, base_url, modelos[], api) del primer motor con >=1 modelo, o (None,None,[],None)."""
    for kind, base, api in ENDPOINTS:
        base = base.rstrip("/")
        models = _discover(base, api)
        if models:
            return kind, base, models, api
    return None, None, [], None


def resolve_for_task(task):
    """HÍBRIDO por tarea (los modelos se TURNAN según la tarea). Con el 8b LOCAL en la iGPU de origo:
      - CÓDIGO -> ANILLO primero (coder especialista qwen2.5-coder/deepseek), fallback local;
      - TODO lo demás, incl. PESADAS (balanced/analysis) y ligeras -> LOCAL primero (8b rápido en iGPU,
        sin depender del anillo intermitente), fallback anillo.
    Si el motor preferido no responde, cae al otro (degradación grácil)."""
    def _pref(ep):
        k = ep[0]
        if task == "code":
            return 0 if k == "ring" else 1           # código: coder del anillo (especialista)
        return 0 if k.startswith("local") else 1      # resto (incl. pesadas): 8b LOCAL primero

    for kind, base, api in sorted(ENDPOINTS, key=_pref):
        base = base.rstrip("/")
        models = _discover(base, api)
        if models:
            return kind, base, models, api
    return None, None, [], None


def classify(text):
    t = (text or "").lower()
    if any(h in t for h in _CODE_HINTS):
        return "code"
    if any(h in t for h in _ANALYSIS_HINTS):
        return "balanced"
    return "fast"


def _pick_model(task, available, api):
    # llama-server (openai): un único modelo cargado -> usarlo tal cual.
    if api == "openai":
        return available[0] if available else "local"
    order = {"code": ["code", "code_alt", "balanced", "fast", "fallback"],
             "balanced": ["balanced", "fast", "fallback"],
             "fast": ["fast", "balanced", "fallback"],
             "embed": ["embed"]}.get(task, ["fast", "fallback"])
    for key in order:
        m = MODELS.get(key)
        if m and (not available or m in available or any(a.startswith(m.split(":")[0]) for a in available)):
            return m
    # ROBUSTEZ: si ningún nombre del mapa coincide con lo REALMENTE disponible en el motor
    # (p.ej. el anillo ofrece qwen2.5-coder/deepseek pero no llama3.2), usar un modelo de
    # GENERACIÓN de los reportados (excluye embebedores) en vez de un nombre fijo inexistente.
    if available:
        gen = [a for a in available if not any(x in a.lower() for x in ("embed", "bge", "nomic"))]
        if gen:
            return gen[0]
    return MODELS["fallback"]


def _infer(base, api, model, prompt):
    """Devuelve el texto de respuesta con la API correcta del motor."""
    if api == "openai":
        resp = _http_json(base + "/v1/chat/completions",
                          {"model": model, "messages": [{"role": "user", "content": prompt}],
                           "stream": False,
                           # qwen3 y afines son modelos "thinking": sin esto gastan TODO el presupuesto de
                           # tokens razonando (reasoning_content) y devuelven content VACÍO. Desactivar el
                           # modo-razonamiento -> respuesta directa. Ignorado por modelos no-thinking (seguro).
                           "chat_template_kwargs": {"enable_thinking": False}}, timeout=120)
        if isinstance(resp, dict):
            ch = resp.get("choices") or []
            if ch:
                return ((ch[0].get("message") or {}).get("content") or "").strip()
        return None
    resp = _http_json(base + "/api/generate",
                      {"model": model, "prompt": prompt, "stream": False}, timeout=120)
    if isinstance(resp, dict) and "response" in resp:
        return resp.get("response", "").strip()
    return None


def cmd_probe():
    kind, base, models, api = resolve_endpoint()
    note = ("IA local (llama-native)" if kind == "local" else
            "IA local (ollama)" if kind == "local-ollama" else
            "IA por anillo (master WG)" if kind == "ring" else "sin motor de IA")
    rec = {"svc": "ai_router", "ts": int(time.time()), "node": _node_id(),
           "endpoint_kind": kind, "endpoint": base, "api": api,
           "status": "router-ready" if kind else "en-espera",
           "n_models": len(models), "models": models[:12], "note": note}
    print(json.dumps(rec, ensure_ascii=False))
    _record(rec)
    return 0


def cmd_classify(text):
    print(classify(text))
    return 0


def cmd_ask(prompt, task=None):
    task = task or classify(prompt)
    # HÍBRIDO: elige el motor según la tarea (pesadas->anillo 8b, ligeras->local)
    kind, base, models, api = resolve_for_task(task)
    if not kind:
        out = {"svc": "ai_router", "action": "ask", "ok": False,
               "error": "sin motor de IA (local llama/ollama ni anillo)"}
        print(json.dumps(out, ensure_ascii=False)); _record(out); return 1
    model = _pick_model(task, models, api)
    t0 = time.time()
    answer = _infer(base, api, model, prompt)
    if not answer:
        out = {"svc": "ai_router", "action": "ask", "ok": False, "endpoint_kind": kind,
               "api": api, "model": model, "error": "sin respuesta del modelo"}
        print(json.dumps(out, ensure_ascii=False)); _record(out); return 1
    out = {"svc": "ai_router", "action": "ask", "ok": True, "endpoint_kind": kind, "api": api,
           "task": task, "model": model, "elapsed_s": round(time.time() - t0, 1),
           "prompt": prompt[:200], "answer": answer}
    _record({k: v for k, v in out.items() if k != "answer"} | {"answer_len": len(answer)})
    print(json.dumps(out, ensure_ascii=False))
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "probe"
    try:
        if cmd == "probe":
            return cmd_probe()
        if cmd == "classify":
            return cmd_classify(sys.argv[2] if len(sys.argv) > 2 else "")
        if cmd == "ask":
            args = sys.argv[2:]
            task = None
            if "--task" in args:
                i = args.index("--task"); task = args[i + 1]; del args[i:i + 2]
            return cmd_ask(" ".join(args), task=task)
        print(json.dumps({"svc": "ai_router", "error": "modo desconocido: %s" % cmd}))
        return 2
    except Exception as e:
        print(json.dumps({"svc": "ai_router", "ok": False, "fatal": str(e)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())
