#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""node_assistant — asistente del NODO: responde preguntas del operador GROUNDED en (a) el estado vivo
del nodo y (b) el RAG (lecciones + axiomas + capacidades), con la IA local. READ-ONLY / observe-advisory:
explica y propone, NUNCA actúa (nivel A3 ANALYZE_AND_REPORT). Herramienta on-demand (no la supervisa layerd).

Uso:  node_assistant.py ask "<pregunta>"        → respuesta fundamentada + fuentes citadas
      node_assistant.py ask "<pregunta>" --json  → JSON
Solo stdlib. Fail-safe."""
import os
import sys
import json
import time

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")


def _node_id():
    for p in ("/persist/anvos-node.id", "/etc/anvos-node.id"):
        try:
            v = open(p).read().strip()
            if v:
                return v
        except Exception:
            pass
    import socket
    return socket.gethostname() or "anvos-node"


def _state_summary():
    """Resumen COMPACTO del estado vivo del nodo (reutiliza build_status del servidor de estado)."""
    try:
        import node_status_server as nss
        st = nss.build_status()
    except Exception:
        return "(estado no disponible)"
    def g(sec, *keys):
        d = st.get(sec, {}) or {}
        return " ".join("%s=%s" % (k, d.get(k)) for k in keys if d.get(k) is not None)
    lines = [
        "salud: " + g("core_audit", "state") + " " + g("twin", "state") + " cpu=%s mem=%s" % (
            (st.get("health") or {}).get("cpu_load"), (st.get("health") or {}).get("mem_pct")),
        "integridad: " + g("integrity", "attestation", "verified", "total"),
        "gobernanza: " + g("governance", "veredicto", "observe_only"),
        "IA: " + g("ai", "engine", "model", "corpus"),
        "aprendizaje: " + g("aprendizaje", "estado", "lecciones_en_rag", "de_metricas"),
        "defensa: " + g("defensa_fib", "modo", "ips_vigiladas") + " " + g("deception", "hits_total"),
        "sensor: " + g("sensor", "estado", "ingeridas", "alertas"),
        "modulos: " + g("modulos", "activos"),
        "malla: " + g("mesh", "state", "peers"),
    ]
    return "\n".join("- " + ln for ln in lines if ln.strip(" -:"))


def _recall(question, k=4):
    try:
        import ai_rag
        items, _ = ai_rag.load_corpus()
        if not items:
            return []
        hits = ai_rag.retrieve(items, question, None, topk=k)
        return [(h.get("id"), h.get("text", "")) for h in hits if h.get("score", 0) >= 0.12]
    except Exception:
        return []


def ask(question, as_json=False):
    node = _node_id()
    state = _state_summary()
    recalled = _recall(question)
    ctx = "\n".join("- [%s] %s" % (rid, (txt or "")[:240]) for rid, txt in recalled) or "(sin conocimiento relevante)"
    prompt = (
        "/no_think\n"
        "Eres el ASISTENTE del nodo AstraNovaOS \"%s\". Responde la pregunta del operador de forma BREVE y "
        "precisa en español, SOLO con los DATOS de abajo (estado del nodo + conocimiento recuperado). Si la "
        "respuesta no está en los datos, dilo claramente. Eres observe/advisory: explica y, si acaso, PROPÓN, "
        "pero NUNCA ordenes ni ejecutes acciones destructivas.\n\n"
        "ESTADO DEL NODO:\n%s\n\nCONOCIMIENTO RECUPERADO (RAG):\n%s\n\nPREGUNTA: %s"
        % (node, state, ctx, question)
    )
    answer, model, engine = None, None, None
    try:
        import ai_router
        eng = ai_router.resolve_for_task("balanced") if hasattr(ai_router, "resolve_for_task") else ai_router.resolve_endpoint()
        kind, base, models, api = eng
        if kind:
            model = ai_router._pick_model("balanced", models, api)
            t0 = time.time()
            answer = ai_router._infer(base, api, model, prompt)
            engine = kind
    except Exception as e:
        answer = None
    if not answer:
        # degradación grácil: respuesta extractiva del RAG (sin generación)
        answer = "IA no disponible; contexto relevante:\n" + ctx
        engine = "extractivo"
    out = {"svc": "node_assistant", "node": node, "question": question, "engine": engine, "model": model,
           "sources": [rid for rid, _ in recalled], "answer": answer}
    if as_json:
        print(json.dumps(out, ensure_ascii=False))
    else:
        print("\n🤖 asistente de %s (motor=%s)\n" % (node, engine))
        print(answer.strip())
        if recalled:
            print("\nFuentes: " + ", ".join(rid for rid, _ in recalled))
    return 0


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "ask":
        as_json = "--json" in sys.argv
        q = " ".join(a for a in sys.argv[2:] if a != "--json")
        return ask(q, as_json)
    print(json.dumps({"svc": "node_assistant", "uso": "node_assistant.py ask \"<pregunta>\" [--json]"}, ensure_ascii=False))
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(json.dumps({"svc": "node_assistant", "ok": False, "fatal": str(e)}, ensure_ascii=False))
        sys.exit(0)
