#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""event_learn — Aprendizaje automático del NODO (observe/DRAFT-only, la IA NUNCA firma).

Porta el loop de aprendizaje del master (anv-event-learn) a la capa ANVOS, respetando la
doctrina del nodo: la IA PROPONE un borrador, el humano firma (aquí ni siquiera hay clave en
el nodo — el borrador viaja al operador/master para revisión y firma).

Cada ciclo (periódico, acotado a < MAX_RUNTIME de layerd):
  1. Lee la memoria episódica del nodo (event_ledger -> memory/events.jsonl) desde un CURSOR (por seq).
  2. Selecciona transiciones SIGNIFICATIVAS (degradaciones: 'to' fuera del conjunto sano).
  3. Agrupa por 'kind'; toma UN grupo por ciclo (para no exceder MAX_RUNTIME).
  4. Pide a la IA LOCAL (vía ai_router, timeout acotado) una LECCIÓN DEFENSIVA breve en Markdown
     -> borrador PENDIENTE en learning/pending/DRAFT_LEARN_<kind>_<ts>.md. Si la IA no responde a
     tiempo, escribe el borrador ESQUELETO con los eventos crudos (nada se pierde) marcado
     'IA_PENDIENTE'. La IA NUNCA firma; el borrador es solo propuesta.
  5. Avanza el cursor (solo por lo procesado).

Gobernanza: IA propone (borrador no firmado); operador confirma (firma en el master = activo).
Solo stdlib. Fail-safe: nunca lanza excepción al supervisor. Print = ledger del servicio."""
import os
import sys
import json
import time

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
EVENTS = os.path.join(DATA, "memory", "events.jsonl")            # memoria episódica (event_ledger)
LEARN_DIR = os.path.join(DATA, "learning")
PENDING_DIR = os.path.join(LEARN_DIR, "pending")                 # borradores PENDIENTES (IA no firma)
CURSOR = os.path.join(LEARN_DIR, "cursor.json")
REC = os.path.join(LEARN_DIR, "event_learn.jsonl")              # latido/registro del servicio
SENSOR_EVENTS = os.path.join(DATA, "modules", "sensor_events.jsonl")  # CABLE 1: métricas del módulo sensor
FIB_EVENTS = os.path.join(DATA, "security", "fib_guard.jsonl")        # SEGURIDAD: fuerza bruta SSH (fib_guard)
DECEP_HITS = os.path.join(DATA, "deception", "hits.jsonl")            # SEGURIDAD: hits del honeypot (intrusos)
NETFLOW_EVENTS = os.path.join(DATA, "modules", "netflow", "netflow_events.jsonl")  # RED: peers EXTERNOS nuevos (mod_netflow)
MODBUS_EVENTS = os.path.join(DATA, "modules", "modbus_events.jsonl")               # OT: alertas de umbral roto (mod_modbus)
MERKLE_EVENTS = os.path.join(DATA, "chain", "block_anchor.jsonl")                  # INTEGRIDAD: cadena de bloques rota (block_anchor)
CADUCIDAD_EVENTS = os.path.join(DATA, "caducidades", "escalated.jsonl")            # TIEMPO: caducidades ALTA/MAXIMA (caducidad_watch)
# Modelos demasiado pequeños para razonar una lección coherente (rápidos pero flojos): evitarlos para lecciones.
TINY_HINTS = ("0.5b", "0_5b", ":0.5", "0b5", "tiny", "135m", "360m", "0.6b", "1b", "1.5b", "1_5b")

# Presupuesto de tiempo total del ciclo (layerd mata a los 30s los periódicos colgados).
TIME_BUDGET_S = 28.0
AI_TIMEOUT_S = 22          # medido: el 8b local (iGPU/Vulkan) genera ~6,6 tok/s; con LESSON_TOKENS=110 la
                           # inferencia son ~17s -> cabe bajo TIME_BUDGET_S=28 y el cap MAX_RUNTIME=30 de layerd
MAX_EVENTS_IN_PROMPT = 10  # muestra acotada
MIN_DRAFT_BYTES = 200      # ITB-080: por debajo de esto un borrador es esqueleto o corte severo
LESSON_TOKENS = 110        # lección concisa (~85 palabras) que el 8b LOCAL completa dentro del presupuesto de
                           # tiempo (el cap de layerd es 30s; 160 tokens se pasaban -> esqueleto). Soberanía local.

# Estados "sanos": una transición cuyo 'to' NO esté aquí se considera SIGNIFICATIVA (degradación).
HEALTHY_STATES = {"HEALTHY", "COHERENTE", "ONLINE", "SEALED", "OK", "GREEN", "UP", "READY", "NORMAL"}


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


def _ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _append(path, rec):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 (revisor-a): el fallo de registro deja huella por stderr en vez de callar.
        # stderr llega al .jsonl de la capa; el silencio de un instrumento ya no es
        # indistinguible de un estado sin hallazgos.
        print("REG_FAIL event_learn._append(%s): %r" % (path, e), file=sys.stderr, flush=True)


def _load_cursor():
    try:
        d = json.load(open(CURSOR))
        # retrocompat: 'last_seq' antiguo = cursor episódico
        return {"episodic": int(d.get("episodic", d.get("last_seq", 0))),
                "metrics": int(d.get("metrics", 0)),
                "fib": int(d.get("fib", 0)), "deception": int(d.get("deception", 0)),
                "netflow": int(d.get("netflow", 0)), "modbus": int(d.get("modbus", 0)),
                "merkle": int(d.get("merkle", 0)), "caducidad": int(d.get("caducidad", 0))}
    except Exception:
        return {"episodic": 0, "metrics": 0, "fib": 0, "deception": 0, "netflow": 0, "modbus": 0,
                "merkle": 0, "caducidad": 0}


def _save_cursor(cur):
    try:
        os.makedirs(LEARN_DIR, exist_ok=True)
        tmp = CURSOR + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"episodic": int(cur.get("episodic", 0)), "metrics": int(cur.get("metrics", 0)),
                       "fib": int(cur.get("fib", 0)), "deception": int(cur.get("deception", 0)),
                       "netflow": int(cur.get("netflow", 0)), "modbus": int(cur.get("modbus", 0)),
                       "merkle": int(cur.get("merkle", 0)), "caducidad": int(cur.get("caducidad", 0)),
                       "updated": _ts()}, f)
        os.replace(tmp, CURSOR)
    except Exception:
        pass


def _read_episodic(since_seq):
    """FUENTE 1 (memoria episódica): transiciones significativas (degradación) con seq > since_seq.
    Devuelve (lista_significativos, max_seq_leido)."""
    sig = []
    max_seq = since_seq
    try:
        with open(EVENTS) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                seq = int(d.get("seq", 0))
                if seq <= since_seq:
                    continue
                max_seq = max(max_seq, seq)
                to = str(d.get("to", "")).upper()
                if to and to not in HEALTHY_STATES:   # deja/entra en estado no-sano
                    d["_src"] = "episodic"
                    sig.append(d)
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return sig, max_seq


def _read_metrics(since_line):
    """FUENTE 2 (CABLE 1 — métricas del sensor): lecturas CON alerta (umbral roto) desde la línea since_line.
    Devuelve (lista_significativos, nueva_cuenta_de_lineas). El ruido (lecturas normales) se ignora;
    la señal de aprendizaje son las ALERTAS."""
    sig = []
    n = 0
    try:
        with open(SENSOR_EVENTS) as f:
            for n, line in enumerate(f, start=1):
                if n <= since_line:
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                alerts = d.get("alerts") or []
                if alerts:   # solo las lecturas que rompieron umbral son significativas
                    types = ",".join("%s:%s" % (a.get("type"), a.get("metric")) for a in alerts)
                    sig.append({"_src": "metrics", "kind": "sensor_alert",
                                "ts": d.get("ts"), "sensor_id": d.get("sensor_id"),
                                "sensor_type": d.get("sensor_type"),
                                "from": "lectura", "to": types, "reading": d.get("reading"),
                                "alerts": alerts})
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return sig, (n if n else since_line)


def _read_lines(path, since_line, keep):
    """Genérico por-línea con cursor de línea: aplica keep(dict)->dict|None a cada línea nueva.
    Devuelve (lista_significativos, nueva_cuenta_de_lineas)."""
    sig = []
    n = 0
    try:
        with open(path) as f:
            for n, line in enumerate(f, start=1):
                if n <= since_line:
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                r = keep(d)
                if r:
                    sig.append(r)
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return sig, (n if n else since_line)


def _read_fib(since_line):
    """FUENTE 3 (SEGURIDAD): fuerza bruta SSH detectada por fib_guard (recomienda bloqueo)."""
    def keep(d):
        if d.get("event") == "ssh_fail" and (d.get("recommend_block_secs") or 0) > 0:
            return {"_src": "fib", "kind": "ssh_bruteforce", "ts": d.get("ts"),
                    "from": "ssh", "to": "fuerza_bruta", "ip": d.get("ip"),
                    "count": d.get("count"), "recommend_block_secs": d.get("recommend_block_secs")}
        return None
    return _read_lines(FIB_EVENTS, since_line, keep)


def _read_deception(since_line):
    """FUENTE 4 (SEGURIDAD): hits del honeypot (un intruso tocó un puerto señuelo)."""
    def keep(d):
        return {"_src": "deception", "kind": "honeypot_hit", "ts": d.get("ts"),
                "from": "señuelo", "to": "intruso", "ip": d.get("src_ip") or d.get("src"),
                "bait_port": d.get("bait_port") or d.get("port")}
    return _read_lines(DECEP_HITS, since_line, keep)


def _read_netflow(since_line):
    """FUENTE 5 (RED — mod_netflow): peer EXTERNO NUEVO a la malla soberana. Solo los externos son
    señal (external=true); un peer interno nuevo es ruido esperado. No implica intrusión por sí solo,
    pero una contraparte externa no vista antes merece una lección de contexto/vigilancia."""
    def keep(d):
        if d.get("event") == "new_peer" and d.get("external") is True:
            return {"_src": "netflow", "kind": "external_peer", "ts": d.get("ts"),
                    "from": "malla", "to": "peer_externo_nuevo", "ip": d.get("ip"),
                    "node": d.get("node")}
        return None
    return _read_lines(NETFLOW_EVENTS, since_line, keep)


def _read_modbus(since_line):
    """FUENTE 6 (OT — mod_modbus): alerta de umbral roto en un registro Modbus (OVER_MAX/UNDER_MIN).
    Solo las lecturas con 'alerts' son señal; el sondeo normal es ruido. Un proceso industrial fuera
    de rango es un incidente OT que merece lección (causa/impacto/prevención), observado en lectura."""
    def keep(d):
        alerts = d.get("alerts") or []
        if alerts:
            types = ",".join("%s:%s" % (a.get("type"), a.get("metric")) for a in alerts)
            return {"_src": "modbus", "kind": "modbus_alert", "ts": d.get("ts"),
                    "from": "registro", "to": types, "target": d.get("target"),
                    "register": d.get("register"), "value": d.get("value"), "alerts": alerts}
        return None
    return _read_lines(MODBUS_EVENTS, since_line, keep)


def _read_merkle(since_line):
    """FUENTE 7 (INTEGRIDAD — block_anchor): la cadena de bloques merkle del nodo se rompió
    (verified=False). Es un incidente CRÍTICO (manipulación de la historia del nodo) -> lección que
    escalará al operador. Solo los ciclos con verified False son señal; los verificados son ruido sano."""
    def keep(d):
        if d.get("verified") is False:
            fb = d.get("first_bad") or {}
            return {"_src": "merkle", "kind": "chain_tamper", "ts": d.get("ts"),
                    "from": "cadena_bloques", "to": "MANIPULADA:%s" % (fb.get("why") or "?"),
                    "bad_height": fb.get("height"), "blocks": d.get("blocks")}
        return None
    return _read_lines(MERKLE_EVENTS, since_line, keep)


def _read_caducidad(since_line):
    """FUENTE 8 (TIEMPO — caducidad_watch): una caducidad crítica venció o se manipuló la política.
    Solo se leen las escaladas (ALTA/MAXIMA: VENCIDO de activo crítico, POLITICA_MANIPULADA); los avisos
    rutinarios T-90/60 no son señal. Un vencimiento crítico o una política manipulada -> lección que
    escala al operador (observe-only: la IA propone la lección, el humano actúa y re-firma el calendario)."""
    def keep(d):
        return {"_src": "caducidad", "kind": "caducidad_alert", "ts": d.get("ts"),
                "from": d.get("categoria") or "?",
                "to": "%s:%s" % (d.get("evento") or "?", d.get("id") or "?"),
                "sev": d.get("severidad")}
    return _read_lines(CADUCIDAD_EVENTS, since_line, keep)


def _choose_model(models):
    """Mejor modelo de GENERACIÓN de los disponibles: excluye embebedores y PREFIERE no-enanos
    (un 0.5b es rápido pero razona lecciones incoherentes; mejor un 7b aunque tarde más)."""
    if not models:
        return None
    gen = [m for m in models if m and not any(x in m.lower() for x in ("embed", "bge", "nomic"))]
    if not gen:
        return None
    big = [m for m in gen if not any(t in m.lower() for t in TINY_HINTS)]
    pool = big or gen   # preferir no-enanos; si SOLO hay enanos, usar lo que haya
    for pref in ("qwen2.5-coder", "deepseek", "qwen", "llama3", "llama", "mistral", "phi"):
        for m in pool:
            if m.lower().startswith(pref):
                return m
    return pool[0]


def _best_engine(deadline):
    """CALIDAD: recorre TODOS los motores (ai_router.ENDPOINTS) y devuelve (kind,base,api,model) con el
    MEJOR modelo — priorizando NO-enano. Así una lección usa el 7b del anillo aunque el motor local solo
    tenga un 0.5b. Respeta el deadline (discovery acotado)."""
    try:
        import ai_router
    except Exception:
        return None
    best = None  # (rank, kind, base, api, model); rank 0 = no-enano, 1 = enano
    for ep in getattr(ai_router, "ENDPOINTS", []):
        if time.time() >= deadline:
            break
        kind = ep[0]
        base = str(ep[1]).rstrip("/")
        api = ep[2] if len(ep) > 2 else ("openai" if ":8090" in base else "ollama")
        try:
            models = ai_router._discover(base, api)
        except Exception:
            models = None
        model = _choose_model(models) if models else None
        if not model and api == "openai" and models is not None:
            model = "local"
        if not model:
            continue
        rank = 1 if any(t in model.lower() for t in TINY_HINTS) else 0
        if best is None or rank < best[0]:
            best = (rank, kind, base, api, model)
        if rank == 0:
            break  # ya tenemos uno de calidad; no seguir sondeando
    if not best:
        return None
    return best[1], best[2], best[3], best[4]


def _recall(query, deadline, k=2, min_score=0.15):
    """CABLE 3: recupera del RAG local (ai_rag, indice FIRMADO) las lecciones/conocimiento PREVIO
    relevante a 'query', para inyectarlo como contexto en la generacion. Rapido (BM25 local).
    Devuelve [(id, text), ...]. Fail-safe: [] si no hay indice/tiempo."""
    if time.time() >= deadline:
        return []
    try:
        import ai_rag
        items, _dim = ai_rag.load_corpus()   # verifica firma 653C fail-closed
        if not items:
            return []
        hits = ai_rag.retrieve(items, query, None, topk=k)
        out = []
        for h in hits:
            if h.get("score", 0) >= min_score and h.get("text"):
                out.append((h.get("id"), h.get("text")))
        return out
    except Exception:
        return []


def _ai_lesson(kind, events, deadline):
    """Pide una LECCIÓN DEFENSIVA breve al MEJOR motor/modelo disponible. None si no hay tiempo/motor.
    Acepta eventos episódicos (from/to de estado) y de métricas (alertas de sensor).
    CABLE 3: inyecta como contexto las lecciones previas relevantes recuperadas del RAG."""
    if time.time() >= deadline:
        return None
    try:
        import ai_router
        eng = _best_engine(deadline)
        if not eng:
            return None
        kindq, base, api, model = eng
        # muestra genérica: transición de estado o alerta de métrica
        sample = []
        for e in events[:MAX_EVENTS_IN_PROMPT]:
            s = e.get("_src")
            if s == "metrics":
                sample.append({"ts": e.get("ts"), "sensor": e.get("sensor_id"),
                               "tipo": e.get("sensor_type"), "alerta": e.get("to"), "lectura": e.get("reading")})
            elif s == "fib":
                sample.append({"ts": e.get("ts"), "ip": e.get("ip"), "intentos": e.get("count"),
                               "bloqueo_recomendado_s": e.get("recommend_block_secs")})
            elif s == "deception":
                sample.append({"ts": e.get("ts"), "ip": e.get("ip"), "puerto_señuelo": e.get("bait_port")})
            elif s == "netflow":
                sample.append({"ts": e.get("ts"), "ip": e.get("ip"), "nodo": e.get("node"),
                               "evento": "peer externo nuevo a la malla soberana"})
            elif s == "modbus":
                sample.append({"ts": e.get("ts"), "registro": e.get("register"), "objetivo": e.get("target"),
                               "alerta": e.get("to"), "valor": e.get("value")})
            elif s == "merkle":
                sample.append({"ts": e.get("ts"), "anomalia": e.get("to"), "bloque_malo": e.get("bad_height"),
                               "bloques": e.get("blocks")})
            else:
                sample.append({"ts": e.get("ts"), "kind": e.get("kind"),
                               "from": e.get("from"), "to": e.get("to")})
        que = {"sensor_alert": "estas ALERTAS de métricas de sensores (umbral roto)",
               "ssh_bruteforce": "estos intentos de FUERZA BRUTA SSH detectados en el nodo",
               "honeypot_hit": "estos HITS de honeypot (accesos de intrusos a puertos señuelo)",
               "external_peer": ("estas CONTRAPARTES EXTERNAS NUEVAS observadas en la red del nodo (IPs "
                                 "fuera de la malla soberana no vistas antes; observadas en modo lectura, "
                                 "sin implicar intrusión por sí solas)"),
               "modbus_alert": ("estas ALERTAS de proceso industrial (registros Modbus fuera de umbral, "
                                "OVER_MAX/UNDER_MIN; observadas en modo SOLO LECTURA, sin actuar sobre el proceso)"),
               "chain_tamper": ("esta ROTURA de la CADENA DE BLOQUES merkle del nodo (verified=False: la "
                                "historia local fue MANIPULADA o corrompida). Es un incidente de INTEGRIDAD "
                                "CRÍTICO -> causa raíz probable, impacto y como responder/recuperar"),
               "caducidad_alert": ("estas CADUCIDADES críticas (un activo VENCIÓ —clave, dato personal, "
                                   "expediente de estado o credencial OT eléctrica— o la POLÍTICA de caducidades "
                                   "fue MANIPULADA). El operador debe actuar y re-firmar el calendario -> impacto "
                                   "de un vencimiento inadvertido y como remediarlo/prevenirlo")
               }.get(kind, "estas transiciones de estado de tipo '%s'" % kind)
        # CABLE 3: recuperar lecciones previas relevantes y anclarlas como contexto
        query = kind + " " + " ".join(str(e.get("to", "")) for e in events[:5])
        recalled = _recall(query, deadline)
        ctx = ""
        if recalled:
            ctx = ("\n\nCONTEXTO recuperado (lo que el nodo YA aprendió sobre temas afines). Si el patrón "
                   "ya está cubierto, dilo en 1 línea y SOLO añade lo nuevo; no repitas lo ya sabido:\n"
                   + "\n".join("- [%s] %s" % (rid, (txt or "")[:220]) for rid, txt in recalled))
        prompt = (
            "/no_think\n"  # qwen3 y afines: sin modo-razonamiento (no gastar el presupuesto de tokens pensando)
            "Eres el analista defensivo del nodo AstraNovaOS. Analiza " + que + " y produce una "
            "LECCIÓN DEFENSIVA breve en español (Markdown): causa raíz probable, impacto, y 2-3 reglas "
            "accionables para prevenir recurrencia. No inventes datos ausentes. No incluyas comandos "
            "destructivos. Máximo 150 palabras.\n\nDatos:\n" + json.dumps(sample, ensure_ascii=False) + ctx
        )
        rec_ids = [rid for rid, _ in recalled]
        remaining = min(AI_TIMEOUT_S, max(2, int(deadline - time.time())))
        if api == "openai":
            resp = ai_router._http_json(base + "/v1/chat/completions",
                                        {"model": model, "messages": [{"role": "user", "content": prompt}],
                                         "stream": False, "max_tokens": LESSON_TOKENS}, timeout=remaining)
            if isinstance(resp, dict) and resp.get("choices"):
                return ((resp["choices"][0].get("message") or {}).get("content") or "").strip(), model, kindq, rec_ids
        else:
            resp = ai_router._http_json(base + "/api/generate",
                                        {"model": model, "prompt": prompt, "stream": False,
                                         "options": {"temperature": 0.2, "num_predict": LESSON_TOKENS}}, timeout=remaining)
            if isinstance(resp, dict) and "response" in resp:
                return resp["response"].strip(), model, kindq, rec_ids
    except Exception:
        return None
    return None


def _write_draft(kind, events, lesson, model, engine, recalled=None):
    os.makedirs(PENDING_DIR, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = os.path.join(PENDING_DIR, "DRAFT_LEARN_%s_%s.md" % (kind, stamp))
    # ITB-080 (revisor-b): un borrador cortado por el tope de tokens NO debe pasar como completo.
    # Si la leccion no cierra (corta a media frase, bloque markdown abierto, o demasiado corta),
    # se fuerza esqueleto: lesson=None conserva el evento raw para regenerar, y el estado lo declara.
    def _draft_looks_complete(text):
        if not text:
            return False
        t = text.rstrip()
        if len(t.encode("utf-8")) < MIN_DRAFT_BYTES:
            return False
        last = t.splitlines()[-1].rstrip() if t.splitlines() else ""
        if not last or last[-1] not in ".?!)}\"'`]":
            return False
        if t.count("```") % 2 != 0:      # bloque de codigo sin cerrar
            return False
        return True

    if lesson and not _draft_looks_complete(lesson):
        lesson = None  # ITB-080: truncado -> esqueleto declarado, no leccion falsa-completa
    status = "PENDIENTE_REVISION" if lesson else "PENDIENTE_REVISION (IA_PENDIENTE/TRUNCADO)"

    def _fmt(e):
        s = e.get("_src")
        if s == "metrics":
            return "- métrica %s (%s): alerta %s | lectura %s (ts %s)" % (
                e.get("sensor_id"), e.get("sensor_type"), e.get("to"), e.get("reading"), e.get("ts"))
        if s == "fib":
            return "- fuerza bruta SSH: ip %s | %s intentos | bloqueo recomendado %ss (ts %s)" % (
                e.get("ip"), e.get("count"), e.get("recommend_block_secs"), e.get("ts"))
        if s == "deception":
            return "- hit honeypot: ip %s | puerto señuelo %s (ts %s)" % (
                e.get("ip"), e.get("bait_port"), e.get("ts"))
        if s == "netflow":
            return "- peer externo nuevo: ip %s | nodo %s (ts %s)" % (
                e.get("ip"), e.get("node"), e.get("ts"))
        if s == "modbus":
            return "- alerta OT (modbus): registro %s en %s | %s | valor %s (ts %s)" % (
                e.get("register"), e.get("target"), e.get("to"), e.get("value"), e.get("ts"))
        if s == "merkle":
            return "- INTEGRIDAD: cadena de bloques %s | bloque malo %s | %s bloques (ts %s)" % (
                e.get("to"), e.get("bad_height"), e.get("blocks"), e.get("ts"))
        if s == "caducidad":
            return "- CADUCIDAD [%s]: %s | categoria %s (ts %s)" % (
                e.get("sev"), e.get("to"), e.get("from"), e.get("ts"))
        return "- seq %s: %s → %s (ts %s)" % (e.get("seq"), e.get("from"), e.get("to"), e.get("ts"))
    trans = "\n".join(_fmt(e) for e in events[:MAX_EVENTS_IN_PROMPT])
    src = {"sensor_alert": "métricas del sensor", "ssh_bruteforce": "seguridad: fuerza bruta SSH (fib_guard)",
           "honeypot_hit": "seguridad: hits de honeypot (deception)",
           "external_peer": "red: peers externos nuevos (mod_netflow)",
           "modbus_alert": "OT: alertas de umbral roto (mod_modbus)",
           "chain_tamper": "integridad: cadena de bloques rota (block_anchor)",
           "caducidad_alert": "tiempo: caducidad crítica / política manipulada (caducidad_watch)"}.get(kind, "memoria episódica (estados)")
    body = "# ANV — Borrador de Aprendizaje del nodo (auto): %s\n" % kind
    body += "## Estado: %s\n## Nodo: %s\n## Fecha: %s\n## Fuente: %s\n" % (status, _node_id(), _ts(), src)
    body += "## Motor IA: %s / %s\n## Clase: node-incident-learning (auto, event_learn — la IA NO firma)\n\n" % (engine or "-", model or "-")
    body += "### Datos observados\n%s\n\n" % (trans or "- (sin detalle)")
    if recalled:
        body += "### Contexto usado (cable 3: lecciones/conocimiento previo recuperado del RAG)\n%s\n\n" % \
                "\n".join("- %s" % r for r in recalled)
    body += "### Lección propuesta (IA propone; el operador revisa y firma en el master)\n"
    body += (lesson if lesson else "_IA no disponible en el presupuesto de tiempo; borrador esqueleto para enriquecer en el próximo ciclo o por el operador._") + "\n"
    try:
        with open(path, "w") as f:
            f.write(body)
    except Exception:
        return None
    return path


def cmd_cycle():
    t0 = time.time()
    deadline = t0 + TIME_BUDGET_S
    node = _node_id()
    cur = _load_cursor()
    # F1 episódica (estados) · F2 métricas del sensor · F3 fuerza bruta SSH · F4 hits de honeypot · F5 peers externos (netflow)
    sig_ep, max_seq = _read_episodic(cur["episodic"])
    sig_me, new_line = _read_metrics(cur["metrics"])
    sig_fb, new_fib = _read_fib(cur["fib"])
    sig_dc, new_dec = _read_deception(cur["deception"])
    sig_nf, new_nf = _read_netflow(cur["netflow"])
    sig_mb, new_mb = _read_modbus(cur["modbus"])
    sig_mk, new_mk = _read_merkle(cur["merkle"])
    sig_cd, new_cd = _read_caducidad(cur["caducidad"])   # F8 tiempo: caducidades criticas (caducidad_watch)
    significant = sig_ep + sig_me + sig_fb + sig_dc + sig_nf + sig_mb + sig_mk + sig_cd

    drafted = None
    if significant:
        # agrupar por kind (estados + 'sensor_alert'); tomar el grupo con más eventos (1 grupo/ciclo)
        groups = {}
        for e in significant:
            groups.setdefault(e.get("kind", "unknown"), []).append(e)
        kind, group = max(groups.items(), key=lambda kv: len(kv[1]))
        res = _ai_lesson(kind, group, deadline)
        if res:
            lesson, model, engine = res[0], res[1], res[2]
            recalled = res[3] if len(res) > 3 else []
        else:
            lesson, model, engine, recalled = None, None, None, []
        path = _write_draft(kind, group, lesson, model, engine, recalled)
        drafted = {"kind": kind, "n_events": len(group), "draft": os.path.basename(path) if path else None,
                   "ai": bool(lesson), "model": model, "engine": engine,
                   "src": (group[0].get("_src") if group else "episodic"),
                   "recalled": recalled}   # CABLE 3: lecciones previas usadas como contexto

    # avanzar los OCHO cursores por todo lo leído
    _save_cursor({"episodic": max_seq, "metrics": new_line, "fib": new_fib,
                  "deception": new_dec, "netflow": new_nf, "modbus": new_mb, "merkle": new_mk,
                  "caducidad": new_cd})

    rec = {"svc": "event_learn", "ts": int(t0), "node": node, "mode": "observe-draft",
           "status": "learning",
           "cursor": {"episodic": max_seq, "metrics": new_line, "fib": new_fib,
                      "deception": new_dec, "netflow": new_nf, "modbus": new_mb, "merkle": new_mk,
                      "caducidad": new_cd},
           "new_significant": len(significant), "from_episodic": len(sig_ep), "from_metrics": len(sig_me),
           "from_fib": len(sig_fb), "from_deception": len(sig_dc), "from_netflow": len(sig_nf),
           "from_modbus": len(sig_mb), "from_merkle": len(sig_mk), "from_caducidad": len(sig_cd),
           "drafted": drafted, "elapsed_s": round(time.time() - t0, 1),
           "note": "IA propone borrador (nunca firma); el operador revisa y firma en el master"}
    print(json.dumps(rec, ensure_ascii=False))
    _append(REC, rec)
    return 0


def cmd_status():
    cur = _load_cursor()
    pend = []
    try:
        pend = [f for f in os.listdir(PENDING_DIR) if f.startswith("DRAFT_LEARN_")]
    except Exception:
        pass
    print(json.dumps({"svc": "event_learn", "node": _node_id(), "mode": "observe-draft",
                      "cursor": cur, "pending_drafts": len(pend),
                      "drafts": sorted(pend)[-10:]}, ensure_ascii=False))
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "cycle"
    try:
        if cmd in ("cycle", "probe", "run"):
            return cmd_cycle()
        if cmd == "status":
            return cmd_status()
        print(json.dumps({"svc": "event_learn", "error": "modo desconocido: %s" % cmd}))
        return 2
    except Exception as e:
        print(json.dumps({"svc": "event_learn", "ok": False, "fatal": str(e)}, ensure_ascii=False))
        return 0


if __name__ == "__main__":
    sys.exit(main())
