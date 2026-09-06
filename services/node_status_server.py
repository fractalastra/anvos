#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""node_status_server v2 — ITE-015 — servidor de ESTADO LOCAL del nodo ANVOS (matriz item 12: dashboard).

Residente (LONG_RUNNING bajo layerd). Hasta ahora el nodo solo EMPUJABA telemetría al panel del
master (cliente). Esto lo hace AUTO-OBSERVABLE de forma autónoma: agrega el estado vivo desde
/persist/anvos-data/*/*.jsonl y lo sirve por HTTP — GET /api/status (JSON) y GET / (HTML mínimo).
Paso hacia "ecosistema COMO OS": el nodo se inspecciona solo, sobreviva o no el master.

v2 — ITE-015: ya NO es estrictamente read-only — escribe el token de a bordo del panel
(panel/token, 0600) y el registro de accesos a /attest. Autenticación por token de a bordo con
sesión por cookie (las rutas /attest, /lineage y /blocks siguen PÚBLICAS por diseño, para la
federación). Chat con el modelo LOCAL del nodo (127.0.0.1:8090) vía POST /api/chat.
No firma, no ejecuta código sin firma válida. Solo stdlib."""
import os
import re
import sys
import json
import hmac
import time
import glob
import subprocess
import threading
import socketserver
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
NODE_ID_FILE = "/persist/anvos-node.id"
PORT = int(os.environ.get("ANVOS_STATUS_PORT", "8088"))
TOKEN_FILE = os.path.join(DATA, "panel", "token")
SESSIONS = {}            # sid -> ts de creación (memoria del proceso; reiniciar = re-login)
SESSION_TTL = 86400
_LOCK = threading.Lock()
# /attest, /lineage y /blocks son PÚBLICOS POR DISEÑO para la federación (ver las notas de cada
# ruta en do_GET); /login tiene que ser público para poder entrar.
PUBLIC = ("/attest", "/alerts", "/dialogo", "/lineage", "/blocks", "/login")
# Prefijo de la malla de pares: por configuracion (ANVOS_MESH_PREFIX, p.ej. "192.0.2.").
# Vacio = ningun acceso a /fleet sin sesion (fail-closed).
_MESH_PREFIX = os.environ.get("ANVOS_MESH_PREFIX", "").strip()
MS = os.path.join(STAGING, "pylayer-verify")
PUB = os.path.join(STAGING, "pylayer", "release.pub")


def _token():
    """Token de a bordo del panel: se crea una sola vez (0600) y NUNCA se loguea."""
    try:
        t = open(TOKEN_FILE).read().strip()
        if t:
            return t
    except Exception:
        pass
    os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
    t = os.urandom(24).hex()
    with open(TOKEN_FILE, "w") as f:
        f.write(t)
    os.chmod(TOKEN_FILE, 0o600)
    return t


def _sig_ok(target):
    """Firma 653C válida (minisign embebido); fail-closed."""
    ld = None
    for c in glob.glob(os.path.join(MS, "ld-linux*.so.2")):
        ld = c
    sig = target + ".minisig"
    if not (ld and os.path.exists(os.path.join(MS, "minisign")) and os.path.exists(PUB)
            and os.path.isfile(target) and os.path.isfile(sig)):
        return False
    try:
        r = subprocess.run([ld, "--library-path", MS, os.path.join(MS, "minisign"),
                            "-Vm", target, "-p", PUB, "-x", sig], capture_output=True, timeout=6)
        return r.returncode == 0
    except Exception:
        return False


def _master_view():
    """HETEROIMAGEN: el juicio del master sobre este nodo, FIRMADO 653C (fail-closed: sin firma
    válida se muestra como NO_VERIFICADO y no se confía en su contenido)."""
    p = os.path.join(DATA, "master-view", "verdict.json")
    if not os.path.isfile(p):
        return {"state": "SIN_VISTA"}
    if not _sig_ok(p):
        return {"state": "NO_VERIFICADO", "verified": False}
    try:
        v = json.loads(open(p).read())
    except Exception:
        return {"state": "NO_VERIFICADO", "verified": False}
    # frescura por mtime LOCAL del fichero (el ts del master no es comparable: el reloj del
    # nodo no tiene RTC sincronizado — lección: no comparar relojes entre máquinas)
    try:
        age = max(0, int(time.time() - os.path.getmtime(p)))
    except Exception:
        age = None
    return {"state": v.get("veredicto_global"), "verified": True,
            "espejo": v.get("espejo"), "anclas": v.get("anclas"),
            "escaladas_abiertas": v.get("escaladas_abiertas"),
            "escalada_pendiente": v.get("escalada_pendiente"),
            "escaladas_lista": v.get("escaladas_lista"),
            "edad_s": age, "fresca": (age is not None and age <= 1800)}


def _publicar_cuando_acabe(tmp, destino, plazo=90):
    """Publica el refresco SOLO cuando el fichero temporal es JSON completo y utilizable.

    Sin esto, mover el temporal en cuanto el hijo arranca reproduciria el defecto una linea mas
    abajo. Se espera a que el contenido PARSEE y traiga la lista de flota; si en el plazo no lo
    consigue, se descarta y la cache anterior se queda como estaba, que es lo correcto: un dato
    viejo y legible vale mas que uno nuevo y roto.
    """
    fin = time.time() + plazo
    while time.time() < fin:
        time.sleep(2)
        try:
            if os.path.getsize(tmp) < 2:
                continue
            d = json.loads(open(tmp).read())
        except Exception:
            continue
        if isinstance(d.get("flota"), list):
            try:
                os.replace(tmp, destino)
            except Exception:
                pass
            return
    try:
        os.unlink(tmp)
    except Exception:
        pass


def _fleet_view():
    """CONFIANZA DE FLOTA (federación fractal): resume la última verificación de peers (fleet_attest).
    LEE la caché (rápido, sin red en el render); si está vieja (>120s) lanza fleet_attest en 2º plano
    (fire-and-forget, throttled 30s) para que la PRÓXIMA carga esté fresca. Verify-only."""
    fdir = os.path.join(DATA, "fleet")
    cache = os.path.join(fdir, "fleet_status.json")
    peersf = os.path.join(fdir, "peers.txt")
    age = None
    try:
        age = max(0, int(time.time() - os.path.getmtime(cache)))
    except Exception:
        pass
    # refresco en 2º plano si falta o está viejo, con throttle por marcador (evita spawns en ráfaga)
    if age is None or age > 120:
        mark = os.path.join(fdir, ".refreshing")
        try:
            mage = time.time() - os.path.getmtime(mark)
        except Exception:
            mage = 1e9
        if mage > 30:
            try:
                peers = ",".join(l.strip() for l in open(peersf) if l.strip() and not l.startswith("#"))
            except Exception:
                peers = ""
            if peers:
                try:
                    os.makedirs(fdir, exist_ok=True)
                    open(mark, "w").write("1")
                    env = dict(os.environ, ANV_FLEET_PEERS=peers)
                    # FAIL-CLOSED: la capa esta FIRMADA; no debe ejecutar codigo sin firma valida.
                    # (hueco cerrado 2026-07-28: /persist/anvos-tools/*.py se ejecutaba SIN verificar)
                    _tool = "/persist/anvos-staging/services/fleet_attest.py"
                    if not _sig_ok(_tool):
                        raise RuntimeError("herramienta sin firma 653C valida: " + _tool)
                    # ESCRIBIR EN UN TEMPORAL Y MOVER, nunca sobre la cache viva.
                    #
                    # DEFECTO MEDIDO (revisor-a, 05-ago-2026): esto abria la cache con "w", lo que la
                    # TRUNCA al instante, y el hijo tardaba segundos en rellenarla. Cualquiera que
                    # leyese en esa ventana veia un fichero vacio o a medias — y quien lee es
                    # precisamente el consenso, porque LA MISMA CADUCIDAD que dispara el refresco es
                    # la que el se encuentra. Resultado: el par aparecia mudo, sus votos se perdian
                    # y origo figuraba SIN_VERIFICADORES teniendo dos pares que lo daban por valido.
                    #
                    # El ecosistema ya tenia la regla escrita —productor a temporal, luego mover—
                    # y aqui no se aplicaba. Refrescar algo no puede empezar por destruirlo.
                    _tmp = cache + ".refresh"
                    _fh = open(_tmp, "w")
                    subprocess.Popen(["anvos-python3", _tool], env=env,
                                     stdout=_fh, stderr=subprocess.DEVNULL)
                    _fh.close()
                    threading.Thread(target=_publicar_cuando_acabe, args=(_tmp, cache),
                                     daemon=True).start()
                except Exception:
                    pass
    if age is None:
        return {"estado": "sin evaluar (configura fleet/peers.txt)"}
    try:
        d = json.loads(open(cache).read())
    except Exception:
        return {"estado": "caché ilegible", "edad_s": age}
    nodos = " ".join("%s:%s" % (f.get("node", "?"), f.get("verdict", "?")) for f in d.get("flota", []))
    return {"peers": d.get("peers"), "validas": d.get("validas"), "nodos": nodos or "-",
            "edad_s": age, "fresca": age <= 300}


def _caducidad_view():
    """CADUCIDADES: resume la última pasada de caducidad_watch (lee resumen.json; rápido, sin red ni
    subprocess). Señala VENCIDO / POLITICA_MANIPULADA en rojo, avisos en ámbar, AL_DIA en verde."""
    cdir = os.path.join(DATA, "caducidades")
    resu = os.path.join(cdir, "resumen.json")
    try:
        age = max(0, int(time.time() - os.path.getmtime(resu)))
    except Exception:
        age = None
    try:
        r = json.loads(open(resu).read())
    except Exception:
        return {"estado": "SIN_DATOS"}
    pol = r.get("estado_politica")
    venc = r.get("vencidos", 0) or 0
    prox = r.get("proximos", []) or []
    porsev = r.get("por_severidad", {}) or {}
    esc = 0
    try:
        esc = sum(1 for _ in open(os.path.join(cdir, "escalated.jsonl")))
    except Exception:
        pass
    if pol == "POLITICA_MANIPULADA":
        estado = "POLITICA_MANIPULADA"
    elif pol == "SIN_CALENDARIO":
        estado = "SIN_CALENDARIO"
    elif venc:
        estado = "VENCIDO"
    elif any(porsev.get(s) for s in ("MAXIMA", "ALTA")):
        estado = "AVISO_T30"
    elif prox:
        estado = "AVISO_T90"
    else:
        estado = "AL_DIA"
    p0 = prox[0] if prox else None
    out = {"estado": estado, "politica": pol, "vencidos": venc,
           "proximo": ("%s · %sd" % (p0["id"], p0["dias"])) if p0 else "-",
           "avisos_abiertos": len(prox), "escaladas": esc, "edad_s": age}
    if r.get("reloj_dudoso"):
        out["reloj"] = "DUDOSO"
    return out


def _codegen_view():
    """CODEGEN SOBERANO: AstraNova Code creando código EN el nodo (hito 2026-07-27).
    Lee la auditoría continua (codegen_audit) + el ledger de codegen (hash-chain firmada 9c)."""
    aud = _last("codegen/codegen_audit.jsonl") or {}
    estado = aud.get("estado")
    if not estado or estado == "SIN_CODEGEN":
        return {"estado": "SIN_CODEGEN"}
    led = "/persist/anvos-data/astra-code/codegen_ledger.jsonl"
    head = None
    try:
        with open(led) as f:
            for ln in f:
                ln = ln.strip()
                if ln:
                    head = json.loads(ln)
    except Exception:
        pass
    out = {"estado": estado, "eventos_firmados_9c": aud.get("eventos"),
           "aplicados": aud.get("aplicados")}
    if head:
        out["ultimo"] = head.get("filename") or head.get("event")
        out["cabeza"] = (head.get("hash") or "")[:16]
    if aud.get("fallos"):
        out["fallos"] = "; ".join(aud["fallos"])[:120]
    return out


def _dr_view():
    """DR VERIFICADO: la replica del nodo en el 2o disco, comprobada (autoridad+integridad+
    autenticidad+restaurabilidad). Un backup no verificado no es un backup."""
    dv = _last("dr/dr_verify.jsonl") or {}
    v = dv.get("verdict")
    if not v or v == "DR_NO_MONTADO":
        return {"estado": "DR_NO_MONTADO"}
    out = {"estado": v, "ficheros": dv.get("esperados"), "faltan": dv.get("faltan"),
           "corruptos": dv.get("corruptos"), "firmas_ok": dv.get("firmas_comprobadas"),
           "firmas_malas": dv.get("firmas_invalidas"), "edad_s": dv.get("edad_s")}
    if dv.get("criticos_ausentes"):
        out["criticos_ausentes"] = ", ".join(dv["criticos_ausentes"])[:60]
    return out


def _queue_view():
    """COLA OPERADOR (nodo): incidentes vivos con auto-resolución (queue_watch)."""
    try:
        est = json.loads(open(os.path.join(DATA, "queue/estado.json")).read())
    except Exception:
        return {"estado": "SIN_DATOS"}
    ab = est.get("abiertos", {}) or {}
    peor = "CRIT" if any(i.get("sev") == "CRIT" for i in ab.values()) else (
        "WARN" if ab else "COLA_LIMPIA")
    out = {"estado": peor, "abiertos": len(ab),
           "auto_resueltos": est.get("resueltos_auto", 0),
           "historicos": est.get("total_incidentes", 0)}
    if ab:
        k = sorted(ab, key=lambda x: 0 if ab[x].get("sev") == "CRIT" else 1)[0]
        out["peor"] = "%s: %s" % (k, (ab[k].get("detalle") or "")[:80])
    return out


def _servicios_view():
    """SERVICIOS (capa viva): cruza el latido de layerd (estado REAL por servicio) con el
    manifiesto de la capa (lo que DEBERÍA estar supervisado). Un servicio que figura en el
    manifiesto y no aparece en el latido es una promesa sin proceso; uno con fail>ok está
    fallando aunque layerd lo mantenga."""
    ld = _last("layerd/layerd.jsonl") or {}
    svcs = ld.get("services") or {}
    manifest = []
    try:
        with open(os.path.join(STAGING, "services", "manifest.txt")) as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                # formato: fichero|intervalo|salida|modulo?
                fich = ln.split("|")[0].strip()
                if fich:
                    manifest.append(fich)
    except Exception:
        pass
    longs = {n: s for n, s in svcs.items() if s.get("kind") == "long"}
    perio = {n: s for n, s in svcs.items() if s.get("kind") != "long"}
    corrieron = {n: s for n, s in perio.items() if (s.get("runs") or 0) > 0}
    malas = sum(1 for s in svcs.values()
                if (s.get("sig_fail") or 0) > 0 or s.get("sig_ok") is False)
    sin_sup = [n for n in manifest if n not in svcs]
    fallando = [n for n, s in svcs.items() if (s.get("fail") or 0) > (s.get("ok") or 0)]
    return {
        "supervisados": len(svcs),
        "vivos_long": "%d/%d" % (sum(1 for s in longs.values() if s.get("alive")), len(longs)),
        "periodicos_ok": "%d/%d" % (sum(1 for s in corrieron.values() if (s.get("ok") or 0) > 0),
                                    len(corrieron)),
        "firmas_invalidas": malas if malas else "0",
        "en_manifiesto_sin_supervisar": ", ".join(sin_sup) if sin_sup else "ninguno",
        "fallando": ", ".join(fallando) if fallando else "ninguno",
    }


def _last(rel):
    """Última línea JSON de un ledger del nodo (o None, defensivo)."""
    try:
        with open(os.path.join(DATA, rel)) as f:
            lines = f.readlines()
        for ln in reversed(lines):
            ln = ln.strip()
            if ln:
                return json.loads(ln)
    except Exception:
        pass
    return None


def _node_id():
    try:
        return open(NODE_ID_FILE).read().strip()
    except Exception:
        return "unknown"


def build_status():
    beacon = _last("eco-telem/beacon.jsonl") or {}
    si = _last("integrity/self_integrity.jsonl") or {}
    cg = _last("governance/cognition_guard.jsonl") or {}
    ld = _last("layerd/layerd.jsonl") or {}
    ring = _last("ring/ring_link.jsonl") or {}
    gpu = _last("gpu/gpu_enable.jsonl") or {}
    rag = _last("ai/rag.jsonl") or {}
    drift = _last("asct/drift.jsonl") or {}
    router = _last("ai/router.jsonl") or {}
    # --- capa de autoconciencia (servicios nuevos) ---
    ca = _last("sentinel/core_audit.jsonl") or {}
    tw = _last("twin/twin_forward.jsonl") or {}
    adv = _last("governance/advisor.jsonl") or {}
    inv = _last("inventory/inventory_sensor.jsonl") or {}
    dec = _last("deception/deception_sensor.jsonl") or {}
    dechit = _last("deception/hits.jsonl") or {}
    evl = _last("memory/event_ledger.jsonl") or {}
    pol = _last("asct/policy.jsonl") or {}
    rsim = _last("asct/rollback_sim.jsonl") or {}
    isim = _last("asct/incident_sim.jsonl") or {}
    # --- fuentes NUEVAS (capacidades portadas): aprendizaje, defensa fib, métricas sensor, módulos ---
    fib = _last("security/fib_guard.jsonl") or {}
    evlearn = _last("learning/event_learn.jsonl") or {}
    sensor = _last("modules/sensor.jsonl") or {}
    netflow = _last("modules/netflow/netflow.jsonl") or {}
    modbus = _last("modules/modbus.jsonl") or {}
    banchor = _last("chain/block_anchor.jsonl") or {}      # cadena de bloques merkle propia del nodo
    realm = _last("realm/realm.jsonl") or {}               # soberanía del nodo (realm propio, Vía A)
    iam = _last("iam/iam_verify.jsonl") or {}              # confianza de DOS niveles con alcance firmado
    tpm = _last("tpm/tpm_attest.jsonl") or {}              # raíz de confianza del equipo, leída del aparato
    rdrift = _last("runtime/runtime_drift.jsonl") or {}    # lo EJECUTADO frente a lo desplegado
    invhw = (inv.get("inventory") or {})
    twm = tw.get("metrics") or {}
    # módulos habilitados por el perfil firmado del nodo
    mods = []
    try:
        mods = (json.loads(open("/persist/anvos-modules/profile.json").read()).get("enabled_modules") or [])
    except Exception:
        mods = []
    # nº de lecciones aprendidas ya en el índice RAG firmado
    n_lessons = None
    try:
        idx = json.loads(open(os.path.join(DATA, "semantic", "knowledge_vectors.json")).read())
        n_lessons = sum(1 for it in idx.get("items", []) if it.get("source") == "learned_lesson")
    except Exception:
        n_lessons = None
    drf = evlearn.get("drafted") or {}
    # APRENDIZAJE de 6 sentidos: cuántas fuentes traen señal en el último ciclo
    _lsrc = ("from_episodic", "from_metrics", "from_fib", "from_deception", "from_netflow", "from_modbus", "from_merkle")
    sentidos_activos = sum(1 for k in _lsrc if (evlearn.get(k, 0) or 0) > 0)
    # borradores de lección PENDIENTES de revisión (IA propone; el operador firma en el master)
    borradores = []
    try:
        pdir = os.path.join(DATA, "learning", "pending")
        for f in os.listdir(pdir):
            if not (f.startswith("DRAFT_LEARN_") and f.endswith(".md")):
                continue
            # DRAFT_LEARN_<clase>_<YYYYmmddTHHMMSSZ>.md
            mid = f[len("DRAFT_LEARN_"):-3]
            clase, _, stamp = mid.rpartition("_")
            ia = False
            try:
                head = open(os.path.join(pdir, f)).read(600)
                ia = ("IA_PENDIENTE" not in head)   # con lección de IA vs esqueleto
            except Exception:
                pass
            borradores.append({"archivo": f, "clase": clase or "?", "ts": stamp, "con_ia": ia,
                               "mtime": os.path.getmtime(os.path.join(pdir, f))})
        borradores.sort(key=lambda b: b["mtime"], reverse=True)
    except Exception:
        borradores = []
    st = {
        "node": _node_id(),
        "ts": int(time.time()),
        "core_audit": {"state": ca.get("state"), "score": ca.get("core_health_score")},
        "twin": {"state": tw.get("state"), "idg": tw.get("idg"), "projection": tw.get("projection_next"),
                 "worst_metric": tw.get("worst_metric"), "first_to_break": tw.get("first_to_break"),
                 "metricas": {k: v.get("verdict") for k, v in twm.items()} or None},
        "advisor": {"level": adv.get("recommended_level")},
        "policy": {"state": pol.get("conformidad"), "dictamen": (pol.get("dictamen") or {}).get("respuesta"),
                   "regla": (pol.get("dictamen") or {}).get("regla"),
                   "signed": pol.get("policy_signed"), "version": pol.get("policy_version")},
        "drills": {"state": ("OK" if (rsim.get("verdict") == "RECOVERY_OK"
                                      and isim.get("verdict") == "DETECTOR_OK") else "REGRESION"),
                   "detector": isim.get("verdict"), "detector_n": "%s/%s" % (isim.get("passed", "-"), isim.get("total", "-")),
                   "recovery": rsim.get("verdict"), "recovery_n": "%s/%s" % (rsim.get("passed", "-"), rsim.get("total", "-"))},
        "health": {"cpu_load": beacon.get("cpu_load"), "mem_pct": beacon.get("mem_pct"),
                   "disk_pct": beacon.get("disk_pct")},
        "integrity": {"attestation": si.get("attestation"), "verified": si.get("verified"),
                      "total": si.get("total"), "all_valid": si.get("all_valid")},
        "governance": {"veredicto": cg.get("veredicto") or cg.get("verdict"),
                       "observe_only": cg.get("observe_only")},
        "layer": {"supervised": ld.get("supervised"), "fail_closed_blocks": ld.get("fail_closed_blocks"),
                  "uptime_s": ld.get("uptime_s")},
        "mesh": {"iface": ring.get("iface"), "state": ring.get("state"),
                 "peers": ring.get("peers"), "handshakes_fresh": ring.get("handshakes_fresh"),
                 "ring_pub": ring.get("node_wg_pub")},
        "gpu": {"state": gpu.get("state"), "driver": gpu.get("gpu_driver"), "dri": gpu.get("dri_nodes")},
        "ai": {"engine": router.get("endpoint_kind"), "api": router.get("api"),
               "model": (os.path.basename(str(router.get("model") or "")) or None) if router.get("model") else router.get("note"),
               "corpus": rag.get("n_corpus"), "status": router.get("status")},
        "aprendizaje": {"estado": evlearn.get("status"), "sentidos": "%d/7" % sentidos_activos,
                        "de_estados": evlearn.get("from_episodic"), "de_metricas": evlearn.get("from_metrics"),
                        "de_seguridad": (evlearn.get("from_fib", 0) or 0) + (evlearn.get("from_deception", 0) or 0),
                        "de_red": evlearn.get("from_netflow"), "de_ot": evlearn.get("from_modbus"),
                        "de_integridad": evlearn.get("from_merkle"),
                        "ultimo_draft": drf.get("draft"), "clase": drf.get("kind"), "motor": drf.get("engine"),
                        "recordado": (drf.get("recalled") or [None])[0], "lecciones_en_rag": n_lessons},
        "defensa_fib": {"modo": fib.get("mode"), "ips_vigiladas": fib.get("tracked_ips"),
                        "recomendaciones": fib.get("active_recommendations"), "nuevos_fallos": fib.get("new_fails")},
        "sensor": {"estado": sensor.get("status"), "ingeridas": sensor.get("ingested"),
                   "alertas": sensor.get("alerts"), "puerto": sensor.get("port")},
        "red_netflow": {"modo": netflow.get("mode"), "conexiones": netflow.get("established"),
                        "peers_unicos": netflow.get("unique_peers"), "peers_externos": netflow.get("external_peers"),
                        "peers_nuevos": netflow.get("new_peers")},
        "ot_modbus": {"modo": modbus.get("mode"), "objetivos": modbus.get("targets"),
                      "sondeados": modbus.get("polled"), "alertas": modbus.get("alerts")},
        "modulos": {"activos": ", ".join(mods) if mods else "(ninguno)", "n": len(mods)},
        "borradores": borradores[:12],
        "asct": {"risk": drift.get("risk") or drift.get("risk_level"),
                 "drift_events": drift.get("drift_events")},
        "inventory": {"cpu": (invhw.get("cpu") or {}).get("model"), "ram_gb": invhw.get("ram_gb"),
                      "disks": [d.get("model") for d in invhw.get("disks", [])],
                      "fingerprint": inv.get("fingerprint")},
        "deception": {"bait_ports": dec.get("bait_ports"), "hits_total": dec.get("hits_total"),
                      "last_hit_port": dechit.get("bait_port"), "last_hit_src": dechit.get("src_ip")},
        "memory": {"total_events": evl.get("total_seq"), "head": evl.get("head"),
                   "chain_ok": evl.get("chain_ok")},
        "cadena_bloques": {"altura": banchor.get("height"), "cabeza": banchor.get("head"),
                           "verificada": banchor.get("verified"), "bloques": banchor.get("blocks"),
                           "ultimo_merkle": banchor.get("merkle_root")},
        "soberania": {"estado": realm.get("estado") or "-", "soberano": realm.get("soberano"),
                      "realm": realm.get("realm_id"), "node_id": realm.get("node_id"),
                      "firma_manifiesto": realm.get("firma_manifiesto")},
        # --- capacidades cargadas el 01-ago-2026 -------------------------------------------
        # Se exponen aqui porque una capacidad que corre en el nodo y no se ve en su tablero
        # es una capacidad que nadie mira: lo aprendido hoy con los modulos de dominio, que
        # llevaban meses en la capa de un nodo sin perfil que los encendiera.
        #
        # Cada una publica ADEMAS su limite, no solo su estado. El TPM sobre todo: dice que lo
        # suyo es una lectura y NO un quote firmado, para que nadie lea "TPM" en el tablero y
        # concluya que hay atestacion. Un tablero que enseña la virtud y esconde el limite
        # induce exactamente el error que este ecosistema lleva todo el dia corrigiendo.
        "iam": {"veredicto": iam.get("veredicto"), "niveles": iam.get("niveles"),
                "ancla": iam.get("ancla"),
                "delegaciones_avaladas": iam.get("delegaciones_avaladas"),
                "con_alcance_emision": iam.get("delegaciones_con_emision"),
                "politica": (iam.get("politica") or {}).get("id"),
                "tokens": iam.get("tokens_validos")},
        "tpm": {"veredicto": tpm.get("veredicto"), "fabricante": tpm.get("fabricante"),
                "pcr_leidos": tpm.get("pcr_leidos"),
                "arranque_seguro_medido": tpm.get("arranque_seguro_medido"),
                "huella": (tpm.get("huella_compuesta") or "")[:16],
                "clase": tpm.get("clase"),
                "quote_firmado": tpm.get("quote_firmado"),
                "apto_voto_ponderado": tpm.get("apto_para_voto_ponderado")},
        "ejecucion": {"veredicto": rdrift.get("veredicto"),
                      "residentes": len(rdrift.get("residentes") or {}),
                      "puertos": len(rdrift.get("puertos") or {}),
                      "hallazgos": len(rdrift.get("hallazgos") or []),
                      "detalle": "; ".join(
                          "%s %s" % (h.get("tipo"), h.get("servicio") or h.get("puerto"))
                          for h in (rdrift.get("hallazgos") or [])[:3]) or "-"},
        "master_view": _master_view(),
        "federacion": _fleet_view(),
        "caducidades": _caducidad_view(),
        "codegen": _codegen_view(),
        "dr": _dr_view(),
        "cola_operador": _queue_view(),
    }
    st["servicios_capa"] = _servicios_view()
    return st


_HTML = """<!doctype html><html lang=es><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>ANVOS · {node}</title>
<style>
:root{{--bg:#0a0e13;--card:#111823;--card2:#0e141d;--ink:#dce8f2;--dim:#7488a0;--line:#1d2836;
--g:#4ade80;--a:#fbbf24;--r:#f87171;--ac:#38bdf8}}
*{{box-sizing:border-box}}body{{background:linear-gradient(160deg,#0a0e13,#0c1420);color:var(--ink);
font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;margin:0;padding:22px;max-width:1180px;margin:auto}}
header{{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:6px}}
h1{{font-size:22px;margin:0;color:#fff;font-weight:650}}
.seal{{font-size:12px;padding:4px 12px;border-radius:20px;font-weight:600}}
.sub{{color:var(--dim);font-size:12.5px;margin:2px 0 18px}}
.loop{{display:flex;gap:8px;flex-wrap:wrap;background:var(--card2);border:1px solid var(--line);
border-radius:12px;padding:12px 14px;margin-bottom:20px;align-items:center}}
.loop b{{color:var(--ac)}}.loop .st{{color:var(--dim)}}.loop .ar{{color:#3a4a5e;font-size:16px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:14px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px}}
.card h3{{margin:0 0 10px;font-size:13px;letter-spacing:.3px;color:#fff;display:flex;
align-items:center;gap:8px;text-transform:uppercase;font-weight:650}}
.row{{display:flex;justify-content:space-between;gap:10px;padding:3px 0;border-top:1px solid #17212e}}
.row:first-of-type{{border-top:0}}.row .k{{color:var(--dim);font-size:12.5px}}
.row .v{{font-weight:600;text-align:right;word-break:break-word}}
.g{{color:var(--g)}}.a{{color:var(--a)}}.r{{color:var(--r)}}.k2{{color:var(--ink)}}
.drafts{{margin-top:22px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px}}
.drafts h3{{margin:0 0 10px;font-size:13px;letter-spacing:.3px;color:#fff;text-transform:uppercase;font-weight:650}}
.draft{{display:flex;gap:10px;align-items:center;padding:8px 10px;border:1px solid var(--line);border-radius:10px;
margin:6px 0;text-decoration:none;color:var(--ink);background:var(--card2)}}
.draft:hover{{border-color:var(--ac)}}
.draft .dc{{font-weight:650;color:var(--ac);min-width:150px}}.draft .dt{{color:var(--dim);font-size:12px;flex:1}}
.draft .dia{{font-size:11px;padding:2px 8px;border-radius:10px}}
.draft .ok{{background:#12331d;color:var(--g)}}.draft .sk{{background:#332b12;color:var(--a)}}
footer{{color:var(--dim);font-size:12px;margin-top:22px;text-align:center}}
</style>
<header><h1>\U0001f9ec ANVOS · {node}</h1><span class=seal style="background:{sealbg};color:#04240f">{seal}</span></header>
<p class=sub>estado vivo del nodo · {when} · auto-observado (read-only)</p>
<div class=loop><b>\U0001f504 bucle</b> <span>recoge</span><span class=ar>→</span><span>aprende</span>
<span class=ar>→</span><span>recuerda</span><span class=ar>→</span><span>firma</span>
<span class=st>&nbsp;· {loopnote}</span></div>
<div class=grid>{cards}</div>
{drafts}
{svctable}
<details style="margin-top:20px"><summary style="cursor:pointer;color:var(--ac);font-size:13px;font-weight:600">\U0001f5a5️ Cockpit gráfico soberano (snapshot)</summary>
<img src="/cockpit.png?t={cbust}" alt="cockpit soberano" style="width:100%;border:1px solid var(--line);border-radius:12px;margin-top:12px" onerror="this.insertAdjacentHTML('afterend','&lt;p class=sub&gt;(sin snapshot aún; el cockpit lo genera cada ciclo)&lt;/p&gt;');this.remove()"></details>
<details style="margin-top:20px"><summary style="cursor:pointer;color:var(--ac);font-size:13px;font-weight:600">\U0001f4ac Conversar con el nodo</summary>
<div style="background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px;margin-top:12px">
<div id=chatlog style="overflow-y:auto;max-height:300px;display:flex;flex-direction:column;gap:6px;margin-bottom:10px"></div>
<div style="display:flex;gap:8px">
<input id=chatin type=text placeholder="pregunta al nodo por su estado…" style="flex:1;background:var(--card2);border:1px solid var(--line);border-radius:8px;color:var(--ink);padding:8px 10px;font:inherit">
<button id=chatbtn style="background:var(--ac);border:0;border-radius:8px;color:#04240f;font-weight:650;padding:8px 14px;cursor:pointer;font:inherit">Enviar</button>
</div></div>
<script>
var _hist=[];
function _msg(rol,txt){{var d=document.createElement('div');
d.style.cssText='padding:6px 10px;border-radius:10px;white-space:pre-wrap;word-break:break-word;max-width:85%;font-size:13px;'+
(rol==='user'?'align-self:flex-end;background:#123047':'align-self:flex-start;background:var(--card2);border:1px solid var(--line)');
d.textContent=txt;document.getElementById('chatlog').appendChild(d);d.scrollIntoView();}}
function _enviar(){{var inp=document.getElementById('chatin'),btn=document.getElementById('chatbtn');
var m=inp.value.trim();if(!m||btn.disabled)return;inp.value='';_msg('user',m);
btn.disabled=true;btn.textContent='…';
fetch('/api/chat',{{method:'POST',headers:{{'Content-Type':'application/json'}},
body:JSON.stringify({{message:m,history:_hist.slice(-6)}})}})
.then(function(r){{return r.json();}})
.then(function(j){{if(j.error){{_msg('assistant','⚠ '+j.error);}}
else{{_msg('assistant',j.reply||'(sin respuesta)');
_hist.push({{role:'user',content:m}});_hist.push({{role:'assistant',content:j.reply||''}});
_hist=_hist.slice(-6);}}}})
.catch(function(e){{_msg('assistant','⚠ '+e);}})
.finally(function(){{btn.disabled=false;btn.textContent='Enviar';inp.focus();}});}}
document.getElementById('chatbtn').addEventListener('click',_enviar);
document.getElementById('chatin').addEventListener('keydown',function(e){{if(e.key==='Enter')_enviar();}});
</script></details>
<footer>node_status_server · read-only · <code>/api/status</code> JSON · <code>/cockpit.png</code> imagen</footer></html>"""


def _band(section, d):
    st = str(d.get("attestation") or d.get("state") or d.get("veredicto")
             or d.get("level") or "")
    # El color por defecto de lo desconocido es ROJO (ver la linea del calculo). Es una eleccion
    # deliberada y correcta —un veredicto que nadie declaro no puede pintarse de verde— pero
    # obliga a DECLARAR cada veredicto nuevo. Si no, una capacidad recien cargada y sana sale en
    # rojo, y unas cuantas asi enseñan al operador a no mirar el rojo. Que es peor que no tenerlo.
    green = ("SEALED", "RENDER_READY", "LINKED", "GOBERNADO", "HEALTHY", "COHERENTE",
             "A0_OBSERVAR", "DETECTOR_OK", "CONFORME", "OK", "NODO_EN_ORDEN",
             "CADENA_VALIDA", "AL_DIA", "PCR_LEIDOS")
    amber = ("READY_PEERS", "READY_NO_PEERS", "WATCH", "DIVERGENCIA_LEVE",
             "A1_VIGILAR", "A2_ADVERTIR", "SIN_ADVISOR", "CALIBRANDO", "SIN_VISTA",
             # Ambar, no rojo: en una maquina virtual la ausencia de TPM no es una averia, es un
             # hecho del hardware. Pintarla de rojo seria dar una alarma que nadie puede atender.
             "SIN_APARATO", "ANCLA_SIN_DELEGACIONES", "CADENA_VALIDA_CON_TOKENS_RECHAZADOS")
    red = ("CRITICAL", "DEGRADED", "CAMBIO_REGIMEN", "SIN_GOBIERNO", "A5_ESCALAR", "BLOCKED_SIG",
           "DESVIACION", "REGRESION", "ATENCION_REQUERIDA", "NO_VERIFICADO",
           # Estos SI son averia: una cadena de dos niveles sin su raiz, un proceso sirviendo
           # codigo anterior, y un aparato presente que no responde.
           "SIN_ANCLA", "DESFASE", "NO_CONFORME", "LECTURA_FALLIDA", "NO_RESPONDE", "SIN_PCR")
    cls = "g" if st in green else "a" if st in amber else "r" if st in red else ("r" if st else "k")
    return cls


_GREEN = ("SEALED", "RENDER_READY", "LINKED", "GOBERNADO", "HEALTHY", "COHERENTE", "OK", "NODO_EN_ORDEN",
          "router-ready", "listening", "watching", "learning", "observe", "CONFORME", "active", "vulkan-igpu",
          "FIRMADO_OK", "AL_DIA", "AUDIT_OK", "COLA_LIMPIA", "DR_VERIFICADO",
          "CADENA_VALIDA", "PCR_LEIDOS", "ninguno")
_AMBER = ("READY_PEERS", "READY_NO_PEERS", "WATCH", "DIVERGENCIA_LEVE", "en-espera", "SIN_VISTA", "cpu",
          "SIN_CALENDARIO", "AVISO_T90", "AVISO_T60", "DUDOSO", "SIN_CODEGEN", "DR_NO_MONTADO", "DR_VIEJO", "DR_INCOMPLETO", "DR_FIRMA_PENDIENTE", "PENDIENTE",
          "SIN_APARATO", "ANCLA_SIN_DELEGACIONES", "CADENA_VALIDA_CON_TOKENS_RECHAZADOS")
_RED = ("CRITICAL", "DEGRADED", "CAMBIO_REGIMEN", "SIN_GOBIERNO", "REGRESION", "NO_VERIFICADO", "BLOCKED_SIG",
        "POLITICA_MANIPULADA", "VENCIDO", "AVISO_T30", "AUDIT_FALLA", "AUDIT_ERROR", "CRIT", "DR_TAMPER", "DR_MANIFIESTO_NO_AUTENTICO")


def _vcls(v):
    s = str(v)
    if s in _GREEN or s.startswith("qwen") or s.endswith(".gguf") or s == "True":
        return "g"
    if s in _AMBER:
        return "a"
    if s in _RED or s == "False":
        return "r"
    return "k2"


def _card(icon, title, d):
    rows = []
    for k, v in d.items():
        if v is None or v == "":
            continue
        rows.append('<div class=row><span class=k>%s</span><span class="v %s">%s</span></div>'
                    % (k, _vcls(v), v))
    return '<div class=card><h3>%s %s</h3>%s</div>' % (icon, title, "".join(rows) or '<div class=row><span class=k>—</span></div>')


def render_html(st):
    integ = st.get("integrity", {})
    ver, tot = integ.get("verified"), integ.get("total")
    sealed = bool(integ.get("all_valid"))
    seal = ("SEALED %s/%s" % (ver, tot)) if ver is not None else "?"
    sealbg = "var(--g)" if sealed else "var(--a)"
    ai, apr = st.get("ai", {}), st.get("aprendizaje", {})
    nl = apr.get("lecciones_en_rag")
    loopnote = "IA local %s · aprende %s sentidos · %s lecciones en RAG · %s módulos activos" % (
        ai.get("model") or ai.get("engine") or "-", apr.get("sentidos") or "-",
        nl if nl is not None else "-", st.get("modulos", {}).get("n", 0))
    cards = [
        _card("\U0001f9e0", "IA local", st.get("ai", {})),
        _card("\U0001f4da", "Aprendizaje", st.get("aprendizaje", {})),
        _card("\U0001f6e1", "Defensa", {**st.get("defensa_fib", {}), "deception_hits": st.get("deception", {}).get("hits_total")}),
        _card("\U0001f4c8", "Sensor / Métricas", st.get("sensor", {})),
        _card("\U0001f310", "Red / NetFlow", st.get("red_netflow", {})),
        _card("\U0001f3ed", "OT / Modbus", st.get("ot_modbus", {})),
        _card("\U0001f9e9", "Módulos (perfil)", st.get("modulos", {})),
        _card("❤️", "Salud núcleo", {"core": st.get("core_audit", {}).get("state"),
              "twin": st.get("twin", {}).get("state"), "cpu_load": st.get("health", {}).get("cpu_load"),
              "mem_pct": st.get("health", {}).get("mem_pct"), "disk_pct": st.get("health", {}).get("disk_pct")}),
        _card("⚖️", "Gobernanza", {"veredicto": st.get("governance", {}).get("veredicto"),
              "observe_only": st.get("governance", {}).get("observe_only"),
              "advisor": st.get("advisor", {}).get("level"), "policy": st.get("policy", {}).get("state")}),
        _card("\U0001f517", "Malla WG", st.get("mesh", {})),
        _card("\U0001f512", "Integridad + capa", {"sello": seal, "attestation": integ.get("attestation"),
              "capa_svc": st.get("layer", {}).get("supervised"), "gpu": st.get("gpu", {}).get("state")}),
        _card("⚙️", "Servicios (capa viva)", st.get("servicios_capa", {})),
        _card("\U0001f4dc", "Memoria / Ledger", {**st.get("memory", {}), "asct_risk": st.get("asct", {}).get("risk")}),
        _card("⛓️", "Cadena de bloques (nodo)", st.get("cadena_bloques", {})),
        _card("\U0001f451", "Soberanía / Realm", st.get("soberania", {})),
        _card("\U0001f6f0", "Federación de flota", st.get("federacion", {})),
        _card("\U000023f3", "Caducidades", st.get("caducidades", {})),
        _card("\U0001f9ec", "Codegen soberano", st.get("codegen", {})),
        _card("\U0001f4e5", "Cola operador (nodo)", st.get("cola_operador", {})),
        _card("\U0001f6df", "DR verificado", st.get("dr", {})),
    ]
    # sección de borradores de lección pendientes (IA propone; el operador revisa/firma en el master)
    _SRC = {"external_peer": "🌐 red · peer externo", "modbus_alert": "🏭 OT · umbral",
            "sensor_alert": "📈 sensor · umbral", "ssh_bruteforce": "🛡️ seguridad · fuerza bruta",
            "honeypot_hit": "🛡️ seguridad · honeypot"}
    bl = st.get("borradores") or []
    if bl:
        items = []
        for b in bl:
            clase = b.get("clase", "?")
            etiq = _SRC.get(clase, "🧠 %s" % clase)
            ia = b.get("con_ia")
            badge = '<span class="dia ok">con IA</span>' if ia else '<span class="dia sk">esqueleto</span>'
            items.append('<a class=draft href="/draft?f=%s" target=_blank><span class=dc>%s</span>'
                         '<span class=dt>%s</span>%s</a>' % (b.get("archivo", ""), etiq, b.get("ts", ""), badge))
        drafts = ('<section class=drafts><h3>\U0001f4dd Borradores de aprendizaje pendientes · '
                  'IA propone, tú firmas (%d)</h3>%s</section>' % (len(bl), "".join(items)))
    else:
        drafts = ('<section class=drafts><h3>\U0001f4dd Borradores de aprendizaje pendientes</h3>'
                  '<p class=sub style="margin:0">sin borradores pendientes · el nodo aprende y propone al detectar algo significativo</p></section>')
    # tabla por servicio desde el MISMO latido de layerd que alimenta la tarjeta
    _svcs = (_last("layerd/layerd.jsonl") or {}).get("services") or {}
    if _svcs:
        _td = 'style="padding:5px 10px;border-top:1px solid var(--line)"'
        _th = 'style="padding:5px 10px;text-align:left;color:var(--dim);font-size:12px"'
        filas = "".join(
            ('<tr><td %s>%s</td><td %s>%s</td><td %s>%s</td><td %s>%s</td>'
             '<td %s><span class=%s>%s</span></td><td %s><span class=%s>%s</span></td></tr>')
            % (_td, n, _td, s.get("kind", "?"), _td, s.get("ok", 0), _td, s.get("fail", 0),
               _td, ("r" if ((s.get("sig_fail") or 0) > 0 or s.get("sig_ok") is False) else "g"),
               ("invalida" if ((s.get("sig_fail") or 0) > 0 or s.get("sig_ok") is False) else "ok"),
               _td, ("g" if s.get("alive") else ("k2" if s.get("kind") != "long" else "r")),
               ("sí" if s.get("alive") else ("—" if s.get("kind") != "long" else "no")))
            for n, s in sorted(_svcs.items()))
        svctable = ('<details style="margin-top:20px"><summary style="cursor:pointer;color:var(--ac);'
                    'font-size:13px;font-weight:600">⚙️ Servicios de la capa · detalle por servicio</summary>'
                    '<div style="overflow-x:auto;background:var(--card);border:1px solid var(--line);'
                    'border-radius:12px;margin-top:12px"><table style="border-collapse:collapse;width:100%;'
                    'font-size:13px"><tr><th ' + _th + '>servicio</th><th ' + _th + '>kind</th>'
                    '<th ' + _th + '>ok</th><th ' + _th + '>fail</th><th ' + _th + '>sig</th>'
                    '<th ' + _th + '>vivo</th></tr>' + filas + '</table></div></details>')
    else:
        svctable = ""
    return _HTML.format(node=st["node"], seal=seal, sealbg=sealbg,
                        when=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st["ts"])),
                        loopnote=loopnote, cards="".join(cards), cbust=st["ts"], drafts=drafts,
                        svctable=svctable)


class _Server(ThreadingHTTPServer):
    """ThreadingHTTPServer (v2: concurrente — el chat con el modelo local puede tardar y no debe
    congelar el panel) que NO llama socket.getfqdn() al bind: en ANVOS busybox no hay resolución
    de nombres (sin /etc/hosts ni DNS) y getfqdn('0.0.0.0') aborta el arranque del servidor."""
    daemon_threads = True

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "anvos", self.server_address[1]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # silencioso

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _autorizado(self):
        """True si la cookie anv_sess trae una sesión viva (purga las caducadas)."""
        sid = None
        for parte in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = parte.strip().partition("=")
            if k == "anv_sess":
                sid = v
        now = time.time()
        with _LOCK:
            for s in [s for s, ts in SESSIONS.items() if now - ts > SESSION_TTL]:
                SESSIONS.pop(s, None)
            return sid in SESSIONS

    def _gate(self):
        """Puerta de autenticación: rutas PUBLIC pasan (federación por diseño); el resto exige
        sesión. Sin sesión: 401 JSON para /api/*, 303 a /login para lo navegable.
        DECISIÓN operador ITE-015 (2026-08-09, corregida tras medir): /fleet puede abrirse a los
        pares de la malla porque su consumidor real es fleet_consensus entre nodos (misma
        familia de federación que /attest, /lineage y /blocks, ya públicos) — pero SOLO si el
        prefijo de la malla está DECLARADO (ANVOS_MESH_PREFIX); sin declaración, /fleet exige
        sesión como todo lo demás (fail-closed). TODO /api/* exige sesión y /api/chat SIEMPRE."""
        if any(self.path.startswith(p) for p in PUBLIC):
            return True
        if self.path.startswith("/fleet") and _MESH_PREFIX:
            ip = self.client_address[0] if self.client_address else ""
            if ip.startswith(_MESH_PREFIX):   # par de la malla declarada (misma heurística que _log_attest_access)
                return True
        if self._autorizado():
            return True
        if self.path.startswith("/api/"):
            self._send(401, "application/json; charset=utf-8", b'{"error":"no_autenticado"}')
        else:
            self.send_response(303)
            self.send_header("Location", "/login")
            self.send_header("Content-Length", "0")
            self.end_headers()
        return False

    def _log_attest_access(self):
        """Defensa en profundidad (grieta #3 red-team red-team 2026-07-27): /attest es PUBLICO por diseno
        (atestacion compartible para federacion), NO es fail-open. Pero se registra QUIEN lo consulta para
        hacer visible un sondeo inesperado: los pares de la malla declarada son ruido esperado; un origen
        'externo' es la senal. Observe-only, best-effort: NUNCA bloquea ni hace fallar la respuesta.
        v2: bajo _LOCK — el servidor es concurrente y dos hilos no deben trocear el mismo log."""
        with _LOCK:
            try:
                ip = self.client_address[0] if self.client_address else "?"
                malla = bool(_MESH_PREFIX) and ip.startswith(_MESH_PREFIX)   # par de la malla declarada
                rec = {"ts": int(time.time()), "ip": ip, "path": self.path,
                       "origen": "malla" if malla else "externo",
                       "ua": (self.headers.get("User-Agent") or "")[:80]}
                ad = os.path.join(DATA, "attest")
                os.makedirs(ad, exist_ok=True)
                log = os.path.join(ad, "access.jsonl")
                with open(log, "a") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                # tope de tamano: si crece de 512KB, conserva las ultimas ~2000 lineas (no borra historia critica,
                # solo recorta ruido de polling de la malla; archiva-nunca-borra no aplica a un log de acceso volatil)
                if os.path.getsize(log) > 512 * 1024:
                    with open(log) as f:
                        lines = f.readlines()
                    with open(log, "w") as f:
                        f.writelines(lines[-2000:])
            except Exception as e:
                # ITB-079 clase A: el registro de ACCESOS es evidencia; si no puede
                # escribirse, el fallo deja huella por stderr en vez de perderse en silencio.
                print("REG_FAIL node_status_server.access_log: %r" % (e,), file=sys.stderr, flush=True)

    def do_GET(self):
        try:
            if not self._gate():
                return
            # login del panel (ruta PÚBLICA): formulario del token de a bordo
            if self.path.startswith("/login"):
                err = ('<p style="color:#f87171;font-size:13px;margin:10px 0 0">token incorrecto</p>'
                       if "e=1" in self.path.partition("?")[2] else "")
                page = ("""<!doctype html><html lang=es><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>ANVOS · acceso</title>
<style>body{background:linear-gradient(160deg,#0a0e13,#0c1420);color:#dce8f2;
font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;margin:0;display:flex;align-items:center;
justify-content:center;min-height:100vh}
.box{background:#111823;border:1px solid #1d2836;border-radius:14px;padding:26px 28px;width:320px}
h1{font-size:17px;margin:0 0 4px;color:#fff}p.s{color:#7488a0;font-size:12.5px;margin:0 0 14px}
input{width:100%;box-sizing:border-box;background:#0e141d;border:1px solid #1d2836;border-radius:8px;
color:#dce8f2;padding:9px 11px;font:inherit;margin-bottom:12px}
button{width:100%;background:#38bdf8;border:0;border-radius:8px;color:#04240f;font-weight:650;
padding:9px;cursor:pointer;font:inherit}</style>
<div class=box><h1>\U0001f9ec ANVOS · acceso al panel</h1>
<p class=s>introduce el token de a bordo del nodo</p>
<form method=post action=/login><input type=password name=token autofocus
placeholder="token de a bordo" autocomplete=current-password><button>Entrar</button></form>"""
                        + err + "</div></html>")
                return self._send(200, "text/html; charset=utf-8", page.encode())
            # snapshot gráfico del cockpit (PNG que escribe anvos-cockpit-fb cuando el fb físico
            # no es pintable, p.ej. i915 DRM): se sirve sin construir el estado completo
            if self.path.startswith("/cockpit.png"):
                try:
                    with open("/persist/anvos-data/cockpit/cockpit.png", "rb") as f:
                        return self._send(200, "image/png", f.read())
                except Exception:
                    return self._send(404, "text/plain", b"sin snapshot del cockpit")
            # CANAL DE ALERTAS (ITA hueco 27-ago, medido por red-team y revisor-a por vias separadas):
            # sirve el sobre que emite alerts_channel.py + su firma de AUTORIA en una respuesta
            # autocontenida, para que el poller verifique sin segunda peticion. PUBLICO por el
            # mismo diseno que /attest (material de federacion, acceso registrado). Si el sobre
            # no existe aun, 404 explicito: el poller distingue "canal sin desplegar" de "nodo caido".
            # CANAL DE DIALOGO (sala de malla fase 1, ITA-021): sirve el sobre de HALLAZGOS
            # firmados que emite hallazgo_channel + su firma + el cert de autoria, autocontenido
            # como /alerts. El poller de los pares cierra la cadena genesis-del-realm->cert->autoria sin
            # material pre-compartido. Publico por el mismo diseno que /alerts y /attest.
            if self.path.startswith("/dialogo"):
                self._log_attest_access()
                try:
                    with open(os.path.join(DATA, "dialogo", "outbox.json")) as f:
                        sobre = f.read()
                    try:
                        with open(os.path.join(DATA, "dialogo", "outbox.json.autoria.minisig")) as f:
                            sig = f.read()
                    except OSError:
                        sig = None
                    cert = certsig = None
                    try:
                        with open(os.path.join(DATA, "authorship", "authorship_cert.json")) as f:
                            cert = f.read()
                        with open(os.path.join(DATA, "authorship", "authorship_cert.json.minisig")) as f:
                            certsig = f.read()
                    except OSError:
                        pass
                    cuerpo = ('{"sobre": %s, "autoria_minisig": %s, '
                              '"authorship_cert": %s, "authorship_cert_minisig": %s}'
                              % (sobre, json.dumps(sig), json.dumps(cert), json.dumps(certsig)))
                    return self._send(200, "application/json; charset=utf-8", cuerpo.encode())
                except OSError:
                    return self._send(404, "text/plain", b"sin sobre de dialogo (hallazgo_channel aun no emitio)")
            if self.path.startswith("/alerts"):
                self._log_attest_access()
                try:
                    with open(os.path.join(DATA, "alerts", "outbox.json")) as f:
                        sobre = f.read()
                    try:
                        with open(os.path.join(DATA, "alerts", "outbox.json.autoria.minisig")) as f:
                            sig = f.read()
                    except OSError:
                        sig = None
                    # SOBRE AUTOCONTENIDO (regla de revisor-b, 21-ago): el certificado de autoria
                    # VIAJA EN LA RESPUESTA. /lineage sirve el paquete de linaje, no este cert;
                    # sin incluirlo aqui el poller no podria cerrar la cadena
                    # genesis del realm -> cert -> pub de autoria -> sobre  sin material pre-compartido.
                    cert = certsig = None
                    try:
                        with open(os.path.join(DATA, "authorship", "authorship_cert.json")) as f:
                            cert = f.read()
                        with open(os.path.join(DATA, "authorship", "authorship_cert.json.minisig")) as f:
                            certsig = f.read()
                    except OSError:
                        pass
                    cuerpo = ('{"sobre": %s, "autoria_minisig": %s, '
                              '"authorship_cert": %s, "authorship_cert_minisig": %s}'
                              % (sobre, json.dumps(sig), json.dumps(cert), json.dumps(certsig)))
                    return self._send(200, "application/json; charset=utf-8", cuerpo.encode())
                except OSError:
                    return self._send(404, "text/plain", b"sin sobre de alertas (alerts_channel aun no emitio)")
            # atestación soberana del nodo (para federación/padre/master): anclada a la cadena merkle
            if self.path.startswith("/attest"):
                self._log_attest_access()   # defensa en profundidad: registra quien consulta (no bloquea)
                # /attest/tpm — quote TPM2 crudo del ultimo ciclo (ITF-002): publico por el mismo
                # diseno que /attest (material de federacion, verificable por cualquiera; la clave
                # de atestacion no sale del aparato). Lo produce tpm_attest.py; sin TPM no existe.
                if self.path.startswith("/attest/tpm"):
                    try:
                        with open(os.path.join(DATA, "tpm", "quote_publico.json"), "rb") as f:
                            return self._send(200, "application/json; charset=utf-8", f.read())
                    except Exception:
                        return self._send(404, "text/plain",
                                          b"sin quote publicado (nodo sin TPM o tpm_attest sin ciclo)")
                try:
                    with open(os.path.join(DATA, "attest", "attestation.json"), "rb") as f:
                        return self._send(200, "application/json; charset=utf-8", f.read())
                except Exception:
                    return self._send(404, "text/plain", b"sin atestacion (node_attest aun no emitio)")
            # LINAJE: certificados públicos del nodo y de su raíz de realm, para que un PEER
            # COMPRUEBE la pertenencia en vez de creerse la que el nodo declara.
            #
            # Hasta el 31-jul-2026 un par leía "realm: realm-X" de la atestación y no tenía con
            # qué contrastarlo: la pertenencia era una afirmación. Sirviendo los certs, el par
            # verifica que el cert del nodo está firmado por la raíz que dice, y lee del propio
            # cert su profundidad, su peso y la huella de su padre.
            #
            # Es material PÚBLICO por definición (certificados y clave pública de realm). Se
            # excluye cualquier otra cosa del directorio de realm: ahí viven también referencias
            # de custodia y el registro, que no son para publicar.
            if self.path.startswith("/lineage"):
                REALM_DIR = os.environ.get("ANVOS_REALM", "/persist/anvos-realm")
                # Se publica tambien la identidad del PADRE (material publico). Sin ella un par
                # solo recibe una REFERENCIA a ese padre y no puede comprobar nada: ni que la
                # adhesion declarada corresponda a quien dice, ni si un tercero cuelga del mismo
                # ascendiente. Con ella, la pertenencia deja de ser una afirmacion.
                # Se publican tambien las FIRMAS. Sin ellas un par recibia el texto de los
                # certificados y ninguna manera de comprobarlo, de modo que solo podia verificar
                # la coherencia interna de lo que el otro contaba: que su cert casara con la raiz
                # que el mismo servia. Eso lo cumple igual de bien un nodo legitimo que uno que se
                # inventa su propia raiz.
                #
                # Con la firma entra un tercero en la conversacion: `parent-node.cert` es el
                # certificado del nodo CONTRAFIRMADO por la raiz del padre, y el par lo valida
                # contra la publica de ESE padre, que ya tiene. La pertenencia pasa de declarada
                # a demostrada (ITA-013, 01-ago-2026).
                publicables = ("realm-root.cert", "realm_root.pub",
                               "parent-realm-root.cert", "parent_realm_root.pub",
                               "parent-node.cert", "parent-node.cert.minisig")
                out = {}
                try:
                    for n in sorted(os.listdir(REALM_DIR)):
                        if n in publicables or (n.endswith(".cert") and not n.startswith("realm-root")):
                            try:
                                with open(os.path.join(REALM_DIR, n), "r", errors="replace") as f:
                                    out[n] = f.read()
                            except Exception:
                                pass
                except Exception:
                    pass
                if not out:
                    return self._send(404, "text/plain", b"sin linaje provisionado")
                cuerpo = json.dumps({"kind": "ANV_LINEAGE_PACK", "files": out},
                                    ensure_ascii=False).encode()
                return self._send(200, "application/json; charset=utf-8", cuerpo)
            # cadena de bloques merkle del nodo (para que un PEER la verifique junto a la atestación)
            if self.path.startswith("/blocks"):
                try:
                    with open(os.path.join(DATA, "chain", "blocks.jsonl"), "rb") as f:
                        return self._send(200, "application/x-ndjson; charset=utf-8", f.read())
                except Exception:
                    return self._send(404, "text/plain", b"sin cadena de bloques")
            # federación de flota: verifica peers de malla (reusa fleet_attest); caché 120s (no bloquea por request)
            if self.path.startswith("/fleet"):
                fdir = os.path.join(DATA, "fleet")
                cache = os.path.join(fdir, "fleet_status.json")
                peersf = os.path.join(fdir, "peers.txt")
                try:
                    # v2 (servidor concurrente): la escritura SINCRONA de la caché va bajo _LOCK
                    # para que dos peticiones simultáneas no la pisen ni dupliquen el refresco.
                    with _LOCK:
                        fresh = os.path.exists(cache) and (time.time() - os.path.getmtime(cache)) < 120
                        if not fresh:
                            peers = ""
                            try:
                                peers = ",".join(l.strip() for l in open(peersf) if l.strip() and not l.startswith("#"))
                            except Exception:
                                pass
                            if peers:
                                tool = "/persist/anvos-staging/services/fleet_attest.py"
                                if not _sig_ok(tool):          # FAIL-CLOSED (ver nota arriba)
                                    raise RuntimeError("herramienta sin firma 653C valida: " + tool)
                                env = dict(os.environ, ANV_FLEET_PEERS=peers)
                                r = subprocess.run(["anvos-python3", tool], env=env,
                                                   capture_output=True, text=True, timeout=25)
                                try:
                                    os.makedirs(fdir, exist_ok=True)
                                except Exception:
                                    pass
                                open(cache, "w").write(r.stdout or '{"note":"sin salida de fleet_attest"}')
                            else:
                                return self._send(200, "application/json; charset=utf-8",
                                                  b'{"svc":"fleet","note":"sin peers de malla configurados (fleet/peers.txt)"}')
                    with open(cache, "rb") as f:
                        return self._send(200, "application/json; charset=utf-8", f.read())
                except Exception as e:
                    return self._send(200, "application/json; charset=utf-8",
                                      ('{"svc":"fleet","error":"%s"}' % e).encode()[:200])
            # borrador de lección (read-only): /draft?f=DRAFT_LEARN_...md — solo basenames válidos del dir pending
            if self.path.startswith("/draft"):
                from urllib.parse import urlparse, parse_qs
                fn = (parse_qs(urlparse(self.path).query).get("f") or [""])[0]
                fn = os.path.basename(fn)   # anti-traversal: descarta cualquier componente de ruta
                if not (fn.startswith("DRAFT_LEARN_") and fn.endswith(".md")):
                    return self._send(400, "text/plain", b"nombre de borrador invalido")
                p = os.path.join(DATA, "learning", "pending", fn)
                try:
                    with open(p, "rb") as f:
                        return self._send(200, "text/plain; charset=utf-8", f.read())
                except Exception:
                    return self._send(404, "text/plain", b"borrador no encontrado (quiza ya revisado/firmado)")
            st = build_status()
            if self.path.startswith("/api/status"):
                self._send(200, "application/json; charset=utf-8",
                           json.dumps(st, ensure_ascii=False).encode())
            elif self.path in ("/", "/index.html"):
                self._send(200, "text/html; charset=utf-8", render_html(st).encode())
            else:
                self._send(404, "text/plain", b"not found")
        except Exception as e:
            self._send(500, "text/plain", ("error: %s" % e).encode()[:200])

    def do_POST(self):
        try:
            # /login es PÚBLICO: es la puerta. Comparación en tiempo constante + freno de 1.5s
            # ante token erróneo (anti fuerza bruta). El token NUNCA se loguea.
            if self.path.startswith("/login"):
                try:
                    n = min(int(self.headers.get("Content-Length") or "0"), 4096)
                except Exception:
                    n = 0
                cuerpo = self.rfile.read(n).decode("utf-8", "replace") if n > 0 else ""
                tok = (urllib.parse.parse_qs(cuerpo).get("token") or [""])[0]
                if not hmac.compare_digest(tok, _token()):
                    time.sleep(1.5)
                    self.send_response(303)
                    self.send_header("Location", "/login?e=1")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                sid = os.urandom(16).hex()
                with _LOCK:
                    SESSIONS[sid] = time.time()
                self.send_response(303)
                self.send_header("Location", "/")
                self.send_header("Set-Cookie",
                                 "anv_sess=%s; HttpOnly; SameSite=Strict; Path=/" % sid)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            # /api/chat exige sesión (401 JSON si no)
            if self.path.startswith("/api/chat"):
                if not self._autorizado():
                    return self._send(401, "application/json; charset=utf-8",
                                      b'{"error":"no_autenticado"}')
                return self._chat()
            self._send(404, "text/plain", b"not found")
        except Exception as e:
            self._send(500, "text/plain", ("error: %s" % e).encode()[:200])

    def _chat(self):
        """POST /api/chat — conversa con el modelo LOCAL del nodo (127.0.0.1:8090).

        El contexto es COMPACTO y se arma de tres ledgers + el node id, SIN llamar a
        build_status() completo (es carísimo por petición y el chat no lo necesita)."""
        try:
            n = min(int(self.headers.get("Content-Length") or "0"), 65536)
        except Exception:
            n = 0
        try:
            req = json.loads(self.rfile.read(n).decode("utf-8", "replace")) if n > 0 else {}
        except Exception:
            req = {}
        message = str(req.get("message") or "").strip()
        history = [{"role": h.get("role"), "content": str(h.get("content") or "")}
                   for h in (req.get("history") or [])[:6]
                   if isinstance(h, dict) and h.get("role") in ("user", "assistant")]
        ld = _last("layerd/layerd.jsonl") or {}
        svcs = ld.get("services") or {}
        cg = _last("governance/cognition_guard.jsonl") or {}
        beacon = _last("eco-telem/beacon.jsonl") or {}
        estado = {
            "servicios_vivos": sum(1 for s in svcs.values() if s.get("alive")),
            "servicios_supervisados": len(svcs) or ld.get("supervised"),
            "bloqueos_fail_closed": ld.get("fail_closed_blocks"),
            "gobernanza": cg.get("veredicto") or cg.get("verdict"),
            "cpu_load": beacon.get("cpu_load"), "mem_pct": beacon.get("mem_pct"),
            "disk_pct": beacon.get("disk_pct"),
        }
        sistema = ("Eres el nodo ANVOS %s. Responde SIEMPRE en español, breve y factual, "
                   "SOLO sobre tu propio estado. Estado actual: %s. Si te preguntan algo "
                   "fuera de tu estado o de tu naturaleza, dilo claramente. /no_think"
                   % (_node_id(), json.dumps(estado, ensure_ascii=False)))
        try:
            payload = json.dumps({
                "messages": [{"role": "system", "content": sistema}] + history
                            + [{"role": "user", "content": message}],
                "temperature": 0.3, "max_tokens": 512,
                # FIX chat-vacio (red-team 28-ago): sin este flag qwen3 gasta los 512 tokens en
                # reasoning_content y devuelve content vacio. Mismo flag que ai_router l.162.
                # Consolidacion posible: que _chat() delegue en ai_router.
                "chat_template_kwargs": {"enable_thinking": False}}).encode()
            r = urllib.request.urlopen(urllib.request.Request(
                "http://127.0.0.1:8090/v1/chat/completions", data=payload,
                headers={"Content-Type": "application/json"}), timeout=120)
            d = json.loads(r.read().decode("utf-8", "replace"))
            txt = ((d.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
            txt = re.sub(r"<think>.*?</think>", "", txt, flags=re.S).strip()
            self._send(200, "application/json; charset=utf-8",
                       json.dumps({"reply": txt}, ensure_ascii=False).encode())
        except Exception as e:
            self._send(502, "application/json; charset=utf-8",
                       json.dumps({"error": str(e)[:200]}, ensure_ascii=False).encode())


def main():
    # idempotente: layerd mantiene node_status_server vivo por poll() (LONG_RUNNING). Si por una carrera de
    # relevo llegara a haber 2 procesos, el 2º no podría bindear :8088; salimos LIMPIO (exit 0, sin traceback
    # EADDRINUSE que floodee SERVICE_FAILURE) en vez de crashear. Defensa pura; no cambia el caso normal.
    try:
        srv = _Server(("0.0.0.0", PORT), Handler)
    except OSError as e:
        print(json.dumps({"svc": "node_status_server", "state": "already-serving",
                          "note": "puerto ya servido por otra instancia; salgo limpio", "err": str(e)},
                         ensure_ascii=False), flush=True)
        return
    print(json.dumps({"svc": "node_status_server", "ts": int(time.time()),
                      "listen": "0.0.0.0:%d" % PORT, "state": "serving"}, ensure_ascii=False), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
