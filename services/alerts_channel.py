#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""alerts_channel — CANAL DE SALIDA DE ALERTAS DEL NODO: publica en un sobre firmado lo que hoy
muere dentro de /persist. Hueco constatado por DOS vías independientes (red-team 27-ago midiendo el
nodo; revisor-a 27-ago cruzando cobertura contra el master): origo genera avisos de caducidades y fallos
de atestación que NO SALEN DEL NODO. Coste ya materializado: nodo-c estuvo ~11 h discrepante y
el master no se enteró.

QUÉ HACE (single-shot, lo corre layerd periódicamente):
  1. LEE las fuentes locales de alerta (caducidades, escalados, atestación propia, veredictos
     de pares) — solo lectura, nunca las modifica.
  2. DEDUPLICA por clave estable (fuente+id): la última aparición gana; un aviso repetido en
     cada ciclo del vigía es UNA alerta, no cincuenta.
  3. ESCRIBE EL SOBRE AUTOCONTENIDO en alerts/outbox.json (escritura atómica) y lo firma con
     la clave de AUTORÍA del nodo (authorship.key, mismo mecanismo que codegen_nodo). La firma
     acredita QUÉ NODO EMITIÓ el sobre — autoría, no admisión: no da al nodo ninguna capacidad
     de alta, que es la partición autoría/admisión (patent pending, ver NOTICE).
  4. El sobre SIEMPRE se emite, haya alertas o no: el sobre vacío ES el latido. Un poller que
     ve el outbox envejecer sabe que el canal (o el nodo) está caído — la ausencia se vuelve señal.

DOCTRINA DE FALLO — ALERT-OPEN, y es deliberado: si la firma de autoría no se puede producir
(clave ausente, minisign roto), el sobre se publica IGUAL con firmado:false. Para un canal de
ALERTAS, callar por no poder firmar es peor que hablar sin firma: el poller del master distingue
los dos casos y degrada la confianza, no la visibilidad. (Contraste deliberado con la puerta de
capa, que es fail-closed: allí se decide qué EJECUTA el nodo; aquí solo qué se CUENTA de él.)

LÍMITE DECLARADO: las entradas con id que empieza por 'prueba_' se marcan es_prueba:true pero NO
se filtran — el canal transporta, no juzga (medido el 28-ago: los 2 únicos VENCIDO/MÁXIMA del
nodo eran pruebas de IA; filtrarlos en silencio habría ocultado también un vencido real futuro).

Solo stdlib. Observe-only sobre las fuentes. Fail-safe: cualquier fallo interno se registra y
el ciclo termina en 0 (nunca tumba a layerd)."""
import os
import json
import time
import glob
import subprocess

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
MS = os.path.join(STAGING, "pylayer-verify")
AUTH_DIR = os.path.join(DATA, "authorship")
AUTH_KEY = os.path.join(AUTH_DIR, "authorship.key")
AUTH_PUB = os.path.join(AUTH_DIR, "authorship.pub")
OUT_DIR = os.path.join(DATA, "alerts")
OUTBOX = os.path.join(OUT_DIR, "outbox.json")
SEQF = os.path.join(OUT_DIR, "seq")

# Fuentes: (ruta relativa a DATA, nombre, modo)
#   tail_all  -> cada línea es una alerta potencial
#   last_rec  -> solo el último registro se examina (estado, no histórico)
FUENTES = [
    ("caducidades/alerts.jsonl", "caducidades", "tail_all"),
    ("caducidades/escalated.jsonl", "caducidades_escaladas", "tail_all"),
    ("attest/node_attest.jsonl", "atestacion_propia", "last_rec"),
    ("fleet/attest.jsonl", "pares_flota", "last_rec"),
]
MAX_POR_FUENTE = 50   # el sobre es un estado, no un archivo histórico; el histórico vive en el nodo


def _machine_node():
    try:
        with open('/etc/machine-id') as f:
            mid = f.read().strip()
    except OSError:
        mid = ''
    return os.environ.get("ANVOS_NODE", "") or (mid[:8] if mid else "desconocido")


def _leer_jsonl(path, solo_ultima=False):
    try:
        with open(path, 'rb') as f:
            lines = [l for l in f.read().splitlines() if l.strip()]
    except OSError:
        return []
    if solo_ultima:
        lines = lines[-1:]
    else:
        lines = lines[-MAX_POR_FUENTE:]
    out = []
    for l in lines:
        try:
            out.append(json.loads(l))
        except ValueError:
            continue
    return out


def _extraer(nombre, modo, recs):
    """Convierte registros crudos en alertas normalizadas. Devuelve lista de dicts con
    clave estable 'k' para deduplicar."""
    alerts = []
    if nombre in ("caducidades", "caducidades_escaladas"):
        for r in recs:
            aid = str(r.get("id") or r.get("evento") or "sin_id")
            alerts.append({
                "k": "%s:%s" % (nombre, aid),
                "fuente": nombre, "ts": r.get("ts"),
                "severidad": r.get("severidad"), "evento": r.get("evento"),
                "id": aid, "descripcion": r.get("descripcion"),
                "critico": bool(r.get("critico")),
                "es_prueba": aid.startswith("prueba_"),
            })
    elif nombre == "atestacion_propia":
        for r in recs:
            if r.get("verificada") is False:
                alerts.append({
                    "k": "atestacion_propia:no_verificada",
                    "fuente": nombre, "ts": r.get("ts"),
                    "severidad": "ALTA", "evento": "ATESTACION_NO_VERIFICADA",
                    "id": "node_attest", "descripcion": r.get("note"),
                    "critico": True, "es_prueba": False,
                })
    elif nombre == "pares_flota":
        for r in recs:
            for p in r.get("pares", []):
                ver = str(p.get("veredicto") or "")
                if ver and ver not in ("OK", "SI_MISMO", "CONFORME"):
                    alerts.append({
                        "k": "pares_flota:%s" % p.get("peer"),
                        "fuente": nombre, "ts": p.get("ts") or r.get("ts"),
                        "severidad": "MEDIA", "evento": "PAR_DISCREPANTE",
                        "id": str(p.get("peer")), "descripcion": "%s: %s" % (ver, str(p.get("detalle"))[:160]),
                        "critico": False, "es_prueba": False,
                    })
    return alerts


def _firmar(path):
    """Firma de AUTORÍA del sobre (authorship.key). Devuelve (ok, ruta_sig|motivo)."""
    ld = next(iter(glob.glob(os.path.join(MS, "ld-linux*.so.2"))), None)
    mini = os.path.join(MS, "minisign")
    if not (ld and os.path.exists(mini) and os.path.exists(AUTH_KEY) and os.path.exists(AUTH_PUB)):
        return False, "herramental_o_clave_ausente"
    sig = path + ".autoria.minisig"
    try:
        r = subprocess.run([ld, "--library-path", MS, mini, "-S", "-s", AUTH_KEY,
                            "-t", "alerts_channel sobre de alertas", "-m", path, "-x", sig],
                           capture_output=True, input=b"\n", timeout=30)
        if r.returncode != 0:
            return False, "firma_fallo"
        v = subprocess.run([ld, "--library-path", MS, mini, "-Vm", path, "-x", sig, "-p", AUTH_PUB],
                           capture_output=True, timeout=30)
        return (v.returncode == 0), (sig if v.returncode == 0 else "verificacion_fallo")
    except Exception as e:
        return False, "excepcion:%s" % str(e)[:80]


def main():
    rec = {"svc": "alerts_channel", "ts": int(time.time()), "node": _machine_node()}
    vistos = {}
    fuentes_ok = []
    for rel, nombre, modo in FUENTES:
        path = os.path.join(DATA, rel)
        recs = _leer_jsonl(path, solo_ultima=(modo == "last_rec"))
        if recs:
            fuentes_ok.append(nombre)
        for a in _extraer(nombre, modo, recs):
            k = a.pop("k")
            prev = vistos.get(k)
            # la última aparición gana (dedup por clave estable)
            if prev is None or (a.get("ts") or 0) >= (prev.get("ts") or 0):
                vistos[k] = a
    alerts = sorted(vistos.values(), key=lambda x: (x.get("ts") or 0), reverse=True)

    # secuencia monótona: permite al poller detectar sobres perdidos o repetidos
    try:
        seq = int(open(SEQF).read().strip()) + 1
    except (OSError, ValueError):
        seq = 1

    sobre = {
        "svc": "alerts_channel", "node": rec["node"], "seq": seq,
        "ts": rec["ts"], "heartbeat": True,
        "n_alertas": len(alerts), "n_criticas": sum(1 for a in alerts if a.get("critico")),
        "n_pruebas": sum(1 for a in alerts if a.get("es_prueba")),
        "fuentes_leidas": fuentes_ok,
        "alertas": alerts,
        "_que_acredita_la_firma": "autoria del nodo (authorship.key): QUE NODO emitio el sobre. "
                                  "NO admision, NO gobierno humano.",
    }
    try:
        os.makedirs(OUT_DIR, exist_ok=True)
        tmp = OUTBOX + ".tmp"
        with open(tmp, 'w') as f:
            json.dump(sobre, f, ensure_ascii=False)
        os.replace(tmp, OUTBOX)
        with open(SEQF + ".tmp", 'w') as f:
            f.write(str(seq))
        os.replace(SEQF + ".tmp", SEQF)
    except OSError as e:
        rec["error"] = "escritura:%s" % str(e)[:80]
        print(json.dumps(rec, ensure_ascii=False))
        return

    ok, detalle = _firmar(OUTBOX)
    rec.update({"seq": seq, "n_alertas": len(alerts),
                "firmado": ok, "firma_detalle": None if ok else detalle,
                "state": "PUBLICADO" if ok else "PUBLICADO_SIN_FIRMA"})
    print(json.dumps(rec, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(json.dumps({"svc": "alerts_channel", "ts": int(time.time()),
                          "error": str(e)[:200]}, ensure_ascii=False))
