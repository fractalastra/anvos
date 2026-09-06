#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""hallazgo_channel — EMISOR de la sala de malla, fase 1 (ITA-021 v2 aprobada por el operador).
HALLAZGOS FIRMADOS, SIN VOTOS: el nodo publica datos MEDIDOS con refs; las IAs de los pares los
leen como fuente citable marcada por origen. Sin respuestas automáticas (el bucle de eco muere
por construcción) y sin recuento de opiniones ("consenso" queda reservado al quórum de la autoridad con raíz física).

COMPUERTA DE PUBLICACIÓN (recomendación 1 de red-team, patrón codegen_nodo): la IA local REDACTA
borradores en dialogo/borradores/; SOLO lo que el operador del nodo mueva a dialogo/aprobados/
entra al sobre. Este servicio no genera contenido: publica lo aprobado.

CONTRATO (los 7 flancos de red-team convertidos en requisitos por revisor-b, 28-ago):
  B. era_id: el sobre lleva {era_id, seq}. Sin estado previo => ERA NUEVA declarada DENTRO del
     sobre (era_decl con ts y motivo, firmada con el sobre entero): un renacer es señal, no
     silencio. seq monótona POR era.
  F. rotación: el outbox lleva las últimas N entradas; el excedente se COMPACTA a
     dialogo/historico/lote-<ts>.jsonl + .minisig (archivar, nunca borrar).
  D. datos sensibles JAMÁS en el outbox: si un hallazgo los necesita, viaja la referencia (id)
     y el detalle queda en el nodo por canal autenticado.
  A/C. el sobre entero se firma con la AUTORÍA del nodo (todo-o-nada: la responsabilidad de
     integridad es del emisor; el poller rechaza seguro).
Alert-open como /alerts: si no puede firmar, publica con firmado:false — el receptor degrada
confianza, no visibilidad. Solo stdlib. Uso: hallazgo_channel.py [cycle]"""
import os
import json
import time
import glob
import subprocess

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
MS = os.environ.get("ANV_MS_DIR", os.path.join(STAGING, "pylayer-verify"))
AUTH_KEY = os.environ.get("ANV_AUTH_KEY", os.path.join(DATA, "authorship", "authorship.key"))
AUTH_PUB = os.environ.get("ANV_AUTH_PUB", os.path.join(DATA, "authorship", "authorship.pub"))
DIR = os.path.join(DATA, "dialogo")
APROBADOS = os.path.join(DIR, "aprobados")
HIST = os.path.join(DIR, "historico")
OUTBOX = os.path.join(DIR, "outbox.json")
ESTADO = os.path.join(DIR, ".estado.json")
# APROBACION CRIPTOGRAFICA (ataque de red-team 28-ago): mover un fichero a aprobados/ es CONVENCION,
# no control — cualquier proceso con el uid del servicio lo hace. La aprobacion real es una
# CONTRAFIRMA del operador del nodo con una clave que este servicio NO posee. Su publica vive
# aqui; la privada, solo en manos del operador del nodo (pendrive/tarjeta, fuera del alcance del
# servicio). Sin contrafirma valida, la entrada NO se publica: la compuerta pasa de convencion
# a frontera.
APROBACION_PUB = os.environ.get("ANV_APROBACION_PUB",
                                os.path.join(DATA, "dialogo", "aprobacion_operador.pub"))
MAX_ENTRADAS = 50
NODE = os.environ.get("ANV_NODE_ID", "") or (open("/etc/machine-id").read().strip()[:8]
                                             if os.path.exists("/etc/machine-id") else "desconocido")


def _firmar(path):
    ld = next(iter(glob.glob(os.path.join(MS, "ld-linux*.so.2"))), None)
    mini = os.path.join(MS, "minisign")
    if not (os.path.exists(mini) and os.path.exists(AUTH_KEY)):
        return False
    cmd = ([ld, "--library-path", MS, mini] if ld else [mini])
    try:
        r = subprocess.run(cmd + ["-S", "-s", AUTH_KEY, "-t", "hallazgo_channel sobre de dialogo",
                                  "-m", path, "-x", path + ".autoria.minisig"],
                           capture_output=True, input=b"\n", timeout=30)
        return r.returncode == 0
    except Exception:
        return False


def _verificar_aprobacion(path):
    """La entrada solo se publica si trae <path>.aprob.minisig valida contra APROBACION_PUB —
    contrafirma del operador del nodo. Fail-closed: sin pub o sin firma, NO se aprueba."""
    sig = path + ".aprob.minisig"
    if not (os.path.exists(APROBACION_PUB) and os.path.exists(sig)):
        return False
    ld = next(iter(glob.glob(os.path.join(MS, "ld-linux*.so.2"))), None)
    mini = os.path.join(MS, "minisign")
    cmd = ([ld, "--library-path", MS, mini] if ld else [mini])
    try:
        r = subprocess.run(cmd + ["-Vm", path, "-x", sig, "-p", APROBACION_PUB],
                           capture_output=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


def main():
    rec = {"svc": "hallazgo_channel", "ts": int(time.time()), "node": NODE}
    os.makedirs(APROBADOS, exist_ok=True)
    os.makedirs(HIST, exist_ok=True)
    # estado de era/seq — sin estado => ERA NUEVA (flanco B: renacer declarado, no silencioso)
    try:
        st = json.load(open(ESTADO))
        era_decl = None
    except Exception:
        st = {"era_id": "era-%s-%d" % (NODE, int(time.time())), "seq": 0, "entradas": []}
        era_decl = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "motivo": "sin estado previo: primer arranque o perdida de estado — un renacer es señal"}
    # COMPUERTA CRIPTOGRAFICA: solo entra lo que el operador del nodo CONTRAFIRMO (no lo que
    # alguien dejo caer en aprobados/). Sin contrafirma valida => rechazado y anotado, nunca
    # publicado. Es la diferencia entre "acredita origen del nodo" y "acredita aprobacion humana".
    nuevos = 0
    rechazados = 0
    for f in sorted(glob.glob(os.path.join(APROBADOS, "*.json"))):
        try:
            e = json.load(open(f))
        except ValueError:
            continue
        if not (e.get("tema_id") and e.get("texto")):
            continue
        if not _verificar_aprobacion(f):
            os.replace(f, f + ".rechazado_sin_aprobacion")
            rechazados += 1
            continue
        e.setdefault("tipo", "HALLAZGO")
        e.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        e["id"] = "%s-%s-%d" % (NODE, e["tema_id"], int(time.time() * 1000) % 100000000)
        e.setdefault("refs", [])
        # rec 3 red-team + sensor del vigia de convergencia (revisor-b): dejar rastro de auditoria de
        # QUE aprobo (mtime del acta de aprobacion + el id). Escritura en aprobados/ es un ACTO
        # medible; el vigia lo lee. Barato, no bloquea.
        try:
            aprob_mt = int(os.path.getmtime(f + ".aprob.minisig"))
        except OSError:
            aprob_mt = None
        e["_aprobacion"] = {"contrafirmada": True, "acta_mtime": aprob_mt}
        st["entradas"].append(e)
        os.replace(f, f + ".publicado")
        nuevos += 1
    # rotación (flanco F): compactar excedente a histórico firmado, nunca borrar
    if len(st["entradas"]) > MAX_ENTRADAS:
        exceso = st["entradas"][:-MAX_ENTRADAS]
        st["entradas"] = st["entradas"][-MAX_ENTRADAS:]
        lote = os.path.join(HIST, "lote-%d.jsonl" % int(time.time()))
        with open(lote, "w") as f:
            for e in exceso:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        _firmar(lote)
    st["seq"] += 1
    sobre = {"svc": "hallazgo_channel", "node": NODE, "era_id": st["era_id"], "seq": st["seq"],
             "ts": int(time.time()), "n_entradas": len(st["entradas"]),
             "entradas": st["entradas"],
             "_que_acredita_la_firma": "autoria del nodo: QUE NODO emitio. NO admision, NO verdad del contenido. La COMPUERTA exige contrafirma del operador del nodo por entrada (APROBACION_PUB); su fortaleza depende de DONDE viva la clave de aprobacion: como fichero en el nodo es mejor que convencion pero no frontera absoluta (un proceso que lea la privada firma); frontera REAL con la clave sellada en soporte fisico bajo ceremonia del operador. Hasta entonces, el receptor ingiere NO_VERIFICABLE y no cita como fuente firme."}
    if era_decl:
        sobre["era_decl"] = era_decl
    tmp = OUTBOX + ".tmp"
    with open(tmp, "w") as f:
        json.dump(sobre, f, ensure_ascii=False)
    os.replace(tmp, OUTBOX)
    ok = _firmar(OUTBOX)
    tmp = ESTADO + ".tmp"
    json.dump(st, open(tmp, "w"), ensure_ascii=False)
    os.replace(tmp, ESTADO)
    rec.update({"era_id": st["era_id"], "seq": st["seq"], "nuevas": nuevos, "rechazados_sin_aprobacion": rechazados,
                "n_entradas": len(st["entradas"]), "firmado": ok,
                "state": "PUBLICADO" if ok else "PUBLICADO_SIN_FIRMA"})
    print(json.dumps(rec, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(json.dumps({"svc": "hallazgo_channel", "error": str(e)[:200]}, ensure_ascii=False))
