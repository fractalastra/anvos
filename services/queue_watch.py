#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""queue_watch — cola de operador NODE-SIDE con auto-resolución (patrón del master en el nodo).

Porta al nodo el par operator_queue + anv-queue-reaper del ecosistema master: los estados
anómalos de la capa se vuelven INCIDENTES con identidad (no líneas sueltas en N jsonls), y
cuando la condición se despeja el incidente se AUTO-RESUELVE con evidencia y traza. El
operador ve UNA cola en el dashboard, no 40 ficheros.

Fuentes v1 (solo lectura, cada una fail-safe si falta):
  self_integrity   !all_valid            -> CRIT NODO_NO_SELLADO
  cognition_guard  verdict!=GOBERNADO*   -> CRIT SIN_GOBIERNO / WARN GOBERNANZA_DEGRADADA
  vigias_watch     verdict!=SUPERVISION_OK    -> WARN VIGIAS_PROBLEMA
  storage_watch    verdict!=ALMACENAMIENTO_OK -> WARN ALMACENAMIENTO
  clock_watch      verdict!=RELOJ_OK          -> WARN RELOJ
  dev_ensure       entropia_viva=False        -> CRIT ENTROPIA_MUERTA / WARN DEV_NODOS
  boot_sanity      cmdline ilegible           -> WARN (CRIT si ademas no hay escotilla)
  dr_verify        DR_TAMPER/INCOMPLETO/VIEJO -> CRIT/WARN (replica DR no fiable)
  codegen_audit    AUDIT_FALLA/AUDIT_ERROR    -> CRIT/WARN CODEGEN_DERIVA
  caducidades      POLITICA_MANIPULADA / vencidos>0 -> CRIT/WARN CADUCIDAD

NO duplica a vigias_watch (la frescura de salidas ya es SU dominio; aquí se consumen
veredictos). Archiva-nunca-borra: la cola es append-only (OPEN/RESUELTO); estado.json es
caché derivada. Observe-only: NO bloquea nada. Solo stdlib.

Manifest: queue_watch.py|300|queue/queue_watch.jsonl
"""
import os
import json
import time

DATA = "/persist/anvos-data"
QDIR = os.path.join(DATA, "queue")
QUEUE = os.path.join(QDIR, "operator_queue.jsonl")
ESTADO = os.path.join(QDIR, "estado.json")

# margen normal entre que dr_sync regenera el manifiesto y llega su firma master-side
FIRMA_TOLERANCIA_S = 2 * 3600


def _last(rel):
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


def _detectar():
    """Evalúa las fuentes -> dict {clave: incidente} de condiciones ACTIVAS ahora."""
    act = {}

    si = _last("integrity/self_integrity.jsonl")
    if si and not si.get("all_valid", True):
        act["NODO_NO_SELLADO"] = {"sev": "CRIT", "detalle": "self_integrity %s/%s invalid=%s" % (
            si.get("verified"), si.get("total"), ",".join(si.get("invalid", [])[:5]))}

    cgd = _last("governance/cognition_guard.jsonl")
    if cgd:
        v = cgd.get("verdict")
        if v in ("SIN_GOBIERNO", "ERROR"):
            act["SIN_GOBIERNO"] = {"sev": "CRIT", "detalle": "cognition_guard=%s" % v}
        elif v not in ("GOBERNADO", "GOBERNADO_SIN_VERIFICADOR", None):
            act["GOBERNANZA_DEGRADADA"] = {"sev": "WARN", "detalle": "cognition_guard=%s" % v}

    for rel, ok, clave in (("vigias/vigias_watch.jsonl", "SUPERVISION_OK", "VIGIAS_PROBLEMA"),
                           ("storage/storage_watch.jsonl", "ALMACENAMIENTO_OK", "ALMACENAMIENTO"),
                           ("clock/clock_watch.jsonl", "RELOJ_OK", "RELOJ")):
        d = _last(rel)
        if d and d.get("verdict") not in (ok, None):
            act[clave] = {"sev": "WARN", "detalle": "%s (con_problema=%s)" % (
                d.get("verdict"), d.get("con_problema"))}

    de = _last("dev/dev_ensure.jsonl")
    if de:
        if de.get("entropia_viva") is False:
            act["ENTROPIA_MUERTA"] = {"sev": "CRIT",
                                      "detalle": "/dev/urandom no da entropia (nodo tapado/fichero regular)"}
        elif de.get("verdict") == "DEV_PROBLEMA":
            act["DEV_NODOS"] = {"sev": "WARN", "detalle": "; ".join(de.get("fallos", []))[:150]}

    dv = _last("dr/dr_verify.jsonl")
    if dv:
        v = dv.get("verdict")
        if v == "DR_TAMPER":
            act["DR_TAMPER"] = {"sev": "CRIT", "detalle": "replica DR alterada: %s corruptos, %s firmas invalidas" % (
                dv.get("corruptos"), dv.get("firmas_invalidas"))}
        elif v in ("DR_MANIFIESTO_NO_AUTENTICO", "DR_MANIFIESTO_ILEGIBLE"):
            act["DR_MANIFIESTO"] = {"sev": "CRIT", "detalle": v}
        elif v == "DR_INCOMPLETO":
            act["DR_INCOMPLETO"] = {"sev": "WARN", "detalle": "faltan %s ficheros; criticos ausentes: %s" % (
                dv.get("faltan"), ",".join(dv.get("criticos_ausentes", []))[:80])}
        elif v == "DR_FIRMA_PENDIENTE":
            # dr_sync regenera el manifiesto cada hora y la firma master-side llega detras:
            # un desfase CORTO es operacion normal, no incidente. Solo se abre si el ancla de
            # autoridad lleva ausente mas de FIRMA_TOLERANCIA_S (si no, seria un WARN cronico
            # que se aprende a ignorar, justo lo que hace inutil una cola).
            desfase = dv.get("firma_desfase_s")
            if desfase is None or desfase > FIRMA_TOLERANCIA_S:
                act["DR_FIRMA_PENDIENTE"] = {
                    "sev": "WARN",
                    "detalle": "manifiesto DR sin ancla de autoridad valida desde hace %s" % (
                        ("%ss" % desfase) if desfase is not None else "tiempo indeterminado")}
        elif v == "DR_VIEJO":
            act["DR_VIEJO"] = {"sev": "WARN", "detalle": "replica sin refrescar (edad_s=%s)" % dv.get("edad_s")}

    bs = _last("boot/boot_sanity.jsonl")
    if bs:
        v = bs.get("verdict")
        if v == "ARRANQUE_DEGRADADO_SIN_ESCOTILLA":
            act["ARRANQUE_SIN_ESCOTILLA"] = {"sev": "CRIT", "detalle":
                "el nodo arranco con cmdline ilegible Y su init no acepta el flag de recuperacion: "
                "la escotilla de emergencia del operador esta INERTE"}
        elif v in ("ARRANQUE_DEGRADADO", "SIN_CMDLINE", "CMDLINE_SIN_PARAMETROS"):
            act["ARRANQUE_DEGRADADO"] = {"sev": "WARN", "detalle": (bs.get("detalle") or v)[:150]}

    ca = _last("codegen/codegen_audit.jsonl")
    if ca and ca.get("estado") in ("AUDIT_FALLA", "AUDIT_ERROR"):
        act["CODEGEN_DERIVA"] = {"sev": "CRIT" if ca["estado"] == "AUDIT_FALLA" else "WARN",
                                 "detalle": "; ".join(ca.get("fallos", []))[:200] or ca.get("error", "")[:200]}

    try:
        r = json.loads(open(os.path.join(DATA, "caducidades/resumen.json")).read())
        if r.get("estado_politica") == "POLITICA_MANIPULADA":
            act["CADUCIDAD_POLITICA"] = {"sev": "CRIT", "detalle": "calendario firmado NO verifica"}
        elif r.get("vencidos"):
            act["CADUCIDAD_VENCIDA"] = {"sev": "WARN", "detalle": "%s vencido(s)" % r["vencidos"]}
    except Exception:
        pass

    return act


def main():
    os.makedirs(QDIR, exist_ok=True)
    try:
        os.chmod(QDIR, 0o750)
    except OSError:
        pass
    try:
        est = json.loads(open(ESTADO).read())
    except Exception:
        est = {"abiertos": {}, "resueltos_auto": 0, "total_incidentes": 0}
    abiertos = est.get("abiertos", {})

    ahora = int(time.time())
    activos = _detectar()
    nuevos = resueltos = 0

    with open(QUEUE, "a") as q:
        for clave, inc in activos.items():
            if clave not in abiertos:
                nuevos += 1
                est["total_incidentes"] = est.get("total_incidentes", 0) + 1
                abiertos[clave] = {"sev": inc["sev"], "detalle": inc["detalle"], "ts_open": ahora}
                q.write(json.dumps({"typ": "OPEN", "ts": ahora, "clave": clave,
                                    "sev": inc["sev"], "detalle": inc["detalle"]},
                                   ensure_ascii=False) + "\n")
            else:
                abiertos[clave]["detalle"] = inc["detalle"]     # refrescar evidencia
        for clave in list(abiertos):
            if clave not in activos:
                resueltos += 1
                est["resueltos_auto"] = est.get("resueltos_auto", 0) + 1
                q.write(json.dumps({"typ": "RESUELTO", "ts": ahora, "clave": clave,
                                    "resolucion": "auto: condicion despejada",
                                    "abierto_s": ahora - abiertos[clave].get("ts_open", ahora)},
                                   ensure_ascii=False) + "\n")
                del abiertos[clave]

    est["abiertos"] = abiertos
    est["ts"] = ahora
    tmp = ESTADO + ".tmp"
    with open(tmp, "w") as f:
        json.dump(est, f, ensure_ascii=False)
    os.replace(tmp, ESTADO)

    peor = "CRIT" if any(i["sev"] == "CRIT" for i in abiertos.values()) else (
        "WARN" if abiertos else "OK")
    print(json.dumps({"svc": "queue_watch", "ts": ahora, "abiertos": len(abiertos),
                      "nuevos": nuevos, "auto_resueltos": resueltos, "peor_sev": peor,
                      "verdict": "COLA_LIMPIA" if not abiertos else "COLA_CON_ABIERTOS"},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
