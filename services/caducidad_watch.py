#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""caducidad_watch — VIGÍA DE CADUCIDADES: vuelve VERIFICABLE el paso del tiempo. Las caducidades de
artefactos y obligaciones no avisan solas — una clave que rota, la retención legal de datos personales,
la revisión de un certificado/credencial OT de una instalación eléctrica, una prueba de restauración DR
o un sello vencen en silencio. Este vigía lee una POLÍTICA DE CADUCIDADES FIRMADA 653C (la fuente de
verdad) y emite avisos escalados T-90 / T-60 / T-30 / VENCIDO, con severidad por CRITICIDAD del activo.

Modelo de amenaza (agentes ofensivos que roban datos / atacan infraestructura crítica): el propio vigía
es tamper-evident y FAIL-CLOSED — si la política existe pero su firma NO valida, se emite
POLITICA_MANIPULADA con severidad MÁXIMA y NO se confía en su contenido (un atacante que edita el
calendario para ocultar un vencimiento es una señal fuerte, no un silencio). Sanidad de reloj: si el reloj
del nodo parece derivado (año < 2024), los VENCIDOS se degradan a VENCIDO_RELOJ_DUDOSO para no disparar
máxima severidad en falso (un reloj de confianza es requisito de una caducidad de confianza).

Doctrina: OBSERVE/ALERT-ONLY. No renueva, no borra, no firma — solo alerta y ESCALA al operador, que
decide y re-firma el calendario con la nueva fecha ("IA propone, humano firma"). Solo stdlib. Fail-safe:
cualquier fallo interno se registra y el ciclo termina en 0 (nunca tumba a layerd).

Uso: caducidad_watch.py [cycle|report]   (por defecto cycle; layerd lo corre periódicamente)."""
import os
import sys
import json
import time
import glob
import calendar as _cal
import subprocess

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
MS = os.path.join(STAGING, "pylayer-verify")
PUB = os.path.join(STAGING, "pylayer", "release.pub")

CDIR = os.path.join(DATA, "caducidades")
CAL = os.path.join(CDIR, "calendario.json")
ALERTS = os.path.join(CDIR, "alerts.jsonl")
ESCALATION = os.path.join(CDIR, "escalated.jsonl")      # lo revisa el operador
CURSOR = os.path.join(CDIR, "cursor.json")              # {id: etapa_ya_emitida} (dedup)
RESUMEN = os.path.join(CDIR, "resumen.json")            # último resumen (para el dashboard)
OUT = os.path.join(CDIR, "caducidad_watch.jsonl")       # latido/salida

DAY = 86400
# umbrales de aviso (días antes del vencimiento) y su orden de gravedad creciente
ETAPAS = ["OK", "AVISO_T90", "AVISO_T60", "AVISO_T30", "VENCIDO"]
ORDEN = {e: i for i, e in enumerate(ETAPAS)}
# categorías cuyo vencimiento es CRÍTICO (datos personales, estado, OT eléctrico, clave soberana)
CRITICAS = {"CLAVE_SOBERANA", "DATOS_PERSONALES", "ESTADO_CRITICO", "OT_ELECTRICO"}


def _now():
    return int(time.time())


def _ensure():
    try:
        os.makedirs(CDIR, exist_ok=True)
    except Exception:
        pass


def _append(path, rec):
    _ensure()
    try:
        with open(path, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL caducidad_watch._append: %r" % (e,), file=sys.stderr, flush=True)


def _write_json(path, obj):
    _ensure()
    try:
        json.dump(obj, open(path + ".tmp", "w"), ensure_ascii=False)
        os.replace(path + ".tmp", path)
    except Exception:
        pass


def _sig_ok(target):
    """Firma 653C válida (minisign embebido de la capa); fail-closed."""
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


def _load_cursor():
    try:
        return json.load(open(CURSOR))
    except Exception:
        return {}


def _save_cursor(c):
    _write_json(CURSOR, c)


def _to_epoch(v):
    """Acepta epoch (int/str numérica) o fecha ISO 'YYYY-MM-DD' (medianoche UTC). None si no se entiende."""
    if v is None:
        return None
    try:
        if isinstance(v, (int, float)):
            return int(v)
        s = str(v).strip()
        if s.isdigit():
            return int(s)
        return int(_cal.timegm(time.strptime(s[:10], "%Y-%m-%d")))
    except Exception:
        return None


def _etapa(dias):
    if dias is None:
        return None
    if dias < 0:
        return "VENCIDO"
    if dias <= 30:
        return "AVISO_T30"
    if dias <= 60:
        return "AVISO_T60"
    if dias <= 90:
        return "AVISO_T90"
    return "OK"


def _severidad(etapa, categoria, reloj_dudoso):
    crit = categoria in CRITICAS
    if etapa == "VENCIDO":
        if reloj_dudoso:
            return "ALTA"          # no máxima: el reloj no es de fiar
        return "MAXIMA" if crit else "ALTA"
    if etapa == "AVISO_T30":
        return "ALTA" if crit else "MEDIA"
    if etapa == "AVISO_T60":
        return "MEDIA"
    if etapa == "AVISO_T90":
        return "BAJA"
    return "INFO"


def cmd_cycle():
    _ensure()
    now = _now()
    reloj_dudoso = time.gmtime(now).tm_year < 2024
    cursor = _load_cursor()
    nuevas = []
    resumen = {"svc": "caducidad_watch", "ts": now, "reloj_dudoso": reloj_dudoso,
               "por_severidad": {}, "vencidos": 0, "proximos": [], "estado_politica": None}

    # 1) política de caducidades firmada (fuente de verdad, fail-closed)
    if not os.path.isfile(CAL):
        resumen["estado_politica"] = "SIN_CALENDARIO"
    elif not _sig_ok(CAL):
        resumen["estado_politica"] = "POLITICA_MANIPULADA"
        ev = {"svc": "caducidad_watch", "ts": now, "severidad": "MAXIMA",
              "evento": "POLITICA_MANIPULADA", "id": "calendario",
              "note": "la política de caducidades existe pero su firma 653C NO valida -> posible manipulación; NO se confía en su contenido; escalar YA"}
        _append(ALERTS, ev)
        _append(ESCALATION, ev)
        nuevas.append(ev)
    else:
        resumen["estado_politica"] = "FIRMADO_OK"
        try:
            cal = json.loads(open(CAL).read())
        except Exception:
            cal = {}
        entradas = cal.get("entradas", []) if isinstance(cal, dict) else []
        vistos = set()
        for e in entradas:
            try:
                eid = str(e.get("id") or "?")
                vistos.add(eid)
                categoria = str(e.get("categoria") or "GENERAL")
                venc = _to_epoch(e.get("vence"))
                if venc is None:
                    continue
                dias = int((venc - now) // DAY)
                etapa = _etapa(dias)
                if dias < 0:
                    resumen["vencidos"] += 1
                if etapa in ("AVISO_T90", "AVISO_T60", "AVISO_T30", "VENCIDO"):
                    resumen["proximos"].append({"id": eid, "categoria": categoria,
                                                "dias": dias, "etapa": etapa})
                prev = cursor.get(eid, "OK")
                # emitir solo si la etapa EMPEORA respecto a lo ya avisado (evita spam por ciclo)
                if ORDEN.get(etapa, 0) > ORDEN.get(prev, 0):
                    etiqueta = "VENCIDO_RELOJ_DUDOSO" if (etapa == "VENCIDO" and reloj_dudoso) else etapa
                    sev = _severidad(etapa, categoria, reloj_dudoso)
                    ev = {"svc": "caducidad_watch", "ts": now, "severidad": sev,
                          "evento": etiqueta, "id": eid, "categoria": categoria,
                          "descripcion": e.get("descripcion"), "dias_restantes": dias,
                          "vence": e.get("vence"), "responsable": e.get("responsable"),
                          "critico": categoria in CRITICAS,
                          "note": "caducidad %s; el operador debe actuar y re-firmar el calendario (observe-only)" % etiqueta}
                    _append(ALERTS, ev)
                    if sev in ("ALTA", "MAXIMA"):
                        _append(ESCALATION, ev)
                    nuevas.append(ev)
                    cursor[eid] = etapa
                elif ORDEN.get(etapa, 0) < ORDEN.get(prev, 0):
                    cursor[eid] = etapa   # renovado/alejado -> baja de etapa, silencioso
                    resumen.setdefault("renovados", []).append(eid)
            except Exception:
                continue
        # limpiar del cursor ids que ya no están en el calendario
        for gone in [k for k in cursor if k not in vistos and k != "calendario"]:
            cursor.pop(gone, None)

    # 2) resumen por severidad de las nuevas alertas de este ciclo
    for ev in nuevas:
        s = ev.get("severidad", "INFO")
        resumen["por_severidad"][s] = resumen["por_severidad"].get(s, 0) + 1
    resumen["proximos"] = sorted(resumen["proximos"], key=lambda x: x["dias"])[:10]
    resumen["nuevas_alertas"] = len(nuevas)

    _save_cursor(cursor)
    _write_json(RESUMEN, resumen)
    for ev in nuevas:
        print(json.dumps(ev, ensure_ascii=False))
    print(json.dumps(resumen, ensure_ascii=False), flush=True)   # latido para layerd
    _append(OUT, {"ts": now, "estado_politica": resumen["estado_politica"],
                  "nuevas_alertas": len(nuevas), "vencidos": resumen["vencidos"],
                  "reloj_dudoso": reloj_dudoso})
    return 0


def cmd_report():
    try:
        r = json.load(open(RESUMEN))
    except Exception:
        r = {"estado_politica": "SIN_DATOS"}
    esc = 0
    try:
        esc = sum(1 for _ in open(ESCALATION))
    except Exception:
        pass
    print(json.dumps({"svc": "caducidad_watch", "resumen": r, "escalaciones_totales": esc},
                     ensure_ascii=False))
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "cycle"
    try:
        if cmd in ("cycle", "run", "probe"):
            return cmd_cycle()
        if cmd == "report":
            return cmd_report()
        print(json.dumps({"svc": "caducidad_watch", "error": "modo desconocido: %s" % cmd}))
        return 2
    except Exception as e:
        print(json.dumps({"svc": "caducidad_watch", "ok": False, "fatal": str(e)}, ensure_ascii=False))
        return 0


if __name__ == "__main__":
    sys.exit(main())
