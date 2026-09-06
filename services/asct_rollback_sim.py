#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""asct_rollback_sim — SIMULACRO del plano de RECUPERACIÓN (fire-drill de rollback) del ASCT (matriz item 10).

Completa asct_sim (pre-vuelo de código), asct_drift (deriva en runtime) y asct_incident_sim
(fire-drill del DETECTOR) con lo que faltaba: probar que la RECUPERACIÓN funciona. Un rollback
que nunca se ensaya puede estar roto en silencio — y es la red de seguridad de TODAS las
promociones del tri-ring del nodo.

Monta un TRI-RING SOMBRA aislado (staging/persist/data propios bajo /persist/anvos-rollback-shadow;
verificador minisign y clave release REALES enlazados solo-lectura; bundle mínimo de ficheros YA
firmados — el nodo no firma by-design) y ejercita el ring_promote REAL (importado con sus rutas
apuntando a la sombra) por sus caminos críticos:
  1. init_siembra    — sembrar DEV/MIRROR desde MAIN (baseline verificada).
  2. promocion_sana  — cambio REAL en DEV (quitar un servicio, firmas intactas) → promoción
                       completa: MAIN queda idéntico a DEV + respaldo creado.
  3. dev_manipulado  — se corrompe un .py de DEV → la promoción ABORTA y MAIN queda INTACTO.
  4. auto_rollback   — fallo de integridad SINTÉTICO tras promover (inyectado en
                       _self_integrity_ok) → AUTO-ROLLBACK restaura MAIN byte-idéntico.
  5. rollback_manual — se corrompe el MAIN vivo → cmd_rollback restaura del último respaldo.
  6. cadena_integra  — la promotion.chain de la sombra re-verifica eslabón a eslabón.
  7. gobernanza_deniega_sin_dictamen — sin dictamen, la promoción DEBE ser denegada
                       y MAIN quedar intacto: la ausencia de juicio no vale por un sí.
  8. gobernanza_deniega_caduco       — con dictamen fuera de plazo, igual: un juicio
                       viejo describe un nodo que ya no existe.
Si algún camino no se comporta como debe → REGRESIÓN del plano de recuperación.

TOTALMENTE AISLADO: solo escribe bajo la sombra (NUNCA toca el tri-ring real ni la capa activa
del nodo). OBSERVE-only sobre el estado real, determinista, solo stdlib. Single-shot bajo layerd.
Convención layerd: el stdout del servicio ES su .jsonl → se emite SOLO el registro final
(los prints internos de ring_promote se silencian con redirect_stdout)."""
import io
import os
import sys
import json
import time
import glob
import shutil
import hashlib
import contextlib

REAL_STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
REAL_MAIN = os.path.join(REAL_STAGING, "services")

SHADOW = "/persist/anvos-rollback-shadow"
S_STAGING = os.path.join(SHADOW, "staging")
S_PERSIST = os.path.join(SHADOW, "persist")
S_DATA = os.path.join(SHADOW, "data")

# bundle mínimo (ficheros reales ya firmados; suficiente para ejercitar todo el pipeline)
BUNDLE = ["manifest.txt", "self_integrity.py", "asct_sim.py", "node_health_beacon.py"]
GEN = "0" * 64


def _build_shadow():
    """Construye el tri-ring sombra. Devuelve la lista de ficheros del bundle que falten."""
    shutil.rmtree(SHADOW, ignore_errors=True)
    smain = os.path.join(S_STAGING, "services")
    os.makedirs(smain)
    os.makedirs(S_PERSIST)
    os.makedirs(S_DATA)
    # verificador embebido + clave release reales (solo-lectura vía symlink)
    os.symlink(os.path.join(REAL_STAGING, "pylayer-verify"), os.path.join(S_STAGING, "pylayer-verify"))
    os.symlink(os.path.join(REAL_STAGING, "pylayer"), os.path.join(S_STAGING, "pylayer"))
    missing = []
    for name in BUNDLE:
        src = os.path.join(REAL_MAIN, name)
        if os.path.isfile(src) and os.path.isfile(src + ".minisig"):
            shutil.copy2(src, os.path.join(smain, name))
            shutil.copy2(src + ".minisig", os.path.join(smain, name + ".minisig"))
        else:
            missing.append(name)
    return missing


def _sembrar_dictamen(veredicto="GOBERNADO", edad_s=0):
    """Escribe un dictamen de gobernanza en la SOMBRA. Devuelve la ruta del fichero.

    POR QUE HACE FALTA (ITV-051, 2026-08-05/07)
    --------------------------------------------
    Este simulacro se escribio ANTES de que ring_promote tuviera puerta de gobernanza. Cuando la
    puerta se anadio, la sombra siguio montandose sin dictamen, y la promocion empezo a denegarse
    con veredicto SIN_DICTAMEN. Es decir: la puerta hacia EXACTAMENTE lo que debe —la ausencia de
    juicio no vale por un si— y el simulacro lo contaba como regresion del plano de recuperacion.

    El resultado medido era 4/6, y los dos que fallaban no eran dos fallos sino UNO: sin promocion
    no se crea respaldo, y sin respaldo el rollback manual no tiene de donde restaurar.

    QUE SE SIEMBRA, y por que sintetico en vez de tomar el del nodo
    ----------------------------------------------------------------
    La sombra ya toma prestados el verificador y la clave release REALES, de modo que tomar tambien
    el dictamen vivo seria coherente. Pero entonces el resultado del simulacro dependeria del estado
    de gobernanza del momento: un nodo legitimamente DEGRADADO haria fallar un simulacro que no
    prueba gobernanza, sino recuperacion. Se siembra uno sintetico y explicito, y la puerta en si se
    prueba aparte, en su propio escenario.
    """
    gdir = os.path.join(S_DATA, "governance")
    os.makedirs(gdir, exist_ok=True)
    p = os.path.join(gdir, "cognition_guard.jsonl")
    reg = {"svc": "cognition_guard", "ts": int(time.time()) - edad_s,
           "node": "sombra-simulacro", "verdict": veredicto, "governed": veredicto == "GOBERNADO",
           "origen": "SEMBRADO POR asct_rollback_sim: dictamen sintetico del tri-ring sombra, "
                     "no describe al nodo real"}
    with open(p, "w") as f:
        f.write(json.dumps(reg, ensure_ascii=False) + "\n")
    return p


def _load_ring_promote():
    """Importa el ring_promote REAL con sus rutas resueltas hacia la sombra."""
    os.environ["ANVOS_STAGING"] = S_STAGING
    os.environ["ANVOS_PERSIST"] = S_PERSIST
    os.environ["ANVOS_DATA"] = S_DATA
    sys.path.insert(0, REAL_MAIN)
    import importlib
    import ring_promote
    return importlib.reload(ring_promote)


def _tamper(d, name):
    """Corrompe un fichero firmado (contenido cambia -> su firma deja de validar)."""
    with open(os.path.join(d, name), "a") as f:
        f.write("\n# corrupcion sintetica del simulacro\n")


def _chain_ok(chain_path):
    """Re-verifica la promotion.chain eslabón a eslabón (prev + hash recomputado)."""
    prev, n = GEN, 0
    try:
        with open(chain_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                h = rec.pop("hash", None)
                if rec.get("prev") != prev:
                    return False, n
                if hashlib.sha256((prev + json.dumps(rec, sort_keys=True)).encode()).hexdigest() != h:
                    return False, n
                prev, n = h, n + 1
    except Exception:
        return False, n
    return n > 0, n


def _scenarios(check):
    """Ejercita los 8 caminos críticos del plano de recuperación en la sombra.

    Eran 6 hasta ITV-051. Los dos nuevos prueban la PUERTA DE GOBERNANZA, que hasta
    entonces no se comprobaba: se padecía. Denegaba con razón —sin dictamen y con
    dictamen caducado— y el simulacro contaba esa denegación como regresión del plano
    de recuperación, dando 4/6 de forma permanente.
    """
    rp = _load_ring_promote()
    MAIN, DEV = rp.MAIN, rp.DEV

    # La sombra necesita su propio dictamen de gobernanza: sin el, la puerta deniega —con razon— y
    # los escenarios 2 y 5 fallaban por una causa que NO es del plano de recuperacion (ITV-051).
    gov_path = _sembrar_dictamen("GOBERNADO")

    # 1) siembra del tri-ring sombra desde MAIN
    rc = rp.cmd_init()
    check("init_siembra", rc == 0 and os.path.isdir(DEV) and os.path.isdir(rp.MIRROR))

    # 2) promoción SANA con cambio real: DEV pierde un servicio (firmas intactas)
    pre = rp._content_hash(MAIN)
    os.remove(os.path.join(DEV, "node_health_beacon.py"))
    os.remove(os.path.join(DEV, "node_health_beacon.py.minisig"))
    # La retirada de un servicio es DELIBERADA en este escenario: es como se provoca un cambio real
    # con las firmas intactas. Desde ITV-061 la promocion se detiene ante una retirada no declarada
    # —correctamente: quien promociona un servicio no espera retirar otro— de modo que aqui hay que
    # AUTORIZARLA explicitamente, que es justo la via que aquel arreglo dejo abierta.
    #
    # Este fallo lo encontro el propio simulacro al bajar de 8/8 a 7/8 tras desplegarse la guarda:
    # dos arreglos correctos por separado chocaban, y ninguna revision de codigo lo habria visto.
    # Es exactamente para lo que sirve ensayar la recuperacion en vez de suponerla.
    os.environ["ANV_PROMOTE_ACEPTA_RETIRADA"] = "1"
    try:
        rc = rp.cmd_promote()
    finally:
        os.environ.pop("ANV_PROMOTE_ACEPTA_RETIRADA", None)
    backups = glob.glob(os.path.join(rp.BACKUPS, "main_*"))
    check("promocion_sana",
          rc == 0 and rp._content_hash(MAIN) == rp._content_hash(DEV)
          and rp._content_hash(MAIN) != pre and len(backups) >= 1,
          backups=len(backups))

    # 3) DEV manipulado -> la promoción ABORTA y MAIN queda intacto
    pre = rp._content_hash(MAIN)
    _tamper(DEV, "self_integrity.py")
    rc = rp.cmd_promote()
    intact = rp._content_hash(MAIN) == pre
    check("dev_manipulado", rc != 0 and intact, main_intacto=intact)
    rp._copy_bundle(MAIN, DEV)   # restaurar DEV desde el MAIN bueno

    # 4) fallo de integridad SINTÉTICO post-promoción -> AUTO-ROLLBACK byte-idéntico
    pre = rp._content_hash(MAIN)
    orig = rp._self_integrity_ok
    rp._self_integrity_ok = lambda: (False, 0, 0)   # inyección del simulacro
    try:
        rc = rp.cmd_promote()
    finally:
        rp._self_integrity_ok = orig
    check("auto_rollback", rc != 0 and rp._content_hash(MAIN) == pre)

    # 5) corrupción del MAIN vivo -> rollback manual restaura del último respaldo
    good = rp._content_hash(MAIN)
    _tamper(MAIN, "self_integrity.py")
    corrupted = rp._content_hash(MAIN) != good
    rc = rp.cmd_rollback()
    restored = rp._content_hash(MAIN) == good
    okv, _, _ = rp.verify_dir(rp._ld(), MAIN)
    check("rollback_manual", corrupted and rc == 0 and restored and okv,
          restaurado_identico=restored)

    # 6) la cadena de promoción de la sombra re-verifica completa
    cok, links = _chain_ok(rp.CHAIN)
    check("cadena_integra", cok, links=links)

    # 7) y 8) LA PUERTA DE GOBERNANZA, ahora bajo prueba en vez de ser la causa de un falso fallo.
    #
    # Hasta ITV-051 esta puerta no se comprobaba: se PADECIA. Denegaba —correctamente— y el
    # simulacro lo contaba como regresion del plano de recuperacion. Al sembrar el dictamen los
    # seis escenarios originales vuelven a medir lo suyo, pero entonces la puerta dejaria de
    # ejercitarse por completo, y una puerta que nadie prueba es exactamente lo que este simulacro
    # existe para evitar. De ahi que su denegacion pase a ser un resultado ESPERADO y verificado.
    #
    # Se prueban los dos motivos de denegacion por separado, porque son distintos: no haber juicio
    # y haberlo pero viejo. Un solo caso dejaria el otro camino sin recorrer.
    for nombre, ver, edad in (("gobernanza_deniega_sin_dictamen", None, 0),
                              ("gobernanza_deniega_caduco", "GOBERNADO", rp.GOV_MAX_EDAD_S + 600)):
        pre = rp._content_hash(MAIN)
        if ver is None:
            open(gov_path, "w").close()          # dictamen ausente: fichero vacio
        else:
            _sembrar_dictamen(ver, edad_s=edad)  # dictamen valido pero fuera de plazo
        rc = rp.cmd_promote()
        intacto = rp._content_hash(MAIN) == pre
        check(nombre, rc != 0 and intacto, main_intacto=intacto)
    _sembrar_dictamen("GOBERNADO")               # devolver la sombra a su estado gobernado


def run():
    if not os.path.isdir(os.path.join(REAL_STAGING, "pylayer-verify")):
        return {"svc": "asct_rollback_sim", "ts": int(time.time()), "ok": False,
                "error": "verificador embebido no disponible en este entorno"}
    missing = _build_shadow()
    if missing:
        shutil.rmtree(SHADOW, ignore_errors=True)
        return {"svc": "asct_rollback_sim", "ts": int(time.time()), "ok": False,
                "error": "bundle sombra incompleto (sin fichero+firma)", "missing": missing}

    results = []

    def check(name, ok, **extra):
        results.append({"scenario": name, "ok": bool(ok), **extra})

    try:
        # silenciar los prints internos de ring_promote (bajo layerd, stdout = el .jsonl)
        with contextlib.redirect_stdout(io.StringIO()):
            _scenarios(check)
    except Exception as e:
        check("excepcion", False, error=str(e)[:120])
    finally:
        shutil.rmtree(SHADOW, ignore_errors=True)           # limpiar la sombra SIEMPRE

    passed = sum(1 for r in results if r["ok"])
    total = len(results)
    return {"svc": "asct_rollback_sim", "ts": int(time.time()), "observe_only": True,
            "aislamiento": SHADOW, "ejercita": "ring_promote (promote/auto-rollback/rollback/chain)",
            "passed": passed, "total": total,
            "verdict": "RECOVERY_OK" if (passed == total and total >= 6) else "RECOVERY_REGRESION",
            "results": results}


def main():
    # print-only: bajo layerd el stdout se anexa al .jsonl del manifiesto (no escribir aparte)
    print(json.dumps(run(), ensure_ascii=False))


if __name__ == "__main__":
    main()
