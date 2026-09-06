#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""dr_verify — VERIFICA la réplica DR del nodo. "Un backup no verificado no es un backup".

`dr_sync` copia 145 artefactos críticos al 2º disco físico… y hasta ahora NADIE comprobaba que
esa copia siguiera siendo íntegra, AUTÉNTICA y completa. Este servicio cierra ese hueco con el
mismo listón que el resto del ecosistema: la confianza se demuestra con evidencia, no se declara.

Cuatro comprobaciones, todas fail-closed:
  1. AUTORIDAD  — el `dr_manifest.json` verifica con su firma (an_service, verificador embebido).
                  Se distingue con cuidado: firma ausente o MÁS VIEJA que el manifiesto = desfase
                  benigno (la firma master-side llega minutos después de cada dr_sync) -> WARN;
                  firma NO anterior al manifiesto que aun así falla = manipulación -> CRIT y corta.
  2. INTEGRIDAD — cada fichero del manifiesto existe y su sha256 coincide (detecta bit-rot y
                  manipulación del disco externo).
  3. AUTENTICIDAD — los .py replicados verifican su .minisig 653C con el verificador embebido:
                  la réplica no solo está intacta, sigue siendo la capa FIRMADA (no un impostor
                  con hashes recalculados en un manifiesto que alguien re-firmara).
  4. RESTAURABILIDAD — están las piezas SIN LAS QUE NO SE PUEDE RECONSTRUIR el nodo
                  (manifiesto de la capa, activador, identidad, certs del realm).

Además vigila la FRESCURA (una réplica vieja miente sobre el estado actual).

Nodo sin disco DR (nodo-c) = no-op fail-safe (DR_NO_MONTADO). Observe-only: NUNCA repara ni
borra ni bloquea nada. Solo stdlib. Coste acotado: el nº de verificaciones de firma se limita.

Manifest: dr_verify.py|1800|dr/dr_verify.jsonl
"""
import os
import json
import time
import glob
import hashlib
import subprocess

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
MS = os.path.join(STAGING, "pylayer-verify")
PUB_RELEASE = os.path.join(STAGING, "pylayer", "release.pub")   # clásica (caída de compatibilidad)
RELEASE_D = os.path.join(STAGING, "pylayer", "release.d")


# _release_pubs de F0 (verificación contra release.d) ELIMINADO tras el gate de gobernanza
# (higiene 15-ago): la firma de capa va por la partición A/B (verify_file en
# _verifica_firma_release). PUB_SERVICE sigue usándose para el manifiesto (an_service).
def _ap():
    """Carga el helper de partición A/B — pero PRIMERO lo verifica contra la 653C HORNEADA
    (authority_partition.py es Set B: si origo, que es root, lo intercambiara, colapsaría
    todo el gate). minisign INLINE, sin depender del propio helper que va a cargar; fail-
    closed: si el helper no ancla en la horneada, se levanta excepción (nada se verifica)."""
    import sys as _s, glob as _g, subprocess as _sp
    d = os.path.dirname(os.path.abspath(__file__))
    mod = os.path.join(d, "authority_partition.py")
    baked = "/opt/anvos-verify/release.pub"
    if os.environ.get("ANVOS_TWIN") == "1" and os.path.exists("/etc/anvos-twin"):
        baked = os.environ.get("ANVOS_BAKED_PUB", baked)
    ms = os.path.join(os.environ.get("ANVOS_STAGING", "/persist/anvos-staging"), "pylayer-verify")
    lds = _g.glob(os.path.join(ms, "ld-linux*.so.2"))
    ok = False
    if lds and all(os.path.exists(x) for x in (mod, mod + ".minisig", baked, os.path.join(ms, "minisign"))):
        try:
            ok = _sp.run([lds[0], "--library-path", ms, os.path.join(ms, "minisign"),
                          "-Vm", mod, "-p", baked, "-x", mod + ".minisig"],
                         capture_output=True, timeout=6).returncode == 0
        except Exception:
            ok = False
    if not ok:
        raise RuntimeError("authority_partition.py no verifica contra la clave horneada (fail-closed)")
    if d not in _s.path:
        _s.path.insert(0, d)
    import authority_partition
    return authority_partition


def _verifica_firma_release(ld, fichero):
    """Firma de capa bajo la PARTICIÓN A/B: Set B solo contra la 653C horneada, Set A
    contra release.d. Un guardián re-firmado por origo se cuenta como firma inválida."""
    return _ap().verify_file(fichero)
PUB_SERVICE = os.path.join(STAGING, "pylayer", "an_service.pub")

FRESCURA_MAX_S = 48 * 3600          # dr_sync corre cada hora; 48h sin copia = réplica vieja
MAX_FIRMAS = 80                     # techo de verificaciones de firma por pasada (coste acotado)

# Sin estas piezas el nodo NO se puede reconstruir desde la réplica. Se calculan por-nodo:
# el cert propio lleva el nombre del nodo, y las piezas de realm SOLO se exigen si el nodo es
# soberano (un nodo sin realm — nodo-c — no debe salir INCOMPLETO por no tener lo que no le toca).
CRITICOS_BASE = ("layer/manifest.txt", "node/anvos-node.id")
CRITICOS_REALM = ("realm/realm-root.cert", "realm/node_registry.json")


def _criticos(nodo, manifiesto):
    req = list(CRITICOS_BASE)
    if (manifiesto.get("counts", {}) or {}).get("realm"):     # solo si la réplica incluye realm
        req += list(CRITICOS_REALM) + ["realm/%s.cert" % nodo]
    return req


def _ld():
    for c in glob.glob(os.path.join(MS, "ld-linux*.so.2")):
        return c
    return None


def _verifica_firma(ld, fichero, pub):
    sig = fichero + ".minisig"
    if not (ld and os.path.isfile(fichero) and os.path.isfile(sig) and os.path.exists(pub)):
        return False
    try:
        r = subprocess.run([ld, "--library-path", MS, os.path.join(MS, "minisign"),
                            "-Vm", fichero, "-p", pub, "-x", sig],
                           capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _raiz_dr():
    """Ubicación de la réplica de ESTE nodo (la publica dr_sync en su último registro)."""
    try:
        with open(os.path.join(DATA, "dr", "dr_sync.jsonl")) as f:
            ult = None
            for ln in f:
                ln = ln.strip()
                if ln:
                    ult = json.loads(ln)
    except Exception:
        return None, None
    if not ult:
        return None, None
    raiz, nodo = ult.get("dr_root"), ult.get("node")
    if not (raiz and nodo):
        return None, None
    cur = os.path.join(raiz, nodo, "current")
    return (cur if os.path.isdir(cur) else None), nodo


def main():
    out = {"svc": "dr_verify", "ts": int(time.time())}
    cur, nodo = _raiz_dr()
    if not cur:
        out["verdict"] = "DR_NO_MONTADO"          # nodo sin disco DR o disco desmontado: no-op
        print(json.dumps(out, ensure_ascii=False))
        return
    out["node"] = nodo
    manif = os.path.join(cur, "dr_manifest.json")
    ld = _ld()

    # 1. AUTORIDAD del manifiesto. Se distingue (doctrina del plano DR):
    #    firma AUSENTE = retraso benigno de la firma master-side -> WARN, se sigue comprobando
    #    integridad; firma PRESENTE pero INVÁLIDA = manipulación -> CRIT y se corta (fail-closed:
    #    un índice manipulado no sirve para juzgar la réplica).
    firma_manifiesto = "OK"
    if not os.path.isfile(manif):
        out.update({"verdict": "DR_SIN_MANIFIESTO"})
        print(json.dumps(out, ensure_ascii=False))
        return
    sigf = manif + ".minisig"
    if not os.path.isfile(sigf):
        firma_manifiesto = "PENDIENTE"
    elif not _verifica_firma(ld, manif, PUB_SERVICE):
        # OBSERVADO 2026-07-28: dr_sync regenera el manifiesto cada hora y la firma master-side
        # llega minutos después -> hay una VENTANA en la que la firma es de la versión anterior.
        # Una firma MÁS VIEJA que el manifiesto es desfase benigno, NO manipulación: gritar
        # "tamper" cada hora destruiría la credibilidad de la cola (el que avisa en falso deja
        # de ser creído). Solo es tamper si la firma NO es anterior al fichero que firma.
        try:
            desfasada = os.path.getmtime(sigf) < os.path.getmtime(manif)
        except OSError:
            desfasada = False
        if desfasada:
            firma_manifiesto = "DESFASADA"
            try:
                out["firma_desfase_s"] = int(os.path.getmtime(manif) - os.path.getmtime(sigf))
            except OSError:
                pass
        else:
            out.update({"verdict": "DR_MANIFIESTO_NO_AUTENTICO",
                        "detalle": "firma NO anterior al manifiesto y NO verifica (posible manipulación)"})
            print(json.dumps(out, ensure_ascii=False))
            return
    out["firma_manifiesto"] = firma_manifiesto
    try:
        m = json.loads(open(manif).read())
    except Exception as e:
        out.update({"verdict": "DR_MANIFIESTO_ILEGIBLE", "detalle": str(e)[:80]})
        print(json.dumps(out, ensure_ascii=False))
        return

    ficheros = m.get("files", [])
    out["esperados"] = len(ficheros)

    # 2. INTEGRIDAD (sha256 de cada fichero replicado)
    faltan, corruptos = [], []
    for it in ficheros:
        p = os.path.join(cur, it.get("rel", ""))
        if not os.path.isfile(p):
            faltan.append(it.get("rel"))
            continue
        try:
            if _sha256(p) != it.get("sha256"):
                corruptos.append(it.get("rel"))
        except Exception:
            corruptos.append(it.get("rel"))
    out["faltan"] = len(faltan)
    out["corruptos"] = len(corruptos)
    if faltan:
        out["faltan_ej"] = faltan[:5]
    if corruptos:
        out["corruptos_ej"] = corruptos[:5]

    # 3. AUTENTICIDAD (firmas 653C de los .py replicados; techo de coste)
    firmados = malas = 0
    for it in ficheros:
        rel = it.get("rel", "")
        if not rel.endswith(".py"):
            continue
        if firmados >= MAX_FIRMAS:
            break
        p = os.path.join(cur, rel)
        if not os.path.isfile(p + ".minisig"):
            continue
        firmados += 1
        if not _verifica_firma_release(ld, p):
            malas += 1
    out["firmas_comprobadas"] = firmados
    out["firmas_invalidas"] = malas

    # 4. RESTAURABILIDAD (piezas sin las que no se reconstruye)
    ausentes = [c for c in _criticos(nodo, m) if not os.path.isfile(os.path.join(cur, c))]
    out["criticos_ausentes"] = ausentes

    # FRESCURA (una réplica vieja miente sobre el estado actual)
    edad = None
    try:
        edad = int(time.time() - os.path.getmtime(os.path.join(cur, "dr_last_sync.json")))
    except Exception:
        pass
    out["edad_s"] = edad
    fresca = edad is not None and edad <= FRESCURA_MAX_S
    out["fresca"] = fresca

    if corruptos or malas:
        out["verdict"] = "DR_TAMPER"              # contenido alterado: lo más grave
    elif firma_manifiesto in ("PENDIENTE", "DESFASADA"):
        out["verdict"] = "DR_FIRMA_PENDIENTE"     # íntegro; el ancla de autoridad aún no ha llegado
    elif faltan or ausentes:
        out["verdict"] = "DR_INCOMPLETO"          # no restaurable tal cual
    elif not fresca:
        out["verdict"] = "DR_VIEJO"
    else:
        out["verdict"] = "DR_VERIFICADO"
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()
