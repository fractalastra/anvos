#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""mint_guard — decide si este nodo puede EMITIR. Fail-closed: por defecto, no.

Hasta hoy `can_mint` era una bandera sin dueño. La escribia la genesis cableada a false, el
verificador de pares la REPORTABA, y **ninguna rama de codigo la imponia**. Encenderla no habria
encendido nada: no hay servicio de emision, no reside ninguna clave secreta en el nodo, y la
propia bandera vive donde el nodo puede tocarla.

Peor aun: la facultad la declara HOY el certificado propio del nodo, firmado por su PROPIA raiz
de realm (`ANV_NODE_CAN_MINT=false`). Es decir, un nodo soberano se concede a si mismo la
facultad de emitir. Es la averia de "la adhesion se declara, no se demuestra" un nivel mas
adentro: quien manda sobre lo que puedo hacer no puedo ser yo.

DE DONDE TOMA LA FACULTAD ESTE GUARDIAN

  Del certificado del nodo **CONTRAFIRMADO por la raiz del ascendiente** (`parent-node.cert`),
  no del que el nodo emite sobre si mismo. Y **su ausencia es negativa**, nunca permisiva.

  Consecuencia deliberada: conceder la facultad exige reemitir el certificado del nodo con
  `ANV_NODE_CAN_MINT=true` firmado por la raiz del padre, que no reside en ningun nodo (custodia externa de la autoridad). O sea, exige una ceremonia del operador. Que es exactamente lo que la
  politica del ecosistema quiere decir cuando reserva el alta de nodos al master con su llave.

LAS CUATRO CONDICIONES, TODAS EXIGIDAS

  1. CONTRAFIRMA   existe `parent-node.cert` y valida contra `parent_realm_root.pub` — la clave
                   del ascendiente que este nodo ya tiene, nunca una que venga de fuera.
  2. FACULTAD      ese certificado declara `ANV_NODE_CAN_MINT=true`. Ausente o false -> vedado.
  3. DELEGACION    existe una clave de emision avalada con `scope=mint` por la raiz del realm
                   propio. Sin ella no hay con que firmar lo emitido, y una facultad sin clave
                   es una facultad de mentira.
  4. NORMA         el plano de politica del nodo no esta en desviacion.

Si falta cualquiera, el veredicto es EMISION_VEDADA **y se dice cual falta**. Un guardian que
niega sin decir por que obliga a adivinar, y quien adivina acaba apagando el guardian.

NO EMITE NADA. Dictamina. La emision, cuando exista, consulta este dictamen; separar quien
decide de quien ejecuta es lo que impide que un fallo en el ejecutor se conceda permisos solo.

Fail-safe en lo que ejecuta (cualquier excepcion -> registrar y salir 0) y fail-closed en lo que
juzga (cualquier duda -> vedado). Solo stdlib + el minisign embebido.

Manifest: mint_guard.py|1800|mint/mint_guard.jsonl
Uso: mint_guard.py [cycle]
"""
import os
import re
import sys
import glob
import json
import time
import subprocess

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
REALM = os.environ.get("ANVOS_REALM", "/persist/anvos-realm")
IAM = os.environ.get("ANVOS_IAM", "/persist/anvos-iam")
MS = os.path.join(STAGING, "pylayer-verify")
OUT = os.path.join(DATA, "mint", "mint_guard.jsonl")

CERT_PADRE = os.path.join(REALM, "parent-node.cert")
PUB_PADRE = os.path.join(REALM, "parent_realm_root.pub")
PUB_PROPIA = os.path.join(REALM, "realm_root.pub")
DELEG = os.path.join(IAM, "delegations")
SCOPE_MINT = "mint"


def _emit(d):
    print(json.dumps(d, ensure_ascii=False), flush=True)
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "a") as f:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL mint_guard._emit: %r" % (e,), file=sys.stderr, flush=True)


def _ld():
    for c in ("ld-linux-x86-64.so.2", "ld-musl-x86_64.so.1"):
        p = os.path.join(MS, c)
        if os.path.exists(p):
            return p
    return None


def _verifica(target, pub):
    """Verifica contra UNA clave concreta y devuelve (ok, comentario_firmado).

    Contra una sola clave a proposito: aceptar la primera de una lista que encaje deja pasar a
    cualquiera que traiga la suya, y aqui se esta decidiendo quien puede emitir.
    """
    sig = target + ".minisig"
    if not (os.path.isfile(target) and os.path.isfile(sig) and os.path.isfile(pub)):
        return False, ""
    ld = _ld()
    binario = os.path.join(MS, "minisign")
    if ld and os.path.exists(binario):
        base = [ld, "--library-path", MS, binario]
    else:
        import shutil
        if not shutil.which("minisign"):
            return False, ""
        base = ["minisign"]
    try:
        r = subprocess.run(base + ["-Vm", target, "-p", pub, "-x", sig],
                           capture_output=True, timeout=15)
        if r.returncode != 0:
            return False, ""
        txt = (r.stdout or b"").decode("utf-8", "replace") + (r.stderr or b"").decode("utf-8", "replace")
        m = re.search(r"Trusted comment:\s*(.*)", txt)
        return True, (m.group(1).strip() if m else "")
    except Exception:
        return False, ""


def _campos(path):
    d = {}
    try:
        for ln in open(path, errors="replace").read().splitlines():
            if "=" in ln and not ln.strip().startswith("#"):
                k, _, v = ln.partition("=")
                d[k.strip()] = v.strip()
    except Exception:
        pass
    return d


def _clave_de_emision():
    """Clave avalada con scope=mint por la raiz del realm PROPIO. (nombre, alcances) o (None, [])."""
    for pub in sorted(glob.glob(os.path.join(DELEG, "*.pub"))):
        ok, comentario = _verifica(pub, PUB_PROPIA)
        if not ok:
            continue
        alcances = set(re.findall(r"scope=([A-Za-z0-9_.\-]+)", comentario or ""))
        if SCOPE_MINT in alcances:
            return os.path.basename(pub), sorted(alcances)
    return None, []


def _norma():
    """Ultimo dictamen del plano de politica. None si no hay."""
    p = os.path.join(DATA, "asct", "policy.jsonl")
    try:
        ultimo = None
        for ln in open(p, errors="replace"):
            ln = ln.strip()
            if ln.startswith("{"):
                ultimo = ln
        return json.loads(ultimo) if ultimo else None
    except Exception:
        return None


def cmd_cycle():
    ahora = int(time.time())
    faltan = []
    detalle = {}

    # 1 · CONTRAFIRMA del ascendiente
    ok_c, _ = _verifica(CERT_PADRE, PUB_PADRE)
    detalle["contrafirma_del_ascendiente"] = ok_c
    if not ok_c:
        faltan.append("CONTRAFIRMA: no hay certificado de este nodo contrafirmado por la raiz de "
                      "su ascendiente, o no valida contra ella")

    # 2 · FACULTAD, tomada de ESE certificado y no del propio
    campos = _campos(CERT_PADRE) if ok_c else {}
    bruto = (campos.get("ANV_NODE_CAN_MINT") or "").strip().lower()
    facultad = bruto == "true"
    detalle["facultad_declarada_por_el_ascendiente"] = bruto or None
    detalle["nodo_en_la_contrafirma"] = campos.get("ANV_NODE_ID")
    if not facultad:
        faltan.append("FACULTAD: el certificado contrafirmado %s. Concederla exige reemitirlo con "
                      "ANV_NODE_CAN_MINT=true firmado por la raiz del padre, que no reside en "
                      "ningun nodo (custodia externa de la autoridad)" %
                      ("no declara la facultad de emitir" if not bruto else "la declara como '%s'" % bruto))

    # 3 · DELEGACION con alcance de emision
    clave, alcances = _clave_de_emision()
    detalle["clave_de_emision"] = clave
    detalle["alcances_de_esa_clave"] = alcances
    if not clave:
        faltan.append("DELEGACION: no hay ninguna clave avalada con scope=mint por la raiz del "
                      "realm propio, asi que no hay con que firmar lo que se emitiera")

    # 4 · NORMA
    pol = _norma()
    conf = (pol or {}).get("conformidad") or (pol or {}).get("estado")
    detalle["norma"] = conf
    if pol is not None and str(conf).upper() in ("DESVIACION", "REGRESION", "NO_CONFORME"):
        faltan.append("NORMA: el plano de politica del nodo esta en %s" % conf)

    rec = {"svc": "mint_guard", "ts": ahora,
           "veredicto": "EMISION_AUTORIZADA" if not faltan else "EMISION_VEDADA",
           "condiciones": detalle,
           "faltan": faltan,
           "nota": ("la facultad se toma del certificado CONTRAFIRMADO por el ascendiente, nunca "
                    "del que el nodo emite sobre si mismo: quien manda sobre lo que puedo hacer no "
                    "puedo ser yo. Este servicio dictamina y NO emite")}
    _emit(rec)
    return 0


def main():
    try:
        return cmd_cycle()
    except Exception as e:
        # Fail-closed en el juicio: si el guardian se rompe, no autoriza.
        _emit({"svc": "mint_guard", "ts": int(time.time()), "veredicto": "EMISION_VEDADA",
               "faltan": ["ERROR_INTERNO: el guardian no pudo evaluar, y sin evaluacion no autoriza"],
               "error": str(e)[:200]})
        return 0


if __name__ == "__main__":
    sys.exit(main())
