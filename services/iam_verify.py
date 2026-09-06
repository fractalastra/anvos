#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""iam_verify — IAM de DOS NIVELES dentro del nodo. Solo verifica; no concede nada.

Hasta hoy la confianza del nodo era PLANA: una sola clave de publicacion (release.pub) avalaba
todo lo firmado. El ecosistema del master, en cambio, lleva desde mayo una estructura de dos
niveles que el nodo no sabia leer:

    iam_vaultd  (RAIZ, su parte secreta no reside en el nodo)
        └── avala →  vaultd_node  (OPERATIVA, la que firma los tokens del dia a dia)
                         └── firma →  token F-TOKv1

Lo que hace que esto sea una delegacion y no dos claves sueltas es que **el alcance viaja dentro
de la firma**: minisign firma tambien el comentario de confianza, y ahi el master escribe

    AstraNova IAM delegation | scope=iam_token_issue | node=master | service=ejemplo

De modo que una operativa no puede ampliarse el alcance a si misma: tendria que re-firmar el
comentario con la raiz, que no reside aqui ni en ningun nodo. Ese es el valor de portar esto: el
nodo pasa de "confio en quien tenga la clave" a "confio en quien la raiz avalo, y SOLO para lo
que la raiz escribio".

QUE COMPRUEBA, en este orden y sin saltarse ninguno:

  1. ANCLA        existe la publica de la raiz en el nodo. Sin ella no se verifica nada y el
                  veredicto es SIN_ANCLA. Nunca se degrada a "confio en la operativa a secas":
                  una cadena de dos niveles sin su raiz es una cadena de uno.
  2. DELEGACION   cada publica delegada valida contra la RAIZ, y se extrae su scope del
                  comentario firmado. Sin scope legible -> DELEGACION_SIN_ALCANCE.
  3. TOKEN        cada token valida contra la delegada cuyo scope cubre la emision, no contra
                  "alguna" clave. Verificar con la primera que encaje es como no verificar.
  4. VENTANA      nbf <= ahora <= exp, con el skew declarado en el propio token.
  5. POLITICA     audiencia, tipo, canal, roles y ttl contra la politica firmada del nodo.

NO CONCEDE PERMISOS. Emite el dictamen y termina. Un servicio que ademas concediera seria un
plano de control, y un plano de control equivocado abre mas de lo que cierra. La concesion vive
donde debe vivir: en quien consume este dictamen.

Fail-closed en lo que juzga (ante la duda, NO_CONFORME) y fail-safe en lo que ejecuta (cualquier
excepcion se registra y termina en 0: este servicio no puede tumbar la capa ni el arranque).

Solo stdlib + el minisign embebido de la capa.

Manifest: iam_verify.py|900|iam/iam_verify.jsonl
Uso: iam_verify.py [cycle]
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
MS = os.path.join(STAGING, "pylayer-verify")            # minisign embebido + ld + libs
KEYS = os.path.join(STAGING, "pylayer")                 # convencion: binario en verify, claves aqui
RAIZ = os.path.join(KEYS, "iam_vaultd.pub")             # ancla de dos niveles (publica, sin secreto)

IAM = os.environ.get("ANVOS_IAM", "/persist/anvos-iam")
DELEG = os.path.join(IAM, "delegations")
TOKENS = os.path.join(IAM, "tokens")
POLICY = os.path.join(IAM, "policy")
OUT = os.path.join(DATA, "iam", "iam_verify.jsonl")

SCOPE_EMISION = "iam_token_issue"
TIPO_TOKEN = "F-TOKv1"


def _emit(d):
    print(json.dumps(d, ensure_ascii=False), flush=True)
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "a") as f:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL iam_verify._emit: %r" % (e,), file=sys.stderr, flush=True)


def _find_ld():
    for c in glob.glob(os.path.join(MS, "ld-linux*.so.2")):
        return c
    return None


def _verify(ld, target, pub, sig=None):
    """Verifica y DEVUELVE el comentario de confianza, que es donde viaja el alcance.

    self_integrity solo necesita saber si la firma vale; aqui hace falta ademas QUE dice la
    firma, porque el alcance de la delegacion esta dentro del comentario firmado. Por eso se
    captura la salida en vez de mirar solo el codigo de retorno.
    """
    sig = sig or (target + ".minisig")
    if not (ld and os.path.isfile(target) and os.path.isfile(sig) and os.path.isfile(pub)):
        return False, ""
    try:
        r = subprocess.run(
            [ld, "--library-path", MS, os.path.join(MS, "minisign"),
             "-Vm", target, "-p", pub, "-x", sig],
            capture_output=True, timeout=8)
        if r.returncode != 0:
            return False, ""
        txt = (r.stdout or b"").decode("utf-8", "replace") + (r.stderr or b"").decode("utf-8", "replace")
        m = re.search(r"Trusted comment:\s*(.*)", txt)
        return True, (m.group(1).strip() if m else "")
    except Exception:
        return False, ""


def _scopes(comentario):
    """Alcances declarados dentro del comentario FIRMADO. Vacio si no hay ninguno legible."""
    return set(re.findall(r"scope=([A-Za-z0-9_.\-]+)", comentario or ""))


def _delegaciones(ld):
    """Publicas delegadas que la RAIZ avala, con su alcance firmado."""
    out = []
    for pub in sorted(glob.glob(os.path.join(DELEG, "*.pub"))):
        ok, comentario = _verify(ld, pub, RAIZ)
        sc = _scopes(comentario)
        d = {"clave": os.path.basename(pub), "ruta": pub,
             "avalada_por_raiz": ok, "alcances": sorted(sc),
             "comentario": comentario[:160]}
        if not ok:
            d["veredicto"] = "NO_AVALADA"
        elif not sc:
            # Avalada pero sin alcance legible: no se le presume ninguno. Una delegacion sin
            # alcance no es una delegacion universal, es una delegacion incompleta.
            d["veredicto"] = "DELEGACION_SIN_ALCANCE"
        else:
            d["veredicto"] = "AVALADA"
        out.append(d)
    return out


def _politica(ld):
    """Politica del nodo, valida solo si su firma verifica contra la raiz o la de publicacion."""
    for p in sorted(glob.glob(os.path.join(POLICY, "*.json"))):
        for pub in (RAIZ, os.path.join(KEYS, "release.pub")):
            ok, _ = _verify(ld, p, pub)
            if ok:
                try:
                    return json.load(open(p)), os.path.basename(p), os.path.basename(pub)
                except Exception:
                    return None, os.path.basename(p), "ilegible"
    return None, None, None


def _juzga_token(ld, ruta, delegs, pol, ahora):
    r = {"token": os.path.basename(ruta), "hallazgos": []}
    try:
        t = json.load(open(ruta))
    except Exception as e:
        r["veredicto"] = "ILEGIBLE"
        r["hallazgos"].append(str(e)[:60])
        return r

    r["sub"] = t.get("sub")
    r["roles"] = t.get("roles")
    r["typ"] = t.get("typ")

    # 3 · firma contra una delegada CON alcance de emision, no contra cualquiera que encaje
    emisoras = [d for d in delegs if d["veredicto"] == "AVALADA" and SCOPE_EMISION in d["alcances"]]
    firmante = None
    for d in emisoras:
        ok, _ = _verify(ld, ruta, d["ruta"])
        if ok:
            firmante = d["clave"]
            break
    r["firmado_por"] = firmante
    if not firmante:
        r["hallazgos"].append("FIRMA_NO_VALIDA_CON_DELEGADA_DE_EMISION")

    # 4 · ventana temporal, con el margen que declara el propio token
    skew = t.get("skew_sec") or 0
    nbf, exp = t.get("nbf"), t.get("exp")
    if isinstance(nbf, (int, float)) and ahora + skew < nbf:
        r["hallazgos"].append("AUN_NO_VALIDO")
    if isinstance(exp, (int, float)):
        r["caduca_en_s"] = int(exp - ahora)
        if ahora - skew > exp:
            r["hallazgos"].append("CADUCADO")

    # 5 · politica firmada del nodo
    if pol:
        if pol.get("audience") and t.get("aud") != pol["audience"]:
            r["hallazgos"].append("AUDIENCIA_DISTINTA")
        cond = pol.get("conditions") or {}
        if cond.get("token_type") and t.get("typ") != cond["token_type"]:
            r["hallazgos"].append("TIPO_NO_ADMITIDO")
        if cond.get("channel") and t.get("channel") not in cond["channel"]:
            r["hallazgos"].append("CANAL_NO_ADMITIDO")
        subj = pol.get("subjects") or {}
        roles_pol, roles_tok = set(subj.get("roles") or []), set(t.get("roles") or [])
        if roles_pol and not (roles_pol & roles_tok):
            r["hallazgos"].append("ROL_NO_ADMITIDO")
        con = pol.get("constraints") or {}
        if isinstance(nbf, (int, float)) and isinstance(exp, (int, float)):
            ttl = exp - nbf
            if con.get("max_ttl") and ttl > con["max_ttl"]:
                r["hallazgos"].append("TTL_EXCEDE_MAXIMO")
            if con.get("min_ttl") and ttl < con["min_ttl"]:
                r["hallazgos"].append("TTL_BAJO_MINIMO")
        if con.get("require_nonce") and not t.get("nonce"):
            r["hallazgos"].append("SIN_NONCE_EXIGIDO")
    else:
        r["hallazgos"].append("SIN_POLITICA_FIRMADA")

    r["veredicto"] = "VALIDO" if not r["hallazgos"] else "NO_CONFORME"
    return r


def cmd_cycle():
    ahora = int(time.time())
    ld = _find_ld()
    rec = {"svc": "iam_verify", "ts": ahora, "niveles": 2,
           "ancla": os.path.basename(RAIZ)}

    if not ld or not os.path.isfile(RAIZ):
        # Sin ancla de raiz no hay dos niveles. No se degrada a uno: se dice que falta.
        rec.update({"veredicto": "SIN_ANCLA",
                    "detalle": ("no esta la publica de la raiz IAM en el nodo; una cadena de dos "
                                "niveles sin su raiz es una cadena de uno, y eso no se presume"),
                    "verificador": bool(ld)})
        _emit(rec)
        return 0

    delegs = _delegaciones(ld)
    pol, pol_fichero, pol_avalada_por = _politica(ld)
    tokens = [_juzga_token(ld, p, delegs, pol, ahora)
              for p in sorted(glob.glob(os.path.join(TOKENS, "*.json")))]

    avaladas = [d for d in delegs if d["veredicto"] == "AVALADA"]
    emisoras = [d for d in avaladas if SCOPE_EMISION in d["alcances"]]
    validos = [t for t in tokens if t["veredicto"] == "VALIDO"]

    # El veredicto global NO puede decir "valida" mientras un token de dentro esta rechazado.
    #
    # Medido en el laboratorio el 01-ago-2026: con 1 token bueno y 1 caducado, la primera version
    # emitia CADENA_VALIDA y dejaba el "1/2" en otro campo. Quien leyera solo el veredicto —que es
    # lo que hace un tablero— no veria el rechazo. Es el MISMO defecto que se corrigio esta manana
    # en el verificador de pares: un resumen que aplica un criterio distinto al del dato que
    # resume deja de resumir y pasa a ocultar.
    #
    # La cadena y los tokens son cosas distintas y las dos se nombran: la cadena puede estar bien
    # y un token no, y eso tiene su propio veredicto en vez de perderse.
    rechazados = [t for t in tokens if t["veredicto"] != "VALIDO"]
    if not delegs:
        veredicto = "ANCLA_SIN_DELEGACIONES"
    elif not avaladas:
        veredicto = "NO_CONFORME"
    elif tokens and not validos:
        veredicto = "NO_CONFORME"
    elif rechazados:
        veredicto = "CADENA_VALIDA_CON_TOKENS_RECHAZADOS"
    else:
        veredicto = "CADENA_VALIDA"

    rec.update({
        "veredicto": veredicto,
        "delegaciones": delegs,
        "delegaciones_avaladas": len(avaladas),
        "delegaciones_con_emision": len(emisoras),
        "politica": {"fichero": pol_fichero, "avalada_por": pol_avalada_por,
                     "id": (pol or {}).get("policy_id")},
        "tokens": tokens,
        "tokens_validos": "%d/%d" % (len(validos), len(tokens)),
        "nota": ("el alcance viaja DENTRO de la firma de la raiz: una operativa no puede ampliarse "
                 "el suyo sin la raiz, que no reside en ningun nodo. Este servicio dictamina y no "
                 "concede: la concesion vive en quien consume el dictamen")})
    _emit(rec)
    return 0


def main():
    try:
        return cmd_cycle()
    except Exception as e:
        _emit({"svc": "iam_verify", "ts": int(time.time()), "error": str(e)[:200],
               "veredicto": "ERROR_INTERNO"})
        return 0


if __name__ == "__main__":
    sys.exit(main())
