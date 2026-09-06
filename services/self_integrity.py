#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""self_integrity — AUTO-ATESTACIÓN criptográfica de la capa autónoma de ANVOS.
Cada ciclo verifica que la firma minisign de CADA fichero firmado de la capa (activador,
manifiesto y todos los servicios) sigue VÁLIDA contra la clave release. Detección
fail-closed de manipulación: si un fichero fue alterado tras firmarse, su firma no valida.
Single-shot, solo stdlib (subprocess al minisign embebido), defensivo (nunca lanza).
Overridable por entorno ANVOS_STAGING para que la puerta de verificación pueda ejercitarlo."""
import os
import json
import time
import glob
import subprocess

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
MS = os.path.join(STAGING, "pylayer-verify")           # minisign embebido + ld + libs
BAKED_PUB = "/opt/anvos-verify/release.pub"   # ancla real de verificación (653C horneada)
# _release_pubs de F0 ELIMINADO tras el gate de gobernanza (higiene 15-ago): la
# verificación va por la partición A/B (verify_file en _verify). El "hay verificador"
# se ancla a minisign+horneada, no a release.d (que tras la partición son claves Set-A).


def _machine_id():
    try:
        with open('/etc/machine-id') as f:
            return f.read().strip() or 'unknown'
    except OSError:
        return 'unknown'


def _find_ld():
    for c in glob.glob(os.path.join(MS, "ld-linux*.so.2")):
        return c
    return None


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


def _verify(ld, target, sig):
    """Verifica firma bajo la PARTICIÓN A/B: un fichero de gobernanza (Set B) solo cuenta
    como SEALED si va firmado por la 653C horneada; los rutinarios (Set A) por release.d.
    Así un self_integrity/cognition_guard re-firmado por origo se reporta TAMPER."""
    return _ap().verify_file(target, sig)


# --- AMBITO EXTENDIDO (2026-07-28): artefactos firmados FUERA de la capa -------------------
# self_integrity/SEALED describe la CAPA y no debe cambiar de semantica. Pero habia artefactos
# firmados que NADIE vigilaba periodicamente: /persist/anvos-tools/*.py (que la capa EJECUTA) y
# astra-code/bin/* (el toolkit del codegen soberano). Se verifican aparte, con contadores propios.
AMBITO_EXTRA = ("/persist/anvos-tools/*.py", "/persist/anvos-data/astra-code/bin/*")


def scan_extra(verify):
    total = ok = 0
    malos = []
    for patron in AMBITO_EXTRA:
        for p in sorted(glob.glob(patron)):
            # P1 PQC: los sidecars .mldsa (firma ML-DSA aditiva) NO son artefactos a verificar por
            # Ed25519; sin excluirlos, uno sin su propio .minisig contaria como no-firmado -> falso TAMPER.
            if p.endswith((".minisig", ".mldsa")) or os.path.isdir(p):
                continue
            total += 1
            if os.path.isfile(p + ".minisig") and verify(p):
                ok += 1
            else:
                malos.append(os.path.basename(p))
    return total, ok, malos


def main():
    ld = _find_ld()
    # "hay verificador" = ld + minisign + la clave ANCLA (horneada). NO release.d (esas son
    # claves Set-A tras la partición; su ausencia no significa "sin verificador").
    verifier_ok = bool(ld) and os.path.exists(os.path.join(MS, "minisign")) and os.path.isfile(BAKED_PUB)
    if not verifier_ok:
        # sin verificador disponible (p.ej. en la puerta del master): reportar, NO es error
        print(json.dumps({"svc": "self_integrity", "ts": int(time.time()),
                          "node": _machine_id(), "verifier_ok": False,
                          "note": "verificador embebido no disponible en este entorno"},
                         ensure_ascii=False))
        return

    # ficheros firmados de la capa: activador, manifiesto y servicios
    #
    # DOS DEFECTOS CORREGIDOS AQUI (ITV-071, medidos el 2026-08-07)
    # --------------------------------------------------------------
    # 1) EL RECORRIDO ERA PLANO. `glob(services/*.py)` no ve los subdirectorios, y el arbol
    #    semantic_core vive precisamente en uno. Medido: la capa tenia 81 ficheros .py y este
    #    servicio contaba 77.
    #
    # 2) Y PEOR: un fichero SIN firma no se marcaba invalido, se SALTABA. La condicion exigia que
    #    existiera el .minisig para siquiera mirarlo, de modo que lo no firmado no entraba en la
    #    cuenta ni en la lista de invalidos. El resultado era una atestacion que declaraba
    #    "SEALED, 77 de 77, todas validas" mientras habia un .py sin firma dentro de la capa.
    #    No mentia en lo que decia: mentia en lo que callaba.
    #
    #    Es el MISMO patron que ya se hallo en el verificador de restauracion (ITB-024, encontrado
    #    por otro carril): saltarse lo no firmado en vez de marcarlo. Que aparezca dos veces en dos
    #    componentes distintos indica que el reflejo natural al escribir estos bucles es "si no
    #    tiene firma, no me toca" — y es justo al reves: si no tiene firma, es lo que mas importa.
    #
    # Un fichero sin firma es ahora SIN_FIRMA y cuenta como no valido, que es lo que es: dentro de
    # una capa que se declara sellada, la ausencia de firma no es un vacio, es un hallazgo.
    def _py_de_la_capa():
        base = os.path.join(STAGING, "services")
        salida = []
        for raiz, _dirs, ficheros in os.walk(base):
            if "__pycache__" in raiz:
                continue
            for n in sorted(ficheros):
                if n.endswith(".py"):
                    salida.append(os.path.join(raiz, n))
        return sorted(salida)

    candidatos = ([os.path.join(STAGING, "anvos-activate.sh"),
                   os.path.join(STAGING, "services", "manifest.txt")]
                  + _py_de_la_capa())

    targets, sin_firma = [], []
    for path in candidatos:
        if not os.path.isfile(path):
            continue
        if os.path.isfile(path + ".minisig"):
            targets.append(path)
        else:
            sin_firma.append(os.path.relpath(path, STAGING))

    verified, invalid = 0, []
    for t in targets:
        if _verify(ld, t, t + ".minisig"):
            verified += 1
        else:
            invalid.append(os.path.relpath(t, STAGING))
    # Lo no firmado se suma a lo no valido: si se dejara aparte, un lector que mire "invalid" o
    # "all_valid" seguiria sin enterarse, que es exactamente el fallo que esto corrige.
    invalid += ["%s [SIN FIRMA]" % p for p in sin_firma]

    rec = {
        "svc": "self_integrity",
        "ts": int(time.time()),
        "node": _machine_id(),
        "verifier_ok": True,
        # El denominador es lo que DEBERIA estar firmado, no solo lo que lo esta: con el
        # anterior, un fichero sin firma desaparecia tambien del total y la razon salia
        # "77 de 77" en vez de "77 de 81". Un cociente que se ajusta a si mismo no informa.
        "total": len(targets) + len(sin_firma),
        "sin_firma": sin_firma,
        "verified": verified,
        "invalid": invalid,
        "all_valid": len(invalid) == 0 and len(targets) > 0,
        "attestation": "SEALED" if (len(invalid) == 0 and targets) else "TAMPER",
    }
    # ambito extendido: NO altera total/verified/attestation (la semantica de SEALED = la CAPA)
    try:
        e_tot, e_ok, e_malos = scan_extra(lambda p: _verify(ld, p, p + ".minisig"))
        if e_tot:
            rec["extra_total"] = e_tot
            rec["extra_verified"] = e_ok
            rec["extra_sin_firma_o_invalidos"] = e_malos
            rec["extra_ok"] = not e_malos
    except Exception as _e:
        rec["extra_error"] = str(_e)[:80]
    print(json.dumps(rec, ensure_ascii=False))



if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # nunca romper el supervisor
        print(json.dumps({"svc": "self_integrity", "ts": int(time.time()),
                          "error": str(e)}, ensure_ascii=False))
