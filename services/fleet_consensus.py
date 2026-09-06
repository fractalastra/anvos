#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""fleet_consensus — CONSENSO DE FLOTA (colmena fractal Nivel 2): la confianza en un nodo no depende de
UN solo verificador, sino de un QUÓRUM de pares que lo corroboran de forma independiente. Cierra el hueco
que deja fleet_attest (una sola atalaya): un verificador comprometido podría mentir; el consenso exige que
la MAYORÍA de los demás nodos coincidan en que un sujeto es VÁLIDO antes de que la flota confíe en él.

Cómo: consulta /fleet de cada nodo (que ya contiene el veredicto de ESE nodo sobre sus pares) + /attest
(id del nodo) -> construye la MATRIZ verificador->sujeto->veredicto -> para cada sujeto cuenta cuántos
OTROS nodos lo dan VALIDA -> CONSENSO_VALIDA si alcanza el quórum (mayoría de verificadores disponibles).
Observe/verify-only: NO otorga autoridad; emite el mapa de consenso para que el operador/consenso decida.
Solo stdlib. Fail-safe. "IA propone, humano firma".

Peers: ANV_FLEET_PEERS (URLs coma-separadas) o argumentos; default = origo+nodo-c (LAN). Quórum:
ANV_FLEET_QUORUM (entero) o por defecto mayoría de los verificadores que respondieron sobre cada sujeto.Manifest: fleet_consensus.py|1800|fleet/consensus.jsonl
"""
import os
import sys
import json
import math
import time
import urllib.request

# Direcciones de los pares de flota: SIEMPRE por configuracion (ANVOS_FLEET_PEERS, URLs
# separadas por comas). Sin declaracion no hay pares (fail-closed).
DEFAULT_PEERS = [p.strip() for p in os.environ.get("ANVOS_FLEET_PEERS", "").split(",") if p.strip()]
TIMEOUT = 8
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")


def _malla_enlazada():
    """Ultimo estado de ring_link, leido de su registro. 'desconocido' si no hay registro aun.

    Existe para distinguir dos silencios que NO son lo mismo (ITF-002, 9-ago-2026): en el primer
    ciclo tras arrancar, este servicio preguntaba antes de que ring_link enlazara (~120 s) y el
    rc=2 de 'nadie respondio' quedaba en el latido como averia. Medido: el mismo ciclo a mano,
    con la malla ya enlazada, daba rc=0. Sin malla no hay medicion posible y eso no es un fallo
    del servicio; con malla enlazada y silencio total, si lo es."""
    try:
        with open(os.path.join(DATA, "ring", "ring_link.jsonl")) as f:
            ultimo = None
            for linea in f:
                if linea.strip():
                    ultimo = linea
        return (json.loads(ultimo).get("state") or "desconocido") if ultimo else "desconocido"
    except Exception:
        return "desconocido"

# ─── PRESUPUESTO DE TIEMPO, y por que existe ────────────────────────────────────────────────
# DEFECTO MEDIDO EL 5-ago-2026, y explica 478 asientos rotos. El supervisor de la capa mata a un
# servicio periodico a los 6 SEGUNDOS (linea 75 de anvos-layerd). Este servicio consultaba a tres
# pares, DOS peticiones por par, con 8 s de plazo CADA UNA: medido, tardaba 16 s. O sea que la capa
# lo decapitaba SIEMPRE, a media escritura, y lo que quedaba en su registro era el trozo del bufer
# que alcanzo a salir: lineas sueltas de un array —"nodo-c", "nodo-d"— sin llaves ni veredictos.
#
# El fichero acumulo 478 fragmentos y CERO asientos completos. Y como cada fragmento es JSON valido
# por si solo, una comprobacion de sintaxis lo daba por sano: hizo falta mirar el CONTENIDO.
#
# La regla que se aplica: un servicio debe caber en el plazo que su supervisor le da. No al reves.
PRESUPUESTO_S = 4.0        # margen holgado dentro de los 6 s del supervisor
PLAZO_MINIMO_S = 0.6       # por debajo de esto, preguntar no tiene sentido


def _get_json(url, plazo=None):
    try:
        return json.loads(urllib.request.urlopen(url, timeout=plazo or TIMEOUT).read())
    except Exception:
        return None


def _node_of(base, plazo=None):
    a = _get_json(base + "/attest", plazo)
    return (a or {}).get("node")


def gather(peers):
    """Devuelve (nodos_por_url, matriz, sin_vista). matriz[verificador][sujeto]=veredicto.

    DEFECTO CORREGIDO (revisor-a, 05-ago-2026, ITA-010 reabierto por verificador interno)
    -------------------------------------------------------------------------------
    La version anterior devolvia una fila VACIA tanto cuando un par habia verificado a nadie como
    cuando su vista NO SE PUDO DESCARGAR. Son cosas distintas y el consenso las contaba igual: cero
    votos. Medido hoy sobre la flota real: en frio el veredicto era `origo SIN_VERIFICADORES 0/0`, y
    calentando las vistas con una consulta previa la MISMA orden daba `origo 2/2`. El resultado
    dependia de si la cache del par estaba templada, y nada lo indicaba.

    De ahi que el cierre que yo di el 1-ago —«2/2 en los tres»— no se sostuviera: era una foto con
    las caches calientes. Quien lo reabrio tenia razon, y la tenia por segunda vez.

    Ahora se distingue: `sin_vista` recoge los pares cuya vista no se pudo obtener, y el consenso
    lo DICE en vez de contarlo como ausencia de votos. Un verificador mudo no es un verificador que
    absuelve.
    """
    node_by_url = {}
    matrix = {}
    sin_vista = []
    sin_preguntar = []
    fin = time.monotonic() + PRESUPUESTO_S
    restantes = max(1, len(peers) * 2)
    for base in peers:
        base = base.rstrip("/")
        # El plazo de cada peticion sale de lo que QUEDA de presupuesto, repartido entre las que
        # faltan. Asi un par lento se come lo suyo y no el turno de los demas.
        queda = fin - time.monotonic()
        if queda <= PLAZO_MINIMO_S:
            # Sin tiempo para preguntar. NO es lo mismo que no responder, y se dice aparte:
            # atribuirle silencio a quien no se ha llegado a llamar seria inventar una abstencion.
            sin_preguntar.append(base)
            continue
        plazo = max(PLAZO_MINIMO_S, queda / restantes)
        who = _node_of(base, plazo) or base
        restantes = max(1, restantes - 1)
        node_by_url[base] = who
        queda = fin - time.monotonic()
        plazo = max(PLAZO_MINIMO_S, queda / max(1, restantes))
        fed = _get_json(base + "/fleet", plazo)
        restantes = max(1, restantes - 1)
        if not (fed and isinstance(fed.get("flota"), list)):
            # No se pudo leer su vista. NO se le atribuye una fila vacia: se le aparta y se nombra.
            sin_vista.append(who)
            continue
        row = {}
        for f in fed["flota"]:
            s = f.get("node")
            if s:
                row[s] = f.get("verdict")
        matrix[who] = row
    return node_by_url, matrix, sin_vista, sin_preguntar


def consensus(node_by_url, matrix, quorum=None):
    verifiers = list(matrix.keys())
    # universo de sujetos = todo nodo que aparece como verificador o como sujeto
    subjects = set(verifiers)
    for row in matrix.values():
        subjects.update(row.keys())
    out = {}
    for subj in sorted(subjects):
        votos_validos = 0
        votos_totales = 0
        detalle = {}
        for v in verifiers:
            if v == subj:
                continue                       # un nodo no se vota a sí mismo (no auto-confianza)
            verd = matrix.get(v, {}).get(subj)
            if verd is None:
                continue                       # ese verificador no opinó sobre el sujeto
            votos_totales += 1
            detalle[v] = verd
            if verd == "VALIDA":
                votos_validos += 1
        # quórum: el dado, o mayoría estricta de los que opinaron (al menos 1)
        need = quorum if quorum else (math.floor(votos_totales / 2) + 1 if votos_totales else 1)
        veredicto = "CONSENSO_VALIDA" if (votos_totales > 0 and votos_validos >= need) else (
            "SIN_QUORUM" if votos_totales > 0 else "SIN_VERIFICADORES")
        out[subj] = {"veredicto": veredicto, "votos_validos": votos_validos,
                     "votos_totales": votos_totales, "quorum_requerido": need, "detalle": detalle}
    return out


def main():
    peers = sys.argv[1:] or (os.environ.get("ANV_FLEET_PEERS", "").split(",")
                             if os.environ.get("ANV_FLEET_PEERS") else DEFAULT_PEERS)
    peers = [p.strip() for p in peers if p.strip()]
    q = os.environ.get("ANV_FLEET_QUORUM")
    quorum = int(q) if (q and q.isdigit()) else None
    node_by_url, matrix, sin_vista, sin_preguntar = gather(peers)
    cons = consensus(node_by_url, matrix, quorum)
    n_cons = sum(1 for c in cons.values() if c["veredicto"] == "CONSENSO_VALIDA")

    # El veredicto viaja en el REGISTRO, no en el código de salida. Se declara explícito para que
    # nadie tenga que deducirlo, y en particular se nombra el caso que más engaña: un sujeto puede
    # figurar como CONSENSO_VALIDA sostenido por UN SOLO votante, porque la mayoría exigida se
    # ajusta al número de votantes y la mayoría de uno es uno. Eso no corrobora nada — repite lo
    # que dice el único que pudo mirar — y hasta hoy había que sacarlo leyendo la tabla a mano.
    sin_quorum = [s for s, c in cons.items() if c["veredicto"] != "CONSENSO_VALIDA"]
    un_solo_votante = sorted(s for s, c in cons.items() if c["votos_totales"] == 1)
    # Si nadie respondio, el estado de la malla decide si eso es averia o arranque (ITF-002).
    nadie_respondio = not any(matrix.values())
    enlace = _malla_enlazada() if nadie_respondio else None
    # Los pares MUDOS se nombran aparte. Contarlos como cero votos hacia que un fallo de
    # descarga y una abstencion real fueran indistinguibles, y sobre esa confusion se publico un
    # cierre que no se sostenia.
    print(json.dumps({"svc": "fleet_consensus", "verificadores": list(matrix.keys()),
                      "verificadores_sin_vista": sin_vista,
                      "verificadores_sin_preguntar": sin_preguntar,
                      "aviso_vista": ("hay pares cuya vista NO se pudo leer: sus veredictos NO figuran "
                                      "aqui y su ausencia no equivale a que no verifiquen a nadie"
                                      if sin_vista else None),
                      "nodos_en_consenso": n_cons, "total_sujetos": len(cons),
                      "quorum": quorum or "mayoria-dinamica",
                      "consenso_completo": bool(cons) and n_cons == len(cons),
                      "sujetos_sin_quorum": sin_quorum,
                      "sujetos_con_un_solo_votante": un_solo_votante,
                      "corroboracion_real": sorted(s for s, c in cons.items()
                                                   if c["votos_totales"] >= 2),
                      "estado_malla": enlace,
                      "nota_arranque": ("nadie respondio y ring_link aun no enlaza (%s): sin malla "
                                        "no hay medicion posible, y eso no es averia de este "
                                        "servicio" % enlace
                                        if nadie_respondio and enlace != "LINKED" else None),
                      "consenso": cons},
                     ensure_ascii=False), flush=True)
    # SIN sangria y con volcado inmediato: un .jsonl es UN objeto por linea. Con indent el asiento
    # ocupaba decenas de lineas, y al morir el proceso a mitad quedaban fragmentos que parecian
    # validos. Una linea entera o nada.
    # tabla legible
    # La tabla legible SOLO con --humano. El supervisor lanza cada servicio con stderr fundido en
    # stdout y vuelca EL CONJUNTO al .jsonl, de modo que NO hay canal por el que escribir prosa sin
    # ensuciar el registro. Hasta ahora no se veia porque el proceso moria antes de llegar aqui:
    # arreglar el plazo habria hecho aparecer la tabla dentro del fichero.
    if "--humano" not in sys.argv:
        # rc=2 SOLO cuando el silencio es inexplicable: malla enlazada y nadie contesta.
        # Con la malla sin enlazar (arranque) el silencio es la consecuencia esperada y el
        # servicio HIZO su trabajo: medir que aun no se puede medir (ITF-002, 9-ago-2026).
        if nadie_respondio:
            return 0 if enlace != "LINKED" else 2
        return 0
    print("\n== CONSENSO DE FLOTA (sin master; corroboración cruzada entre pares) ==", file=sys.stderr)
    for subj, c in cons.items():
        print("  %-14s %-18s %d/%d válidos (quórum %d)  votos=%s" % (
            subj, c["veredicto"], c["votos_validos"], c["votos_totales"],
            c["quorum_requerido"], c["detalle"]), file=sys.stderr)
    # ─────────────────────────────────────────────────────────────────────────────────────────
    # DEFECTO MEDIDO Y SUBSANADO (2-ago-2026). Esta línea devolvía 1 cuando NO TODOS los sujetos
    # alcanzaban consenso. Es decir, usaba el código de salida —que el supervisor de la capa lee
    # como «¿funciona este servicio?»— para expresar un VEREDICTO sobre la flota.
    #
    # Efecto medido: el supervisor reportaba `runs=20 ok=0 fail=20`, o sea el servicio roto en
    # todas sus ejecuciones. NO lo estaba: terminaba en menos de un segundo (el límite son 6) y
    # hacía su trabajo perfectamente. Los 20 «fallos» eran 20 informes correctos emitidos mientras
    # dos nodos estaban apagados.
    #
    # Lo grave no es la alarma falsa de hoy, es la simétrica de mañana: desde el supervisor,
    # **«no hay consenso completo» y «el servicio está roto» eran indistinguibles**. El día que
    # este servicio se rompa de verdad, nadie lo mirará — lleva semanas en rojo.
    #
    # REGLA QUE SE APLICA AQUÍ: el código de salida responde a «¿he podido hacer mi trabajo?».
    # El veredicto sobre la flota va en el registro, donde además ahora se declara explícito.
    # ─────────────────────────────────────────────────────────────────────────────────────────
    # OJO con la condición, que ya me equivoqué una vez al escribirla: `matrix` NO está vacía
    # cuando nadie responde. `gather` indexa a todo par consultado, y al que no contesta le pone
    # una FILA VACÍA usando su URL como nombre. Comprobar `if not matrix` daba 0 —«trabajo hecho»—
    # con los tres nodos inalcanzables, que es justo el caso que esta guarda existe para detectar.
    # Lo cazó el control negativo; sin él, el arreglo habría llegado al nodo con el mismo defecto
    # que venía a corregir, solo que al revés.
    if nadie_respondio:
        if enlace != "LINKED":
            print("  [ARRANQUE] nadie respondió y la malla aún no enlaza (%s): sin avería" % enlace,
                  file=sys.stderr)
            return 0
        print("  [FALLO] la malla está enlazada y ningún verificador respondió: no se ha podido "
              "medir nada", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
