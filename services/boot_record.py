#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""boot_record — deja constancia de CADA arranque del nodo, con identidad propia.

POR QUÉ EXISTE (ITA-034, medido el 4/5-ago-2026)
-------------------------------------------------
El nodo no registraba sus arranques en ningún sitio persistente, y eso tenía tres consecuencias
que solo se ven juntas:

  · la voz del nodo declaraba un asunto —«arranque»— cuya fuente **no existía**;
  · **no se podía demostrar que nada sobreviva a un reinicio**, que es justamente la última
    condición pendiente del arreglo del enlace: levantarse CON clave compartida *y aguantar*;
  · y sin marcador de arranque, dos lecturas de tiempo en marcha no distinguen «lleva 10 minutos
    encendido» de «se reinició hace 10 minutos» — que fue lo que llevó a un carril a negar un
    bucle de reinicios que sí existía.

QUÉ NO ERA EL PROBLEMA, porque conviene no arreglar lo que no está roto
------------------------------------------------------------------------
  · **El tiempo en marcha NO miente.** Medido: dos lecturas separadas 10 s dan exactamente 10 de
    diferencia. Es monótono. Lo que confunde es compararlo **entre arranques distintos**.
  · **Ya existía `boot_sanity`**, pero comprueba la línea de mandato del núcleo de forma
    periódica: es una revisión de salud, no un suceso. Y **sin identidad de arranque sus entradas
    son indistinguibles entre sí**, así que no responden «¿cuántas veces has arrancado?».

CÓMO SE IDENTIFICA UN ARRANQUE, y por qué no por la hora
----------------------------------------------------------
Por `boot_id`: un identificador que el núcleo **regenera en cada arranque** y que no depende del
reloj. Es importante que no dependa: este nodo corrige su hora *después* de arrancar, de modo que
fechar los arranques por el reloj produciría exactamente los saltos que ya han engañado a dos
carriles. El `boot_id` no salta.

Idempotente: si el arranque ya está anotado, no escribe. Puede correr cada minuto sin ensuciar.

Solo biblioteca estándar.

Manifest: boot_record.py|300|boot/boot.jsonl
"""
import json
import os
import sys
import time

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
SALIDA = os.path.join(DATA, "boot", "boot.jsonl")
BOOT_ID = "/proc/sys/kernel/random/boot_id"
ENLACE = os.path.join(DATA, "ring", "ring_link.jsonl")


def _boot_id():
    try:
        return open(BOOT_ID).read().strip()
    except Exception:
        return None


def _uptime():
    try:
        return float(open("/proc/uptime").read().split()[0])
    except Exception:
        return None


def _ultimo():
    """Último arranque anotado. Devuelve (registro, cuántos hay)."""
    if not os.path.isfile(SALIDA):
        return None, 0
    ult, n = None, 0
    for l in open(SALIDA, errors="ignore"):
        l = l.strip()
        if not l:
            continue
        try:
            ult = json.loads(l)
            n += 1
        except Exception:
            continue
    return ult, n


def _enlace():
    """Estado del enlace EN ESTE ARRANQUE. Es lo que convierte «arrancó» en «sobrevivió»."""
    if not os.path.isfile(ENLACE):
        return None
    try:
        for l in reversed(open(ENLACE, errors="ignore").readlines()):
            l = l.strip()
            if l.startswith("{"):
                d = json.loads(l)
                return {"state": d.get("state"), "peers": d.get("peers"),
                        "handshakes_fresh": d.get("handshakes_fresh"),
                        "edad_s": int(time.time() - d.get("ts", 0)) if d.get("ts") else None}
    except Exception:
        pass
    return None


def main():
    bid = _boot_id()
    if not bid:
        # Fail-closed: sin identificador no se inventa uno por la hora, porque el reloj de este
        # nodo se corrige después de arrancar y fecharlo así reproduciría el engaño que este
        # servicio viene a cerrar.
        print("SIN_IDENTIFICADOR — el núcleo no expone boot_id; NO se anota nada")
        return 3

    ult, n = _ultimo()
    up = _uptime()

    if ult and ult.get("boot_id") == bid:
        # Mismo arranque: no se reescribe. Se aprovecha para actualizar lo único que cambia y que
        # importa —si el enlace ya habla—, en un registro aparte que no toca el asiento original.
        enl = _enlace()
        # OJO: en el caso "ya anotado" NO se escribe nada en la salida estandar. La capa la vuelca
        # al registro, y repetir un asiento cada 300 s convertiria el historial de arranques en un
        # historial de comprobaciones, que es exactamente el defecto que este servicio vino a
        # corregir en boot_sanity.
        if "--humano" not in sys.argv:
            pass          # bajo el supervisor: silencio absoluto si el arranque ya consta
        else:
            print(f"ARRANQUE YA ANOTADO — es el nº {n} · lleva {int(up or 0)} s en marcha",
                  file=sys.stderr)
            if enl:
                print(f"  enlace en este arranque: {enl.get('state')}, "
                      f"{enl.get('handshakes_fresh')} saludos de {enl.get('peers')} pares",
                      file=sys.stderr)
        return 0

    # OJO CON EL NOMBRE DEL CAMPO: la voz del nodo muestra la antiguedad de cada dato buscando
    # `ts`, y este registro lo llamaba `ts_anotado`. Resultado medido al desplegarlo: la voz
    # contestaba bien pero terminaba con «(sin hora)», rompiendo justo su garantia central —cada
    # frase con su fuente Y SU HORA—, que existe porque un dato caducado con voz de certeza ya
    # engano a un carril durante 95 segundos. Se usa `ts`, como todos los demas servicios.
    reg = {"svc": "boot_record", "ts": int(time.time()), "boot_id": bid,
           "boot_id_anterior": (ult or {}).get("boot_id"),
           "arranque_n": n + 1,
                      "uptime_al_anotar_s": int(up or 0),
           # La hora se anota, pero se DECLARA que puede no ser la del arranque: este nodo ajusta
           # su reloj después de encender. La identidad la da el boot_id, no la fecha.
           "aviso_reloj": "ts es la hora al ANOTAR, no la del arranque; el reloj se ajusta tras encender",
           "enlace_al_anotar": _enlace()}
    # SEGUNDO DEFECTO, cazado por el arnes que imita a la capa y NO por la prueba anterior:
    # este servicio escribia el fichero POR SU CUENTA y ademas imprimia el JSON, que la capa
    # vuelca AL MISMO FICHERO. Resultado: dos asientos por cada arranque.
    #
    # La convencion de la capa es la contraria y esta comprobada en los demas: ni fleet_consensus,
    # ni self_integrity, ni clock_sync escriben su fichero. El servicio IMPRIME y la capa ESCRIBE.
    # Se elimina la escritura propia; el JSON de abajo es el unico asiento.

    # TERCER INTENTO, y los dos anteriores estaban mal. (1) Imprimir la prosa en la salida
    # ESTANDAR ensuciaba el registro. (2) Mandarla a la de ERROR **tampoco sirve**: el supervisor
    # lanza cada servicio con stderr=subprocess.STDOUT —linea 168 de anvos-layerd— y vuelca EL
    # CONJUNTO al .jsonl. No hay canal por el que escribir prosa sin ensuciar.
    #
    # Conclusion: bajo el supervisor un servicio SOLO puede emitir JSON. El texto para personas
    # queda detras de una bandera explicita, apagada por defecto, que el supervisor nunca pasa.
    print(json.dumps(reg, ensure_ascii=False))
    if "--humano" in sys.argv:
        print(f"ARRANQUE ANOTADO — nº {reg['arranque_n']} · id {bid[:8]}…", file=sys.stderr)
        if reg["boot_id_anterior"]:
            print(f"  el anterior era {reg['boot_id_anterior'][:8]}… — o sea que SE REINICIÓ",
                  file=sys.stderr)
        else:
            print("  es el primero que se anota: no hay con qué comparar todavía", file=sys.stderr)
        e = reg["enlace_al_anotar"]
        if e:
            print(f"  enlace tras arrancar: {e.get('state')}, {e.get('handshakes_fresh')} saludos "
                  f"de {e.get('peers')} pares (dato de hace {e.get('edad_s')} s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
