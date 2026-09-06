#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""voz_operador — el nodo le CUENTA su estado al operador, y cada frase lleva de dónde sale.

PARA QUÉ, Y CON QUÉ LÍMITE (petición del operador, 2026-08-02)

El nodo ya lo tiene casi todo: se mide, se juzga, se recuerda y tiene pantalla. Lo que no tenía
es **voz**, y sobre todo un **guardián de lo que puede decir**. Tres niveles, y el tercero no se
negocia:

    CONTAR    lee su propio estado y lo explica.                       Sin permiso.
    PROPONER  redacta el acto y lo deja en la cola del operador.       Él firma.
    ACTUAR    nunca. No tiene con qué: en este nodo no reside clave.

CADA AFIRMACIÓN VA CON SU FUENTE Y SU HORA. No es un adorno: hoy mismo el auditor del propio
nodo estuvo minutos publicando «72 de 73» cuando la realidad ya era «73 de 73» — no mentía,
leía su última medición registrada. Una voz que repitiera esa cifra a secas daría **un dato
caducado con voz de certeza**. Con la fuente y la antigüedad al lado, el operador la descarta
solo. Por eso aquí no existe forma de emitir un dato sin decir de qué fichero sale y de cuándo es.

LO QUE NO SABE, LO DICE

Preguntar por algo que el nodo no mide devuelve **NO_LO_SE con la lista de lo que sí tiene**.
Inventar una respuesta plausible es exactamente el modo de fallo que este ecosistema lleva una
semana cazando en sus instrumentos, y sería peor viniendo de algo que habla.

CANAL: primero local, después la malla — y el orden está medido

Se sirve por el cockpit local y por consulta directa en el nodo. La malla queda para después
**porque el cockpit funciona con la malla caída**, que es justo el caso de esta mañana: si la
voz solo viviera en la red, el nodo se habría quedado mudo precisamente cuando tenía algo que
contar.

Solo biblioteca estándar. No firma, no ejecuta, no escribe fuera de la cola y su propio registro.

Manifest: voz_operador.py|900|voz/voz_operador.jsonl
Uso: voz_operador.py estado | voz_operador.py pregunta "<texto>" | voz_operador.py proponer "<acto>" "<motivo>"
"""
import glob
import json
import os
import sys
import time

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
COLA = os.path.join(DATA, "queue", "operator_queue.jsonl")
SALIDA = os.path.join(DATA, "voz", "voz_operador.jsonl")

# Umbral a partir del cual una fuente se considera MUERTA, no solo vieja.
# Cuando quien emitía el dato deja de hacerlo, repetir su último valor sano es peligroso:
# la ausencia de latido se lee como salud. Ver ITB-073-CADENA-AVISO-ROTA.
FUENTE_MUERTA_S = 600

# Cada asunto declara DE DÓNDE sale. Sin fichero declarado no hay dato: no se inventa ninguno.
ASUNTOS = {
    "integridad":  (os.path.join(DATA, "integrity", "self_integrity.jsonl"),
                    lambda d: f"{d.get('verified')}/{d.get('total')} artefactos de la capa "
                              f"verificados, atestación {d.get('attestation')}"
                              + (f", inválidos: {', '.join(d['invalid'])}" if d.get("invalid") else "")),
    "gobernanza":  (os.path.join(DATA, "governance", "cognition_guard.jsonl"),
                    lambda d: f"veredicto {d.get('veredicto') or d.get('verdict')}"),
    "enlace":      (os.path.join(DATA, "ring", "ring_link.jsonl"),
                    lambda d: f"estado {d.get('state')}, {d.get('handshakes_fresh')} saludos "
                              f"frescos de {d.get('peers')} pares"),
    "salud":       (os.path.join(DATA, "sentinel", "core_audit.jsonl"),
                    lambda d: f"estado {d.get('state')}, puntuación "
                              f"{d.get('score', d.get('core_health_score'))}"),
    "servicios":   (os.path.join(DATA, "layerd", "layerd.jsonl"),
                    lambda d: _resumen_servicios(d)),
    "arranque":    (os.path.join(DATA, "boot", "boot.jsonl"),
                    lambda d: (f"arranque nº {d.get('arranque_n')}, id {str(d.get('boot_id'))[:8]}…"
                               + (f"; el anterior fue {str(d.get('boot_id_anterior'))[:8]}…, o sea que se reinició"
                                  if d.get("boot_id_anterior") else "; es el primero anotado")
                               + (f". Al anotarlo el enlace estaba {d['enlace_al_anotar'].get('state')} "
                                  f"con {d['enlace_al_anotar'].get('handshakes_fresh')} saludos de "
                                  f"{d['enlace_al_anotar'].get('peers')} pares"
                                  if d.get("enlace_al_anotar") else ""))),
    "memoria":     (os.path.join(DATA, "memory", "events.head.json"),
                    lambda d: f"cadena de memoria en el asiento {d.get('seq')}"),
    "plataforma":  (os.path.join(DATA, "tpm", "tpm_attest.jsonl"),
                    lambda d: f"lectura {d.get('veredicto', 'DECLARADA')} — es una lectura, "
                              "no una atestación firmada"),
}


def _resumen_servicios(d):
    """Distingue lo que SÉ que está mal de lo que NO SÉ SI está mal.

    Corregido tras ITV-033: el supervisor cuenta como avería el código de salida con que algunos
    servicios expresan un VEREDICTO —«no todos los pares alcanzan consenso» sale como código 1— y
    desde fuera «no hay consenso» y «el servicio está roto» son indistinguibles. Si yo llamara
    «incidencia» a eso, le estaría dando al operador una alarma falsa con mi voz, y el día que ese
    servicio se rompa de verdad ya nadie lo miraría. Así que digo las dos cosas por separado y
    declaro que la segunda es ambigua.
    """
    s = d.get("services", {})
    firma_mala = [k for k, v in s.items()
                  if v.get("sig_ok") is False or v.get("sig_fail", 0) > 0]
    con_fallos = [k for k, v in s.items()
                  if v.get("fail", 0) > 0 and k not in firma_mala]
    txt = f"{len(s)} servicios supervisados"
    if firma_mala:
        txt += f"; CON FIRMA QUE NO VALIDA: {', '.join(firma_mala)} (esto sí es un problema)"
    if con_fallos:
        txt += (f"; con salidas distintas de cero: {', '.join(con_fallos)} — OJO, no puedo "
                "distinguir una avería de un veredicto: hay servicios que usan el código de "
                "salida para decir algo, no para fallar")
    if not firma_mala and not con_fallos:
        txt += ", ninguno con firma mala ni salidas distintas de cero"
    return txt


def _ultima(ruta):
    """Última línea utilizable + su antigüedad. La ausencia se declara, no se rellena."""
    if not os.path.isfile(ruta):
        return None, f"no existe {ruta}", None
    try:
        if ruta.endswith(".json"):
            d = json.load(open(ruta))
        else:
            d = None
            with open(ruta, errors="replace") as f:
                try:
                    f.seek(-min(65536, os.path.getsize(ruta)), os.SEEK_END)
                except OSError:
                    pass
                for linea in reversed(f.read().splitlines()):
                    try:
                        d = json.loads(linea)
                        break
                    except Exception:
                        continue
            if d is None:
                return None, f"{ruta} no tiene ninguna línea legible", None
        ts = d.get("ts")
        edad = int(time.time()) - int(ts) if isinstance(ts, (int, float)) else None
        return d, None, edad
    except Exception as e:
        return None, f"{ruta} ilegible: {e}", None


def _frase(asunto):
    """Devuelve la frase CON su fuente y su antigüedad, o el motivo por el que no la hay.

    Si la fuente lleva demasiado tiempo sin emitir, se trata como MUERTA, no como vieja:
    repetir el último estado sano de un componente que ha dejado de ciclar es un modo de
    fallo silencioso. Ver ITB-073-CADENA-AVISO-ROTA.
    """
    ruta, formato = ASUNTOS[asunto]
    d, motivo, edad = _ultima(ruta)
    if d is None:
        return {"asunto": asunto, "sé": False, "motivo": motivo, "fuente": ruta}
    if edad is not None and edad > FUENTE_MUERTA_S:
        return {"asunto": asunto, "sé": False,
                "motivo": "la fuente no ha emitido en %ds; quien la medía puede haber muerto"
                           % edad,
                "fuente": ruta, "antigüedad_s": edad}
    try:
        texto = formato(d)
    except Exception as e:
        return {"asunto": asunto, "sé": False,
                "motivo": f"el dato existe pero no supe leerlo ({e})", "fuente": ruta}
    return {"asunto": asunto, "sé": True, "dice": texto, "fuente": ruta,
            "antigüedad_s": edad,
            "aviso": ("ESTE DATO TIENE MÁS DE 5 MINUTOS: puede describir un estado que ya pasó"
                      if (edad is not None and edad > 300) else None)}


def cmd_estado():
    partes = [_frase(a) for a in ASUNTOS]
    print(f"— lo que sé de mí, {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
    for p in partes:
        if p["sé"]:
            edad = f"hace {p['antigüedad_s']}s" if p["antigüedad_s"] is not None else "sin hora"
            print(f"  {p['asunto']:12s} {p['dice']}")
            print(f"  {'':12s}   fuente: {p['fuente']}  ({edad})")
            if p["aviso"]:
                print(f"  {'':12s}   ⚠ {p['aviso']}")
        else:
            print(f"  {p['asunto']:12s} NO_LO_SE — {p['motivo']}")
        print()
    _anotar({"orden": "estado", "asuntos": len(partes),
             "sin_dato": [p["asunto"] for p in partes if not p["sé"]]})
    return 0


# SUJETOS QUE NO SOY YO. Si la pregunta va de otra máquina o de otra persona, la respuesta es
# NO_LO_SE aunque aparezca una palabra de mi vocabulario.
#
# ESTO LO AÑADÍ PORQUE FALLÉ LA PRUEBA: preguntado por «cuánta memoria RAM libre le queda al
# portátil del operador», respondí con MI cadena de memoria, porque la palabra «memoria» estaba
# en la frase. Una respuesta plausible sobre otro sujeto es peor que un silencio: el operador no
# tiene forma de notar que le contesté a otra cosa. La prueba de aceptación existe para cazar
# exactamente esto, y me cazó.
SUJETOS_AJENOS = ("portatil", "portátil", "operador", "tu ordenador", "master", "maestro",
                  "movil", "móvil", "telefono", "teléfono",
                  "internet", "nube", "otro nodo", "los demas", "los demás") + tuple(
                  s.strip() for s in os.environ.get("ANVOS_SUJETOS_AJENOS", "").split(",") if s.strip())
# Términos que NO mido, aunque suenen a lo mío. Nombrarlos explícitamente evita que una
# coincidencia parcial los arrastre a un asunto que no es el suyo.
NO_MIDO = ("ram", "memoria libre", "memoria ram", "swap", "temperatura", "bateria", "batería",
           "cpu del", "disco del")


def cmd_pregunta(texto):
    t = (texto or "").lower()

    ajeno = [s for s in SUJETOS_AJENOS if s in t]
    if ajeno:
        print(f"NO_LO_SE — esa pregunta va de «{ajeno[0]}», y yo solo sé de mí mismo. "
              "No tengo forma de medir otra máquina, y responder con un dato mío haría creer "
              "que te he contestado.")
        _anotar({"orden": "pregunta", "texto": texto, "respuesta": "NO_LO_SE",
                 "motivo": "sujeto ajeno: " + ajeno[0]})
        return 2
    nomido = [s for s in NO_MIDO if s in t]
    if nomido:
        print(f"NO_LO_SE — «{nomido[0]}» no es algo que yo mida. Lo que sí mido está abajo, "
              "y prefiero decirte que no antes que darte lo más parecido que tenga.")
        for a, (ruta, _) in ASUNTOS.items():
            print(f"    {a:12s} {ruta}")
        _anotar({"orden": "pregunta", "texto": texto, "respuesta": "NO_LO_SE",
                 "motivo": "termino no medido: " + nomido[0]})
        return 2

    hallados = [a for a in ASUNTOS if a in t]
    # Sinónimos mínimos, para no obligar al operador a usar mi vocabulario. Deliberadamente
    # estrictos: ante la duda, ninguno — y entonces contesto NO_LO_SE, que es la respuesta segura.
    for clave, asunto in (("firma", "integridad"), ("sellad", "integridad"),
                          ("red", "enlace"), ("malla", "enlace"), ("wireguard", "enlace"),
                          ("saludo", "enlace"),
                          ("salud", "salud"), ("puntuac", "salud"),
                          ("servicio", "servicios"), ("capa", "servicios"),
                          ("tpm", "plataforma"), ("gobier", "gobernanza"),
                          ("cadena", "memoria"), ("asiento", "memoria")):
        if clave in t and asunto not in hallados:
            hallados.append(asunto)
    if not hallados:
        print("NO_LO_SE — no mido eso, o no lo he entendido. Lo que sí puedo contar, "
              "y de dónde lo saco:")
        for a, (ruta, _) in ASUNTOS.items():
            print(f"    {a:12s} {ruta}")
        print("\n  Prefiero decir que no lo sé antes que darte algo que suene bien.")
        _anotar({"orden": "pregunta", "texto": texto, "respuesta": "NO_LO_SE"})
        return 2
    for a in hallados:
        p = _frase(a)
        if p["sé"]:
            edad = f"hace {p['antigüedad_s']}s" if p["antigüedad_s"] is not None else "sin hora"
            print(f"  {p['dice']}\n    fuente: {p['fuente']} ({edad})")
            if p["aviso"]:
                print(f"    ⚠ {p['aviso']}")
        else:
            print(f"  NO_LO_SE sobre «{a}» — {p['motivo']}")
    _anotar({"orden": "pregunta", "texto": texto, "asuntos": hallados})
    return 0


def cmd_proponer(acto, motivo):
    """El nodo NO ejecuta. Redacta y deja en la cola. Quien firma es el operador."""
    entrada = {"typ": "PROPUESTA_DEL_NODO", "ts": int(time.time()),
               "origen": "voz_operador", "acto": acto, "motivo": motivo,
               "estado": "PENDIENTE_DE_FIRMA",
               "nota": "propuesta redactada por el nodo; no se ha ejecutado nada y el nodo no "
                       "tiene clave con la que hacerlo"}
    try:
        os.makedirs(os.path.dirname(COLA), exist_ok=True)
        with open(COLA, "a") as f:
            f.write(json.dumps(entrada, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except OSError as e:
        print(f"NO_PROPUESTO: no pude escribir en la cola ({e}) — y lo digo en vez de "
              "callarlo, porque una propuesta que nadie recibe no es una propuesta", file=sys.stderr)
        return 3
    print(f"PROPUESTO (no ejecutado)  «{acto}»")
    print(f"  dejado en {COLA} a la espera de que lo firme el operador.")
    print("  Este nodo no ejecuta actos: no posee clave con la que autorizarlos.")
    _anotar({"orden": "proponer", "acto": acto})
    return 0


def _anotar(rec):
    rec.update({"svc": "voz_operador", "ts": int(time.time())})
    try:
        os.makedirs(os.path.dirname(SALIDA), exist_ok=True)
        with open(SALIDA, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        print(f"[aviso] NO_REGISTRADO en la caja negra ({e}): lo dicho no queda anotado",
              file=sys.stderr)


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("estado", "cycle"):
        return cmd_estado()
    if a[0] == "pregunta":
        return cmd_pregunta(" ".join(a[1:]))
    if a[0] == "proponer" and len(a) >= 3:
        return cmd_proponer(a[1], " ".join(a[2:]))
    if a[0] == "proponer":
        print('uso: voz_operador.py proponer "<acto>" "<motivo>"', file=sys.stderr)
        return 1
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
