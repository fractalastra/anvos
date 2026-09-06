# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""axioma_vigente — ata las primitivas que el validador aplica al axioma que las declara.

POR QUE EXISTE (ITA-037, revisor-b 2026-08-05)
-------------------------------------------
El nucleo semantico admite o rechaza cada hecho que entra en la memoria del ecosistema segun cinco
primitivas. Esas cinco viven en un fichero de datos SIN FIRMA. Y existe, aparte, un axioma firmado
que declara exactamente las mismas cinco.

Los dos documentos coinciden hoy —se comprobo una a una la correspondencia— pero nada ata uno al
otro: quien edite el fichero de datos cambia lo que el sistema admite en su memoria sin tocar el
axioma, y quien edite el axioma no cambia nada en absoluto. Un axioma al que nadie obedece es
documentacion, por firmado que este.

QUE HACE
--------
Comprueba dos cosas y las declara por separado, porque son distintas:

  VIGENCIA       el axioma figura en un indice firmado, existe, y ese indice valida
  CORRESPONDENCIA las primitivas que el axioma declara son las mismas que el validador aplica

QUE NO HACE, Y ES DELIBERADO
----------------------------
No sustituye las primitivas operativas por las del axioma. El axioma las nombra en ingles y de forma
descriptiva; el validador las aplica en espanol y de forma operativa. Traducir automaticamente entre
ambos seria inventar una equivalencia que nadie ha declarado, y en un componente que gobierna que
entra en la memoria eso es peor que la desconexion actual.

Lo que hace es SENALAR la divergencia. Si alguien cambia una de las dos caras, se sabra.

POR QUE NO BLOQUEA
------------------
Podria negarse a validar mientras el axioma no este vigente. No lo hace: este componente decide que
entra en la memoria del ecosistema entero, y detenerlo por un desacople documental dejaria al sistema
sin aprender nada. La desproporcion entre la causa y el efecto seria tal que alguien acabaria
desactivando la comprobacion, y entonces no habria ni comprobacion ni memoria.

Informa. Quien lea el informe decide.
"""
import os, re, json, subprocess

# Traduccion declarada A MANO entre como nombra el axioma cada primitiva y como la aplica el
# validador. Se escribe aqui, visible, en lugar de deducirla: una equivalencia entre dos idiomas
# es una decision, no un calculo, y conviene que se vea quien la tomo y cuando.
EQUIVALENCIA = {
    "LIFE": "VIDA",
    "SYSTEM": "SISTEMA",
    "IMPACT": "IMPACTO",
    "REVERSIBILITY": "REVERSIBILIDAD",
    "IRREVERSIBILITY": "IRREVERSIBILIDAD",
}

AXIOMA = "SEMANTIC_PRIMITIVES_2B.md"


def _minisign():
    """Devuelve como invocar minisign aqui, que no es lo mismo en cada equipo.

    En el equipo principal es un programa del sistema. En un nodo soberano su raiz vive en memoria
    y los programas viajan en paquetes autocontenidos: el binario NO arranca solo, hay que llamarlo
    a traves de su enlazador y con sus bibliotecas al lado. Un binario que existe y no arranca da
    exactamente el mismo sintoma que un binario ausente, y este modulo tiene que distinguirlos para
    no declarar «no se puede comprobar» cuando si se puede.
    """
    for c in ("/usr/bin/minisign", "/usr/local/bin/minisign"):
        if os.path.exists(c):
            return [c]
    for d in ("/persist/anvos-staging/pylayer-verify", "/opt/anvos-verify",
              "/persist/anvos-staging/pylayer"):
        b, ld = os.path.join(d, "minisign"), os.path.join(d, "ld-linux-x86-64.so.2")
        if os.path.exists(b) and os.path.exists(ld):
            return [ld, "--library-path", d, b]
        if os.path.exists(b):
            return [b]
    return None


def _firma_valida(fichero, pubs):
    ms = _minisign()
    if not ms:
        return None, "no hay con que comprobar firmas en este equipo"
    for p in pubs:
        try:
            r = subprocess.run(ms + ["-Vm", fichero, "-p", p],
                               capture_output=True, timeout=20)
            if r.returncode == 0:
                return True, os.path.basename(p)
        except Exception:
            pass
    return False, "ninguna clave conocida valida el indice"


def comprobar(dir_axiomas, primitivas_operativas, pubs):
    """Devuelve un informe. Nunca lanza: quien lo llama gobierna la memoria y no debe caerse."""
    inf = {"axioma": AXIOMA, "vigente": False, "correspondencia": False, "avisos": []}
    try:
        indice = os.path.join(dir_axiomas, "MANIFEST.md")
        if not os.path.isfile(indice):
            inf["avisos"].append("no hay indice de axiomas: nada rige, y eso es un estado valido")
            return inf

        ok, quien = _firma_valida(indice, pubs)
        if ok is None:
            inf["avisos"].append(quien)
            return inf
        if not ok:
            # Un indice sin firma valida NO se lee: si se leyera, cualquiera que escribiera en el
            # decidiria que axiomas rigen, y entonces el indice no acreditaria nada.
            inf["avisos"].append("el indice existe pero su firma no valida: no se lee")
            return inf
        inf["indice_firmado_por"] = quien

        texto_indice = open(indice, encoding="utf-8", errors="replace").read()
        if AXIOMA not in texto_indice:
            inf["avisos"].append("el axioma no figura en el indice: no rige")
            return inf

        ruta = os.path.join(dir_axiomas, AXIOMA)
        if not os.path.isfile(ruta):
            inf["avisos"].append("el indice lo declara vigente y el documento NO esta")
            return inf
        inf["vigente"] = True

        texto = open(ruta, encoding="utf-8", errors="replace").read()
        declaradas = re.findall(r"^###\s*\d+\.\s*([A-Z_]+)", texto, re.M)
        traducidas = [EQUIVALENCIA.get(d) for d in declaradas]
        inf["declaradas_en_el_axioma"] = declaradas

        sin_equivalencia = [d for d in declaradas if d not in EQUIVALENCIA]
        if sin_equivalencia:
            inf["avisos"].append(
                "el axioma declara primitivas sin equivalencia escrita: %s" % ", ".join(sin_equivalencia))

        faltan = [t for t in traducidas if t and t not in primitivas_operativas]
        sobran = [p for p in primitivas_operativas if p not in traducidas]
        if faltan:
            inf["avisos"].append("el axioma declara y el validador NO aplica: %s" % ", ".join(faltan))
        if sobran:
            inf["avisos"].append("el validador aplica y el axioma NO declara: %s" % ", ".join(sobran))

        inf["correspondencia"] = not faltan and not sobran and not sin_equivalencia
        return inf
    except Exception as e:
        inf["avisos"].append("no se pudo comprobar: %s" % str(e)[:80])
        return inf


if __name__ == "__main__":
    import sys
    d = sys.argv[1] if len(sys.argv) > 1 else "/persist/anvos-data/axioms"
    pj = sys.argv[2] if len(sys.argv) > 2 else "/persist/anvos-staging/services/semantic_core/data/primitives.json"
    pubs = sys.argv[3:] or ["/persist/anvos-data/.an_service_embedded.pub"]
    ops = [x["name"] for x in json.load(open(pj))["primitives"]]
    print(json.dumps(comprobar(d, ops, pubs), ensure_ascii=False, indent=1))
