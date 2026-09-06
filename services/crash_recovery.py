#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""crash_recovery — AUTO-CURADO de estado tras APAGADO SUCIO (resiliencia de la OS, matriz item1).

Lección power-cycle 2026-07-19: un corte de corriente a mitad de escritura deja BYTES NUL en los
ficheros append-only (ext4 delayed-alloc actualiza el tamaño del inodo pero no vuelca el bloque ->
ceros al recuperar). No se puede fsync-endurecer cada writer del ecosistema; en su lugar, al
ARRANCAR el nodo repara TODO su estado append-only de forma genérica y segura:

  - CHAINED (events.jsonl + su head.json): valida la cadena hash desde génesis, trunca en la 1.a
    corrupción y reconcilia el head (misma lógica que event_ledger._heal_ledger, aquí para el ancla).
  - JSONL / CHAIN append-only: cae a la línea VÁLIDA más larga (descarta líneas con NUL o no-JSON
    a partir de la 1.a corrupta — perder la cola de un log tras un corte es aceptable; el prefijo
    sano se conserva). Reescritura ATÓMICA (tmp + fsync + rename).

MEMORIA ACOTADA (ITV-063, 2026-08-07): la versión anterior leía CADA fichero ENTERO en memoria
(f.read() + decode ≈ 2-3x el tamaño). Con un log de 490 MB eso son >1,2 GB y en nodo-c (VM de 2 GB)
el kernel mataba el proceso por OOM en TODAS las pasadas: 638 de 639 fallos medidos, y también a
mano (rc=137, 'Killed'). Esta versión no carga ficheros enteros:

  - los ficheros con escritor ACTIVO (mtime reciente) NO se leen: curarlos ya estaba vetado por la
    quiescencia, así que leerlos solo costaba memoria. Se cuentan y se reportan, no se ocultan.
  - camino RÁPIDO por fichero: barrido de NUL por bloques (velocidad C) + validez JSON de la última
    línea. La corrupción de un corte son bloques NUL o una cola rota: ambos se ven ahí. Una línea
    no-JSON sin NUL en mitad del fichero no la ve este camino (la anterior sí la veía); es el precio
    de que el barrido de arranque quepa en el MAX_RUNTIME de layerd, y queda dicho aquí y en el
    registro (escaneo_rapido/escaneo_profundo).
  - pasada PROFUNDA en streaming (línea a línea, memoria por línea) solo para lo que el camino
    rápido señala, y curado también en streaming.

Solo cura lo CORRUPTO (idempotente/no-op sobre ficheros sanos). OBSERVE por defecto (reporta lo que
haría); con --apply repara. Fail-safe: cada fichero se cura aislado; un error no arrastra a los demás.
Solo stdlib. Pensado para correr TEMPRANO en el arranque (antes de que los servicios lean su estado)."""
import os
import sys
import json
import time
import glob

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
RING = os.environ.get("ANVOS_RING", "/persist/anvos-ring")
GENESIS = "0" * 64
QUIESCE_S = int(os.environ.get("ANVOS_CR_QUIESCE", "60"))  # no curar ficheros escritos hace <N s
                                                          # (evita carrera con un writer activo)
REC = os.path.join(DATA, "recovery", "crash_recovery.jsonl")
# raíces a barrer: todo el estado vivo del nodo. Los .bak/.corrupt_bak se excluyen.
ROOTS = [DATA, RING]
EXTS = (".jsonl", ".json", ".chain")
SKIP_SUBSTR = (".bak", ".corrupt", ".tmp", ".heal.")
CHUNK = 1 << 20
BIG_JSON = 32 * 1024 * 1024   # un .json ÚNICO mayor que esto no se parsea: se reporta, no se calla


def _valida_linea(raw):
    """¿Es <raw> (bytes, una línea) JSON sano? None = vacía (no cuenta)."""
    if not raw.strip():
        return None
    if b"\x00" in raw:
        return False
    try:
        json.loads(raw.decode("utf-8", "replace"))
        return True
    except Exception:
        return False


def _tiene_nul(path):
    """Barrido de NUL por bloques: memoria y tiempo acotados aunque el fichero sea enorme."""
    with open(path, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                return False
            if b"\x00" in b:
                return True


def _ultima_linea(path):
    """Última línea no vacía leyendo solo la cola del fichero. None si está vacío."""
    size = os.path.getsize(path)
    if size == 0:
        return None
    with open(path, "rb") as f:
        f.seek(max(0, size - CHUNK))
        tail = f.read()
    lineas = [l for l in tail.split(b"\n") if l.strip()]
    return lineas[-1] if lineas else None


def _is_chained(path, valid_lines):
    """¿Es un ledger HASH-ENCADENADO (donde una ruptura invalida todo lo posterior) o un LOG
    append-only (líneas independientes)? Encadenado = .chain, events.jsonl, o líneas con prev_hash."""
    if path.endswith(".chain") or os.path.basename(path) in ("events.jsonl", "promotion.chain"):
        return True
    for ln in valid_lines[:5]:
        try:
            if "prev_hash" in json.loads(ln):
                return True
        except Exception:
            pass
    return False


def _escaneo_profundo(path):
    """Streaming línea a línea. Devuelve (total, validas, idx_primera_mala, primeras5_validas,
    es_jsonl).

    es_jsonl decide si el fichero se puede CURAR: la corrupción de un corte son bloques NUL o una
    cola rota, así que en un JSONL de verdad toda línea inválida que no sea la ÚLTIMA lleva NUL.
    Medido en nodo-c (2026-08-07) por qué esto no puede suponerse de la extensión: fleet/anchor.jsonl
    es un informe con cabecera y JSON multilínea, y varlog/*.chain son cadenas de rotación en texto
    (seg=… sha=… prev=…) — CERO líneas JSON y CERO corrupción. La versión anterior los habría
    vaciado al 'curarlos'. Lo que no demuestra ser JSONL no se toca."""
    total = buenas = 0
    primera_mala = None
    primeras5 = []
    invalidas_sin_nul = 0
    ultima_invalida_sin_nul = False
    with open(path, "rb") as f:
        for raw in f:
            v = _valida_linea(raw)
            if v is None:
                continue
            total += 1
            if v:
                buenas += 1
                ultima_invalida_sin_nul = False
                if len(primeras5) < 5:
                    primeras5.append(raw.decode("utf-8", "replace").rstrip("\n"))
            else:
                if primera_mala is None:
                    primera_mala = total - 1
                sin_nul = b"\x00" not in raw
                invalidas_sin_nul += 1 if sin_nul else 0
                ultima_invalida_sin_nul = sin_nul
    # la única línea inválida SIN NUL admisible es la final (cola rota a medio escribir)
    es_jsonl = invalidas_sin_nul == (1 if ultima_invalida_sin_nul else 0)
    return total, buenas, primera_mala, primeras5, es_jsonl


def _curar_stream(path, chained):
    """Reescribe conservando solo líneas sanas, en streaming y de forma atómica.
    CHAINED: prefijo hasta la 1.a corrupta (una ruptura invalida la cadena). LOG: descarta solo
    las corruptas y conserva TODAS las válidas. Devuelve las líneas escritas."""
    tmp = path + ".crashfix.%d.tmp" % os.getpid()
    escritas = 0
    with open(path, "rb") as src, open(tmp, "wb") as dst:
        for raw in src:
            v = _valida_linea(raw)
            if v is None:
                continue
            if v:
                dst.write(raw.rstrip(b"\r\n") + b"\n")
                escritas += 1
            elif chained:
                break
        dst.flush()
        os.fsync(dst.fileno())
    os.replace(tmp, path)
    return escritas


def _heal_json(raw):
    """Fichero JSON único (p.ej. *.head.json): válido si parsea entero; si no, es irreparable
    aquí (lo reconstruye su productor)."""
    text = raw.decode("utf-8", "replace")
    if "\x00" not in text:
        try:
            json.loads(text)
            return True   # sano
        except Exception:
            return False
    return False


def _scan_json_unico(path):
    """*.json (no ledger de líneas). Son pequeños; si uno no lo es, se dice en vez de tragárselo."""
    try:
        if os.path.getsize(path) > BIG_JSON:
            return {"path": path, "state": "JSON_GRANDE_NO_PARSEADO",
                    "bytes": os.path.getsize(path), "action": None}
        with open(path, "rb") as f:
            raw = f.read()
    except Exception:
        return None
    if path.endswith(".head.json"):
        ok = _heal_json(raw)
        return {"path": path, "state": "OK" if ok else "CORRUPTO",
                "action": None if ok else "reconciliar-head"}
    if b"\x00" in raw:
        return {"path": path, "state": "CORRUPTO_NUL", "action": "regenera-productor"}
    try:
        json.loads(raw.decode("utf-8", "replace"))
        return {"path": path, "state": "OK"}
    except Exception:
        return {"path": path, "state": "JSON_ROTO", "action": "regenera-productor"}


def main():
    # bajo layerd (sin args) CURA por defecto (auto-reparación autónoma; seguro: solo ficheros
    # corruptos Y quiescentes, reescritura atómica). ANVOS_CR_OBSERVE=1 o --observe = solo reporta.
    apply = not (os.environ.get("ANVOS_CR_OBSERVE") or "--observe" in sys.argv)
    now = int(time.time())
    files = []
    for root in ROOTS:
        for ext in EXTS:
            files += glob.glob(os.path.join(root, "**", "*" + ext), recursive=True)
    files = sorted(set(f for f in files if not any(s in f for s in SKIP_SUBSTR)))
    # NUNCA tocar ficheros FIRMADOS (con hermano .minisig): reescribirlos —aunque sea para
    # 'curar'— invalida su firma de release y los servicios fail-closed que la verifican los rechazan
    # (lección auditoría 2026-07-20: rompió ring_link_peers.json -> malla caída). El .minisig es
    # la fuente de verdad; un firmado corrupto lo re-despliega el master, no crash_recovery.
    files = [f for f in files if not os.path.exists(f + ".minisig")]

    healed, corrupt = [], []
    ok = rapidos = profundos = 0
    activos, otros_formatos = [], []
    for path in files:
        # quiescencia ANTES de leer: un fichero con writer activo no se puede curar (carrera) y
        # leerlo solo cuesta memoria/tiempo — en el arranque, que es cuando este servicio importa,
        # todo está quiescente y se escanea completo.
        try:
            mtime = os.path.getmtime(path)
        except Exception:
            continue
        if now - mtime < QUIESCE_S:
            activos.append(path)
            continue

        if path.endswith(".json") and not path.endswith(".head.json"):
            r = _scan_json_unico(path)
        elif path.endswith(".head.json"):
            r = _scan_json_unico(path)
        else:
            # ledgers de líneas (.jsonl, .chain): camino rápido, y profundo solo si hay señal
            try:
                nul = _tiene_nul(path)
                ult = _ultima_linea(path)
            except Exception:
                continue
            rapidos += 1
            if not nul and (ult is None or _valida_linea(ult)):
                r = {"path": path, "state": "OK"}
            else:
                profundos += 1
                total, buenas, primera_mala, primeras5, es_jsonl = _escaneo_profundo(path)
                if not es_jsonl:
                    # otro formato legítimo bajo la misma extensión: NO se cura. Si además trae
                    # NUL sí es corrupción, pero de un formato que aquí no se sabe reconstruir.
                    if nul:
                        r = {"path": path, "state": "CORRUPTO_NUL", "formato": "no-jsonl",
                             "action": "regenera-productor"}
                    else:
                        otros_formatos.append(path)
                        r = {"path": path, "state": "OK_OTRO_FORMATO", "_no_contar": True}
                else:
                    chained = _is_chained(path, primeras5)
                    conservar = ((primera_mala if primera_mala is not None else total)
                                 if chained else buenas)
                    if conservar == total:
                        r = {"path": path, "state": "OK"}
                    else:
                        r = {"path": path, "state": "CORRUPTO_NUL" if nul else "CORRUPTO",
                             "action": "truncar-a-sano", "lineas": total, "sanas": conservar,
                             "descartadas": total - conservar, "_chained": chained}
        if r is None:
            continue
        if r.get("_no_contar"):
            continue
        if r["state"] == "OK":
            ok += 1
            continue
        det = {k: v for k, v in r.items() if not k.startswith("_")}
        if apply and r.get("action") == "truncar-a-sano":
            # re-comprobar la quiescencia justo antes de reescribir (entre el escaneo y el curado
            # puede haber despertado un writer)
            try:
                quiet = (int(time.time()) - os.path.getmtime(path)) >= QUIESCE_S
            except Exception:
                quiet = True
            if quiet:
                try:
                    _curar_stream(path, r.get("_chained", False))
                    det["healed"] = True
                    healed.append(r["path"])
                except Exception as e:
                    det["heal_error"] = str(e)[:80]
            else:
                det["diferido"] = "writer activo (mtime<%ds)" % QUIESCE_S
        corrupt.append(det)

    rec = {"svc": "crash_recovery", "ts": now, "observe_only": not apply,
           "escaneados": len(files) - len(activos), "sanos": ok, "corruptos": len(corrupt),
           "curados": len(healed), "omitidos_activos": len(activos),
           "escaneo_rapido": rapidos, "escaneo_profundo": profundos,
           "otros_formatos": len(otros_formatos), "otros_formatos_rutas": otros_formatos[:10],
           "detalle": corrupt[:20],
           "verdict": ("CURADO" if healed else ("CORRUPCION_DETECTADA" if corrupt else "SIN_CORRUPCION"))}
    try:
        os.makedirs(os.path.dirname(REC), exist_ok=True)
        with open(REC, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass
    print(json.dumps(rec, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
