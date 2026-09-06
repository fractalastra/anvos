#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""node_health_beacon — baliza de salud del nodo para la capa autónoma de ANVOS.
Ejecución single-shot (se ejecuta una vez, imprime UNA línea JSON y termina). El
activador la invoca en bucle con intervalo, así que aquí NO hay bucles propios.
Solo stdlib, sin red, defensivo: cada lectura devuelve None si falla en vez de romper.
Métricas: carga de CPU, % memoria usada, % disco usado, identidad del nodo y marca de tiempo."""
import os
import json
import time


def carga_cpu():
    """Carga media del sistema a 1 min (getloadavg). None si el SO no la expone."""
    try:
        return os.getloadavg()[0]
    except OSError:
        return None


def porcentaje_memoria():
    """% de memoria usada leyendo /proc/meminfo: (total - libre) / total * 100."""
    try:
        with open('/proc/meminfo', 'r') as f:
            meminfo = f.read()
        memoria_total = int(meminfo.split('MemTotal:')[1].split()[0])
        # v3: MemFree cuenta la cache de paginas como 'usada' — en origo dio 74%
        # con 25.6G realmente disponibles (llama-server mapea el modelo y la cache crece).
        # MemAvailable es lo que el kernel declara disponible (cache reclamable descontada).
        # Formula de la propuesta MEMAVAIL de ITB-079 (21-ago), fusionada aqui con el fix de
        # disco v2 vigente. MemFree queda como respaldo para kernels sin el campo (pre-3.14).
        if 'MemAvailable:' in meminfo:
            memoria_libre = int(meminfo.split('MemAvailable:')[1].split()[0])
        else:
            memoria_libre = int(meminfo.split('MemFree:')[1].split()[0])
        return (memoria_total - memoria_libre) / memoria_total * 100
    except (FileNotFoundError, ValueError, IndexError):
        return None


def porcentaje_disco():
    """% de disco usado en el ALMACENAMIENTO REAL del nodo (donde crecen ledgers/beacon/chain/
    alertas), NO en el raíz EFÍMERO de arranque ('/'). Devuelve (pct_o_None, ruta_medida, degradado).
    Resolución:
      1) ANVOS_DISK_PATH del entorno -> se HONRA tal cual (elección deliberada del operador).
      2) el filesystem que contiene ANVOS_DATA (default /persist/anvos-data), SOLO si es una
         PARTICIÓN DISTINTA del raíz (st_dev != st_dev de '/'). Si /persist es solo un directorio
         del root (p.ej. en el master), medirlo = medir el root efímero -> NO cuenta como almacén real
         (matiz de revisor-a: seria el mismo bug que arreglamos, en pequeño).
      3) '/persist' con el mismo criterio de partición-distinta.
      4) '/' como último recurso, MARCADO degradado (no engañar con el % del root efímero).
    El llamador NO debe fiarse del pct si degradado=True: no es el disco de datos."""
    try:
        root_dev = os.stat('/').st_dev
    except OSError:
        root_dev = None

    def _medir(ruta):
        st = os.statvfs(ruta)
        total = st.f_blocks * st.f_frsize
        if total <= 0:
            raise OSError("statvfs total<=0")
        libre = st.f_bfree * st.f_frsize
        return (total - libre) / total * 100

    # 1) override explícito: la ruta que el operador eligió, se honra
    _env = os.environ.get("ANVOS_DISK_PATH")
    if _env:
        try:
            return _medir(_env), _env, False
        except OSError:
            pass
    # 2/3) auto-derivados: válidos SOLO si son partición distinta del raíz
    for ruta in (os.environ.get("ANVOS_DATA", "/persist/anvos-data"), "/persist"):
        try:
            if root_dev is not None and os.stat(ruta).st_dev == root_dev:
                continue  # misma partición que '/': no es un almacén de datos distinto
            return _medir(ruta), ruta, False
        except OSError:
            continue
    # 4) último recurso: el raíz efímero -> DEGRADADO
    try:
        return _medir('/'), '/', True
    except OSError:
        return None, None, True

def identidad_nodo():
    """Identificador del nodo desde /etc/machine-id; 'unknown' si no existe."""
    for _p in ("/persist/anvos-node.id", "/etc/anvos-node.id"):
        try:
            _v = open(_p).read().strip()
            if _v:
                return _v
        except Exception:
            pass
    try:
        with open('/etc/machine-id', 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        return 'unknown'


def marca_tiempo():
    """Marca de tiempo epoch en segundos (entero)."""
    return int(time.time())


def main():
    _disk_pct, _disk_path, _disk_degradado = porcentaje_disco()
    # 'or 0' mantiene el contrato numérico del ledger (evita null en métricas); disk_degraded avisa
    # cuando ese número es el root efímero y NO el almacenamiento real (punto 3 del diseño).
    registro = {
        "cpu_load": carga_cpu() or 0,
        "mem_pct": porcentaje_memoria() or 0,
        "disk_pct": _disk_pct if _disk_pct is not None else 0,
        "disk_path": _disk_path,            # dónde se midió (transparencia; medir '/' era el bug)
        "disk_degraded": _disk_degradado,   # True -> disk_pct es el root efímero, no el disco de datos
        "node": identidad_nodo(),
        "ts": marca_tiempo(),
    }
    print(json.dumps(registro, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except Exception as e:  # nunca romper el supervisor del activador
        print(json.dumps({"svc": "node_health_beacon", "ts": int(time.time()),
                          "error": str(e)}, ensure_ascii=False))
