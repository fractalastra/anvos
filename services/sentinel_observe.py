#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""sentinel_observe — agente inmune OBSERVE-ONLY para la capa autónoma de ANVOS.
Ejecución single-shot: escanea el estado del nodo y emite UNA línea JSON con hallazgos.
Sin red, solo stdlib, defensivo (nunca lanza). No actúa: solo observa y reporta (diodo de evidencia)."""
import os, json, time, hashlib

def _machine_id():
    try:
        with open('/etc/machine-id') as f:
            return f.read().strip() or 'unknown'
    except OSError:
        return 'unknown'

def _count_procs():
    try:
        return sum(1 for d in os.listdir('/proc') if d.isdigit())
    except OSError:
        return -1

def _count_mounts():
    try:
        with open('/proc/mounts') as f:
            return sum(1 for _ in f)
    except OSError:
        return -1

def _sha256_file(p):
    try:
        h = hashlib.sha256()
        with open(p, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None

def _uptime():
    try:
        with open('/proc/uptime') as f:
            return float(f.read().split()[0])
    except (OSError, ValueError):
        return None

def _listening_ports():
    """Puertos TCP a la escucha (LISTEN=0A) de /proc/net/tcp[6]. Sin red, solo lectura."""
    ports = set()
    for proc in ('/proc/net/tcp', '/proc/net/tcp6'):
        try:
            with open(proc) as f:
                next(f, None)  # cabecera
                for line in f:
                    parts = line.split()
                    if len(parts) > 3 and parts[3] == '0A':  # 0A = TCP_LISTEN
                        try:
                            ports.add(int(parts[1].split(':')[1], 16))
                        except (ValueError, IndexError):
                            pass
        except OSError:
            pass
    return ports

def _disk_pct(path):
    """% de disco usado en path (statvfs)."""
    try:
        s = os.statvfs(path)
        tot = s.f_blocks * s.f_frsize
        return round((tot - s.f_bfree * s.f_frsize) / tot * 100, 1) if tot else None
    except OSError:
        return None

def main():
    findings = []
    # 1) ¿capa activa? (wrapper presente = leucocito 'self' sano)
    layer_active = os.path.exists('/usr/bin/anvos-python3')
    if not layer_active:
        findings.append({"sev": "warn", "code": "LAYER_ABSENT",
                         "msg": "wrapper anvos-python3 ausente"})
    # 2) integridad del activador (el guardián de la puerta)
    act = '/persist/anvos-staging/anvos-activate.sh'
    act_sha = _sha256_file(act)
    # 3) carga de procesos: umbral heurístico observe-only
    procs = _count_procs()
    if procs > 400:
        findings.append({"sev": "watch", "code": "PROC_HIGH", "msg": f"{procs} procesos"})
    # 4) montajes: un salto brusco puede indicar montaje no previsto
    mounts = _count_mounts()
    # 5) ¿el beacon está produciendo datos? (señal de vida de otro servicio)
    beacon = os.path.join(os.environ.get('ANVOS_DATA', '/persist/anvos-data'),
                          'eco-telem/beacon.jsonl')
    beacon_fresh = False
    try:
        st = os.stat(beacon)
        beacon_fresh = (time.time() - st.st_mtime) < 300  # <5min = fresco
        if not beacon_fresh:
            findings.append({"sev": "watch", "code": "BEACON_STALE",
                             "msg": "beacon sin datos recientes (>5min)"})
    except OSError:
        findings.append({"sev": "watch", "code": "BEACON_MISSING",
                         "msg": "beacon.jsonl inexistente"})
    # 6) puertos a la escucha: solo :22 (dropbear) es esperado; el resto = anomalía
    ports = sorted(_listening_ports())
    # 22=ssh, 8088=status_server, 8090=llama-server (IA local), 51821=ring; 2323/8081/5555/9200=cebos honeypot (abren a proposito)
    # 7790=mod_sensor, 7793=mod_edu_identity: modulos de la capa desplegados DESPUES de escribirse esta
    # lista. Se anaden el 2026-08-01 (revisor-b) tras comprobar que los sirven procesos de la capa firmada.
    #
    # La lista se mantiene EXPLICITA a proposito. Derivarla de los servicios que esten corriendo seria
    # comodo y la volveria inutil: cualquier proceso que abriera un puerto se autorizaria a si mismo, y
    # un control que aprueba todo lo que encuentra no distingue un modulo nuevo de un intruso. El precio
    # es que hay que actualizarla al desplegar, y ese es exactamente el aviso que este codigo debe dar.
    ESPERADOS = {22, 8088, 8090, 51821, 2323, 8081, 5555, 9200, 7790, 7793}
    inesperados = [p for p in ports if p not in ESPERADOS]
    if inesperados:
        findings.append({"sev": "warn", "code": "PORT_UNEXPECTED",
                         "msg": f"puertos a la escucha no esperados: {inesperados}"})
    # 7) alerta temprana de disco (/persist)
    disk_pct = _disk_pct('/persist')
    if disk_pct is not None and disk_pct > 85:
        findings.append({"sev": "warn", "code": "DISK_HIGH",
                         "msg": f"/persist al {disk_pct}%"})
    # 8) honeypot: un hit RECIENTE a los cebos = sondeo/intrusión → hallazgo de seguridad real.
    # Cierra el bucle: el honeypot (deception_sensor) detecta → aquí se convierte en finding →
    # core_audit lo taxonomiza (red) y baja el score → governance_advisor recomienda respuesta.
    try:
        hp = os.path.join(os.environ.get("ANVOS_DATA", "/persist/anvos-data"), "deception", "hits.jsonl")
        if os.path.isfile(hp):
            hlines = [l for l in open(hp).read().splitlines() if l.strip()]
            if hlines:
                lasthit = json.loads(hlines[-1])
                if lasthit.get("event") == "HONEYPOT_HIT" and (int(time.time()) - int(lasthit.get("ts", 0))) < 900:
                    findings.append({"sev": "warn", "code": "HONEYPOT_HIT",
                                     "msg": "sondeo a cebo %s desde %s" % (lasthit.get("bait_port"), lasthit.get("src_ip"))})
    except Exception:
        pass
    rec = {
        "svc": "sentinel_observe",
        "ts": int(time.time()),
        "node": _machine_id(),
        "uptime_s": _uptime(),
        "layer_active": layer_active,
        "activate_sha256": act_sha[:16] if act_sha else None,
        "procs": procs,
        "mounts": mounts,
        "beacon_fresh": beacon_fresh,
        "listen_ports": ports,
        "disk_pct": disk_pct,
        "immune_state": "CALM" if not findings else "ALERT",
        "findings": findings,
        "observe_only": True,
    }
    print(json.dumps(rec, ensure_ascii=False))

if __name__ == '__main__':
    try:
        main()
    except Exception as e:  # nunca romper el supervisor
        print(json.dumps({"svc": "sentinel_observe", "ts": int(time.time()),
                          "error": str(e)}, ensure_ascii=False))
