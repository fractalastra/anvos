#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""anvos-layerd — DAEMON RESIDENTE de la capa autónoma de AstraNovaOS.
Un ÚNICO proceso Python de larga vida que supervisa TODOS los servicios de la capa, en
lugar de N bucles de shell independientes (uno por servicio). Ventajas: un solo punto de
control, planificación escalonada, reinicio con backoff, salud centralizada y apagado limpio.
Preserva la propiedad fail-closed: verifica la firma minisign de CADA servicio ANTES de cada
ejecución; si no valida, NO lo ejecuta (y lo reporta). Solo stdlib.

Modelo:
  - servicios PERIÓDICOS (oneshot): se lanzan a su intervalo, su stdout se anexa a su .jsonl.
  - servicios de LARGA DURACIÓN (bucle interno propio, p.ej. el cockpit): se mantienen vivos
    (respawn con backoff si mueren). Se identifican en LONG_RUNNING.
El daemon NO se planifica a sí mismo (no está en el manifiesto). Emite un latido con el
estado de cada servicio (última ejecución, OK/fallo, firma válida) para que el master vigile."""
import os
import sys
import json
import time
import glob
import signal
import subprocess

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
MS = os.path.join(STAGING, "pylayer-verify")               # minisign embebido + ld + libs
# La verificación de servicios va TODA por la partición A/B (verify_file, ver _verify y
# _pqc_enforce_on). Los antiguos _release_pubs/_any_pub_verifies de F0 se ELIMINARON tras
# el gate de gobernanza (higiene 15-ago): eran código de verificación muerto contra
# release.d — una mina si un futuro los recableara y reintrodujera la grieta.
# Fase 2 PQC (ADITIVO): verificador ML-DSA portado + clave publica raiz PQC. Mientras no esten
# desplegados, la verificacion PQC se OMITE y la capa sigue exactamente igual (solo Ed25519). Cuando
# existen, un sidecar .mldsa presente pero INVALIDO tumba la carga (fail-closed). Un artefacto sin
# sidecar sigue siendo legacy legitimo hasta P4 (marca pq:true en el manifiesto, Fase 3).
MLDSA_DIR = os.path.join(STAGING, "anvos-mldsa")            # bundle del verificador ML-DSA (Fase 2)
PQC_PUB = os.path.join(STAGING, "pqc_public", "pqc_root.pub")  # clave publica raiz PQC (Fase 1)
# P4 PQC (anti-degradacion, GOBERNADO por bandera). Cuando el operador la active (Fase 3), un fichero
# marcado pq:true en el main_manifest.json FIRMADO cuyo sidecar .mldsa falte o no valide -> fail-closed
# (TAMPER), cerrando el ataque de "borrar el sidecar". Default OFF: la capa se comporta IGUAL que hoy.
PQC_ENFORCE_FLAG = os.path.join(STAGING, "pqc_public", "ENFORCE")


def _pqc_enforce_on():
    """Fase 3 activa si: env ANVOS_PQC_ENFORCE=1, o existe el FLAG FIRMADO en disco (sobrevive
    reinicios y viaja por la tuberia firmada).
    K3 (gate de gobernanza): la POSTURA de enforcement PQC es GOBERNANZA — su flag se verifica
    por verify_file (Set B -> 653C HORNEADA), NO contra release.d. Asi la llave autonoma de
    origo, aunque este en release.d, NO puede activar/gestionar la postura de seguridad PQC.
    Desactivar = retirar el flag (acto visible); el techo lo pone la cadena de arranque."""
    if os.environ.get("ANVOS_PQC_ENFORCE") == "1":
        return True
    if not (os.path.isfile(PQC_ENFORCE_FLAG) and os.path.isfile(PQC_ENFORCE_FLAG + ".minisig")):
        return False
    try:
        return _ap().verify_file(PQC_ENFORCE_FLAG) is True   # Set B: solo la horneada
    except Exception:
        return False


_PQC_ENFORCE_CACHE = None    # perezoso: _find_ld/MS aun no existen al importar; se evalua al 1er uso


def _pqc_enforce():
    global _PQC_ENFORCE_CACHE
    if _PQC_ENFORCE_CACHE is None:
        _PQC_ENFORCE_CACHE = _pqc_enforce_on()
    return _PQC_ENFORCE_CACHE


def _load_pq_required():
    """Basenames marcados pq:true en el main_manifest.json firmado (si esta presente). Vacio si no."""
    req = set()
    for cand in (os.path.join(STAGING, "..", "anvos-ring", "main_manifest.json"),
                 os.path.join(STAGING, "main_manifest.json")):
        try:
            with open(cand) as fh:
                for e in (json.load(fh).get("files") or []):
                    if e.get("pq"):
                        req.add(e.get("name"))
            break
        except Exception:
            continue
    return req


_PQ_REQUIRED = _load_pq_required()
SVCDIR = os.path.join(STAGING, "services")
MANIFEST = os.path.join(SVCDIR, "manifest.txt")
MODDIR = os.environ.get("ANVOS_MODULES", "/persist/anvos-modules")  # perfil + config de módulos opcionales
PROFILE = os.path.join(MODDIR, "profile.json")                       # perfil FIRMADO del nodo (qué módulos activa)
PY = os.environ.get("ANVOS_PY", "/usr/bin/anvos-python3")
HB = os.path.join(DATA, "layerd", "layerd.jsonl")
HB_INTERVAL = 30          # cada cuánto emite su propio latido
HB_MAX = int(os.environ.get("ANVOS_HB_MAX", str(32 * 1024 * 1024)))  # rotar el latido al superar esto
MAX_RUNTIME = 30          # un servicio periódico que exceda esto se considera colgado y se mata
BACKOFF_BASE = 5          # backoff inicial (s) tras un fallo, crece hasta BACKOFF_MAX
BACKOFF_MAX = 120

# servicios con bucle interno propio (no periódicos): se mantienen vivos, no se relanzan por intervalo
LONG_RUNNING = {"codegen_nodo.py", "anvos-cockpit-fb.py", "node_status_server.py", "deception_sensor.py",
                "ai_llama_server.py", "liveness_watchdog.py", "mod_sensor.py", "mod_edu_identity.py"}

# ROTACIÓN DEL PROPIO LATIDO (ITE-001, 2026-08-07). Medido: sin rotación el latido alcanzó
# 556 MB en origo y 490 MB en nodo-c (~25 KB × 2880 latidos/día) y era el fichero que disparaba
# el OOM de crash_recovery en nodo-c. El núcleo de la OS ya rota SUS ficheros por segmentos
# encadenados, pero su lista vive dentro de la UKI; el latido lo escribe este daemon, así que
# lo rota su escritor: renombrado atómico al superar HB_MAX (nadie mantiene el fichero abierto:
# cada latido abre y cierra) y el trabajo caro —comprimir, sha, encadenar— en un HIJO aparte,
# porque el primer segmento heredado son cientos de MB y comprimirlo en el bucle pararía la
# supervisión decenas de segundos. Los segmentos .gz se CONSERVAN (compactar, no borrar); la
# cadena va en JSON por líneas con prev_hash, que es lo que crash_recovery sabe tratar.
_ROT_CHILD = r'''
import gzip, hashlib, json, os, sys, time
seg, chain = sys.argv[1], sys.argv[2]
gz = seg + ".gz"
with open(seg, "rb") as s, gzip.open(gz, "wb", compresslevel=9) as d:
    while True:
        b = s.read(1 << 20)
        if not b:
            break
        d.write(b)
h = hashlib.sha256()
with open(gz, "rb") as f:
    while True:
        b = f.read(1 << 20)
        if not b:
            break
        h.update(b)
prev = "GENESIS"
try:
    lineas = [l for l in open(chain, "rb").read().splitlines() if l.strip()]
    if lineas:
        prev = json.loads(lineas[-1]).get("sha", "GENESIS")
except Exception:
    pass
with open(chain, "a") as f:
    f.write(json.dumps({"seg": os.path.basename(gz), "sha": h.hexdigest(),
                        "prev_hash": prev, "ts": int(time.time())}) + "\n")
os.remove(seg)
'''

_run = True


def _stop(*_a):
    global _run
    _run = False


signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT, _stop)


def _now():
    return time.time()


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


def _verify(ld, target):
    """Verifica la firma de <target> según la PARTICIÓN A/B: los ficheros de gobernanza
    (Set B) solo valen firmados por la 653C horneada; los rutinarios (Set A) por release.d.
    True/False/None (None = verificador/firma ausente)."""
    sig = target + ".minisig"
    if not (ld and os.path.exists(os.path.join(MS, "minisign"))
            and os.path.isfile(target) and os.path.isfile(sig)):
        return None  # verificador o firma ausente: no podemos afirmar (distinto de inválida)
    try:
        if not _ap().verify_file(target, sig):
            return False               # Ed25519 obligatorio (partición A/B): sin el, no hay confianza
        # Fase 2 PQC (aditivo): si hay sidecar .mldsa y el verificador+clave PQC estan desplegados,
        # tambien debe validar ML-DSA. Presente-pero-invalido -> fail-closed; ausente o Fase 2 no
        # desplegada -> se mantiene el veredicto Ed25519 (no rompe la capa actual).
        pq = _verify_mldsa(target)
        if pq is False:
            return False
        # P4/Fase 3 (GOBERNADO por ANVOS_PQC_ENFORCE): si el manifiesto FIRMADO exige PQ para este
        # fichero y no hay sidecar valido -> TAMPER. Cierra el ataque de "borrar el sidecar". Inerte
        # por defecto (pq puede ser None sin consecuencia hasta que el operador active la enforcement).
        if _pqc_enforce() and os.path.basename(target) in _PQ_REQUIRED and pq is not True:
            return False
        return True
    except Exception:
        return False


def _verify_mldsa(target):
    """Verificacion ML-DSA aditiva. True=valida, False=sidecar PRESENTE e invalido (fail-closed),
    None=no aplicable (sin sidecar, o Fase 2/clave PQC aun no desplegadas)."""
    mldsa = target + ".mldsa"
    verifier = os.path.join(MLDSA_DIR, "anv-mldsa-verify.sh")
    if not os.path.isfile(mldsa):
        return None                    # sin sidecar: artefacto legacy legitimo
    if not (os.path.isfile(verifier) and os.path.isfile(PQC_PUB)):
        return None                    # Fase 2/clave PQC no desplegadas: additivo, no rompe
    try:
        r = subprocess.run([verifier, PQC_PUB, target, mldsa], capture_output=True, timeout=8)
        return r.returncode == 0
    except Exception:
        return False                   # error verificando un sidecar presente -> fail-closed


def load_manifest():
    svcs = []
    try:
        with open(MANIFEST) as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                parts = ln.split("|")
                if len(parts) >= 3:
                    # 4º campo OPCIONAL = etiqueta de MÓDULO (dominio). Vacío/ausente = núcleo (siempre corre).
                    mod = parts[3].strip() if len(parts) >= 4 and parts[3].strip() else None
                    svcs.append({"file": parts[0].strip(),
                                 "iv": int(parts[1]),
                                 "out": parts[2].strip(),
                                 "module": mod})
    except Exception:
        pass
    return svcs


def load_enabled_modules(ld):
    """Módulos de dominio HABILITADOS por el PERFIL FIRMADO del nodo (fail-closed).

    Lee /persist/anvos-modules/profile.json solo si su firma 653C verifica con el verificador
    embebido. Si falta, no verifica, o está mal formado -> conjunto VACÍO (los módulos NO corren;
    el núcleo no se ve afectado). Añadir/quitar un módulo = editar el perfil firmado, sin tocar el núcleo."""
    try:
        if not os.path.isfile(PROFILE):
            return set()
        if _verify(ld, PROFILE) is not True:   # firma ausente o inválida -> fail-closed
            return set()
        d = json.load(open(PROFILE))
        mods = d.get("enabled_modules", [])
        return set(m for m in mods if isinstance(m, str)) if isinstance(mods, list) else set()
    except Exception:
        return set()


def _openout(rel):
    path = os.path.join(DATA, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return open(path, "ab")


def main():
    os.makedirs(os.path.dirname(HB), exist_ok=True)
    ld = _find_ld()
    started = int(_now())

    # módulos de dominio habilitados por el perfil FIRMADO del nodo (vacío = solo núcleo)
    enabled_mods = load_enabled_modules(ld)
    skipped_mods = []

    # estado por servicio
    st = {}
    for s in load_manifest():
        mod = s.get("module")
        if mod and mod not in enabled_mods:
            # servicio de MÓDULO no habilitado por el perfil -> no se carga (el núcleo no se toca)
            skipped_mods.append(s["file"])
            continue
        st[s["file"]] = {
            "iv": s["iv"], "out": s["out"], "module": mod,
            "kind": "long" if s["file"] in LONG_RUNNING else "periodic",
            "proc": None, "fh": None, "started_at": 0,
            "next_run": _now() + (len(st) * 2.0),   # arranque escalonado (2s entre servicios)
            "runs": 0, "ok": 0, "fail": 0, "stopped": 0, "sig_fail": 0,
            "last_rc": None, "last_ok_ts": None, "backoff": BACKOFF_BASE, "sig_ok": None,
        }
    print(json.dumps({"svc": "layerd", "event": "modules", "enabled": sorted(enabled_mods),
                      "skipped": skipped_mods}, ensure_ascii=False), flush=True)

    def spawn(name, s):
        path = os.path.join(SVCDIR, name)
        sig_ok = _verify(ld, path)
        s["sig_ok"] = sig_ok
        if sig_ok is not True:
            # FAIL-CLOSED ESTRICTO: solo se ejecuta con firma VÁLIDA. Firma inválida (False) o
            # ausente/sin verificador (None) -> NO ejecutar. En el nodo el verificador embebido
            # siempre está; que falte una firma es señal de manipulación, no de entorno.
            s["sig_fail"] += 1
            s["next_run"] = _now() + max(s["iv"], BACKOFF_BASE)
            return False
        try:
            fh = _openout(s["out"])
            s["fh"] = fh
            s["proc"] = subprocess.Popen([PY, path], stdout=fh, stderr=subprocess.STDOUT,
                                         stdin=subprocess.DEVNULL)
            s["started_at"] = _now()
            s["runs"] += 1
            return True
        except Exception:
            s["fail"] += 1
            if s.get("fh"):
                try: s["fh"].close()
                except Exception: pass
                s["fh"] = None
            s["backoff"] = min(s["backoff"] * 2, BACKOFF_MAX)
            s["next_run"] = _now() + s["backoff"]
            return False

    def reap(s, killed=False):
        rc = s["proc"].poll()
        s["last_rc"] = -9 if killed else rc
        if not killed and rc == 0:
            s["ok"] += 1
            s["last_ok_ts"] = int(_now())
            s["backoff"] = BACKOFF_BASE
        elif not killed and rc == -15:
            # SIGTERM externo = RELEVO deliberado (operador/pipeline de promoción), NO un crash:
            # cuenta aparte y sin backoff (tras un relevo se quiere el respawn inmediato).
            # fail queda para crashes reales y para colgados que mata el propio layerd (-9).
            s["stopped"] += 1
            s["backoff"] = BACKOFF_BASE
        else:
            s["fail"] += 1
            s["backoff"] = min(s["backoff"] * 2, BACKOFF_MAX)
        if s.get("fh"):
            try: s["fh"].close()
            except Exception: pass
            s["fh"] = None
        s["proc"] = None

    rot = {"proc": None}

    def heartbeat():
        # rotar ANTES de anexar: renombrado atómico e hijo asíncrono; cualquier fallo aquí no
        # puede tumbar el latido ni el daemon. Un solo hijo a la vez: si el anterior sigue
        # comprimiendo, la rotación espera al siguiente latido.
        try:
            if (os.path.getsize(HB) > HB_MAX
                    and (rot["proc"] is None or rot["proc"].poll() is not None)):
                seg = HB + "." + time.strftime("%Y%m%dT%H%M%S", time.gmtime())
                os.rename(HB, seg)
                rot["proc"] = subprocess.Popen(
                    [PY, "-c", _ROT_CHILD, seg, HB + ".chain"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL)
        except Exception:
            pass
        rec = {
            "svc": "layerd", "ts": int(_now()), "uptime_s": int(_now() - started),
            "services": {
                name: {
                    "kind": s["kind"], "runs": s["runs"], "ok": s["ok"],
                    "fail": s["fail"], "stopped": s["stopped"],
                    "sig_fail": s["sig_fail"], "sig_ok": s["sig_ok"],
                    "last_rc": s["last_rc"], "last_ok_ts": s["last_ok_ts"],
                    "alive": bool(s["proc"] and s["proc"].poll() is None),
                } for name, s in st.items()
            },
            "supervised": len(st),
            "fail_closed_blocks": sum(s["sig_fail"] for s in st.values()),
        }
        try:
            with open(HB, "a") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            pass

    last_hb = 0.0
    # bucle principal residente
    while _run:
        now = _now()
        for name, s in st.items():
            proc = s["proc"]
            if s["kind"] == "long":
                # mantener vivo: si murió, respawn tras backoff
                if proc is None:
                    if now >= s["next_run"]:
                        if not spawn(name, s):
                            s["next_run"] = now + s["backoff"]
                elif proc.poll() is not None:
                    reap(s)
                    s["next_run"] = now + s["backoff"]   # respawn con backoff
            else:  # periódico
                if proc is not None:
                    if proc.poll() is not None:
                        reap(s)
                        s["next_run"] = now + s["iv"]
                    elif now - s["started_at"] > MAX_RUNTIME:
                        # colgado: matar
                        try: proc.kill()
                        except Exception: pass
                        reap(s, killed=True)
                        s["next_run"] = now + s["iv"]
                elif now >= s["next_run"]:
                    if spawn(name, s):
                        pass  # next_run se fija al reap con el intervalo
                    # si spawn falló por firma, spawn() ya reprogramó next_run

        if now - last_hb >= HB_INTERVAL:
            heartbeat()
            last_hb = now
        time.sleep(1)

    # apagado limpio: terminar hijos vivos
    for s in st.values():
        p = s.get("proc")
        if p and p.poll() is None:
            try: p.terminate()
            except Exception: pass
    time.sleep(1)
    for s in st.values():
        p = s.get("proc")
        if p and p.poll() is None:
            try: p.kill()
            except Exception: pass
    heartbeat()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        try:
            with open(HB, "a") as f:
                f.write(json.dumps({"svc": "layerd", "ts": int(time.time()),
                                    "fatal": str(e)}, ensure_ascii=False) + "\n")
        except Exception:
            pass
        sys.exit(1)
