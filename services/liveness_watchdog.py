#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""liveness_watchdog — recuperación ante CUELGUE del nodo (resiliencia, matriz item1).

Único aporte NUEVO cosechado del prototipo init-v19 (las demás ideas ya estaban cubiertas:
config-sin-eval ya guardada en el core v11, integridad del core vía UKI firmado, escritura
atómica/locks/tests ya estándar). ANVOS no tenía watchdog: si layerd/el core se CUELGA (proceso
vivo pero sin progreso), nada reinicia el nodo. Complementa crash_recovery (cura corrupción de
estado tras corte) y reboot_check (durabilidad) con el eje que faltaba: la RECUPERACIÓN ANTE
CUELGUE.

Patrón watchdog de hardware: el software SANO 'da de comer' a /dev/watchdog; si se CUELGA (deja
de alimentarlo), el HARDWARE reinicia. La 'acción' la ejecuta el hardware ante la AUSENCIA de
alimentación — fail-safe puro, autopreservación local del nodo (coherente con el A/B rollback que
el init ya hace), NO es una acción sobre el ecosistema (respeta OBSERVE_ONLY).

DOS MODOS (fail-safe por defecto):
  - DESARMADO (por defecto): NO abre el watchdog. Monitoriza la vivacidad del nodo (latido de
    layerd fresco, self_integrity SEALED, disco) y reporta; si detecta degradación la escala.
    Cero riesgo: no puede reiniciar el nodo.
  - ARMADO (opt-in del operador, ANVOS_WD_ARM=1 o policy firmada): abre /dev/watchdog, fija el
    timeout y lo alimenta MIENTRAS el nodo está vivo; si la vivacidad falla o este proceso se
    cuelga, el hardware reinicia. Pensado para activarse con el operador presente.

LONG_RUNNING bajo layerd. Solo stdlib."""
import os
import sys
import json
import time
import struct
import fcntl
import glob
import signal

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
WDDEV = os.environ.get("ANVOS_WD_DEV", "/dev/watchdog")
ARM_FLAG = os.path.join(DATA, "recovery", "WATCHDOG_ARMED")   # flag del operador para armar
ARM = os.environ.get("ANVOS_WD_ARM", "0") == "1" or os.path.exists(ARM_FLAG)
WD_KO = os.environ.get("ANVOS_WD_KO", "/persist/anvos-modules/i6300esb.ko")  # dir base de módulos
# orden de carga (core -> soporte -> proveedores de plataforma -> drivers); carga los presentes
WD_MODULE_ORDER = ["watchdog", "iTCO_vendor_support", "intel_pmc_bxt", "lpc_ich",
                   "iTCO_wdt", "i6300esb", "softdog"]  # HW preferido; softdog = respaldo por sw
                   # (origo Meteor Lake no expone el iTCO -> softdog; nodo-c VM -> i6300esb)
WD_TIMEOUT = int(os.environ.get("ANVOS_WD_TIMEOUT", "60"))  # s hasta el reset si no se alimenta
PET_S = int(os.environ.get("ANVOS_WD_PET", "15"))          # cada cuánto se alimenta / se evalúa
WD_GRACE = int(os.environ.get("ANVOS_WD_GRACE", "180"))    # gracia de arranque: alimenta SIEMPRE
                                                          # los 1.os N s (evita boot-loop)
WD_FAIL_STREAK = int(os.environ.get("ANVOS_WD_FAILS", "3"))  # nº de fallos SEGUIDOS antes de soltar
                                                          # (tolera blips transitorios)
REC = os.path.join(DATA, "recovery", "liveness_watchdog.jsonl")
# ioctl del watchdog (linux/watchdog.h)
WDIOC_SETTIMEOUT = 0xC0045706
WDIOC_KEEPALIVE = 0x80045705
WDIOS_DISABLECARD = 0x0001
WDIOC_SETOPTIONS = 0x80045704


def _emit(rec):
    try:
        os.makedirs(os.path.dirname(REC), exist_ok=True)
        with open(REC, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        # ITB-079 clase A: el silencio de un instrumento es indistinguible de "todo bien".
        # stderr llega al .jsonl de la capa, asi que el fallo de registro deja huella.
        print("REG_FAIL liveness_watchdog._emit: %r" % (e,), file=sys.stderr, flush=True)
    print(json.dumps(rec, ensure_ascii=False), flush=True)


def _fresh(path, max_age):
    """True si <path> fue tocado hace < max_age s (mtime local; no comparar relojes)."""
    try:
        return (time.time() - os.path.getmtime(path)) < max_age
    except Exception:
        return False


def liveness():
    """Vivacidad del nodo por señales LOCALES (no depende del master). (vivo, motivos)."""
    motivos = []
    # 1) latido de layerd fresco (layerd escribe su .jsonl cada ~30s)
    hb = os.path.join(DATA, "layerd", "layerd.jsonl")
    if not _fresh(hb, 120):
        motivos.append("layerd_heartbeat_stale")
    # 2) self_integrity SEALED reciente
    si = os.path.join(DATA, "integrity", "self_integrity.jsonl")
    sealed = False
    try:
        with open(si) as f:
            last = [l for l in f if l.strip()][-1]
        sealed = json.loads(last).get("attestation") == "SEALED"
    except Exception:
        sealed = False
    if not sealed:
        motivos.append("self_integrity_no_sealed")
    # 3) beacon del nodo fresco (progreso del ciclo)
    bc = os.path.join(DATA, "eco-telem", "beacon.jsonl")
    if not _fresh(bc, 180):
        motivos.append("beacon_stale")
    return (len(motivos) == 0), motivos


def _is_chardev(path):
    """True solo si <path> es un DISPOSITIVO DE CARÁCTER real (no un fichero regular bogus:
    un printf sobre /dev/watchdog cuando el módulo está descargado crea un fichero normal que
    acepta escrituras pero cuyos ioctl fallan -> 'armado' inerte)."""
    import stat as _stat
    try:
        return _stat.S_ISCHR(os.stat(path).st_mode)
    except Exception:
        return False


def _ensure_device():
    """Asegura que /dev/watchdog es un CHAR DEVICE real: si es fichero regular bogus lo borra;
    carga el módulo del bundle en orden de dependencia y crea el nodo desde sysfs (ANVOS sin udev,
    patrón de gpu_enable). Devuelve True si queda un char device usable."""
    if _is_chardev(WDDEV):
        return True
    # fichero regular bogus (resto de escrituras con el módulo descargado) -> quitarlo
    if os.path.exists(WDDEV) and not _is_chardev(WDDEV):
        try:
            os.remove(WDDEV)
        except Exception:
            pass
    import subprocess
    moddir = os.path.dirname(WD_KO)
    # Cargar en ORDEN los módulos presentes en el bundle (sirve para VM i6300esb Y HW real iTCO):
    # core -> soporte/proveedores de plataforma (crean el platform device) -> drivers.
    for name in WD_MODULE_ORDER:
        if os.path.isdir("/sys/module/" + name):
            continue
        ko = os.path.join(moddir, name + ".ko")
        if os.path.isfile(ko):
            try:
                subprocess.run(["insmod", ko], capture_output=True, timeout=10)
            except Exception:
                pass
    if _is_chardev(WDDEV):
        return True
    # crear el nodo /dev/watchdog desde sysfs si el kernel lo enumeró pero no hay udev
    try:
        dev = open("/sys/class/watchdog/watchdog0/dev").read().strip()  # "major:minor"
        maj, minr = (int(x) for x in dev.split(":"))
        os.mknod(WDDEV, 0o600 | 0o020000, os.makedev(maj, minr))  # S_IFCHR
        return _is_chardev(WDDEV)
    except Exception:
        return _is_chardev(WDDEV)


def _wd_open():
    """Abre /dev/watchdog y fija el timeout. Devuelve fd o None."""
    _ensure_device()
    if not _is_chardev(WDDEV):
        return None, "sin_char_device"
    try:
        fd = os.open(WDDEV, os.O_WRONLY)
        try:
            fcntl.ioctl(fd, WDIOC_SETTIMEOUT, struct.pack("i", WD_TIMEOUT))
        except Exception:
            pass  # algunos watchdog no permiten fijar timeout; usan el suyo
        return fd, "abierto"
    except Exception as e:
        return None, "error:%s" % str(e)[:60]


def _wd_pet(fd):
    try:
        fcntl.ioctl(fd, WDIOC_KEEPALIVE, 0)
        return True
    except Exception:
        try:
            os.write(fd, b"\x00")  # fallback: cualquier escritura alimenta
            return True
        except Exception:
            return False


def _wd_disarm(fd):
    """Desarma de forma limpia (magic close 'V' + WDIOS_DISABLECARD) para no reiniciar al salir."""
    try:
        fcntl.ioctl(fd, WDIOC_SETOPTIONS, struct.pack("i", WDIOS_DISABLECARD))
    except Exception:
        pass
    try:
        os.write(fd, b"V")  # magic close: cerrar sin reiniciar
    except Exception:
        pass
    try:
        os.close(fd)
    except Exception:
        pass


def _has_dev():
    return _is_chardev(WDDEV) or bool(glob.glob("/dev/watchdog*")) or os.path.isdir("/sys/class/watchdog/watchdog0")


def run_disarmed():
    """Monitor de vivacidad SIN armar el HW (cero riesgo). LONG_RUNNING: emite al CAMBIAR de
    estado + latido cada ~10 ciclos. Un cuelgue REAL detendría también a este proceso; el valor
    pleno de recuperación-ante-cuelgue es el modo ARMADO."""
    prev, i = None, 0
    while True:
        vivo, motivos = liveness()
        verdict = "VIVO" if vivo else "DEGRADADO"
        if verdict != prev or i % 10 == 0:
            _emit({"svc": "liveness_watchdog", "ts": int(time.time()), "modo": "DESARMADO",
                   "watchdog_dev": _has_dev(), "vivo": vivo, "motivos": motivos,
                   "nota": "capacidad lista; armar con ANVOS_WD_ARM=1 (operador presente)",
                   "verdict": verdict})
        prev = verdict
        i += 1
        time.sleep(max(15, PET_S) * 2)


def run_armed():
    """Alimenta /dev/watchdog mientras el nodo está vivo; si la vivacidad falla o este proceso
    se cuelga, el hardware reinicia (recuperación ante cuelgue REAL)."""
    fd, st = _wd_open()
    if fd is None:
        _emit({"svc": "liveness_watchdog", "ts": int(time.time()), "modo": "ARMADO",
               "estado": "NO_ARMABLE", "razon": st,
               "nota": "sin /dev/watchdog (¿VM sin -watchdog? ¿modulo iTCO?)"})
        return
    _emit({"svc": "liveness_watchdog", "ts": int(time.time()), "modo": "ARMADO",
           "estado": "ARMADO", "timeout_s": WD_TIMEOUT, "grace_s": WD_GRACE,
           "fail_streak": WD_FAIL_STREAK, "dev": WDDEV})
    # DESARME GARANTIZADO en cualquier salida (lección: softdog NO se desarma al cerrarse el fd
    # de golpe -SIGKILL-, solo con 'V'+close; y sin manejar SIGTERM el relevo de layerd mataba el
    # proceso saltándose el finally -> softdog quedaba armado -> reboot espurio). Registramos:
    #  - manejadores SIGTERM/SIGINT/SIGHUP -> SystemExit -> el finally desarma.
    #  - atexit como cinturón adicional.
    import atexit
    _disarmed = {"done": False}

    def _safe_disarm():
        if not _disarmed["done"]:
            _disarmed["done"] = True
            _wd_disarm(fd)
    atexit.register(_safe_disarm)

    def _on_signal(signum, frame):
        raise SystemExit(128 + signum)  # dispara el finally -> desarma
    for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(_sig, _on_signal)
        except Exception:
            pass

    start = time.time()
    fails = 0
    soltado = False
    try:
        while True:
            in_grace = (time.time() - start) < WD_GRACE
            # RESILIENCIA (Bug 1): un error transitorio en liveness/pet NO debe tumbar el servicio
            # (si el servicio muere y layerd tarda en respawnear, softdog dispararía). Ante error:
            # asumir vivo y ALIMENTAR (fail-safe hacia NO reiniciar por un fallo del propio guardián).
            try:
                vivo, motivos = liveness()
            except Exception as e:
                vivo, motivos = True, ["liveness_error:%s" % str(e)[:40]]
            if vivo:
                fails = 0
                if soltado:
                    soltado = False
                    _emit({"svc": "liveness_watchdog", "ts": int(time.time()), "modo": "ARMADO",
                           "estado": "RECUPERADO_REALIMENTA"})
                _wd_pet(fd)
            else:
                fails += 1
                # ARRANQUE (gracia) o pocos fallos seguidos -> seguir alimentando (tolerar blips).
                # Solo tras WD_FAIL_STREAK fallos consecutivos ya fuera de gracia se SUELTA el
                # watchdog -> si el cuelgue persiste, el HW reinicia al vencer el timeout.
                if in_grace or fails < WD_FAIL_STREAK:
                    _wd_pet(fd)
                elif not soltado:
                    soltado = True
                    _emit({"svc": "liveness_watchdog", "ts": int(time.time()), "modo": "ARMADO",
                           "estado": "SOLTADO_NO_ALIMENTA", "motivos": motivos, "fails": fails,
                           "nota": "cuelgue sostenido; si persiste %ss el HW reinicia" % WD_TIMEOUT})
                # (si soltado: NO alimentar -> el HW cuenta hasta el reset)
            time.sleep(PET_S)
    finally:
        _safe_disarm()  # salida limpia (relevo/señal) NO debe reiniciar el nodo


def main():
    if ARM:
        run_armed()
    else:
        run_disarmed()
    return 0


if __name__ == "__main__":
    sys.exit(main())
