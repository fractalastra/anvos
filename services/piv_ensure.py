#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""piv_ensure — asegura el stack PIV LOCAL del nodo (autonomía de autoridad). Puebla /dev/bus/usb (busybox/
mdev no lo hace, y el /dev del nodo es un tmpfs sobre devtmpfs) y mantiene pcscd vivo, para que el nodo
hable con SU PROPIA YubiKey (slot 9c ECCP384) SIN el master -> pueda firmar su propia génesis/evolución.

El bundle portado vive en /persist/anvos-piv (yubico-piv-tool 2.7.2 glibc + loader-wrapper + pcscd + driver
CCID + libpcsclite_real; pcscd arranca con --disable-polkit porque el nodo no tiene polkit/dbus). Nodo SIN
bundle (p.ej. nodo-c) -> NO-OP fail-safe. Observe/ensure-corto, idempotente, <30s. Solo stdlib. Uso: [cycle]."""
import os
import sys
import json
import time
import glob
import hashlib
import subprocess

PIV = "/persist/anvos-piv"
OUT = "/persist/anvos-data/piv/piv_ensure.jsonl"
MANIFEST = PIV + "/bundle_manifest.sha256"                        # manifiesto FIRMADO del bundle
MS = "/persist/anvos-staging/pylayer-verify"                      # verificador minisign embebido de la capa
PUB = "/persist/anvos-staging/pylayer/release.pub"               # clave release


def _sh(cmd, t=20):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t).stdout or ""
    except Exception:
        return ""


def _minisign_verify(target):
    """Verifica <target>.minisig con el verificador EMBEBIDO de la capa + release.pub. Fail-closed."""
    sig = target + ".minisig"
    if not (os.path.isfile(target) and os.path.isfile(sig) and os.path.isfile(PUB)):
        return False
    try:
        lds = glob.glob(os.path.join(MS, "ld-*.so*"))
        mbin = os.path.join(MS, "minisign")
        if not (lds and os.path.exists(mbin)):
            return False
        r = subprocess.run([lds[0], "--library-path", MS, mbin, "-Vm", target, "-p", PUB, "-x", sig],
                           capture_output=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


def _sha256(p):
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for c in iter(lambda: f.read(1 << 20), b""):
                h.update(c)
        return h.hexdigest()
    except Exception:
        return None


def _verify_bundle():
    """Integridad del bundle PIV contra su manifiesto FIRMADO 653C. (ok, motivo). Fail-closed: si el
    manifiesto no está, su firma no verifica, o un binario/lib/driver fue alterado -> NO se lanza pcscd
    (un yubico-piv-tool/libccid tocado no debe manejar la autoridad del nodo)."""
    if not os.path.isfile(MANIFEST):
        return False, "SIN_MANIFIESTO"
    if not _minisign_verify(MANIFEST):
        return False, "FIRMA_MANIFIESTO_INVALIDA"
    bad = []
    try:
        for ln in open(MANIFEST):
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            parts = ln.split(None, 1)
            if len(parts) != 2:
                continue
            want, rel = parts[0], parts[1].strip()
            if _sha256(os.path.join(PIV, rel)) != want:
                bad.append(rel)
                if len(bad) >= 3:
                    break
    except Exception as e:
        return False, "ERROR_VERIFY:" + str(e)[:40]
    if bad:
        return False, "INTEGRIDAD_FALLA:" + ",".join(bad)
    return True, "OK"


def _pcscd_alive():
    return "anvos-piv/bin/pcscd" in _sh("ps w 2>/dev/null")


def _yk_visible():
    # ¿hay una YubiKey conectada por USB? (si no, no tiene sentido levantar pcscd)
    for base in ("/sys/bus/usb/devices",):
        try:
            for d in os.listdir(base):
                p = os.path.join(base, d, "product")
                if os.path.isfile(p) and "yubi" in open(p).read().lower():
                    return True
        except Exception:
            pass
    return False


def main():
    st = {"svc": "piv_ensure", "ts": int(time.time())}
    if not os.path.isdir(PIV):
        st["estado"] = "SIN_BUNDLE"                       # nodo sin PIV portado -> no-op (fail-safe)
    elif not _yk_visible():
        _sh("%s/usb-nodes.sh >/dev/null 2>&1" % PIV)      # puebla nodos por si acaso
        st["estado"] = "SIN_YUBIKEY"                      # bundle presente pero sin llave conectada
    else:
        _sh("%s/usb-nodes.sh >/dev/null 2>&1" % PIV)      # /dev/bus/usb (busybox no lo crea)
        if _pcscd_alive():
            st["estado"] = "PCSCD_VIVO"                    # ya vivo (integridad verificada al arrancar)
        else:
            ok, motivo = _verify_bundle()                 # FAIL-CLOSED antes de (re)lanzar
            st["bundle"] = motivo
            if not ok:
                st["estado"] = "BUNDLE_NO_INTEGRO"        # bundle tocado/no firmado -> NO se lanza pcscd
            else:
                _sh("%s/pcscd-start.sh >/dev/null 2>&1" % PIV)
                time.sleep(2)
                st["estado"] = "PCSCD_ARRANCADO" if _pcscd_alive() else "PCSCD_FALLO"
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "a") as f:
            f.write(json.dumps(st, ensure_ascii=False) + "\n")
    except Exception:
        pass
    print(json.dumps(st, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
