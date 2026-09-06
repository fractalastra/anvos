#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""dr_ext_mount — MONTA el disco DR/mirror externo del nodo (2o disco FISICAMENTE separado) de forma
IDEMPOTENTE y FAIL-SAFE. Config por-nodo en /persist/anvos-data/dr/dr_disk.json (uuid+mount): un nodo SIN
config (p.ej. nodo-c sin disco DR) hace NO-OP. Resuelve el UUID leyendo el SUPERBLOQUE ext4 de cada
particion (busybox no trae blkid funcional ni /dev/disk/by-uuid fiable). Observe/act-minimo: solo monta;
nunca formatea, nunca borra. Cualquier fallo -> se registra y termina en 0 (NO bloquea el ecosistema/OS).

Es el cimiento del tri-ring FISICO del nodo: el layer MAIN vive en el nvme interno; su copia DR vive en
este disco independiente (lo escribe dr_sync). Solo stdlib. Uso: dr_ext_mount.py [cycle]."""
import os
import sys
import json
import glob

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
CFG = os.path.join(DATA, "dr", "dr_disk.json")
OUT = os.path.join(DATA, "dr", "dr_ext_mount.jsonl")
SB_OFFSET = 1128           # offset del UUID (s_uuid) en el superbloque ext4
EXT_MAGIC_OFF = 1080       # 0x438: magic 0xEF53 (little-endian) del superbloque ext2/3/4


def _emit(d):
    print(json.dumps(d, ensure_ascii=False), flush=True)
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "a") as f:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL dr_ext_mount._emit: %r" % (e,), file=sys.stderr, flush=True)


def _mounted(mp):
    try:
        with open("/proc/mounts") as f:
            return any(mp == ln.split()[1] for ln in f if len(ln.split()) > 1)
    except Exception:
        return False


def _read_uuid(dev):
    """UUID ext4 del dispositivo leyendo su superbloque (o None si no es ext o falla)."""
    try:
        with open(dev, "rb") as f:
            f.seek(EXT_MAGIC_OFF)
            if f.read(2) != b"\x53\xef":       # 0xEF53 little-endian
                return None
            f.seek(SB_OFFSET)
            b = f.read(16)
        if len(b) != 16:
            return None
        h = b.hex()
        return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
    except Exception:
        return None


def _ensure_dev_nodes():
    """Busybox NO auto-crea /dev/vdb1 etc. -> crea los nodos de bloque que falten desde /proc/partitions,
    para que un disco DR (2o disco de una VM) se ENCUENTRE tras un reboot. Idempotente, best-effort."""
    try:
        for ln in open("/proc/partitions"):
            p = ln.split()
            if len(p) >= 4 and p[0].isdigit():
                dev = "/dev/" + p[3]
                if not os.path.exists(dev):
                    try:
                        os.mknod(dev, 0o600 | 0o60000, os.makedev(int(p[0]), int(p[1])))  # S_IFBLK
                    except Exception:
                        pass
    except Exception:
        pass


def _candidates():
    """Particiones de disco reales (sd*, nvme*p*, vd*), excluyendo el disco raiz montado en /."""
    _ensure_dev_nodes()   # crea nodos que busybox no puso (p.ej. vdb1 del 2o disco tras reboot)
    cands = []
    for pat in ("/dev/sd[a-z][0-9]*", "/dev/vd[a-z][0-9]*", "/dev/nvme[0-9]n[0-9]p[0-9]*"):
        cands += glob.glob(pat)
    return sorted(set(cands))


def cmd_cycle():
    try:
        cfg = json.load(open(CFG))
    except Exception:
        _emit({"svc": "dr_ext_mount", "state": "SIN_CONFIG", "note": "nodo sin disco DR configurado (no-op)"})
        return 0
    uuid = (cfg.get("uuid") or "").lower()
    mp = cfg.get("mount") or "/mnt/anvos-dr-ext"
    if not uuid:
        _emit({"svc": "dr_ext_mount", "state": "CONFIG_INVALIDA"})
        return 0
    if _mounted(mp):
        _emit({"svc": "dr_ext_mount", "state": "YA_MONTADO", "mount": mp})
        return 0
    dev = None
    for c in _candidates():
        if _read_uuid(c) == uuid:
            dev = c
            break
    if not dev:
        _emit({"svc": "dr_ext_mount", "state": "DISCO_AUSENTE", "uuid": uuid,
               "note": "el disco DR no esta conectado; se montara cuando aparezca (no bloquea)"})
        return 0
    try:
        os.makedirs(mp, exist_ok=True)
    except Exception:
        pass
    rc = os.system("mount -t ext4 %s %s >/dev/null 2>&1" % (dev, mp))
    if rc == 0 and _mounted(mp):
        _emit({"svc": "dr_ext_mount", "state": "MONTADO", "dev": dev, "mount": mp, "uuid": uuid})
    else:
        _emit({"svc": "dr_ext_mount", "state": "FALLO_MOUNT", "dev": dev, "mount": mp, "rc": rc})
    return 0


def main():
    try:
        return cmd_cycle()
    except Exception as e:
        _emit({"svc": "dr_ext_mount", "ok": False, "fatal": str(e)})
        return 0


if __name__ == "__main__":
    sys.exit(main())
