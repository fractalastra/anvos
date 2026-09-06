#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""inventory_sensor — CMDB nativo del nodo ANVOS (matriz item 14: inventario/GLPI).

El ecosistema usa el agente GLPI (Perl) como sensor commodity; ANVOS busybox no puede correrlo, así
que este es el análogo NATIVO y ligero (patrón envoltorio: sensor propio + inteligencia firmada):
lee el inventario de hardware/software del nodo desde /proc y /sys (CPU, RAM, discos+modelo, GPU,
NICs+MAC, kernel, versión de capa), calcula una HUELLA de hardware estable, detecta CAMBIOS
(INVENTORY_DRIFT: disco cambiado, RAM/NIC añadida) y encadena los snapshots (CMDB tamper-evident).

Especialmente útil con la expansión a hardware real/múltiples máquinas: cada nodo conoce y firma su
propio hardware, y cualquier cambio físico queda registrado. OBSERVE-only. Single-shot. stdlib."""
import os
import json
import time
import hashlib
import platform
import subprocess

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
INVDIR = os.path.join(DATA, "inventory")
LEDGER = os.path.join(INVDIR, "inventory.jsonl")           # snapshots encadenados (solo al cambiar)
HEAD = os.path.join(INVDIR, "inventory.head.json")
STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
GENESIS = "0" * 64


def _read(p, default=""):
    try:
        return open(p).read().strip()
    except Exception:
        return default


def _cpu():
    model, threads = "?", 0
    try:
        for ln in open("/proc/cpuinfo"):
            if ln.startswith("model name") and model == "?":
                model = ln.split(":", 1)[1].strip()
            if ln.startswith("processor"):
                threads += 1
    except Exception:
        pass
    return {"model": model, "threads": threads}


def _ram_gb():
    try:
        for ln in open("/proc/meminfo"):
            if ln.startswith("MemTotal"):
                return round(int(ln.split()[1]) / 1024 / 1024, 1)
    except Exception:
        pass
    return None


def _disks():
    out = []
    for d in sorted(os.listdir("/sys/block")):
        if d.startswith(("loop", "ram", "zram")):
            continue
        base = "/sys/block/" + d
        try:
            size_gb = round(int(_read(base + "/size", "0")) / 2 / 1024 / 1024, 1)
        except Exception:
            size_gb = None
        out.append({"name": d, "model": _read(base + "/device/model", "?").strip() or "?",
                    "size_gb": size_gb, "rotational": _read(base + "/queue/rotational") == "1"})
    return out


def _gpus():
    out = []
    for c in sorted(__import__("glob").glob("/sys/class/drm/card[0-9]")):
        dev = c + "/device"
        pci = ""
        for ln in _read(dev + "/uevent").splitlines():
            if ln.startswith("PCI_ID="):
                pci = ln.split("=", 1)[1]
        drv = os.path.basename(os.path.realpath(dev + "/driver")) if os.path.islink(dev + "/driver") else ""
        out.append({"card": os.path.basename(c), "pci_id": pci, "driver": drv})
    return out


def _nics():
    out = []
    for n in sorted(os.listdir("/sys/class/net")):
        if n == "lo":
            continue
        out.append({"name": n, "mac": _read("/sys/class/net/%s/address" % n)})
    return out


def _layer():
    services = 0
    try:
        mani = os.path.join(STAGING, "services", "manifest.txt")
        services = sum(1 for l in open(mani) if l.strip().endswith(".py") or ".py|" in l)
    except Exception:
        pass
    return {"node_id": _read("/persist/anvos-node.id", "unknown"),
            "kernel": os.uname().release, "services": services}


BUNDLES = ("wg-native", "i915-native", "vulkan-native", "llama-native", "sentinel-tools")


def _sha(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _software():
    """Plano de SOFTWARE del nodo: servicios firmados + manifiesto + bundles.
    Huella de bundle = nombres+tamaños (ligera; la integridad de CONTENIDO la cubre
    self_integrity/firmas — aquí se detecta presencia/alta/baja/cambio estructural)."""
    svcdir = os.path.join(STAGING, "services")
    sw = {"manifest_sha": _sha(os.path.join(svcdir, "manifest.txt")),
          "services": sorted(f for f in (os.listdir(svcdir) if os.path.isdir(svcdir) else [])
                             if f.endswith(".py")),
          "bundles": {}, "versions": _versions()}
    for b in BUNDLES:
        d = os.path.join(STAGING, b)
        if not os.path.isdir(d):
            continue
        items = []
        for root, _dirs, files in os.walk(d):
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    items.append("%s:%d" % (os.path.relpath(p, d), os.path.getsize(p)))
                except Exception:
                    pass
        sw["bundles"][b] = hashlib.sha256("\n".join(sorted(items)).encode()).hexdigest()[:16]
    return sw


def _first_line(cmd, timeout=8):
    """Primera línea de la salida (stdout+stderr) de un comando, defensivo."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        for ln in out.splitlines():
            if ln.strip():
                return ln.strip()[:120]
    except Exception:
        pass
    return ""


def _versions():
    """Plano de VERSIONES de los componentes embarcados (software fino): lo fiable y barato.
    Convención nueva: cada bundle puede llevar un fichero VERSION (viaja firmado dentro del
    bundle) — su contenido entra aquí; sin VERSION -> 'sin_version' (deriva honesta cuando
    aparezca). Un cambio de versión = deriva de CMDB categorizada."""
    v = {"kernel": os.uname().release,
         "python": platform.python_version(),
         "busybox": _first_line(["/bin/busybox"]),
         "dropbear": _first_line(["/opt/dropbear/ld-linux-x86-64.so.2", "--library-path",
                                  "/opt/dropbear", "/opt/dropbear/dropbear", "-V"])}
    for b in BUNDLES:
        vf = os.path.join(STAGING, b, "VERSION")
        if os.path.isdir(os.path.join(STAGING, b)):
            v["bundle_" + b] = _read(vf, "sin_version").strip()[:120]
    return v


def _canon(d):
    return json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def gather():
    hw = {"cpu": _cpu(), "ram_gb": _ram_gb(), "disks": _disks(), "gpus": _gpus(), "nics": _nics()}
    sw = _software()
    # huella ESTABLE v2: hardware (modelos+capacidades+MACs+kernel) + SOFTWARE (manifiesto+
    # servicios+bundles); no incluye %uso ni ts
    stable = {"cpu": hw["cpu"], "ram_gb": hw["ram_gb"], "kernel": os.uname().release,
              "disks": [{"model": d["model"], "size_gb": d["size_gb"]} for d in hw["disks"]],
              "gpus": [g["pci_id"] for g in hw["gpus"]], "nics": [n["mac"] for n in hw["nics"]],
              "sw": {"manifest_sha": sw["manifest_sha"], "services": sw["services"],
                     "bundles": sw["bundles"], "versions": sw["versions"]}}
    fp = hashlib.sha256(_canon(stable).encode()).hexdigest()
    return hw, sw, fp


def _diff(old, new, old_sw, new_sw):
    """Cambios legibles entre dos inventarios (hardware + software)."""
    ch = []
    if not old:
        return ["primer inventario"]
    if old.get("ram_gb") != new.get("ram_gb"):
        ch.append("RAM %s→%s GB" % (old.get("ram_gb"), new.get("ram_gb")))
    om = sorted(d["model"] for d in old.get("disks", []))
    nm = sorted(d["model"] for d in new.get("disks", []))
    if om != nm:
        ch.append("discos %s→%s" % (om, nm))
    if sorted(g["pci_id"] for g in old.get("gpus", [])) != sorted(g["pci_id"] for g in new.get("gpus", [])):
        ch.append("GPU cambiada")
    if sorted(n["mac"] for n in old.get("nics", [])) != sorted(n["mac"] for n in new.get("nics", [])):
        ch.append("NICs cambiadas")
    if old_sw is None and new_sw:
        ch.append("software: inventario ampliado a esquema v2 (servicios+bundles+manifiesto)")
    elif old_sw and new_sw:
        add = sorted(set(new_sw.get("services", [])) - set(old_sw.get("services", [])))
        rem = sorted(set(old_sw.get("services", [])) - set(new_sw.get("services", [])))
        if add:
            ch.append("servicios añadidos: %s" % ",".join(add))
        if rem:
            ch.append("servicios retirados: %s" % ",".join(rem))
        ob, nb = old_sw.get("bundles", {}), new_sw.get("bundles", {})
        for b in sorted(set(ob) | set(nb)):
            if b not in ob:
                ch.append("bundle añadido: %s" % b)
            elif b not in nb:
                ch.append("bundle retirado: %s" % b)
            elif ob[b] != nb[b]:
                ch.append("bundle cambiado: %s" % b)
        if old_sw.get("manifest_sha") != new_sw.get("manifest_sha"):
            ch.append("manifiesto de la capa cambiado")
        ov, nv = old_sw.get("versions"), new_sw.get("versions")
        if ov is None and nv:
            ch.append("software: huella ampliada a esquema v3 (versiones de componentes)")
        elif ov and nv:
            for k in sorted(set(ov) | set(nv)):
                if ov.get(k) != nv.get(k):
                    ch.append("versión cambiada: %s '%s'→'%s'" % (k, ov.get(k), nv.get(k)))
    return ch or ["cambio menor"]


def _load_head():
    try:
        return json.loads(open(HEAD).read())
    except Exception:
        return {"head": GENESIS, "seq": 0, "fp": None, "hw": None}


def main():
    os.makedirs(INVDIR, exist_ok=True)
    hw, sw, fp = gather()
    h = _load_head()
    now = int(time.time())
    drift = (h.get("fp") is not None and h.get("fp") != fp)
    first = h.get("fp") is None
    inv = {**hw, **_layer(), "sw": sw}

    rec = {"svc": "inventory_sensor", "ts": now, "observe_only": True,
           "fingerprint": fp[:16], "inventory": inv,
           "inventory_drift": drift}

    if drift or first:
        changes = _diff(h.get("hw"), hw, h.get("sw"), sw)
        core = {"seq": h.get("seq", 0), "ts": now, "fingerprint": fp, "changes": changes,
                "inventory": inv}
        hh = hashlib.sha256((h.get("head", GENESIS) + _canon({k: core[k] for k in ("seq", "ts", "fingerprint", "changes")})).encode()).hexdigest()
        entry = dict(core, prev_hash=h.get("head", GENESIS), hash=hh)
        with open(LEDGER, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        tmp = HEAD + ".%d.tmp" % os.getpid()
        with open(tmp, "w") as f:
            f.write(json.dumps({"head": hh, "seq": h.get("seq", 0) + 1, "fp": fp,
                                "hw": hw, "sw": sw}, ensure_ascii=False))
        os.replace(tmp, HEAD)
        rec["snapshot_chained"] = True
        rec["changes"] = changes
        rec["chain_head"] = hh[:16]

    print(json.dumps(rec, ensure_ascii=False))


if __name__ == "__main__":
    main()
