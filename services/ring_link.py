#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""ring_link — malla WireGuard NATIVA entre nodos ANVOS (anillo ANVOS↔ANVOS).
Ejecución single-shot bajo layerd (una línea JSON y termina). Da al nodo su enlace de anillo
kernel-nativo sin recompilar: carga los módulos del bundle firmado wg-native (kernel Debian
6.12.90 idéntico al del master, vermagic compatible), crea la interfaz `anvring0` en la subred
del anillo ANVOS (subred declarada en la configuración, SEPARADA de la malla soberana — el nodo NO se
afilia a la malla del ecosistema) y aplica los peers de un fichero de configuración FIRMADO.
FAIL-CLOSED en tres niveles: módulo sin firma válida → no se carga; herramienta wg sin firma →
no se ejecuta; peers sin firma → no se aplican (el enlace queda READY sin peers).
Idempotente y CONVERGENTE bajo el MAX_RUNTIME=30s de layerd: la primera pasada tras un boot
(9 firmas+insmod) puede exceder 30s y ser matada, pero los módulos ya cargados persisten y la
siguiente pasada continúa donde quedó — converge en 2-3 intervalos sin tocar layerd. Solo stdlib."""
import os
import json
import time
import glob
import subprocess

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
SVCDIR = os.path.join(STAGING, "services")
MS = os.path.join(STAGING, "pylayer-verify")
PUB = os.path.join(STAGING, "pylayer", "release.pub")
BUNDLE = os.path.join(STAGING, "wg-native")
MODDIR = os.path.join(BUNDLE, "modules")
WG = os.path.join(BUNDLE, "bin", "wg")
WG_REAL = os.path.join(BUNDLE, "bin", "wg.real")
PEERS_CFG = os.path.join(SVCDIR, "ring_link_peers.json")
KEYDIR = "/persist/anvos-ring-link"
IFACE = "anvring0"
HANDSHAKE_FRESH_S = 180


def _run(cmd, timeout=10, inp=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=inp)
    except Exception:
        return None


def _verify_sig(target):
    """FAIL-CLOSED: firma minisign 653C de <target> con el verificador embebido del nodo."""
    ld = next(iter(glob.glob(os.path.join(MS, "ld-linux*.so.2"))), None)
    sig = target + ".minisig"
    if not (ld and os.path.exists(os.path.join(MS, "minisign")) and os.path.exists(PUB)
            and os.path.isfile(target) and os.path.isfile(sig)):
        return False
    r = _run([ld, "--library-path", MS, os.path.join(MS, "minisign"),
              "-Vm", target, "-p", PUB, "-x", sig], timeout=8)
    return bool(r) and r.returncode == 0


def _wg(*args, inp=None):
    """Ejecuta la herramienta wg del bundle (solo si su firma valida — la asegura main)."""
    return _run([WG] + list(args), inp=inp)


def _module_loaded(name):
    return os.path.isdir("/sys/module/" + name.replace("-", "_"))


def load_modules():
    """Carga los .ko FIRMADOS del bundle en orden de dependencia. Devuelve (cargados, bloqueados)."""
    loaded, blocked = [], []
    for ko in sorted(glob.glob(os.path.join(MODDIR, "*.ko"))):
        name = os.path.basename(ko).split("_", 1)[1][:-3]
        if _module_loaded(name):
            continue
        if not _verify_sig(ko):
            blocked.append(name)
            continue
        r = _run(["insmod", ko])
        (loaded if (r and r.returncode == 0 and _module_loaded(name)) else blocked).append(name)
    return loaded, blocked


def ensure_keypair():
    """Clave WG propia del nodo en PERSIST (privada 0400). La genera una sola vez."""
    os.makedirs(KEYDIR, exist_ok=True)
    priv, pub = os.path.join(KEYDIR, "node.key"), os.path.join(KEYDIR, "node.pub")
    if not os.path.isfile(priv):
        r = _wg("genkey")
        if not (r and r.returncode == 0):
            return None
        fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
        with os.fdopen(fd, "w") as f:
            f.write(r.stdout.strip() + "\n")
    if not os.path.isfile(pub):
        r = _wg("pubkey", inp=open(priv).read())
        if r and r.returncode == 0:
            open(pub, "w").write(r.stdout.strip() + "\n")
    return open(pub).read().strip() if os.path.isfile(pub) else None


def read_peers():
    """Config de peers FIRMADA (653C). Sin firma válida → None (fail-closed, sin peers)."""
    if not (os.path.isfile(PEERS_CFG) and _verify_sig(PEERS_CFG)):
        return None
    try:
        return json.load(open(PEERS_CFG))
    except Exception:
        return None


def ensure_lo():
    """Auto-curado del loopback (bug recurrente del nodo: lo queda en noop tras boot). La entrega
    LOCAL de las IPs del anillo enruta 'dev lo' — sin lo arriba, el transporte del anillo hacia
    la propia IP cae en agujero negro. Devuelve True si tuvo que levantarlo."""
    r = _run(["ip", "-o", "link", "show", "lo"])
    if r and "UP" not in (r.stdout or ""):
        _run(["ip", "link", "set", "lo", "up"])
        _run(["ip", "addr", "add", "127.0.0.1/8", "dev", "lo"])
        return True
    return False


def ensure_iface(cfg):
    """Crea/asegura anvring0: link + clave + puerto + dirección. Devuelve estado parcial."""
    if not os.path.isdir("/sys/class/net/" + IFACE):
        r = _run(["ip", "link", "add", IFACE, "type", "wireguard"])
        if not (r and r.returncode == 0):
            return {"iface_ok": False, "why": (r.stderr.strip()[:80] if r else "ip link timeout")}
    _wg("set", IFACE, "private-key", os.path.join(KEYDIR, "node.key"),
        "listen-port", str((cfg or {}).get("listen_port", 51821)))
    addr = (cfg or {}).get("address")
    if addr:
        have = _run(["ip", "-o", "addr", "show", "dev", IFACE])
        if not (have and addr.split("/")[0] in (have.stdout or "")):
            _run(["ip", "addr", "add", addr, "dev", IFACE])
    _run(["ip", "link", "set", IFACE, "up"])
    return {"iface_ok": True}


def apply_peers(cfg):
    """Aplica cada peer (idempotente: wg set re-asegura). Keepalive SIEMPRE (lección malla)."""
    applied = 0
    for p in (cfg or {}).get("peers", []):
        args = ["set", IFACE, "peer", p["pubkey"],
                "allowed-ips", p.get("allowed_ips", ""),
                "persistent-keepalive", str(p.get("keepalive", 25))]
        if p.get("endpoint"):
            # endpoint va ANTES de 'allowed-ips' (indice 4): insertarlo en [5:5] partia el par
            # 'allowed-ips'<->valor -> comando wg malformado -> los peers CON endpoint (p.ej.
            # nodo-c vía relé) nunca se aplicaban (applied=0) y la malla no auto-recuperaba tras reboot
            args[4:4] = ["endpoint", p["endpoint"]]
        r = _wg(*args)
        if r and r.returncode == 0:
            applied += 1
    return applied


def link_status():
    """Handshakes reales de la interfaz (wg show dump)."""
    r = _wg("show", IFACE, "dump")
    peers, fresh = 0, 0
    if r and r.returncode == 0:
        now = time.time()
        for line in r.stdout.strip().splitlines()[1:]:
            peers += 1
            try:
                hs = int(line.split("\t")[4])
                if hs and (now - hs) < HANDSHAKE_FRESH_S:
                    fresh += 1
            except (IndexError, ValueError):
                pass
    return peers, fresh


def node_id():
    try:
        return open("/persist/anvos-node.id").read().strip()[:32]
    except Exception:
        return "unknown"



def ensure_mesh_wg0():
    """Durabilidad: levanta wg0 (malla soberana 10.99) desde /persist/anvos-mesh/wg0.conf si existe.
    Idempotente, fail-safe, ADITIVO (no afecta a anvring0)."""
    conf = "/persist/anvos-mesh/wg0.conf"; key = "/persist/anvos-mesh/wg0.key"
    if not (os.path.exists(conf) and os.path.exists(key)):
        return {"wg0": "no_config"}
    try:
        cfg = {}; sec = None
        for line in open(conf):
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                sec = line[1:-1]; cfg.setdefault(sec, {}); continue
            if "=" in line and sec and not line.startswith("#"):
                k, _, v = line.partition("="); cfg[sec][k.strip()] = v.strip()
        it = cfg.get("Interface", {}); pe = cfg.get("Peer", {})
        addr = it.get("Address"); port = it.get("ListenPort", "51820")
        pub = pe.get("PublicKey"); ep = pe.get("Endpoint")
        allowed = pe.get("AllowedIPs", os.environ.get("ANVOS_RING_ALLOWED", "")); ka = pe.get("PersistentKeepalive", "25")
        if not (addr and pub and ep and allowed):
            return {"wg0": "config_incompleto"}

        # ITB-057 (revisor-b, 2026-08-02). Esta funcion levantaba el enlace SIN clave compartida: no
        # leia PresharedKeyFile ni PresharedKey, de modo que al arrancar el nodo montaba un enlace
        # que el equipo principal rechaza, porque alli el par SI exige clave compartida. El enlace
        # solo funcionaba mientras alguien lo levantaba a mano, y volvia a caer en cada reinicio.
        # Medido: dia y medio sin saludo con el nodo en pie y reportando por la otra red.
        #
        # La clave compartida es la primera fase de proteccion frente a computacion cuantica del
        # ecosistema: un enlace levantado sin ella no es un enlace degradado, es otro enlace, y
        # ademas no llega a establecerse. Se lee del fichero que indique la configuracion.
        psk = pe.get("PresharedKeyFile") or it.get("PresharedKeyFile")
        if psk and not os.path.exists(psk):
            # Fail-closed: declarada y ausente NO se levanta a medias. Un enlace sin la clave que
            # su propia configuracion exige es peor que ninguno, porque aparenta estar puesto.
            return {"wg0": "psk_declarada_ausente", "wg0_psk": psk}
        if not os.path.isdir("/sys/class/net/wg0"):
            _run(["ip", "link", "add", "wg0", "type", "wireguard"])
        _wg("set", "wg0", "private-key", key, "listen-port", str(port))
        _args = ["set", "wg0", "peer", pub, "endpoint", ep, "allowed-ips", allowed,
                 "persistent-keepalive", ka]
        if psk:
            _args += ["preshared-key", psk]
        _wg(*_args)
        have = _run(["ip", "-o", "addr", "show", "dev", "wg0"])
        if not (have and addr.split("/")[0] in (have.stdout or "")):
            _run(["ip", "addr", "add", addr, "dev", "wg0"])
        _run(["ip", "link", "set", "wg0", "up"])
        return {"wg0": "up", "wg0_addr": addr.split("/")[0]}
    except Exception as e:
        return {"wg0": "error", "wg0_why": str(e)[:60]}


def main():
    rec = {"svc": "ring_link", "ts": int(time.time()), "node": node_id(), "iface": IFACE}
    # 1) herramienta wg: sin firma válida no hay nada que hacer (fail-closed total)
    if not (_verify_sig(WG) and _verify_sig(WG_REAL)):
        rec.update({"state": "BLOCKED_SIG_TOOL", "detail": "wg/wg.real sin firma valida"})
        print(json.dumps(rec, ensure_ascii=False))
        return
    # 2) módulos kernel firmados
    loaded, blocked = load_modules()
    rec.update({"modules_loaded_now": loaded, "modules_blocked": blocked,
                "wireguard_ready": _module_loaded("wireguard")})
    if not rec["wireguard_ready"]:
        rec["state"] = "NO_MODULES"
        print(json.dumps(rec, ensure_ascii=False))
        return
    rec.update(ensure_mesh_wg0())
    # 3) identidad del enlace
    pub = ensure_keypair()
    rec["node_wg_pub"] = pub
    if not pub:
        rec["state"] = "NO_KEYPAIR"
        print(json.dumps(rec, ensure_ascii=False))
        return
    # 4) loopback (entrega local del anillo) + interfaz + peers firmados
    rec["lo_healed"] = ensure_lo()
    cfg = read_peers()
    rec["peers_cfg_signed"] = cfg is not None
    st = ensure_iface(cfg)
    rec.update(st)
    if not st.get("iface_ok"):
        rec["state"] = "IFACE_FAIL"
        print(json.dumps(rec, ensure_ascii=False))
        return
    rec["peers_applied"] = apply_peers(cfg) if cfg else 0
    peers, fresh = link_status()
    rec.update({"peers": peers, "handshakes_fresh": fresh,
                "state": "LINKED" if fresh else ("READY_PEERS" if peers else "READY_NO_PEERS")})
    print(json.dumps(rec, ensure_ascii=False))


if __name__ == "__main__":
    main()
