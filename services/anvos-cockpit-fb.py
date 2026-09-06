#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""anvos-cockpit-fb — Cockpit Soberano PORTABLE de AstraNovaOS (solo stdlib, sin PIL).
Lee el estado vivo del nodo (/persist/anvos-data/*.jsonl que producen los servicios de la
capa firmada) y lo pinta en el framebuffer EFI (/dev/fb0, 1920x1080 32bpp BGRX) via mmap.
Diseno derivado de anvos-cockpit-render.py (que usa PIL en el master). Este corre EN el nodo,
como servicio vivo supervisado. Sin dependencias externas: apto para el nucleo busybox.
Uso: anvos-cockpit-fb.py [once]   (sin arg = bucle vivo; 'once' = un frame y sale)"""
import os, sys, json, mmap, math, struct, time, stat, glob, subprocess, signal, zlib

FBDEV = "/dev/fb0"
PNG_PATH = "/persist/anvos-data/cockpit/cockpit.png"   # snapshot web cuando el fb físico no es pintable
DATA  = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
_MS = os.path.join(STAGING, "pylayer-verify")
_PUB = os.path.join(STAGING, "pylayer", "release.pub")
_MV_CACHE = {"mtime": None, "verified": False}


def _sig_ok(target):
    ld = None
    for c in glob.glob(os.path.join(_MS, "ld-linux*.so.2")):
        ld = c
    sig = target + ".minisig"
    if not (ld and os.path.exists(os.path.join(_MS, "minisign")) and os.path.exists(_PUB)
            and os.path.isfile(target) and os.path.isfile(sig)):
        return False
    try:
        r = subprocess.run([ld, "--library-path", _MS, os.path.join(_MS, "minisign"),
                            "-Vm", target, "-p", _PUB, "-x", sig], capture_output=True, timeout=6)
        return r.returncode == 0
    except Exception:
        return False


def _master_view():
    """HETEROIMAGEN (juicio del master, firmado 653C). Verificación CACHEADA por mtime:
    minisign solo se re-ejecuta cuando el fichero cambia (no cada frame de 4s)."""
    p = os.path.join(DATA, "master-view", "verdict.json")
    try:
        mt = os.path.getmtime(p)
    except Exception:
        return None
    if _MV_CACHE["mtime"] != mt:
        _MV_CACHE["mtime"] = mt
        _MV_CACHE["verified"] = _sig_ok(p)
    try:
        v = json.loads(open(p).read())
    except Exception:
        return {"verdict": "ILEGIBLE", "verified": False, "age_m": None}
    return {"verdict": v.get("veredicto_global"), "verified": _MV_CACHE["verified"],
            "pendientes": v.get("escaladas_abiertas") or 0,
            "age_m": max(0, int((time.time() - mt) / 60))}
W, H, BPP = 1920, 1080, 4          # canvas de diseño (el fb real puede ser mas alto, p.ej. 1920x1200)
STRIDE = W * BPP  # 7680, sin padding


def _fb_ensure():
    """ANVOS sin udev: crea /dev/fb0 desde sysfs si falta (patron gpu_enable/ensure_lo) y
    devuelve la geometria REAL (fw, fh, fstride) del framebuffer, con fallback al canvas."""
    base = "/sys/class/graphics/fb0"
    try:
        if not os.path.exists(FBDEV) and os.path.isfile(base + "/dev"):
            maj, minr = open(base + "/dev").read().strip().split(":")
            os.mknod(FBDEV, 0o600 | stat.S_IFCHR, os.makedev(int(maj), int(minr)))
    except Exception:
        pass
    fw, fh, fstride = W, H, STRIDE
    try:
        fw, fh = [int(x) for x in open(base + "/virtual_size").read().strip().split(",")]
    except Exception:
        pass
    try:
        fstride = int(open(base + "/stride").read().strip())
    except Exception:
        fstride = fw * BPP
    return fw, fh, fstride

# ── paleta (R,G,B) ──
BG=(10,14,22); PANEL=(17,24,37); PANEL2=(23,32,48)
GN=(34,211,122); YW=(234,179,8); RD=(239,68,68)
CY=(34,211,238); VI=(167,139,250); TX=(226,232,240); MT=(120,134,156)

# ── fuente 8x16 embebida (generada con PIL en el master, ver bitacora) ──
_FONT = json.loads('{"32":"00000000000000000000000000000000","33":"00000808080808080000080800000000","34":"00001414141400000000000000000000","35":"00001212167f2424fe28484800000000","36":"0008083e4948683e0b09493e08080000","37":"0000609090620c304609090600000000","38":"00001c20203030494545623d00000000","39":"00000808080800000000000000000000","40":"000c0808101010101010080804000000","41":"00301010080808080808101020000000","42":"000008493e1c6b080000000000000000","43":"000000000808087f0808080000000000","44":"00000000000000000000181810200000","45":"00000000000000003c00000000000000","46":"00000000000000000000181800000000","47":"00000204040408081010202020400000","48":"00001c22414149414141221c00000000","49":"00001828080808080808083e00000000","50":"00003e43010102060c10207f00000000","51":"00003e4101031c030101433e00000000","52":"0000060a1a1222427f02020200000000","53":"00007e40407c42010101423c00000000","54":"00001e3160405e634141231e00000000","55":"00007f03020404080810102000000000","56":"00003e4141413e634141633e00000000","57":"00003c624141633d0103463c00000000","58":"00000000001818000000181800000000","59":"00000000001818000000181810200000","60":"00000000010e3840380e010000000000","61":"00000000007f00007f00000000000000","62":"0000000040380e010e38400000000000","63":"00003844040c18101000101000000000","64":"00001e332147494949494720300e0000","65":"00000814141414223e22414100000000","66":"00007e4141417e434141437e00000000","67":"00001e21404040404040211e00000000","68":"00007c42414141414141427c00000000","69":"00007f4040407f404040407f00000000","70":"00007f4040407f404040404000000000","71":"00001e21404040434141211e00000000","72":"0000414141417f414141414100000000","73":"00003e08080808080808083e00000000","74":"00001e02020202020202463c00000000","75":"00004244485070484c44424100000000","76":"00004040404040404040407f00000000","77":"00006363555555494141414100000000","78":"00006161515149494545434300000000","79":"00001c22414141414141221c00000000","80":"00007e434141437e4040404000000000","81":"00001c22414141414141221e06020000","82":"00007e434141437c4241414000000000","83":"00001e614040300e0101433e00000000","84":"00007f08080808080808080800000000","85":"00004141414141414141633e00000000","86":"00004141222222141414140800000000","87":"0000818181995a5a5a24242400000000","88":"00004122141408141422224100000000","89":"0000412222141c080808080800000000","90":"00007f03020408081020607f00000000","91":"001c101010101010101010101c000000","92":"00004020202010100808040404020000","93":"00380808080808080808080838000000","94":"00000814226300000000000000000000","95":"0000000000000000000000000000ff00","96":"30100800000000000000000000000000","97":"000000001c22023e4242463a00000000","98":"004040407c6442424242645c00000000","99":"000000001c2240404040221c00000000","100":"000202023e2642424242263a00000000","101":"000000003c26427e4040221c00000000","102":"000e10107e1010101010101000000000","103":"000000003a2642424242263a02221c00","104":"004040405c6242424242424200000000","105":"00080800380808080808087f00000000","106":"00080800380808080808080808087000","107":"00404040444850704848444200000000","108":"00f01010101010101010100e00000000","109":"000000007e4949494949494900000000","110":"000000005c6242424242424200000000","111":"000000003c6642424242663c00000000","112":"000000005c6442424242647c40404000","113":"000000003a2642424242263a02020200","114":"000000003c3220202020202000000000","115":"000000003c4240700e02423c00000000","116":"000010107e1010101010100e00000000","117":"00000000424242424242463a00000000","118":"00000000424224242418181800000000","119":"0000000081815a5a5a5a242400000000","120":"00000000422418181824244200000000","121":"00000000422224241418080808103000","122":"000000007e0204081020407e00000000","123":"00060808080808300808080808060000","124":"00080808080808080808080808080800","125":"00300808080808060808080808300000","126":"00000000000000394600000000000000"}')
FONT = {int(k): bytes.fromhex(v) for k, v in _FONT.items()}
GW, GH = 8, 16

class FB:
    def __init__(self):
        self.buf = bytearray(STRIDE * H)
    def clear(self, c):
        r,g,b = c
        row = bytes((b,g,r,0)) * W
        for y in range(H):
            o = y*STRIDE
            self.buf[o:o+STRIDE] = row
    def rect(self, x, y, w, h, c):
        r,g,b = c
        x=max(0,x); y=max(0,y)
        w=min(w, W-x); h=min(h, H-y)
        if w<=0 or h<=0: return
        px = bytes((b,g,r,0)) * w
        for yy in range(y, y+h):
            o = yy*STRIDE + x*BPP
            self.buf[o:o+w*BPP] = px
    def px(self, x, y, c):
        if 0<=x<W and 0<=y<H:
            r,g,b=c; o=y*STRIDE+x*BPP
            self.buf[o]=b; self.buf[o+1]=g; self.buf[o+2]=r; self.buf[o+3]=0
    def text(self, x, y, s, c, scale=2):
        cx = x
        for ch in s:
            glyph = FONT.get(ord(ch))
            if glyph is None:
                cx += (GW+1)*scale; continue
            for gy in range(GH):
                bits = glyph[gy]
                for gx in range(GW):
                    if bits & (1<<(7-gx)):
                        if scale==1:
                            self.px(cx+gx, y+gy, c)
                        else:
                            self.rect(cx+gx*scale, y+gy*scale, scale, scale, c)
            cx += (GW)*scale
        return cx
    def ring(self, cx, cy, rad, frac, c, bgc, thick=16):
        # arco de 270 grados (gauge), pintado por puntos
        import math as _m
        start=135; span=270
        for deg10 in range(0, span*2+1):
            deg = start + deg10/2.0
            on = (deg10/2.0) <= span*frac
            col = c if on else bgc
            a = _m.radians(deg)
            for t in range(thick):
                rr = rad - t
                x = int(cx + rr*_m.cos(a)); y = int(cy + rr*_m.sin(a))
                self.px(x, y, col)
    def blit(self):
        # pinta el canvas 1920x1080 sobre la geometria REAL del fb (p.ej. 1920x1200 del M.2 nativo).
        # Devuelve True si logró escribir el framebuffer; False si el fb NO es escribible (p.ej. el
        # driver DRM i915 no soporta la interfaz legacy fbdev write/mmap) -> el llamador cae a PNG.
        fw, fh, fstride = _fb_ensure()
        if (fw, fh, fstride) == (W, H, STRIDE):
            out = self.buf
        else:
            rows = min(H, fh); rw = min(STRIDE, fstride)
            r,g,b = BG
            bgrow = bytes((b,g,r,0)) * (fstride // BPP)
            out = bytearray(fstride * fh)
            for y in range(fh):
                out[y*fstride:(y+1)*fstride] = bgrow
            for y in range(rows):
                out[y*fstride:y*fstride+rw] = self.buf[y*STRIDE:y*STRIDE+rw]
        try:
            with open(FBDEV, "r+b") as f:
                try:
                    mm = mmap.mmap(f.fileno(), fstride*fh)
                    mm.write(bytes(out)); mm.flush(); mm.close()
                except (OSError, ValueError):
                    # la emulacion fbdev de i915 rechaza mmap (EINVAL) -> via write() plano
                    f.seek(0)
                    f.write(bytes(out))
            return True
        except OSError:
            # ni mmap ni write: el fb no admite la interfaz legacy (DRM/KMS puro) -> señalar fallo
            return False

    def save_png(self, path, scale=1):
        """Escribe el canvas como PNG (solo zlib de stdlib) para VERLO por web cuando el fb físico
        no es pintable (i915 DRM). filtro None, submuestreo opcional por 'scale'. Escritura atómica."""
        W2, H2 = W // scale, H // scale
        raw = bytearray()
        buf = self.buf
        for y in range(H2):
            raw.append(0)                        # filtro None por scanline
            base = (y * scale) * STRIDE
            row = bytearray(W2 * 3)
            j = 0
            for x in range(W2):
                o = base + (x * scale) * BPP     # BGRX -> RGB
                row[j] = buf[o + 2]; row[j + 1] = buf[o + 1]; row[j + 2] = buf[o]; j += 3
            raw += row
        comp = zlib.compress(bytes(raw), 6)

        def _chunk(typ, data):
            return struct.pack(">I", len(data)) + typ + data + struct.pack(">I", zlib.crc32(typ + data) & 0xffffffff)
        png = (b"\x89PNG\r\n\x1a\n"
               + _chunk(b"IHDR", struct.pack(">IIBBBBB", W2, H2, 8, 2, 0, 0, 0))
               + _chunk(b"IDAT", comp) + _chunk(b"IEND", b""))
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(png)
            os.replace(tmp, path)
            return True
        except Exception:
            return False

def _last(path):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2); size=f.tell()
            # 64K: una linea de layerd.jsonl (26 servicios con stats) supera los 4K
            f.seek(max(0, size-65536)); tail=f.read().splitlines()
        for ln in reversed(tail):
            ln=ln.strip()
            if ln:
                return json.loads(ln)
    except Exception:
        pass
    return {}

def _node_id():
    for p in ("/persist/anvos-node.id", "/etc/anvos-node.id"):
        try:
            v = open(p).read().strip()
            if v: return v
        except Exception:
            pass
    return None

def read_state():
    d = lambda p: _last(os.path.join(DATA, p))
    beacon = d("eco-telem/beacon.jsonl")
    sent   = d("sentinel/sentinel.jsonl")
    chain  = d("chain/chain_status.jsonl")
    ai     = d("ai/router.jsonl")
    integ  = d("integrity/self_integrity.jsonl")
    push   = d("push/telem_push.jsonl")
    gov    = d("governance/cognition_guard.jsonl")
    # capa de AUTOCONCIENCIA (sensa/predice/aconseja/recuerda/honeypot/autoprueba)
    core   = d("sentinel/core_audit.jsonl")
    twin   = d("twin/twin_forward.jsonl")
    adv    = d("governance/advisor.jsonl")
    memo   = d("memory/event_ledger.jsonl")
    dec    = d("deception/deception_sensor.jsonl")
    isim   = d("asct/incident_sim.jsonl")
    rsim   = d("asct/rollback_sim.jsonl")
    layerd = d("layerd/layerd.jsonl")
    # FASE 2: módulos de dominio activos (perfil firmado) + APRENDIZAJE de 6 sentidos + NETFLOW
    prof = {}
    try:
        prof = json.loads(open("/persist/anvos-modules/profile.json").read())
    except Exception:
        prof = {}
    mods = [str(m) for m in (prof.get("enabled_modules") or [])]
    learn = d("learning/event_learn.jsonl")
    _LSRC = ("from_episodic", "from_metrics", "from_fib", "from_deception", "from_netflow", "from_modbus", "from_merkle")
    lsrc = sum(1 for k in _LSRC if (learn.get(k, 0) or 0) > 0)
    try:
        lpend = len([f for f in os.listdir(os.path.join(DATA, "learning", "pending"))
                     if f.startswith("DRAFT_LEARN_")])
    except Exception:
        lpend = 0
    nflow = d("modules/netflow/netflow.jsonl")
    banchor = d("chain/block_anchor.jsonl")   # cadena de bloques merkle propia del nodo
    realm = d("realm/realm.jsonl")             # soberanía del nodo (realm propio, Vía A)
    # identidad soberana del nodo: env -> fichero id -> nombre de servicio -> fallback
    node = os.environ.get("ANVOS_NODE") or _node_id() \
        or (beacon.get("node") if beacon.get("node") not in (None,"unknown") else None) or "anvos-node"
    # salud LOCAL del nodo derivada del beacon (el AV soberano lo computa el master; aqui
    # mostramos la salud local honesta: 1 - carga ponderada de cpu/disco/memoria)
    cpu=beacon.get("cpu_load",0) or 0
    disk=(beacon.get("disk_pct",0) or 0)/100.0
    mem=(beacon.get("mem_pct",0) or 0)/100.0
    salud = round(max(0.0, min(1.0, 1.0 - (cpu*0.2 + disk*0.3 + mem*0.2))), 3)
    # uptime real del kernel (fiable), no del beacon
    up = 0
    try: up = float(open("/proc/uptime").read().split()[0])
    except Exception: up = sent.get("uptime_s",0) or 0
    return {
        "node": node,
        "av": salud,
        "cpu": cpu, "mem": beacon.get("mem_pct",0) or 0, "disk": beacon.get("disk_pct",0) or 0,
        "uptime": up,
        "immune": sent.get("immune_state", sent.get("state","CALM")),
        "findings": len(sent.get("findings",[]) or []),
        "chain_ok": bool(chain.get("all_ok", chain.get("ok", False))),
        "ai": ("router-ready" if (ai.get("n_models",0) or 0) > 0 else ai.get("status","en-espera")),
        "ai_models": ai.get("n_models", 0) or 0,
        "attest": integ.get("attestation", "-"),
        "attest_ok": integ.get("all_valid", integ.get("verifier_ok", None)),
        "sealed": "%s/%s" % (integ.get("verified",0), integ.get("total",0)) if integ else "-",
        "gov": gov.get("verdict", "-"),
        "governed": gov.get("governed", None),
        "gov_authority": (gov.get("authority_os_keyid") or "")[:8],
        # autoconciencia
        "chs": core.get("core_health_score"),
        "chs_state": core.get("state", "-"),
        "chs_findings": core.get("findings_dedup", core.get("findings_total", 0)) or 0,
        "twin_state": twin.get("state", "-"),
        "twin_worst": str(twin.get("worst_metric") or "-"),
        "twin_idg": twin.get("idg"),
        "twin_break": str(twin.get("first_to_break") or "NINGUNO"),
        "adv_level": adv.get("recommended_level", "-"),
        "mem_seq": memo.get("total_seq", 0) or 0,
        "mem_ok": memo.get("chain_ok", None),
        "dec_baits": len(dec.get("bait_ports", []) or []),
        "dec_hits": dec.get("hits_total", 0) or 0,
        "isim_ok": isim.get("verdict") == "DETECTOR_OK",
        "isim_n": "%s/%s" % (isim.get("passed", "-"), isim.get("total", "-")),
        "rsim_ok": rsim.get("verdict") == "RECOVERY_OK",
        "rsim_n": "%s/%s" % (rsim.get("passed", "-"), rsim.get("total", "-")),
        "svcs_n": len(layerd.get("services", {}) or {}),
        # Fallos ACTUALES, no acumulado de por vida: un servicio esta en fallo si su ultima ejecucion
        # devolvio codigo != 0, o su firma no valida, o es un daemon 'long' que ya no esta vivo. Un
        # periodico dormido entre ciclos (alive=False con last_rc=0) NO es un fallo. Sumar el contador
        # 'fail' de por vida (bug anterior) mostraba 14 FAIL con 0 fallos reales. Arreglo 2026-08-14.
        "svcs_fail": sum(1 for v in (layerd.get("services", {}) or {}).values()
                         if (v.get("sig_ok") is False)
                         or (v.get("last_rc") not in (0, None))
                         or (v.get("kind") == "long" and not v.get("alive"))),
        # FASE 2 módulos + aprendizaje 6 sentidos + netflow
        "mods": mods, "mods_n": len(mods),
        "learn_status": learn.get("status", "-"),
        "learn_sources": lsrc,
        "learn_pending": lpend,
        "learn_last": (learn.get("drafted") or {}).get("kind") if learn.get("drafted") else None,
        "nf_estab": nflow.get("established", 0) or 0,
        "nf_ext": nflow.get("external_peers", 0) or 0,
        "blk_height": banchor.get("height", 0) or 0,
        "blk_verified": banchor.get("verified", None),
        "realm_sov": realm.get("soberano", None),
        "realm_estado": str(realm.get("estado") or "-"),
        "realm_id": str(realm.get("realm_id") or ""),
        "mv": _master_view(),
    }

def draw(fb, st):
    fb.clear(BG)
    # cabecera
    fb.rect(0,0,W,92,PANEL)
    fb.text(40,26,"ASTRANOVAOS",TX,4)
    fb.text(430,40,"COCKPIT SOBERANO",CY,2)
    online = st["av"]>0
    ec = GN if online else RD
    fb.rect(W-360,30,28,28,ec)
    fb.text(W-315,34,"OPERATIVO" if online else "OFFLINE",ec,2)
    # identidad nodo
    fb.rect(40,120,580,180,PANEL)
    fb.text(66,140,"NODO",MT,2)
    fb.text(66,176,st["node"][:22].upper(),TX,3)
    up=int(st["uptime"] or 0)
    fb.text(66,240,"UPTIME %dH %dM" % (up//3600,(up%3600)//60),MT,2)
    sc = GN if (st["svcs_n"] and not st["svcs_fail"]) else (YW if st["svcs_n"] else MT)
    fb.text(66,268,"CAPA %d SVCS . %d FAIL" % (st["svcs_n"], st["svcs_fail"]),sc,1)
    rsov = st.get("realm_sov")
    rtxt = ("REALM SOBERANO %s" % st.get("realm_id","")[:20]) if rsov else \
           ("REALM: PENDING-GENESIS" if st.get("realm_estado") == "clean-node-pending-genesis" else "REALM: -")
    fb.text(66,286,rtxt, GN if rsov else MT, 1)
    # gauge central: CORE HEALTH SCORE (salud auto-percibida por core_audit); cae a salud local
    fb.rect(650,120,470,350,PANEL)
    chs = st["chs"]
    if isinstance(chs,(int,float)):
        col = GN if chs>=0.8 else (YW if chs>=0.6 else RD)
        fb.ring(885,300,130,min(max(chs,0.0),1.0),col,PANEL2,18)
        fb.text(788,268,"%.3f"%chs,TX,5)
        fb.text(760,428,"CORE HEALTH (AUTOCONCIENCIA)",MT,1)
        fb.text(808,450,"SALUD LOCAL %.3f"%st["av"],MT,1)
    else:
        av=st["av"]; col = GN if av>=0.9 else (YW if av>=0.8 else RD)
        fb.ring(885,300,130,min(av,1.0),col,PANEL2,18)
        fb.text(788,268,"%.3f"%av,TX,5)
        fb.text(808,360,"SALUD DEL NODO",MT,2)
    # inmune / cadena / IA / MÓDULOS+APRENDIZAJE
    fb.rect(1150,120,W-40-1150,350,PANEL)
    ic = GN if st["immune"] in ("CALM","GREEN") else YW
    fb.text(1176,138,"SISTEMA INMUNE",MT,2)
    fb.text(1176,166,str(st["immune"]).upper(),ic,2)
    fb.text(1176,208,"BLOCKCHAIN NODO",MT,2)
    bh = st.get("blk_height", 0); bv = st.get("blk_verified")
    btxt = ("INTEGRA" if st["chain_ok"] else "FALLO") + (" . %d BLOQUES" % bh if bh else "")
    bcol = GN if (st["chain_ok"] and bv is not False) else RD
    fb.text(1176,236,btxt, bcol, 2)
    fb.text(1176,278,"IA LOCAL",MT,2)
    fb.text(1176,306,("%s MODELOS"%st["ai_models"]) if st["ai"]=="router-ready" else "EN ESPERA",
            CY if st["ai"]=="router-ready" else MT,2)
    # MÓDULOS de dominio (Fase 2, perfil firmado) + APRENDIZAJE de 6 sentidos
    mc = GN if st["mods_n"] else MT
    fb.text(1176,348,"MODULOS (PERFIL)",MT,2)
    fb.text(1176,376,("%d . %s" % (st["mods_n"], "+".join(st["mods"]))).upper()[:44] if st["mods_n"] else "NINGUNO",
            mc,1)
    lc = GN if st["learn_sources"] >= 4 else (CY if st["learn_sources"] else MT)
    fb.text(1176,400,"APRENDE %d/7 SENTIDOS . %d BORRADORES" % (st["learn_sources"], st["learn_pending"]),
            lc,1)
    fb.text(1176,420,("ULTIMO: %s" % str(st["learn_last"]).upper()) if st["learn_last"] else "IA PROPONE . HUMANO FIRMA",
            MT,1)
    # AUTOCONCIENCIA (sensa -> predice -> aconseja -> recuerda + honeypot + autoprueba)
    fb.rect(40,500,W-80,310,PANEL)
    fb.text(66,516,"AUTOCONCIENCIA",VI,2)
    att_ok = st["attest_ok"]
    att_col = GN if att_ok else (YW if att_ok is None else RD)
    fb.text(320,522,"SELF_INTEGRITY %s (%s)" % (str(st["attest"]).upper(), st["sealed"]), att_col,1)
    gv = st["governed"]
    gv_col = GN if gv else (YW if gv is None else RD)
    gtxt = "GOBERNANZA %s" % str(st["gov"]).upper()
    if st["gov_authority"]:
        gtxt += " . AUTORIDAD %s" % st["gov_authority"]
    fb.text(700,522,gtxt,gv_col,1)
    mv = st.get("mv")
    if mv is None:
        fb.text(1240,522,"MASTER: SIN VISTA",MT,1)
    else:
        pend = mv.get("pendientes") or 0
        okv = mv.get("verified") and mv.get("verdict") == "NODO_EN_ORDEN" and not pend
        mv_col = GN if okv else RD
        mtxt = "MASTER: %s . %s" % (str(mv.get("verdict") or "?").replace("_"," "),
                                    "FIRMA OK" if mv.get("verified") else "NO VERIFICADA")
        if pend:
            mtxt += " . %d ESCALADAS SIN ATENDER" % pend
        if mv.get("age_m") is not None:
            mtxt += " . HACE %dM" % mv["age_m"]
        fb.text(1240,522,mtxt[:78],mv_col,1)

    _GOOD={"HEALTHY":GN,"WATCH":YW,"DEGRADED":YW,"CRITICAL":RD,
           "COHERENTE":GN,"CALIBRANDO":CY,"DIVERGENCIA_LEVE":YW,"CAMBIO_REGIMEN":RD}
    idg = ("%.3f"%st["twin_idg"]) if isinstance(st["twin_idg"],(int,float)) else "-"
    adv = str(st["adv_level"]).upper()
    adv_col = GN if adv.startswith("A0") else (CY if adv.startswith("A1") else
              (YW if adv.startswith(("A2","A3")) else (RD if adv.startswith(("A4","A5")) else MT)))
    mem_col = GN if st["mem_ok"] else (YW if st["mem_ok"] is None else RD)
    dec_col = YW if (st["dec_hits"] or st["nf_ext"]) else GN
    fd_ok = st["isim_ok"] and st["rsim_ok"]
    tiles=[
        ("SENSA . CORE AUDIT", str(st["chs_state"]).upper(),
         _GOOD.get(st["chs_state"],MT),
         "SCORE %s . %d HALLAZGOS" % (("%.2f"%st["chs"]) if isinstance(st["chs"],(int,float)) else "-",
                                      st["chs_findings"])),
        ("PREDICE . GEMELO 5 METRICAS", str(st["twin_state"]).upper(),
         _GOOD.get(st["twin_state"],MT),
         "PEOR EJE %s . IDG %s . ROMPERIA %s" % (st["twin_worst"].upper(), idg, st["twin_break"].upper())),
        ("ACONSEJA . PLANO DE RESPUESTA", adv, adv_col, "ADVISORY . NUNCA EJECUTA NI FIRMA"),
        ("APRENDE . 7 SENTIDOS -> LECCION",
         "%d/7 FUENTES . %d BORRADORES" % (st["learn_sources"], st["learn_pending"]),
         GN if st["learn_sources"] >= 4 else (CY if st["learn_sources"] else MT),
         "MEM SEQ %d . IA PROPONE, HUMANO FIRMA" % st["mem_seq"]),
        ("RED . HONEYPOT + NETFLOW", "%d SONDEOS . %d PEER EXT" % (st["dec_hits"], st["nf_ext"]), dec_col,
         "%d CEBOS . %d CONEXIONES . OBSERVE-ONLY" % (st["dec_baits"], st["nf_estab"])),
        ("AUTOPRUEBA . FIRE-DRILLS",
         "DETECTOR %s . RECOVERY %s" % (st["isim_n"], st["rsim_n"]),
         GN if fd_ok else YW, "INCIDENT-SIM + ROLLBACK-SIM EN SOMBRA"),
    ]
    for i,(lab,val,vc,sub) in enumerate(tiles):
        cx=66+(i%3)*610; ry=556+(i//3)*122
        fb.rect(cx,ry,580,110,PANEL2)
        fb.text(cx+18,ry+10,lab,MT,1)
        fb.text(cx+18,ry+34,val[:35],vc,2)
        fb.text(cx+18,ry+82,sub[:70],MT,1)
    # recursos (barras)
    fb.rect(40,830,W-80,180,PANEL)
    fb.text(66,846,"RECURSOS DEL NODO",CY,2)
    bars=[("CPU",st["cpu"]*100),("MEM",st["mem"]),("DISK",st["disk"])]
    bx=66
    for name,val in bars:
        val=max(0.0,min(100.0,float(val or 0)))
        bh=int(val/100.0*100)
        bc = GN if val<70 else (YW if val<88 else RD)
        fb.rect(bx,990-bh,180,bh,bc)
        fb.text(bx+200,990-32,"%s %d%%"%(name,int(val)),TX,2)
        bx+=440
    # pie
    fb.text(40,1035,"ASTRANOVAOS . NUCLEO BUSYBOX VERIFICADO + CAPA PYTHON FIRMADA . FAIL-CLOSED",MT,1)
    fb.text(W-330,1030,"COCKPIT FB V2.5 . MODULOS + APRENDIZAJE",MT,1)

CONSOLE_FLAG = "/persist/anvos-data/cockpit/console_mode"


def _set_bind(val):
    """Vincula (1) o desvincula (0) el vtcon del frame buffer. Idempotente: solo escribe
    si el estado difiere (lectura barata, apto por-ciclo)."""
    try:
        for name in os.listdir("/sys/class/vtconsole"):
            p = "/sys/class/vtconsole/" + name
            try:
                if "frame buffer" not in open(p + "/name").read():
                    continue
                if open(p + "/bind").read().strip() != val:
                    open(p + "/bind", "w").write(val + "\n")
            except Exception:
                pass
    except Exception:
        pass


def _own_display():
    """Desvincula fbcon para que el cockpit sea el DUEÑO de la pantalla física.
    RE-AFIRMABLE por ciclo: i915 puede crear/re-vincular el vtcon DESPUÉS del arranque del
    cockpit (parpadeo post-boot)."""
    _set_bind("0")


def _release_display():
    """Devuelve la pantalla a la consola del kernel (fbcon). Vías de uso: modo consola del
    operador (bandera CONSOLE_FLAG) y FAIL-OPEN al salir el cockpit — sin cockpit vivo la
    pantalla física debe ser una consola, nunca un frame congelado."""
    _set_bind("1")


def _sigterm(*_a):
    raise SystemExit(143)



# --- LATIDO (2026-07-29) -------------------------------------------------------------------
# Este servicio solo escribía en su salida CUANDO FALLABA: sano = fichero sin tocar = la
# vigilancia de frescura lo daba por "estancado" para siempre (falso positivo permanente
# observado en origo: 1305 días de "salida vieja" mientras la pantalla se pintaba bien).
# Un latido periódico hace que el silencio signifique de verdad "algo va mal".
_LAT_PATH = "/persist/anvos-data/cockpit/cockpit_heartbeat.jsonl"
_LAT_CADA = 15          # ciclos de 4 s -> ~1 min entre latidos (no infla el disco)
_lat_n = [0]


def _latido(fb_mode, err=None):
    _lat_n[0] += 1
    if err is None and _lat_n[0] % _LAT_CADA:
        return
    try:
        os.makedirs(os.path.dirname(_LAT_PATH), exist_ok=True)
        modo = "fb" if fb_mode else ("png" if fb_mode is False else "iniciando")
        rec = {"svc": "anvos-cockpit-fb", "ts": int(time.time()), "modo": modo,
               "estado": "PINTANDO" if err is None else "ERROR"}
        if err:
            rec["error"] = err
        with open(_LAT_PATH, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass                                   # el latido NUNCA puede tumbar al cockpit


def main():
    once = len(sys.argv)>1 and sys.argv[1]=="once"
    signal.signal(signal.SIGTERM, _sigterm)
    _own_display()
    fb = FB()
    fb_mode = None   # None=sin decidir, True=fb pintable, False=fb NO pintable -> modo PNG web (sin spam)
    try:
        while True:
            # modo consola del operador: con la bandera puesta, el cockpit CEDE la pantalla
            # a fbcon y no pinta; al quitarla, la recupera en el siguiente ciclo
            if os.path.exists(CONSOLE_FLAG):
                _release_display()
                if once: break
                time.sleep(4)
                continue
            try:
                st = read_state()
                draw(fb, st)
                if fb_mode is not False:
                    _own_display()
                    ok = fb.blit()
                    if fb_mode is None:
                        fb_mode = ok
                        if not ok:
                            # el fb no admite la interfaz legacy (DRM/KMS i915): pasar a modo PNG web
                            _release_display()   # devolver la pantalla a fbcon (no la vamos a usar)
                            sys.stderr.write("cockpit: /dev/fb0 no escribible (DRM); modo PNG web -> %s\n" % PNG_PATH)
                # snapshot PNG SIEMPRE (para ver el cockpit por web/dashboard, imprescindible si fb no pinta)
                fb.save_png(PNG_PATH)
                _latido(fb_mode, err=None)
            except Exception as e:
                sys.stderr.write("cockpit err: %s\n" % e)
                _latido(fb_mode, err=str(e)[:120])
            if once: break
            time.sleep(4)
    finally:
        _release_display()

if __name__ == "__main__":
    main()
