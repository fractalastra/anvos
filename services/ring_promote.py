#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""ring_promote — TRI-RING INTERNO del nodo ANVOS: promoción escalonada DEV -> MIRROR -> MAIN.
Réplica node-local del tri-ring de discos del master (promoción dev→mirror→main),
con la MISMA propiedad de integridad + rollback + evolución por etapas, sobre PERSIST.
NO es un servicio periódico (no va en el manifiesto): es una HERRAMIENTA on-demand (operador /
AstraNova Code) que vive en la capa firmada para quedar atestada por self_integrity.

Roles (dirs bajo /persist):
  DEV    = anvos-ring/dev      -> staging: aquí aterrizan capas nuevas firmadas para probar.
  MIRROR = anvos-ring/mirror   -> copia verificada intermedia.
  MAIN   = anvos-staging/services -> capa ACTIVA autoritativa (lo que corre el daemon layerd).
Regla MIRROR-ONLY: MAIN solo se escribe por la promoción desde MIRROR (nunca desde DEV directo).

Pipeline `promote` (fail-closed en cada salto):
  1. verificar TODAS las firmas en DEV (minisign embebido); si alguna falla -> ABORTA, nada cambia.
  2. copiar DEV -> MIRROR; re-verificar MIRROR.
  3. (mirror-only) respaldar MAIN actual -> backups/main_<ts>; copiar MIRROR -> MAIN.
  4. re-verificar MAIN (self_integrity); si falla -> AUTO-ROLLBACK al respaldo.
  5. registrar promoción en promotion.chain (encadenada) + main_manifest.json (índice de
     ficheros+hashes) = GANCHO PARA EL PASO 2 (replicación entre nodos): un peer replica MAIN,
     verifica cada .minisig (653C) y contrasta con este manifiesto + la cabeza de la cadena.

Modos: init | status | verify <dir> | promote | rollback . Solo stdlib + minisign embebido."""
import os
import sys
import json
import time
import glob
import shutil
import hashlib
import subprocess

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
PERSIST = os.environ.get("ANVOS_PERSIST", "/persist")
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
MS = os.path.join(STAGING, "pylayer-verify")
# La verificación de firmas va por la partición A/B (verify_file en _verify_sig). El
# antiguo _release_pubs de F0 (contra release.d) se ELIMINÓ tras el gate de gobernanza
# (higiene 15-ago): código muerto que un futuro podría recablear y reabrir la grieta.
RING = os.path.join(PERSIST, "anvos-ring")
DEV = os.path.join(RING, "dev")
MIRROR = os.path.join(RING, "mirror")
MAIN = os.path.join(STAGING, "services")          # capa ACTIVA = MAIN
BACKUPS = os.path.join(RING, "backups")
CHAIN = os.path.join(RING, "promotion.chain")
CHAIN_HEAD = CHAIN + ".head"
MANIFEST = os.path.join(RING, "main_manifest.json")
REC = os.path.join(DATA, "ring", "ring_promote.jsonl")
GEN = "0" * 64


def _ld():
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


def _verify_sig(ld, target):
    """Promoción bajo PARTICIÓN A/B: un fichero de gobernanza (Set B) NO se promueve si va
    firmado por la llave de origo — solo por la 653C horneada. Cierra que origo se auto-
    promueva un guardián neutralizado."""
    sig = target + ".minisig"
    if not (ld and os.path.exists(os.path.join(MS, "minisign"))
            and os.path.isfile(target) and os.path.isfile(sig)):
        return False   # fail-closed
    return _ap().verify_file(target, sig)


def _bundle_files(d):
    """Ficheros firmables del bundle en dir d: manifest.txt + ejecutables (cada uno con su .minisig).

    EXTENSIONES (2026-07-29): antes el conjunto era manifest.txt + *.py, asi que un .pyz quedaba
    FUERA de la promocion: su binario llegaba al nodo por otra via y su firma NUNCA viajaba. Efecto
    medido: sentinel.pyz estuvo 18 dias en origo Y nodo-c sin .minisig, y la capa inmune se negaba a
    cargarlo (fail-closed correcto) mientras el panel aparentaba vigilancia. Es la misma propiedad
    que hace invisible un sidecar nuevo -lo que en el plan post-cuantico es la ventaja que garantiza
    que nada se rompe- vista por su cara mala: aqui dejaba un ejecutable sin su firma.
    """
    out = []
    mani = os.path.join(d, "manifest.txt")
    if os.path.isfile(mani):
        out.append(mani)
    # RECORRIDO RECURSIVO (ITV-071, 2026-08-07). Antes era un glob PLANO, de modo que todo lo que
    # viviera en un subdirectorio quedaba FUERA de la tuberia: ni se promocionaba, ni se verificaba,
    # ni se limpiaba. El arbol semantic_core llego asi a los dos nodos —por copia directa, fuera del
    # anillo— y uno de sus ficheros paso semanas sin firma sin que nada lo dijera.
    #
    # Es la misma familia que la correccion de 2026-07-29 sobre los .pyz: un artefacto que la capa
    # ejecuta pero la tuberia no reconoce viaja por otra via, y entonces su firma no viaja con el.
    # Alli faltaba una extension; aqui faltaba un nivel de profundidad.
    #
    # Se excluye __pycache__: el bytecode no se firma y no debe promocionarse.
    for raiz, _dirs, ficheros in os.walk(d):
        if "__pycache__" in raiz:
            continue
        for n in sorted(ficheros):
            if n.endswith((".py", ".pyz", ".sh", ".yaml")):
                out.append(os.path.join(raiz, n))
    return sorted(set(out))


def verify_dir(ld, d):
    """Verifica TODAS las firmas del bundle en d. (ok:bool, total, invalid[])."""
    files = _bundle_files(d)
    # Ruta relativa, no nombre suelto: con subdirectorios, "x.py" no dice CUAL es (ITV-071).
    invalid = [os.path.relpath(f, d) for f in files if not _verify_sig(ld, f)]
    return (len(invalid) == 0 and len(files) > 0), len(files), invalid


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _content_hash(d):
    """Hash determinista del CONTENIDO del bundle (RUTA RELATIVA + sha de cada fichero y su firma).

    Se usa la ruta relativa y no el nombre suelto (ITV-071): con el recorrido ya recursivo, dos
    ficheros con el MISMO nombre en carpetas distintas producirian entradas identicas y la huella
    dejaria de distinguir un arbol de otro. Una huella que no distingue no sirve para comparar
    anillos, que es exactamente para lo que existe.
    """
    parts = []
    for f in _bundle_files(d):
        rel = os.path.relpath(f, d)
        parts.append("%s:%s" % (rel, _sha(f)))
        sig = f + ".minisig"
        if os.path.isfile(sig):
            parts.append("%s:%s" % (rel + ".minisig", _sha(sig)))
    return hashlib.sha256("\n".join(sorted(parts)).encode()).hexdigest()


def _copy_bundle(src, dst):
    """Copia el bundle (manifest + *.py + *.minisig) de src a dst de forma limpia."""
    os.makedirs(dst, exist_ok=True)
    # Limpiar dst SOLO de los ficheros que este bundle gestiona, y de SUS firmas.
    #
    # Antes el patron de limpieza incluia "*.minisig" a secas, con lo que se borraba la firma
    # de CUALQUIER artefacto de MAIN, tambien de los que el bundle no gestiona; despues solo se
    # recopiaban las firmas de los suyos. Efecto medido el 30-jul-2026: ring_link_peers.json es
    # una configuracion POR NODO (cada nodo tiene la suya, no viaja por el anillo compartido) y
    # su .minisig desaparecio de origo en la primera promocion posterior a firmarla. ring_link es
    # fail-closed y sin firma valida no aplica ningun par: la malla recien levantada se habria
    # caido en silencio, y en el nodo se veria como "nunca estuvo enlazada".
    #
    # La limpieza no puede ser mas ancha que la copia. Si borro algo que no voy a reponer, lo
    # estoy destruyendo, no promocionandolo.
    #
    # RUTAS RELATIVAS, NO NOMBRES SUELTOS (ITV-071, 2026-08-07). Antes se copiaba con basename, lo
    # cual bastaba mientras el recorrido era plano. Al hacerlo recursivo, copiar por basename
    # APLANARIA el arbol: semantic_core/validators/x.py aterrizaria como x.py en la raiz, machacando
    # posiblemente otro fichero del mismo nombre. La limpieza se hace igual de recursiva, para que
    # siga cumpliendose el principio que este fichero ya llevaba escrito: la limpieza no puede ser
    # mas ancha que la copia, ni mas estrecha —si es mas estrecha, quedan restos de la tanda
    # anterior mezclados con la nueva—.
    _viejos = [os.path.join(dst, "manifest.txt"), os.path.join(dst, "manifest.txt.minisig")]
    for _raiz, _dirs, _fich in os.walk(dst):
        if "__pycache__" in _raiz:
            continue
        for _n in _fich:
            if _n.endswith((".py", ".pyz", ".sh", ".yaml")):
                _f = os.path.join(_raiz, _n)
                _viejos += [_f, _f + ".minisig", _f + ".mldsa"]  # P2 PQC: limpiar tambien el sidecar
    for old in _viejos:
        try:
            if os.path.isfile(old):
                os.remove(old)
        except Exception:
            pass
    for f in _bundle_files(src):
        rel = os.path.relpath(f, src)
        destino = os.path.join(dst, rel)
        os.makedirs(os.path.dirname(destino), exist_ok=True)
        shutil.copy2(f, destino)
        sig = f + ".minisig"
        if os.path.isfile(sig):
            shutil.copy2(sig, destino + ".minisig")
        mldsa = f + ".mldsa"          # P2 PQC: el sidecar ML-DSA viaja con su artefacto
        if os.path.isfile(mldsa):
            shutil.copy2(mldsa, destino + ".mldsa")


def _self_integrity_ok():
    """Ejecuta self_integrity contra MAIN (anvos-staging) y devuelve (ok, verified, total)."""
    si = os.path.join(MAIN, "self_integrity.py")
    if not os.path.isfile(si):
        return None, 0, 0
    try:
        py = os.environ.get("ANVOS_PY", "/usr/bin/anvos-python3")
        r = subprocess.run([py, si], capture_output=True, timeout=30, text=True)
        d = json.loads(r.stdout.strip().splitlines()[-1])
        return bool(d.get("all_valid")), d.get("verified", 0), d.get("total", 0)
    except Exception:
        return None, 0, 0


def _write_manifest():
    files = []
    for f in _bundle_files(MAIN):
        # P4 PQC (anti-degradacion): marca si el artefacto lleva sidecar ML-DSA. Una vez pq:true en el
        # manifiesto FIRMADO+encadenado, borrar el sidecar deja de ser "legacy aceptado" y pasa a
        # TAMPER (el atacante no puede volver pq:false sin romper la firma del manifiesto).
        files.append({"name": os.path.basename(f), "sha256": _sha(f),
                      "pq": os.path.isfile(f + ".mldsa")})
    man = {
        "typ": "ANV-RING-MAIN-MANIFEST-v1",
        "ts": int(time.time()),
        "content_hash": _content_hash(MAIN),
        "files": files,
        "note": "indice de MAIN para replicacion entre nodos (paso 2); cada .py va firmado 653C aparte",
    }
    with open(MANIFEST, "w") as f:
        json.dump(man, f, ensure_ascii=False, indent=2)
    return man["content_hash"]


def _chain_append(action, ch, extra=None):
    prev = open(CHAIN_HEAD).read().strip() if os.path.exists(CHAIN_HEAD) else GEN
    rec = {"ts": int(time.time()), "action": action, "content_hash": ch, "prev": prev}
    if extra:
        rec.update(extra)
    h = hashlib.sha256((prev + json.dumps(rec, sort_keys=True)).encode()).hexdigest()
    rec["hash"] = h
    with open(CHAIN, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    open(CHAIN_HEAD, "w").write(h + "\n")
    return h


def _record(rec):
    os.makedirs(os.path.dirname(REC), exist_ok=True)
    with open(REC, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _emit(d):
    print(json.dumps(d, ensure_ascii=False))
    _record(d)


def cmd_init():
    ld = _ld()
    os.makedirs(RING, exist_ok=True)
    os.makedirs(BACKUPS, exist_ok=True)
    ok, total, invalid = verify_dir(ld, MAIN)
    if not ok:
        _emit({"svc": "ring_promote", "action": "init", "ok": False,
               "error": "MAIN no verifica; no se puede sembrar", "invalid": invalid})
        return 1
    # sembrar DEV y MIRROR desde MAIN (baseline)
    _copy_bundle(MAIN, DEV)
    _copy_bundle(MAIN, MIRROR)
    ch = _write_manifest()
    h = _chain_append("init", ch, {"seeded_from": "MAIN"})
    _emit({"svc": "ring_promote", "action": "init", "ok": True, "roles": {"DEV": DEV, "MIRROR": MIRROR, "MAIN": MAIN},
           "content_hash": ch, "chain_head": h[:16], "files": total})
    return 0


def cmd_status():
    ld = _ld()
    st = {}
    for name, d in (("DEV", DEV), ("MIRROR", MIRROR), ("MAIN", MAIN)):
        if os.path.isdir(d):
            ok, total, invalid = verify_dir(ld, d)
            st[name] = {"exists": True, "verified": ok, "files": total, "invalid": invalid,
                        "content_hash": _content_hash(d)[:16]}
        else:
            st[name] = {"exists": False}
    head = open(CHAIN_HEAD).read().strip()[:16] if os.path.exists(CHAIN_HEAD) else None
    synced = (st.get("MAIN", {}).get("content_hash") == st.get("MIRROR", {}).get("content_hash"))
    _emit({"svc": "ring_promote", "action": "status", "roles": st,
           "chain_head": head, "main_eq_mirror": synced})
    return 0


def cmd_verify(which):
    ld = _ld()
    d = {"dev": DEV, "mirror": MIRROR, "main": MAIN}.get(which.lower())
    if not d:
        _emit({"svc": "ring_promote", "action": "verify", "ok": False, "error": "rol desconocido"})
        return 2
    ok, total, invalid = verify_dir(ld, d)
    _emit({"svc": "ring_promote", "action": "verify", "role": which, "ok": ok,
           "files": total, "invalid": invalid})
    return 0 if ok else 1


def _asct_sim_dev():
    """ASCT ligero (pre-flight): simula el bundle DEV (sintaxis+firma+import+rollback) ANTES de
    promover. Devuelve el veredicto, o None si asct_sim no está (backward-compat -> no bloquea)."""
    sim = os.path.join(MAIN, "asct_sim.py")
    py = os.environ.get("ANVOS_PY", "/usr/bin/anvos-python3")
    if not os.path.isfile(sim):
        return None
    try:
        r = subprocess.run([py, sim, "sim-dev", DEV], capture_output=True, timeout=120, text=True)
        for line in reversed((r.stdout or "").splitlines()):
            line = line.strip()
            if line.startswith("{"):
                return json.loads(line)
    except Exception:
        pass
    return None


# ── LAZO DICTAMEN-ACTO (ITD-008, medido por revisor-d; cerrado el 02-ago-2026) ────────────────────
#
# Hasta hoy el nodo tenia CUATRO guardianes emitiendo juicio y ningun acto que obedeciera. El de
# gobernanza lo leen once servicios y los once lo usan para observar, puntuar, pintar o escalar;
# el anclaje de bloques lo mete como HOJA del bloque, o sea lo constata pero no lo obedece; el
# quorum de flota y el guardian de emision no los consume nadie. Los unicos actos fail-closed
# reales del nodo eran los de FIRMA, nunca los de GOBIERNO.
#
# Un dictamen que nadie obedece no gobierna: describe. Este es el primer lazo cerrado.
#
# POR QUE ESTE ACTO. La promocion es lo que cambia lo que el nodo EJECUTA. Negarla dice algo
# preciso y defendible: *un nodo que no esta gobernado no se cambia a si mismo*. Y negarla es
# seguro en la direccion correcta —el nodo se queda como estaba, que es el estado que ya venia
# funcionando—, a diferencia de negar un arranque o una firma.
#
# EL RIESGO QUE HAY QUE NOMBRAR: si se niega tambien cuando falta el dictamen, un nodo cuyo
# guardian se rompa no podria promover NUNCA MAS, ni siquiera la correccion del propio guardian.
# Eso es un cepo, no una defensa. Por eso la ausencia de dictamen tambien niega —callar no puede
# valer por un si— pero existe una salida de emergencia explicita por entorno que queda
# REGISTRADA en el mismo acto. Una puerta de emergencia que no deja rastro es una puerta trasera.
GOV = os.path.join(DATA, "governance", "cognition_guard.jsonl")
GOV_MAX_EDAD_S = 7200          # margen amplio: negar por un dictamen viejo seria un cepo por reloj


def _gobernanza():
    """Ultimo dictamen de gobernanza: (permite, veredicto, motivo, edad_s)."""
    ultimo = None
    try:
        for ln in open(GOV, errors="replace"):
            ln = ln.strip()
            if ln.startswith("{"):
                ultimo = ln
        d = json.loads(ultimo) if ultimo else None
    except Exception:
        d = None

    if not d:
        return False, "SIN_DICTAMEN", ("no hay dictamen de gobernanza que leer; la ausencia de juicio "
                                       "no vale por un si"), None

    ts = d.get("ts")
    edad = int(time.time() - ts) if isinstance(ts, (int, float)) else None
    if edad is not None and edad > GOV_MAX_EDAD_S:
        return False, "DICTAMEN_CADUCO", ("el ultimo dictamen tiene %d s y el margen es %d: un juicio "
                                          "viejo describe un nodo que ya no existe" % (edad, GOV_MAX_EDAD_S)), edad

    ver = d.get("verdict") or d.get("veredicto") or "?"
    if d.get("governed") is True or ver in ("GOBERNADO", "GOBERNADO_SIN_VERIFICADOR"):
        return True, ver, "el nodo esta bajo gobierno", edad
    if ver == "DEGRADADO":
        # Invariante blando roto. Se deja pasar a proposito y se DEJA CONSTANCIA: negar aqui
        # impediria precisamente la promocion que arregla la degradacion.
        return True, ver, "invariante blando roto; se promueve y queda anotado", edad
    return False, ver, "el nodo no esta bajo gobierno: no procede que se cambie a si mismo", edad


def _faltan_en_dev():
    """Nombres gestionados por el paquete que estan en MAIN y NO en DEV (ITV-061).

    Se compara SOLO lo que _copy_bundle gestiona —los mismos patrones que limpia—, porque es
    exactamente lo que la promocion borraria. Comparar mas seria alarmar por ficheros que la
    promocion ni toca; comparar menos dejaria fuera justo lo que se busca.
    """
    def _gestionados(d):
        # RECURSIVO y por RUTA RELATIVA (ITV-071). Mientras la copia era plana, comparar nombres
        # sueltos bastaba. Al hacerse recursiva la promocion, una comparacion plana NO veria un
        # subarbol entero presente en MAIN y ausente en DEV: la promocion lo borraria y la guarda
        # diria que no falta nada. La guarda tiene que mirar exactamente lo mismo que la copia
        # toca, o deja de ser una guarda.
        n = set()
        for raiz, _dirs, fich in os.walk(d):
            if "__pycache__" in raiz:
                continue
            for f in fich:
                if f.endswith((".py", ".pyz", ".sh", ".yaml")):
                    n.add(os.path.relpath(os.path.join(raiz, f), d))
        return n
    try:
        return sorted(_gestionados(MAIN) - _gestionados(DEV))
    except Exception:
        return []


def cmd_promote():
    ld = _ld()
    t0 = int(time.time())

    # -1) GOBERNANZA: el primer filtro, antes de simular o verificar nada. Si el nodo no esta
    #     gobernado, no importa que el candidato sea impecable.
    gob_ok, gob_ver, gob_motivo, gob_edad = _gobernanza()
    salvoconducto = os.environ.get("ANV_PROMOTE_SIN_GOBIERNO") == "1"
    if not gob_ok and not salvoconducto:
        _emit({"svc": "ring_promote", "action": "promote", "stage": "GOBERNANZA", "ok": False,
               "error": "promocion DENEGADA por el dictamen de gobernanza",
               "veredicto_gobernanza": gob_ver, "motivo": gob_motivo, "dictamen_edad_s": gob_edad,
               "salida_de_emergencia": ("ANV_PROMOTE_SIN_GOBIERNO=1 fuerza la promocion y queda "
                                        "registrado en este mismo asiento")})
        return 1
    if not gob_ok and salvoconducto:
        _emit({"svc": "ring_promote", "action": "promote", "stage": "GOBERNANZA", "ok": True,
               "forzado": True, "veredicto_gobernanza": gob_ver, "motivo": gob_motivo,
               "nota": ("promocion FORZADA con la salida de emergencia pese al dictamen adverso; "
                        "queda constancia a proposito")})

    # -0.5) DEV DEBE CUBRIR A MAIN (ITV-061, medido el 2026-08-05 sobre origo)
    #
    # _copy_bundle limpia el destino de todos los *.py, *.pyz, *.sh y *.yaml y despues repone solo
    # los del paquete de origen. Por tanto, un servicio presente en MAIN y AUSENTE en DEV se BORRA
    # de la capa activa, sin error y con la promocion terminando en exito.
    #
    # Medido: DEV tenia 75 servicios y MAIN 76; el que sobraba era axiom_integrity_checker.py,
    # desplegado por otro carril ese mismo dia. Una promocion rutinaria lo habria retirado y nada
    # lo habria dicho. Quien promociona un servicio no espera retirar otro.
    #
    # El propio _copy_bundle ya lleva escrito el principio que lo evita —"la limpieza no puede ser
    # mas ancha que la copia; si borro algo que no voy a reponer, lo estoy destruyendo, no
    # promocionandolo"—. Aquella correccion estrecho la limpieza para las FIRMAS sueltas y resolvio
    # ese caso; para un SERVICIO ENTERO la limpieza seguia siendo mas ancha que la copia. Aqui se
    # comprueba antes de tocar nada y se ABORTA NOMBRANDO lo que falta, que es lo que convierte un
    # borrado silencioso en una decision consciente.
    faltan = _faltan_en_dev()
    if faltan and os.environ.get("ANV_PROMOTE_ACEPTA_RETIRADA") != "1":
        _emit({"svc": "ring_promote", "action": "promote", "stage": "COBERTURA_DEV", "ok": False,
               "error": "DEV no cubre a MAIN: promocionar RETIRARIA estos servicios de la capa activa",
               "se_retirarian": faltan, "cuantos": len(faltan),
               "como_proceder": ("copia a DEV lo que falte y vuelve a promocionar; si la retirada es "
                                 "intencionada, ANV_PROMOTE_ACEPTA_RETIRADA=1 la autoriza y queda "
                                 "registrada en este mismo asiento")})
        return 1
    if faltan:
        _emit({"svc": "ring_promote", "action": "promote", "stage": "COBERTURA_DEV", "ok": True,
               "retirada_autorizada": faltan,
               "nota": "se retiran de MAIN por autorizacion explicita; queda constancia a proposito"})

    # 0) ASCT LIGERO: simular el candidato DEV (NO_MUTATION) antes de tocar MIRROR/MAIN
    sim = _asct_sim_dev()
    if sim is not None and sim.get("global_verdict") != "GO":
        _emit({"svc": "ring_promote", "action": "promote", "stage": "ASCT_SIM", "ok": False,
               "error": "ASCT sim NO_GO -> promoción abortada (autoevaluación falló)",
               "no_go": sim.get("no_go"), "rollback_available": sim.get("rollback_available")})
        return 1
    # 1) DEV fail-closed
    ok, total, invalid = verify_dir(ld, DEV)
    if not ok:
        _emit({"svc": "ring_promote", "action": "promote", "stage": "DEV", "ok": False,
               "error": "DEV no verifica (fail-closed) -> ABORTADO", "invalid": invalid})
        return 1
    dev_hash = _content_hash(DEV)
    # 2) DEV -> MIRROR + re-verificar
    _copy_bundle(DEV, MIRROR)
    ok, _, invalid = verify_dir(ld, MIRROR)
    if not ok:
        _emit({"svc": "ring_promote", "action": "promote", "stage": "MIRROR", "ok": False,
               "error": "MIRROR no verifica tras copia -> ABORTADO", "invalid": invalid})
        return 1
    # 3) mirror-only: respaldar MAIN y promover MIRROR -> MAIN
    bdir = os.path.join(BACKUPS, "main_%d" % t0)
    _copy_bundle(MAIN, bdir)
    _copy_bundle(MIRROR, MAIN)
    # 4) re-verificar MAIN (self_integrity); si falla -> AUTO-ROLLBACK
    si_ok, verified, sitotal = _self_integrity_ok()
    okmain, _, invalid = verify_dir(ld, MAIN)
    if not okmain or si_ok is False:
        _copy_bundle(bdir, MAIN)   # rollback
        _emit({"svc": "ring_promote", "action": "promote", "stage": "MAIN", "ok": False,
               "error": "MAIN no verifica tras promocion -> AUTO-ROLLBACK", "invalid": invalid,
               "self_integrity": [si_ok, verified, sitotal], "rolled_back_from": bdir})
        return 1
    # 5) manifiesto + cadena (gancho paso 2)
    ch = _write_manifest()
    h = _chain_append("promote", ch, {"dev_hash": dev_hash[:16], "backup": os.path.basename(bdir)})
    _emit({"svc": "ring_promote", "action": "promote", "ok": True,
           "content_hash": ch, "chain_head": h[:16], "files": total,
           "self_integrity": [si_ok, verified, sitotal], "backup": os.path.basename(bdir),
           "note": "MAIN promovido y atestado; manifiesto listo para replicacion (paso 2)"})
    return 0


def cmd_rollback():
    backs = sorted(glob.glob(os.path.join(BACKUPS, "main_*")))
    if not backs:
        _emit({"svc": "ring_promote", "action": "rollback", "ok": False, "error": "sin respaldos"})
        return 1
    last = backs[-1]
    _copy_bundle(last, MAIN)
    ld = _ld()
    ok, _, invalid = verify_dir(ld, MAIN)
    ch = _content_hash(MAIN)
    h = _chain_append("rollback", ch, {"restored_from": os.path.basename(last)})
    _emit({"svc": "ring_promote", "action": "rollback", "ok": ok, "restored_from": os.path.basename(last),
           "chain_head": h[:16], "invalid": invalid})
    return 0 if ok else 1


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    try:
        if cmd == "init":
            return cmd_init()
        if cmd == "status":
            return cmd_status()
        if cmd == "verify":
            return cmd_verify(sys.argv[2] if len(sys.argv) > 2 else "main")
        if cmd == "promote":
            return cmd_promote()
        if cmd == "rollback":
            return cmd_rollback()
        print(json.dumps({"svc": "ring_promote", "error": "modo desconocido: %s" % cmd}))
        return 2
    except Exception as e:
        _emit({"svc": "ring_promote", "action": cmd, "ok": False, "fatal": str(e)})
        return 1


if __name__ == "__main__":
    sys.exit(main())
