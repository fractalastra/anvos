#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""fleet_attest — FEDERACION NIVEL 1: verifica a un par AHORA.

Cierra el escalon que faltaba. fleet_anchor (N3) describe en su cabecera una piramide de tres
niveles y solo existia el de arriba: N1 y N2 no estaban escritos en ninguna parte. N3 vigila si
un par REESCRIBIO su historia entre dos instantes; nadie comprobaba si el par de enfrente es
quien dice ser, si consta autorizado, que rol cumple y si esta integro AHORA MISMO.

QUE VERIFICO YO Y QUE ME LIMITO A REPETIR (la distincion es el nucleo de esto):

  VERIFICADO   la cadena de bloques del par se descarga entera y se le RECALCULAN los hashes.
               Si la cabeza que dice tener no coincide con la que sale de sus propios bloques,
               da igual lo que declare el resto de la atestacion.
  VERIFICADO   el encadenado: cada bloque referencia al anterior y las alturas son consecutivas.
  DECLARADO    integridad, gobernanza, modulos, salud. Son AUTOINFORME del par. Un nodo tomado
               dira que esta perfecto. Se recogen y se marcan como declarados, nunca como
               comprobados. Confundir ambas cosas es como emitir un OK por que existan los
               ficheros de firma sin llegar a validarlos.

El nodo NO firma (doctrina de node_attest): la confianza viene del anclaje a la cadena merkle
autoverificada y del sello de la capa firmada. Por eso N1 recalcula la cadena en vez de pedir
una firma que no existe.

AUTORIZACION: el par se contrasta con el registro de realm local, y ese registro se RESPALDA antes
de usarlo. La primera version buscaba node_registry.json.minisig y, al no encontrarlo, emitia
REGISTRO_SIN_FIRMA: estaba exigiendo un artefacto que el diseno no produce. El registro llega al
nodo dentro del PACK de aprovisionamiento y su integridad la cubre provision_manifest.json, que
si va firmado y lleva el sha256 de cada fichero. Comprobado en origo: el sha casa.

Pedir la firma equivocada no es ser mas estricto. Es dar una alarma falsa sobre algo que si se
puede verificar, y empujar a firmar por separado lo que ya estaba cubierto.

Observe/detect-only: emite veredictos, nunca actua. Fail-safe: cualquier fallo se registra y
termina en 0, NO bloquea el ecosistema/OS. Solo stdlib.

Manifest: fleet_attest.py|900|fleet/attest.jsonl
Uso: fleet_attest.py [http://host:puerto ...]"""
import os
import sys
import json
import time
import struct
import hashlib
import binascii
import urllib.request

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
OUT = os.path.join(DATA, "fleet", "attest.jsonl")
ALERTS = os.path.join(DATA, "fleet", "attest_alerts.jsonl")
REALM = os.environ.get("ANVOS_REALM", "/persist/anvos-realm")
REGISTRY = os.path.join(REALM, "node_registry.json")
# Direcciones de los pares de flota: SIEMPRE por configuracion (ANVOS_FLEET_PEERS, URLs
# separadas por comas, p.ej. "http://192.0.2.1:8088,http://192.0.2.2:8088"). Sin declaracion
# no hay pares: la flota no se inventa (fail-closed).
DEFAULT_PEERS = [p.strip() for p in os.environ.get("ANVOS_FLEET_PEERS", "").split(",") if p.strip()]
TIMEOUT = 8


def _now():
    return int(time.time())


def _sha(s):
    return hashlib.sha256(s.encode() if isinstance(s, str) else s).hexdigest()


def _block_hash(block):
    # MISMO algoritmo que block_anchor/fleet_anchor: sha256 del JSON canonico sin 'hash'.
    b = {k: v for k, v in block.items() if k != "hash"}
    return _sha(json.dumps(b, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


def _emit(d, path=OUT, stdout=True):
    # Solo la linea de resumen sale por stdout: layerd espera UNA linea JSON por ejecucion.
    # Las alertas van a su fichero. Sacarlas tambien por stdout rompia el contrato y dejaba
    # dos objetos JSON pegados, que es como se detecto: el consumidor no pudo parsearlo.
    if stdout:
        print(json.dumps(d, ensure_ascii=False), flush=True)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _get(url):
    try:
        return urllib.request.urlopen(url, timeout=TIMEOUT).read().decode("utf-8", "replace")
    except Exception as e:
        return "__ERR__" + str(e)


def _sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for b in iter(lambda: f.read(65536), b""):
                h.update(b)
        return h.hexdigest()
    except Exception:
        return None


# ── VERIFICACION DEL QUOTE TPM DE UN PAR (ITF-002, 9-ago-2026) ─────────────────────────────
# El par publica en /attest/tpm el quote crudo de su ultimo ciclo (lo produce tpm_attest.py y
# la clave de atestacion vive DENTRO de su TPM). Aqui se repite la verificacion ENTERA desde
# fuera: firma ECDSA P-256 contra la publica publicada, estructura del TPMS_ATTEST y pcrDigest
# recalculado de los PCR publicados. Ademas se vigila la CONTINUIDAD del AK (TOFU): la primera
# vez se apunta; si un dia cambia sin ceremonia, ese nodo ya no es el mismo aparato — alerta.
# Sube el escalon de la cabecera: la cadena merkle prueba la HISTORIA del par; el quote prueba
# que el APARATO de ese par firmo sus PCR. VERIFICADO, no declarado. Solo stdlib.
TPM_TOFU = os.path.join(DATA, "fleet", "tpm_tofu.json")
_EC_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_EC_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
_EC_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
_EC_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
         0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def _ec_suma(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _EC_P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 - 3) * pow(2 * y1, _EC_P - 2, _EC_P) % _EC_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, _EC_P - 2, _EC_P) % _EC_P
    x3 = (lam * lam - x1 - x2) % _EC_P
    return x3, (lam * (x1 - x3) - y1) % _EC_P


def _ec_mul(k, punto):
    r = None
    while k:
        if k & 1:
            r = _ec_suma(r, punto)
        punto = _ec_suma(punto, punto)
        k >>= 1
    return r


def _ecdsa_verifica(hash_bytes, r, s, qx, qy):
    """ECDSA P-256 con la stdlib. True/False; cualquier rareza es un NO."""
    try:
        if not (0 < r < _EC_N and 0 < s < _EC_N):
            return False
        if (qy * qy - (qx * qx * qx - 3 * qx + _EC_B)) % _EC_P != 0:
            return False
        e = int.from_bytes(hash_bytes, "big")
        w = pow(s, _EC_N - 2, _EC_N)
        pt = _ec_suma(_ec_mul(e * w % _EC_N, _EC_G), _ec_mul(r * w % _EC_N, (qx, qy)))
        return pt is not None and pt[0] % _EC_N == r
    except Exception:
        return False


def _attest_campos(attest):
    """(magic, tipo, pcrDigest) del TPMS_ATTEST publicado (mismo troceo que tpm_attest.py)."""
    magic, tipo = struct.unpack(">IH", attest[:6])
    o = 6
    o += 2 + struct.unpack(">H", attest[o:o + 2])[0]      # qualifiedSigner
    o += 2 + struct.unpack(">H", attest[o:o + 2])[0]      # extraData (nonce del propio par)
    o += 17 + 8                                           # clockInfo + firmwareVersion
    n_sel = struct.unpack(">I", attest[o:o + 4])[0]
    o += 4
    for _ in range(n_sel):
        o += 2
        o += 1 + attest[o]
    ln = struct.unpack(">H", attest[o:o + 2])[0]
    return magic, tipo, attest[o + 2:o + 2 + ln]


def _tofu_ak(nid, ak, pub_x):
    """Continuidad del AK del par: primer_avistamiento | estable | AK_CAMBIADA."""
    try:
        libro = json.load(open(TPM_TOFU))
    except Exception:
        libro = {}
    visto = libro.get(str(nid))
    if visto is None:
        libro[str(nid)] = {"ak": ak, "pub_x": pub_x, "primera_vez": _now()}
        try:
            os.makedirs(os.path.dirname(TPM_TOFU), exist_ok=True)
            tmp = TPM_TOFU + ".tmp"
            with open(tmp, "w") as f:
                json.dump(libro, f, ensure_ascii=False)
            os.replace(tmp, TPM_TOFU)
        except Exception:
            pass
        return "primer_avistamiento"
    return "estable" if (visto.get("pub_x") == pub_x and visto.get("ak") == ak) else "AK_CAMBIADA"


def _verifica_tpm(base, nid):
    """Verifica desde fuera el quote publicado por el par. NUNCA lanza: siempre un dict."""
    crudo = _get(base.rstrip("/") + "/attest/tpm")
    if crudo.startswith("__ERR__") or "sin quote publicado" in crudo[:80]:
        return {"estado": "NO_PUBLICA_QUOTE",
                "nota": "sin TPM o sin ciclo de tpm_attest; se queda en lo declarado"}
    try:
        pub = json.loads(crudo)
        attest = binascii.unhexlify(pub["attest_hex"])
        r, s = int(pub["sig_r"], 16), int(pub["sig_s"], 16)
        qx, qy = int(pub["pub_x"], 16), int(pub["pub_y"], 16)
        magic, tipo, digest = _attest_campos(attest)
        h = hashlib.sha256()
        for i in sorted(pub.get("pcr") or {}, key=int):
            h.update(binascii.unhexlify(pub["pcr"][i]))
        hq = hashlib.sha256(attest).digest()
        checks = {
            "estructura_attest": magic == 0xFF544347 and tipo == 0x8018,
            "pcr_digest_coincide": digest == h.digest(),
            "firma_ecdsa_valida": _ecdsa_verifica(hq, r, s, qx, qy),
            "control_negativo_rechaza": not _ecdsa_verifica(
                hashlib.sha256(attest + b"x").digest(), r, s, qx, qy),
        }
    except Exception as e:
        return {"estado": "QUOTE_ILEGIBLE", "detalle": str(e)[:100]}
    if not checks["control_negativo_rechaza"]:
        # El instrumento del verificador no sabe decir que no: no se afirma nada con el roto.
        return {"estado": "VERIFICADOR_ROTO", "checks": checks}
    if not all(checks.values()):
        return {"estado": "QUOTE_INVALIDO", "checks": checks, "ak": pub.get("ak")}
    continuidad = _tofu_ak(nid, pub.get("ak"), pub["pub_x"])
    return {"estado": "VERIFICADO_POR_MI", "ak": pub.get("ak"), "checks": checks,
            "pcr_digest": pub.get("pcr_digest"), "continuidad": continuidad,
            "edad_s": max(0, _now() - int(pub.get("ts") or 0))}


def _tras_optin(v):
    """Valor de adhesion sin el prefijo. El campo se guarda como 'opt-in:<referencia>'."""
    if not v:
        return None
    v = str(v).strip()
    return v.split(":", 1)[1].strip() if v.lower().startswith("opt-in:") else v


def _forma(v):
    """Que tipo de referencia al padre es: huella sha256 o clave publica minisign.

    El mismo campo admite ambas y no son intercambiables sin la identidad del padre. Distinguirlas
    permite decir POR QUE no se puede comparar, en vez de dar un veredicto que la evidencia no sostiene.
    """
    if not v:
        return "ausente"
    v = str(v)
    if len(v) == 64 and all(c in "0123456789abcdefABCDEF" for c in v):
        return "huella-sha256"
    if v.startswith("RW"):
        return "clave-publica"
    return "desconocida"


def _registro():
    """Registro de realm local y si su integridad esta REALMENTE respaldada.

    Correccion del 30-jul: la primera version buscaba node_registry.json.minisig y, al no
    encontrarlo, emitia REGISTRO_SIN_FIRMA. Estaba exigiendo un artefacto que el diseno no
    produce. El registro llega al nodo dentro del PACK de aprovisionamiento y su integridad
    la cubre provision_manifest.json, que SI va firmado con an_service y lleva el sha256 de
    cada fichero del pack. Comprobado en origo: el sha del registro casa con el del manifiesto.

    Pedir la firma equivocada no es ser estricto, es dar una alarma falsa sobre algo que si
    se puede verificar, y ademas empuja a firmar por separado lo que ya estaba cubierto.
    """
    try:
        with open(REGISTRY) as f:
            doc = json.load(f)
    except Exception:
        return None, False, "no hay registro de realm local"

    # Via 1 (la del diseno): manifiesto de aprovisionamiento firmado que respalda el sha del registro.
    man = os.path.join(REALM, "provision_manifest.json")
    if os.path.isfile(man) and os.path.isfile(man + ".minisig"):
        ok_man, motivo_man = _verifica_minisign(man)
        if ok_man:
            real = _sha256(REGISTRY)
            for ln in open(man, "r", errors="replace"):
                p = ln.split()
                if len(p) >= 2 and p[1].endswith("node_registry.json"):
                    if real and p[0] == real:
                        return doc, True, "respaldado por provision_manifest firmado"
                    return doc, False, "el sha del registro NO casa con el manifiesto de aprovisionamiento"
            return doc, False, "el manifiesto firmado no cubre node_registry.json"
        return doc, False, "manifiesto de aprovisionamiento: %s" % motivo_man

    # Via 2: firma propia del registro, si alguien la anadio.
    if os.path.isfile(REGISTRY + ".minisig") and _verifica_minisign(REGISTRY)[0]:
        return doc, True, "firma propia del registro"

    return doc, False, "el registro no esta respaldado ni por manifiesto ni por firma propia"


# Convencion del nodo, copiada de dr_verify y realm_activate para no inventar una tercera:
# el BINARIO minisign y su cargador viven en pylayer-verify/, y las CLAVES en pylayer/.
# La primera version buscaba release.pub dentro de pylayer-verify/ y no la encontraba, con lo
# que el nodo declaraba "el manifiesto no valida" cuando en realidad no estaba mirando ninguna
# clave. Y el manifiesto de provision lo firma an_service, no la clave de release: pedir la
# clave equivocada da el mismo falso negativo que no tener ninguna.
_STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
_MS = os.path.join(_STAGING, "pylayer-verify")
_PUBS = tuple(p for p in (os.path.join(_STAGING, "pylayer", "an_service.pub"),
         os.path.join(DATA, ".an_service_embedded.pub"),
         os.path.join(_STAGING, "pylayer", "release.pub"),
         os.environ.get("ANVOS_EXTRA_SERVICE_PUB", "")) if p)


def _verifica_minisign(target):
    """Verifica target con el minisign EMBEBIDO del nodo. Devuelve (ok, motivo).

    Distingue tres situaciones que NO son lo mismo y que la version anterior mezclaba en un
    unico 'no valida': firma invalida, ausencia de verificador, y ausencia de la clave que
    hace falta. Solo la primera es motivo de alarma.
    """
    import subprocess
    sig = target + ".minisig"
    if not os.path.isfile(sig):
        return False, "no hay fichero de firma"

    ld = None
    for c in ("ld-linux-x86-64.so.2", "ld-musl-x86_64.so.1"):
        if os.path.exists(os.path.join(_MS, c)):
            ld = os.path.join(_MS, c)
            break
    binario = os.path.join(_MS, "minisign")

    claves = [p for p in _PUBS if os.path.exists(p)]
    if not claves:
        return False, "no hay ninguna clave publica con la que verificar"

    if ld and os.path.exists(binario):
        base = [ld, "--library-path", _MS, binario]
    else:
        import shutil
        if not shutil.which("minisign"):
            return False, "no hay verificador minisign disponible"
        base = ["minisign"]

    for pub in claves:
        try:
            r = subprocess.run(base + ["-Vm", target, "-p", pub, "-x", sig],
                               capture_output=True, timeout=20)
            if r.returncode == 0:
                return True, "valida con %s" % os.path.basename(pub)
        except Exception:
            continue
    return False, "ninguna de las %d claves disponibles valida la firma" % len(claves)


def _verifica_con_clave(texto, firma, pub):
    """Verifica un artefacto RECIBIDO POR RED contra UNA clave concreta. Devuelve (ok, motivo).

    Deliberadamente distinto de _verifica_minisign, que prueba una lista de claves y da por buena
    la primera que encaje. Eso vale para artefactos propios, donde solo interesa saber si estan
    intactos. Para una contrafirma NO vale: la pregunta no es "¿alguien firmo esto?" sino
    "¿lo firmo EXACTAMENTE el ascendiente que yo reconozco?". Aceptar cualquier clave que encaje
    convierte la comprobacion en un adorno, porque cualquiera que traiga su propia clave pasa.
    """
    import subprocess
    import tempfile
    if not (texto and firma and os.path.isfile(pub)):
        return False, "falta el certificado, su firma o la clave del ascendiente"

    ld = None
    for c in ("ld-linux-x86-64.so.2", "ld-musl-x86_64.so.1"):
        if os.path.exists(os.path.join(_MS, c)):
            ld = os.path.join(_MS, c)
            break
    binario = os.path.join(_MS, "minisign")
    if ld and os.path.exists(binario):
        base = [ld, "--library-path", _MS, binario]
    else:
        import shutil
        if not shutil.which("minisign"):
            return False, "no hay verificador minisign disponible"
        base = ["minisign"]

    d = tempfile.mkdtemp(prefix=".fa_contra_")
    try:
        # El nombre importa: minisign firma tambien el comentario de confianza, y ahi va el
        # nombre del fichero original. Se reconstruye tal cual para no invalidar una firma buena.
        t = os.path.join(d, "parent-node.cert")
        with open(t, "w") as f:
            f.write(texto)
        with open(t + ".minisig", "w") as f:
            f.write(firma)
        r = subprocess.run(base + ["-Vm", t, "-p", pub, "-x", t + ".minisig"],
                           capture_output=True, timeout=20)
        return (r.returncode == 0,
                "contrafirmado por la raiz que yo reconozco" if r.returncode == 0
                else "la contrafirma NO valida contra la raiz de mi ascendiente")
    except Exception as e:
        return False, str(e)[:80]
    finally:
        try:
            for n in os.listdir(d):
                os.unlink(os.path.join(d, n))
            os.rmdir(d)
        except Exception:
            pass


# ── Nucleo criptografico tomado de attest_verify.py (/persist/anvos-tools), que es mas
# riguroso que la version que este servicio traia. Medido el 31-jul-2026: mi verificacion
# comprobaba el encadenado y el hash de bloque, pero NO anclaba al genesis determinista,
# NO comprobaba que cada bloque declarase el mismo nodo, y NO verificaba la raiz merkle.
# Tres huecos por los que una cadena fabricada podia pasar.
#
# No se reescribe: se adopta tal cual para que exista UN solo algoritmo. Si block_anchor
# cambia, cambia en un sitio.
def _pair(l, r):
    return _sha(l + r)


def _merkle_root(hashes):
    hs = [h for h in hashes if h]
    if not hs:
        return _sha("")
    while len(hs) > 1:
        if len(hs) % 2:
            hs.append(hs[-1])
        hs = [_pair(hs[i], hs[i + 1]) for i in range(0, len(hs), 2)]
    return hs[0]


def _verifica_cadena(texto, nodo=None):
    """Recalcula la cadena del par. Devuelve (ok, altura, cabeza, motivo).

    Ancla al genesis determinista del nodo: sin eso, una cadena inventada que sea internamente
    coherente pasa la comprobacion. Con eso, tiene que partir del punto que el propio nombre
    del nodo determina.
    """
    prev = _sha("ANVOS_BLOCK_GENESIS:" + nodo) if nodo else None
    altura = 0
    cabeza = None
    vistos = 0
    for ln in texto.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            b = json.loads(ln)
        except Exception:
            return False, altura, None, "bloque con json ilegible en altura %s" % (altura + 1)
        vistos += 1
        if nodo and b.get("node") != nodo:
            return False, b.get("height"), None, "el bloque %s declara el nodo %s" % (b.get("height"), b.get("node"))
        if prev is not None and b.get("prev") != prev:
            return False, b.get("height"), None, "el bloque %s no encadena con el anterior" % b.get("height")
        if _merkle_root([h.get("hash") for h in (b.get("leaves") or [])]) != b.get("merkle_root"):
            return False, b.get("height"), None, "la raiz merkle del bloque %s no casa con sus hojas" % b.get("height")
        if _block_hash(b) != b.get("hash"):
            return False, b.get("height"), None, "el hash del bloque %s no casa con su contenido" % b.get("height")
        prev = b.get("hash")
        cabeza = prev
        altura = b.get("height", altura + 1)
    if not vistos:
        return False, -1, None, "cadena vacia o ilegible"
    return True, altura, cabeza, ""

def _es_mi_direccion(host):
    """¿La URL apunta a mi propia maquina?

    Se decide por DIRECCION, nunca por el nombre que el par declara. La primera version
    comparaba el nombre recibido con el propio y salia antes de verificar nada: un par
    hostil solo tenia que decir que se llamaba como yo para saltarse la comprobacion
    entera. Lo detecto la prueba de pares falsos, que al servir la atestacion de origo
    quedaron clasificados como 'soy yo' en vez de como cadena rota.

    Truco de socket sin dependencias: si al abrir un socket hacia el par la direccion
    local que me asigna el kernel coincide con la del par, estoy hablando conmigo mismo.
    """
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((host, 9))
            return s.getsockname()[0] == socket.gethostbyname(host)
        finally:
            s.close()
    except Exception:
        return False


def _yo():
    """Identidad local, solo para informar. NO decide quien soy frente a un par."""
    for p in ("/persist/anvos-node.id", os.path.join(REALM, "node.id")):
        try:
            v = open(p).read().strip()
            if v:
                return v
        except Exception:
            pass
    try:
        import socket
        return socket.gethostname()
    except Exception:
        return None


def _verifica_linaje(base, nid):
    """Descarga el pack de linaje del par y comprueba su coherencia interna.

    Anadido 31-jul-2026. Hasta ahora el par declaraba su realm y no habia con que
    contrastarlo: la pertenencia era una afirmacion. El pack desplegado en un nodo NO lleva
    firma por cert (su integridad la cubre el manifiesto de aprovisionamiento), pero el cert
    del nodo declara la huella de su padre, y esa huella tiene que ser exactamente el sha256
    del certificado raiz que el propio nodo sirve.

    Eso ata el linaje sin necesitar firmas por fichero: un nodo no puede declarar una raiz
    que no tiene, porque la huella no cuadraria. Combinado con el NFT de nacimiento anclado
    en el ledger, la afirmacion pasa a ser comprobable tambien desde fuera.

    Devuelve (ok, datos, motivo). Nunca lanza: un par sin linaje publicado no es un fallo.
    """
    crudo = _get(base.rstrip("/") + "/lineage")
    if crudo.startswith("__ERR__"):
        return False, {}, "el par no publica linaje"
    try:
        pack = json.loads(crudo)
    except Exception:
        return False, {}, "pack de linaje ilegible"
    files = pack.get("files") or {}
    raiz = files.get("realm-root.cert")
    cert = None
    for n, c in files.items():
        if n.endswith(".cert") and n != "realm-root.cert":
            cert = c
            break
    if not (raiz and cert):
        return False, {}, "el pack no trae cert de nodo y de raiz"

    campos = {}
    for ln in cert.splitlines():
        if "=" in ln and not ln.strip().startswith("#"):
            k, _, v = ln.partition("=")
            campos[k.strip()] = v.strip()

    fp_declarada = campos.get("ANV_NODE_PARENT_CERT_FP", "")
    fp_real = _sha(raiz.encode())
    padre = files.get("parent-realm-root.cert")
    datos = {"depth": campos.get("ANV_NODE_DEPTH"), "weight": campos.get("ANV_NODE_WEIGHT"),
             "rol_cert": campos.get("ANV_NODE_ROLE"), "realm_cert": campos.get("ANV_NODE_REALM"),
             "can_mint": campos.get("ANV_NODE_CAN_MINT"),
             # Huella del ascendiente que el par declara y publica. Es lo que hace comparable la
             # adhesion entre nodos cuyos packs la guardan en formatos distintos, y lo que abre la
             # puerta a reconocer primos: dos nodos de padres distintos con el mismo abuelo.
             "cert_padre_sha": _sha(padre.encode()) if padre else None,
             "padre_publicado": bool(padre)}
    if not fp_declarada:
        return False, datos, "el cert del par no declara la huella de su padre"
    if fp_declarada != fp_real:
        return False, datos, ("la huella del padre declarada en el cert no casa con el certificado "
                              "raiz que el propio par sirve")
    if nid and campos.get("ANV_NODE_ID") and campos["ANV_NODE_ID"] != nid:
        return False, datos, "el cert identifica a %s y la atestacion a %s" % (campos["ANV_NODE_ID"], nid)

    # ── CONTRAFIRMA DEL ASCENDIENTE (ITA-013, 01-ago-2026) ──────────────────────────────────
    #
    # Todo lo comprobado hasta esta linea es COHERENCIA INTERNA de lo que el par publica: que su
    # certificado case con la raiz que el mismo sirve. Un nodo legitimo lo cumple, y un nodo que
    # se inventa su propia raiz tambien: basta con ser consistente consigo mismo.
    #
    # Lo que sigue es distinto. `parent-node.cert` es el certificado del par CONTRAFIRMADO por la
    # raiz del padre, y se valida contra la publica de MI propio ascendiente —la que este nodo ya
    # tiene en su realm—, no contra la que el par traiga. Ahi la pertenencia deja de ser algo que
    # el par afirma y pasa a ser algo que un tercero que yo reconozco sostiene.
    #
    # NO se exige todavia: un par sin contrafirma sigue siendo valido y se marca como tal. Volverlo
    # obligatorio de golpe tumbaria a cualquier nodo que aun no la haya recibido, y una comprobacion
    # nueva no debe partir la flota el dia que se estrena. Se mide primero, se exige despues.
    contra = files.get("parent-node.cert")
    contra_sig = files.get("parent-node.cert.minisig")
    mi_padre = os.path.join(REALM, "parent_realm_root.pub")
    if contra and contra_sig:
        ok_c, motivo_c = _verifica_con_clave(contra, contra_sig, mi_padre)
        datos["contrafirmado_por_mi_ascendiente"] = ok_c
        datos["contrafirma_motivo"] = motivo_c
        if ok_c:
            # Que la contrafirma sea valida no basta: tiene que ser la de ESTE par. Una
            # contrafirma legitima de otro nodo validaria igual y no diria nada de quien la trae.
            id_contra = None
            for ln in contra.splitlines():
                if ln.startswith("ANV_NODE_ID="):
                    id_contra = ln.partition("=")[2].strip()
                    break
            datos["contrafirma_de"] = id_contra
            if nid and id_contra and id_contra != nid:
                return False, datos, ("la contrafirma del ascendiente es valida pero corresponde a %s, "
                                      "no al par que la presenta (%s)" % (id_contra, nid))
            return True, datos, "cert del par CONTRAFIRMADO por la raiz de mi ascendiente"
        return True, datos, ("cert del nodo atado a la raiz que publica; la contrafirma que trae "
                             "NO valida contra mi ascendiente: %s" % motivo_c)
    datos["contrafirmado_por_mi_ascendiente"] = None
    return True, datos, ("cert del nodo atado a la raiz que publica; sin contrafirma del "
                         "ascendiente (coherencia interna, no pertenencia demostrada)")


def verifica_par(base, yo=None):
    res = {"peer": base, "ts": _now()}
    try:
        from urllib.parse import urlparse
        res["es_mi_direccion"] = _es_mi_direccion(urlparse(base).hostname or "")
    except Exception:
        res["es_mi_direccion"] = False

    # El auto-par se resuelve ANTES de la descarga. Comprobarlo despues tenia un efecto
    # medido el 30-jul: mientras mi propio servidor de estado reiniciaba, YO aparecia como
    # SIN_RESPUESTA y por tanto contaba como par ajeno, y el resumen dijo 0/2 en vez de 0/1.
    # Mi disponibilidad no es un dato de la federacion.
    if res["es_mi_direccion"]:
        res.update(veredicto="SI_MISMO", detalle="este par soy yo; N1 verifica pares ajenos")
        return res

    crudo = _get(base.rstrip("/") + "/attest")
    if crudo.startswith("__ERR__"):
        res.update(veredicto="SIN_RESPUESTA", detalle=crudo[7:][:120])
        return res
    try:
        att = json.loads(crudo)
    except Exception:
        res.update(veredicto="ATESTACION_ILEGIBLE")
        return res

    sob = att.get("soberania") or {}
    # node_id puede venir a null (medido en origo el 30-jul): se cae al nombre y se dice.
    nid = sob.get("node_id") or att.get("node") or "?"
    res["node"] = nid
    res["realm"] = sob.get("realm")
    if not sob.get("node_id"):
        res["aviso_identidad"] = "el par no declara node_id; identificado por nombre"

    # Un par REMOTO que dice llamarse como yo no es un auto-par: o hay una configuracion
    # duplicada o alguien esta usurpando el nombre. Se sigue verificando y se alerta.
    if yo and str(nid).lower() == str(yo).lower():
        res["aviso_nombre"] = "un par remoto declara mi mismo nombre (%s)" % nid
        _emit(dict(res, severidad="ALTA", evento="NOMBRE_DUPLICADO"), ALERTS, stdout=False)

    # ── VERIFICADO POR MI ──────────────────────────────────────────────────────
    cadena = _get(base.rstrip("/") + "/blocks")
    if cadena.startswith("__ERR__"):
        res.update(veredicto="SIN_CADENA", detalle=cadena[7:][:120])
        return res
    ok, altura, cabeza, motivo = _verifica_cadena(cadena, nid)
    res["cadena"] = {"verificada_por_mi": ok, "altura": altura, "cabeza": cabeza}
    if not ok:
        res.update(veredicto="CADENA_INVALIDA", detalle=motivo)
        _emit(dict(res, severidad="MAXIMA", evento="CADENA_INVALIDA"), ALERTS, stdout=False)
        return res

    # La cabeza que el par dice tener contra la que sale de sus propios bloques.
    #
    # CARRERA DE LECTURA CORREGIDA (ITV-035, hipotesis de revisor-c confirmada en el codigo el
    # 05-ago-2026). La cabeza declarada y los bloques se piden en DOS descargas distintas: /attest
    # primero y /blocks despues. Si el par anade un bloque entre las dos —que es lo que hace un
    # nodo sano— la raiz recalculada no casa con la cabeza que se leyo antes, y saltaba alarma de
    # severidad MAXIMA sobre un nodo que estaba creciendo con normalidad.
    #
    # revisor-c lo dedujo SIN VER EL CODIGO, solo por la oscilacion registrada, y acerto.
    #
    # La correccion no exige tocar al par: se vuelve a leer su cabeza DESPUES de los bloques. Si
    # entre las dos lecturas ha cambiado, la cadena crecio durante la consulta y eso NO es una
    # discrepancia — es una foto movida. Solo si la cabeza esta QUIETA y sigue sin casar hay
    # motivo de alarma.
    #
    # Distinguir «crecio mientras miraba» de «miente» importa mas que el propio veredicto: una
    # alarma maxima que salta por algo normal se acaba ignorando, y entonces tampoco se atiende
    # la que si importa.
    dicha = (att.get("cadena_bloques") or {}).get("cabeza")
    if dicha and cabeza and dicha != cabeza:
        crudo2 = _get(base.rstrip("/") + "/attest")
        dicha2 = None
        if not crudo2.startswith("__ERR__"):
            try:
                dicha2 = ((json.loads(crudo2) or {}).get("cadena_bloques") or {}).get("cabeza")
            except Exception:
                dicha2 = None
        if dicha2 and dicha2 != dicha:
            # La cabeza se movio mientras se leia: crecimiento, no discrepancia.
            res["cadena"]["crecio_durante_la_lectura"] = True
            res["cadena"]["cabeza_al_empezar"] = dicha[:16]
            res["cadena"]["cabeza_al_terminar"] = dicha2[:16]
            res["aviso_carrera"] = ("la cadena del par crecio entre la lectura de su cabeza y la de "
                                    "sus bloques: no se declara discrepancia por una foto movida")
        else:
            res.update(veredicto="CABEZA_DISCREPANTE",
                       detalle=("declara %s, sus bloques dan %s, y su cabeza sigue QUIETA en una "
                                "segunda lectura: no es crecimiento" % (dicha[:16], cabeza[:16])))
            _emit(dict(res, severidad="MAXIMA", evento="CABEZA_DISCREPANTE"), ALERTS, stdout=False)
        return res

    # ── ATESTACION TPM DEL PAR, verificada POR MI (ITF-002) ────────────────────
    # No cambia el veredicto en esta primera iteracion (observe-only): anade evidencia de
    # aparato a un par cuya cadena ya se verifico, y ALERTA si el quote no verifica o si su
    # AK cambio sin ceremonia. El dia que la politica exija aparato, el dato ya esta medido.
    res["tpm"] = _verifica_tpm(base, nid)
    if res["tpm"].get("estado") == "QUOTE_INVALIDO":
        _emit(dict(res, severidad="MAXIMA", evento="QUOTE_TPM_INVALIDO"), ALERTS, stdout=False)
    if res["tpm"].get("continuidad") == "AK_CAMBIADA":
        _emit(dict(res, severidad="MAXIMA", evento="AK_TPM_CAMBIADA"), ALERTS, stdout=False)

    ok_lin, lin, motivo_lin = _verifica_linaje(base, nid)
    res["linaje"] = dict(lin, verificado=ok_lin, motivo=motivo_lin)
    if lin.get("realm_cert") and res.get("realm") and lin["realm_cert"] != res["realm"]:
        res["aviso_realm_cert"] = ("el par declara realm %s en su atestacion y %s en su certificado"
                                   % (res["realm"], lin["realm_cert"]))

    # Lo que el par DECLARA se recoge antes de juzgar, para que cualquier veredicto posterior
    # lo lleve. Antes se recogia al final y la rama de hermano federado salia sin el, perdiendo
    # justo lo util de un hermano: que rol dice cumplir y que modulos dice ejecutar.
    integ = att.get("integridad") or {}
    res["declarado"] = {
        "integridad": integ.get("attestation"),
        "sellos": "%s/%s" % (integ.get("verified"), integ.get("total")),
        "todo_valido": integ.get("all_valid"),
        "gobernanza": att.get("gobernanza"),
        "modulos": att.get("modulos"),
        "uptime_s": att.get("uptime_s"),
    }

    # ── AUTORIZACION ───────────────────────────────────────────────────────────
    doc, respaldado, motivo_reg = _registro()
    if doc is None:
        res.update(veredicto="SIN_REGISTRO",
                   detalle="no hay registro de realm local con el que contrastar")
        return res
    nodos = doc.get("nodes") or {}
    entrada = nodos.get(nid)
    if entrada is None and isinstance(nodos, dict):
        for k, v in nodos.items():
            if k.lower() == str(nid).lower():
                entrada = v
                break
    if entrada is None:
        # No consta en MI realm. En este diseno eso no basta para llamarlo desconocido: cada nodo
        # ES su propio realm, asi que el registro local solo contesta "¿este soy yo?" y cualquier
        # par resulta ajeno por construccion. Lo que decide es si ambos cuelgan del mismo padre.
        mi_fed = _tras_optin(doc.get("federation"))
        su_fed = _tras_optin((att.get("soberania") or {}).get("federation"))
        res["mi_federacion"] = mi_fed
        res["su_federacion"] = su_fed

        if not su_fed:
            res.update(veredicto="SIN_FEDERACION_PUBLICADA",
                       detalle="%s declara realm propio %s y no publica adhesion; sin ese dato no se "
                               "puede distinguir un hermano de un extrano" % (nid, res.get("realm")))
            return res
        if not mi_fed:
            res.update(veredicto="SIN_FEDERACION_PROPIA",
                       detalle="este nodo no declara adhesion, asi que no hay padre con el que comparar")
            return res
        if mi_fed == su_fed:
            res["rol"] = (entrada or {}).get("role")
            res.update(veredicto="FEDERADO",
                       detalle="realm propio %s, distinto del mio, con la misma adhesion: %s"
                               % (res.get("realm"), mi_fed[:24]))
            return res
        # Mismo padre expresado de dos formas distintas NO se puede confirmar aqui: el nodo guarda
        # una REFERENCIA al padre (huella o clave publica) pero no la identidad del padre, asi que
        # no puede convertir una en otra. Medido: origo referencia por huella y nodo-c por
        # clave publica, y ambos designan el mismo realm padre. Decir NO_REGISTRADO ahi seria una
        # afirmacion mas fuerte que la evidencia; decir FEDERADO seria inventarla.
        # Antes de rendirse: si el par publica el certificado de su padre, su huella resuelve
        # cualquiera de las dos representaciones a una sola. Eso convierte un "no puedo comparar"
        # en una comparacion real, y es lo que permite reconocer a un hermano cuyo pack guarda la
        # referencia en el otro formato.
        cert_padre = (lin or {}).get("cert_padre_sha")
        if cert_padre and (su_fed == cert_padre or _forma(su_fed) == "clave-publica"):
            if mi_fed == cert_padre:
                res.update(veredicto="FEDERADO",
                           detalle="realm propio %s con el mismo padre, resuelto por el certificado "
                                   "que el par publica (%s)" % (res.get("realm"), cert_padre[:20]))
                return res
        if _forma(mi_fed) != _forma(su_fed):
            res.update(veredicto="FEDERACION_NO_COMPARABLE",
                       detalle="ambas adhesiones usan representaciones distintas (%s vs %s) y este nodo "
                               "no guarda la identidad del padre para resolverlas"
                               % (_forma(mi_fed), _forma(su_fed)))
            return res
        res.update(veredicto="OTRA_FEDERACION",
                   detalle="%s declara adhesion a un padre distinto del mio" % nid)
        _emit(dict(res, severidad="ALTA", evento="OTRA_FEDERACION"), ALERTS, stdout=False)
        return res

    res["rol"] = entrada.get("role")
    res["peso_consenso"] = entrada.get("consensus_weight")
    res["profundidad"] = entrada.get("depth")

    # El realm declarado por el par contra el del registro: un nodo integro que dice
    # pertenecer a otro realm no es un fallo de integridad, es otro problema.
    if res["realm"] and doc.get("realm_id") and res["realm"] != doc.get("realm_id"):
        res["aviso_realm"] = "declara realm %s, el registro es %s" % (res["realm"], doc.get("realm_id"))

    # ── DECLARADO POR EL PAR (autoinforme, no comprobacion) ────────────────────

    # Un autoinforme malo si vale como aviso: si el propio nodo admite estar roto, creerle
    # es razonable. Lo que no vale es creerle cuando dice estar bien.
    if integ.get("all_valid") is False or att.get("gobernanza") in ("SIN_GOBIERNO", "DEGRADADO"):
        res.update(veredicto="AUTOINFORME_DEGRADADO",
                   detalle="el par declara integridad=%s gobernanza=%s" % (
                       integ.get("all_valid"), att.get("gobernanza")))
        return res

    res["registro_respaldado"] = motivo_reg
    if respaldado:
        res["veredicto"] = "CONFORME"
    else:
        res["veredicto"] = "REGISTRO_NO_RESPALDADO"
        res["detalle"] = ("cadena verificada y par registrado, pero el registro de realm no esta "
                          "respaldado: %s" % motivo_reg)
    return res


def cmd_cycle(peers):
    doc, respaldado, motivo_reg = _registro()
    yo = _yo()
    salida = {"svc": "fleet_attest", "ts": _now(),
              "registro_respaldado": respaldado,
              "registro_motivo": motivo_reg,
              "yo": yo,
              "realm_id": (doc or {}).get("realm_id"),
              "pares": []}
    for p in peers:
        try:
            salida["pares"].append(verifica_par(p, yo))
        except Exception as e:
            salida["pares"].append({"peer": p, "veredicto": "ERROR_INTERNO", "detalle": str(e)[:120]})
    # Compatibilidad: /fleet y fleet_consensus (N2) consumen una lista 'flota' con 'verdict'.
    # Cambiar de verificador no puede romper al consumidor que ya existia: se emiten AMBAS
    # formas. La rica para quien la entienda, la heredada para quien ya la esperaba.
    _VALIDOS = ("CONFORME", "FEDERADO", "REGISTRO_NO_RESPALDADO")
    salida["flota"] = [{
        "peer": r.get("peer"),
        "node": r.get("node"),
        "realm": r.get("realm"),
        "soberano": bool((r.get("declarado") or {}).get("integridad")),
        "verdict": "VALIDA" if r.get("veredicto") in _VALIDOS else r.get("veredicto"),
        "altura_verificada": (r.get("cadena") or {}).get("altura"),
        "head": ((r.get("cadena") or {}).get("cabeza") or "")[:16],
        "sellado": (r.get("declarado") or {}).get("sellos"),
        "altura_coherente": (r.get("cadena") or {}).get("verificada_por_mi"),
        "linaje_verificado": (r.get("linaje") or {}).get("verificado"),
        "tpm": (r.get("tpm") or {}).get("estado"),
        "tpm_continuidad": (r.get("tpm") or {}).get("continuidad"),
        "note": r.get("detalle") or "verificado sin el master",
    } for r in salida["pares"] if r.get("veredicto") != "SI_MISMO"]
    salida["validas"] = sum(1 for f in salida["flota"] if f["verdict"] == "VALIDA")
    salida["peers"] = len(salida["flota"])

    # El resumen usa EL MISMO criterio que los veredictos que acaba de emitir.
    #
    # Defecto medido el 01-ago-2026 (ITA-012, hallado por otro chat al leer attest.jsonl): esta
    # linea contaba solo veredicto=='CONFORME' mientras la flota daba VALIDA a todo lo de _VALIDOS.
    # Con dos pares FEDERADO el registro decia a la vez "validas: 2" y "0/2 pares ajenos conformes".
    # Quien leyera el resumen concluiria que la federacion no verifica a nadie.
    #
    # Un resumen no puede aplicar un criterio distinto al del dato que resume: deja de resumir y
    # pasa a contradecir. Se cuenta con _VALIDOS y se desglosa por veredicto, para que ademas se
    # vea POR QUE es valido cada uno y no haga falta abrir el registro entero.
    ajenos = [r for r in salida["pares"] if r.get("veredicto") != "SI_MISMO"]
    validos = [r for r in ajenos if r.get("veredicto") in _VALIDOS]
    desglose = {}
    for r in ajenos:
        v = r.get("veredicto") or "?"
        desglose[v] = desglose.get(v, 0) + 1
    salida["desglose_veredictos"] = desglose
    salida["resumen"] = "%s/%s pares ajenos validos (%s)" % (
        len(validos), len(ajenos),
        ", ".join("%s %s" % (n, v) for v, n in sorted(desglose.items())) or "sin pares")
    _emit(salida)
    return 0


def main():
    # Origen de los pares, en orden: argumentos, variable de entorno, y por ultimo la lista fija.
    #
    # Regresion corregida el 31-jul-2026: la version anterior de este servicio leia ANV_FLEET_PEERS
    # y la reescritura la perdio, de modo que /fleet y fleet_consensus le pasaban tres pares y solo
    # evaluaba los dos de la lista fija. El tercer nodo quedaba invisible para el consenso sin que
    # nada lo indicara: el resultado parecia correcto, solo que le faltaba un sujeto.
    args = [a for a in sys.argv[1:] if a != "cycle"]
    entorno = [u.strip() for u in os.environ.get("ANV_FLEET_PEERS", "").split(",") if u.strip()]
    peers = args or entorno or DEFAULT_PEERS
    try:
        return cmd_cycle(peers)
    except Exception as e:
        # Fail-safe: este servicio no puede tumbar la capa ni el arranque del nodo.
        _emit({"svc": "fleet_attest", "ts": _now(), "error": str(e)[:200]})
        return 0


if __name__ == "__main__":
    sys.exit(main())
