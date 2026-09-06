#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""tpm_attest — estado del TPM del nodo, leido del aparato. Solo lectura.

La politica de la capa NFT dice, literalmente, que no se concede voto sin atestacion TPM2 mas
Trust Manifest. Por eso todos los certificados de nodo llevan WEIGHT=0: no es que el voto
ponderado no exista, es que no hay con que respaldarlo.

El aparato estaba ahi desde el principio —/dev/tpm0 y /dev/tpmrm0, TPM 2.0, fabricante NTC— y
NADIE lo leia, porque el nodo no tiene las herramientas tpm2 y nadie probo si hacian falta.
Resulta que no: el gestor de recursos habla el protocolo TPM2 por bytes, y eso se hace con la
biblioteca estandar. Cero binarios nuevos en un nodo que ya va justo de herramientas.

QUE ES ESTO, Y QUE NO ES — la distincion importa mas que el dato

  ESTO ES    una LECTURA de los registros de plataforma (PCR) tal y como los tiene el aparato.
             PCR 0-1 miden el firmware y su configuracion; PCR 7 mide el estado del arranque
             seguro. Son la huella del arranque real de esta maquina.

  ESTO NO ES un quote firmado. Un quote lleva la firma de una clave de atestacion que vive
             DENTRO del TPM, y es lo unico que convierte la lectura en prueba frente a un
             tercero. Sin el, un nodo tomado puede decir los PCR que le convengan: el dato es
             fiable para quien ya confia en el nodo, y no vale ante quien no.

Por eso el veredicto se emite como DECLARADO y nunca como ATESTADO. Es la misma linea que el
verificador de pares traza entre lo que comprueba y lo que le cuentan, y por la misma razon: un
nodo comprometido dira que esta perfecto.

**El quote (ITV-050, 9-ago-2026)**: el operador autorizo y creo la clave de atestacion
(0x81010002, ECC P-256 restringida+firma, herramienta anv-tpm-ak-crear.py). Desde entonces
este servicio PRODUCE el quote (TPM2_Quote sobre PCR 0-7 con nonce fresco) y lo VERIFICA a
bordo con la stdlib: ECDSA P-256 contra la publica RELEIDA del aparato, magic/tipo del
TPMS_ATTEST, nonce devuelto y pcrDigest igual al calculado con los PCR leidos en este mismo
ciclo. ATESTADO se concede SOLO con todo eso en verde y ademas con el control negativo pasado
(una firma alterada tiene que ser rechazada: un verificador que dice si a todo no verifica
nada, y un instrumento roto no valida la hipotesis — obliga a no conceder).

Lo que un quote verificado a bordo ES y NO ES: prueba que el aparato de ESTA maquina firmo
estos PCR ahora (la clave no puede salir del TPM); ante un TERCERO el valor completo llega
cuando un par verifique el quote desde fuera (federacion, fleet_attest), que es trabajo aparte.

Fail-safe: sin aparato, sin permiso o con respuesta rara, se registra y se termina en 0. Este
servicio no puede tumbar la capa. Si el quote falla por lo que sea, la clase se queda en
DECLARADO con el fallo anotado: nunca cae la lectura de PCR por culpa de la firma. Solo stdlib.

Manifest: tpm_attest.py|3600|tpm/tpm_attest.jsonl
Uso: tpm_attest.py [cycle]
"""
import os
import sys
import json
import time
import struct
import hashlib
import binascii

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
OUT = os.path.join(DATA, "tpm", "tpm_attest.jsonl")
DEV = "/dev/tpmrm0"                    # el gestor de recursos: no monopoliza el aparato
DEV_ALT = "/dev/tpm0"

TAG_NO_SESSIONS = 0x8001
CC_GET_CAPABILITY = 0x0000017A
CC_PCR_READ = 0x0000017E
ALG_SHA256 = 0x000B
CAP_TPM_PROPERTIES = 0x00000006
PT_MANUFACTURER = 0x00000105
PCRS = (0, 1, 2, 3, 4, 5, 6, 7)         # plataforma, configuracion y arranque seguro


def _emit(d):
    print(json.dumps(d, ensure_ascii=False), flush=True)
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "a") as f:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL tpm_attest._emit: %r" % (e,), file=sys.stderr, flush=True)


def _dev():
    for d in (DEV, DEV_ALT):
        if os.path.exists(d):
            return d
    return None


def _tx(dev, cmd):
    """Una orden, una respuesta. El aparato no admite dos a la vez por el mismo descriptor.
    (Reabrir por orden vale AQUI porque este servicio solo nombra handles PERSISTENTES,
    que son globales; los transitorios viven por-descriptor en /dev/tpmrm0 — leccion del
    9-ago en anv-tpm-ak-crear. Y rc=0x922 es TPM_RC_RETRY: el aparato pide repetirla.)"""
    for intento in range(5):
        with open(dev, "r+b", buffering=0) as f:
            f.write(cmd)
            r = f.read(8192)
        if len(r) < 10:
            raise ValueError("respuesta corta del TPM: %d bytes" % len(r))
        _tag, _size, rc = struct.unpack(">HII", r[:10])
        if rc == 0x922:
            time.sleep(0.2 * (intento + 1))
            continue
        if rc != 0:
            raise ValueError("el TPM devolvio rc=0x%08x" % rc)
        return r
    raise ValueError("el TPM siguio pidiendo reintento (rc=0x922) tras 5 intentos")


def _fabricante(dev):
    cmd = struct.pack(">HIIIII", TAG_NO_SESSIONS, 22, CC_GET_CAPABILITY,
                      CAP_TPM_PROPERTIES, PT_MANUFACTURER, 1)
    r = _tx(dev, cmd)
    # El identificador del fabricante son los ultimos 4 bytes, en ascii.
    return r[-4:].decode("ascii", "replace").replace("\x00", "").strip()


def _pcr_read(dev, indices):
    """Lee un grupo de PCR del banco SHA256. Devuelve (contador_de_actualizacion, {idx: valor})."""
    mapa, contador = {}, None
    for i in indices:
        octeto, bit = divmod(i, 8)
        sel = bytearray(3)
        if octeto > 2:
            continue
        sel[octeto] = 1 << bit
        cuerpo = struct.pack(">I", 1) + struct.pack(">HB", ALG_SHA256, 3) + bytes(sel)
        cmd = struct.pack(">HII", TAG_NO_SESSIONS, 10 + len(cuerpo), CC_PCR_READ) + cuerpo
        r = _tx(dev, cmd)
        off = 10
        contador = struct.unpack(">I", r[off:off + 4])[0]
        off += 4
        n_sel = struct.unpack(">I", r[off:off + 4])[0]
        off += 4
        for _ in range(n_sel):                 # saltar la seleccion devuelta
            off += 2
            tam = r[off]
            off += 1 + tam
        n_dig = struct.unpack(">I", r[off:off + 4])[0]
        off += 4
        if n_dig < 1:
            continue                           # PCR no presente en este banco
        ln = struct.unpack(">H", r[off:off + 2])[0]
        off += 2
        mapa[i] = binascii.hexlify(r[off:off + ln]).decode()
    return contador, mapa


CC_READ_PUBLIC = 0x00000173
CAP_HANDLES = 0x00000001
ATTR_RESTRINGIDA = 0x00010000
ATTR_FIRMA = 0x00040000


def _claves_persistentes(dev):
    """Handles persistentes del aparato. Lista vacia si no se pueden enumerar."""
    cmd = struct.pack(">HIIIII", TAG_NO_SESSIONS, 22, CC_GET_CAPABILITY,
                      CAP_HANDLES, 0x81000000, 32)
    r = _tx(dev, cmd)
    n = struct.unpack(">I", r[15:19])[0]
    return [struct.unpack(">I", r[19 + 4 * i:23 + 4 * i])[0] for i in range(n)]


def _es_clave_de_firma(dev, h):
    """Lee el area publica del handle y dice si es una clave RESTRINGIDA y de FIRMA."""
    cuerpo = struct.pack(">I", h)
    cmd = struct.pack(">HII", TAG_NO_SESSIONS, 10 + len(cuerpo), CC_READ_PUBLIC) + cuerpo
    try:
        r = _tx(dev, cmd)
    except Exception:
        return False
    off = 10
    ln = struct.unpack(">H", r[off:off + 2])[0]
    pub = r[off + 2:off + 2 + ln]
    if len(pub) < 8:
        return False
    attrs = struct.unpack(">I", pub[4:8])[0]
    return bool(attrs & ATTR_RESTRINGIDA) and bool(attrs & ATTR_FIRMA)


# ── Quote y verificacion a bordo (ITV-050 parte 2) ──────────────────────────────
CC_QUOTE = 0x00000158
TAG_SESSIONS = 0x8002
RS_PW = 0x40000009
ALG_NULL = 0x0010
ALG_ECDSA = 0x0018
MAGIC_ATTEST = 0xFF544347
ST_ATTEST_QUOTE = 0x8018

# Curva NIST P-256 con la aritmetica entera de la stdlib: una verificacion por ciclo,
# la velocidad no manda; mandan cero dependencias en un nodo que va justo de herramientas.
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
    """Verificacion ECDSA P-256. True/False, sin excepciones: un fallo raro es un NO."""
    try:
        if not (0 < r < _EC_N and 0 < s < _EC_N):
            return False
        if (qy * qy - (qx * qx * qx - 3 * qx + _EC_B)) % _EC_P != 0:
            return False                     # la publica ni siquiera esta en la curva
        e = int.from_bytes(hash_bytes, "big")
        w = pow(s, _EC_N - 2, _EC_N)
        pt = _ec_suma(_ec_mul(e * w % _EC_N, _EC_G), _ec_mul(r * w % _EC_N, (qx, qy)))
        return pt is not None and pt[0] % _EC_N == r
    except Exception:
        return False


def _publica_xy(dev, h):
    """(x, y) enteros de la publica ECC del handle, releidos del aparato."""
    r = _tx(dev, struct.pack(">HII", TAG_NO_SESSIONS, 14, CC_READ_PUBLIC) + struct.pack(">I", h))
    ln = struct.unpack(">H", r[10:12])[0]
    pub = r[12:12 + ln]
    o = 8
    o += 2 + struct.unpack(">H", pub[o:o + 2])[0] + 10   # authPolicy + parametros ECC
    lx = struct.unpack(">H", pub[o:o + 2])[0]
    x = int.from_bytes(pub[o + 2:o + 2 + lx], "big")
    o += 2 + lx
    ly = struct.unpack(">H", pub[o:o + 2])[0]
    return x, int.from_bytes(pub[o + 2:o + 2 + ly], "big")


def _quote(dev, h, nonce, indices):
    """TPM2_Quote del banco sha256 con sesion de contrasena vacia. (attest, r, s)."""
    sel = bytearray(3)
    for i in indices:
        sel[i // 8] |= 1 << (i % 8)
    ses = struct.pack(">IHBH", RS_PW, 0, 0, 0)
    cuerpo = (struct.pack(">I", h) + struct.pack(">I", len(ses)) + ses
              + struct.pack(">H", len(nonce)) + nonce
              + struct.pack(">H", ALG_NULL)              # inScheme: el propio de la clave
              + struct.pack(">I", 1) + struct.pack(">HB", ALG_SHA256, 3) + bytes(sel))
    r = _tx(dev, struct.pack(">HII", TAG_SESSIONS, 10 + len(cuerpo), CC_QUOTE) + cuerpo)
    off = 14                                             # cabecera + parameterSize
    ln = struct.unpack(">H", r[off:off + 2])[0]
    attest = r[off + 2:off + 2 + ln]
    off += 2 + ln
    sig_alg, hash_alg = struct.unpack(">HH", r[off:off + 4])
    off += 4
    lr = struct.unpack(">H", r[off:off + 2])[0]
    sr = int.from_bytes(r[off + 2:off + 2 + lr], "big")
    off += 2 + lr
    ls = struct.unpack(">H", r[off:off + 2])[0]
    ss = int.from_bytes(r[off + 2:off + 2 + ls], "big")
    if sig_alg != ALG_ECDSA or hash_alg != ALG_SHA256:
        raise ValueError("firma inesperada alg=0x%04x hash=0x%04x" % (sig_alg, hash_alg))
    return attest, sr, ss


def _attest_campos(attest):
    """(magic, tipo, extraData, pcrDigest) del TPMS_ATTEST de un quote."""
    magic, tipo = struct.unpack(">IH", attest[:6])
    o = 6
    o += 2 + struct.unpack(">H", attest[o:o + 2])[0]     # qualifiedSigner
    ln = struct.unpack(">H", attest[o:o + 2])[0]
    extra = attest[o + 2:o + 2 + ln]
    o += 2 + ln + 17 + 8                                 # extraData + clockInfo + firmware
    n_sel = struct.unpack(">I", attest[o:o + 4])[0]
    o += 4
    for _ in range(n_sel):
        o += 2
        o += 1 + attest[o]
    ln = struct.unpack(">H", attest[o:o + 2])[0]
    return magic, tipo, extra, attest[o + 2:o + 2 + ln]


def _atestar(dev, firmante, pcrs):
    """Produce y verifica el quote. Devuelve (ok, detalle_dict). NUNCA lanza hacia arriba."""
    try:
        nonce = os.urandom(16)
        attest, sr, ss = _quote(dev, firmante, nonce, sorted(pcrs))
        magic, tipo, extra, digest = _attest_campos(attest)
        h = hashlib.sha256()
        for i in sorted(pcrs):
            h.update(binascii.unhexlify(pcrs[i]))
        qx, qy = _publica_xy(dev, firmante)
        hq = hashlib.sha256(attest).digest()
        checks = {
            "estructura_attest": magic == MAGIC_ATTEST and tipo == ST_ATTEST_QUOTE,
            "nonce_devuelto": extra == nonce,
            "pcr_digest_coincide": digest == h.digest(),
            "firma_ecdsa_valida": _ecdsa_verifica(hq, sr, ss, qx, qy),
            # Control negativo: un verificador que acepta datos alterados no verifica nada,
            # y con el instrumento roto NO se concede ATESTADO (se remide, no se supone).
            "control_negativo_rechaza": not _ecdsa_verifica(
                hashlib.sha256(attest + b"x").digest(), sr, ss, qx, qy),
        }
        return all(checks.values()), {
            "ak": hex(firmante), "checks": checks,
            "pcr_digest_del_quote": binascii.hexlify(digest).decode(),
            # Material crudo para PUBLICAR: con esto un PAR repite la verificacion entera
            # desde fuera (ITF-002). La clave no sale del TPM; esto es su huella publica.
            "_crudo": {"attest_hex": binascii.hexlify(attest).decode(),
                       "sig_r": "%064x" % sr, "sig_s": "%064x" % ss,
                       "pub_x": "%064x" % qx, "pub_y": "%064x" % qy,
                       "pcr": dict(pcrs)}}
    except Exception as e:
        return False, {"ak": hex(firmante), "quote_error": str(e)[:140]}


def _clase_medida(dev):
    """Deduce la clase PREGUNTANDO al aparato, en vez de afirmarla.

    DEFECTO CORREGIDO (ITD-021, hallado por revisor-d el 05-ago-2026). Este servicio escribia
    clase='DECLARADO' de forma FIJA y su nota afirmaba «sin clave de atestacion dentro del TPM»
    sin comprobarlo. Hoy la afirmacion es cierta —origo tiene dos claves persistentes y las dos
    son de cifrado— pero lo es POR CASUALIDAD: el mismo servicio en el equipo principal, que SI
    tiene una clave restringida y de firma, seguiria diciendo DECLARADO y seria incapaz de ver
    la diferencia.

    Un veredicto cableado no es un veredicto: es una etiqueta. Y una etiqueta que acierta por
    casualidad es peor que una equivocada, porque nadie la revisa.

    Se distinguen TRES situaciones, no dos:
      SIN_CLAVE_DE_ATESTACION  no hay ninguna clave restringida de firma -> no cabe quote.
      CLAVE_DISPONIBLE         la hay: el aparato PODRIA firmar un quote, y este servicio aun no
                               lo produce. Se dice, en vez de esconderlo tras DECLARADO.
      (ATESTADO)               reservado a cuando exista quote PRODUCIDO Y VERIFICADO. No se
                               concede por tener la clave: tenerla no es haber firmado.
    """
    try:
        handles = _claves_persistentes(dev)
    except Exception as e:
        return "DECLARADO", None, "no se pudieron enumerar las claves: %s" % str(e)[:60]
    firmantes = [h for h in handles if _es_clave_de_firma(dev, h)]
    if not firmantes:
        return ("DECLARADO", [],
                "medido: %d claves persistentes y NINGUNA restringida de firma, de modo que este "
                "aparato no puede producir un quote hoy" % len(handles))
    return ("DECLARADO", firmantes,
            "medido: hay %d clave(s) restringida(s) de firma (%s). El aparato PODRIA firmar un "
            "quote y este servicio aun no lo produce: sigue siendo lectura, no atestacion"
            % (len(firmantes), ", ".join(hex(h) for h in firmantes)))


def cmd_cycle():
    ahora = int(time.time())
    rec = {"svc": "tpm_attest", "ts": ahora, "clase": "DECLARADO",
           "nota": ("lectura de PCR del aparato, NO un quote firmado: sin clave de atestacion "
                    "dentro del TPM esto vale para quien ya confia en el nodo y no vale ante "
                    "quien no. El quote exige CREAR una clave en el TPM, que escribe en hardware "
                    "de produccion y no lo hace un servicio observe-only por su cuenta")}

    dev = _dev()
    if not dev:
        rec.update({"veredicto": "SIN_APARATO",
                    "detalle": "no hay /dev/tpmrm0 ni /dev/tpm0 en este nodo"})
        _emit(rec)
        return 0

    rec["aparato"] = dev
    try:
        rec["fabricante"] = _fabricante(dev)
    except Exception as e:
        rec.update({"veredicto": "NO_RESPONDE", "detalle": str(e)[:140]})
        _emit(rec)
        return 0

    try:
        contador, pcrs = _pcr_read(dev, PCRS)
    except Exception as e:
        rec.update({"veredicto": "LECTURA_FALLIDA", "detalle": str(e)[:140]})
        _emit(rec)
        return 0

    if not pcrs:
        rec.update({"veredicto": "SIN_PCR",
                    "detalle": "el aparato responde pero no devolvio ningun PCR del banco sha256"})
        _emit(rec)
        return 0

    # Huella compuesta de los PCR leidos: una sola cifra que cambia si cambia cualquiera de ellos.
    # Sirve para comparar arranques entre ciclos sin publicar los ocho valores en cada sitio.
    h = hashlib.sha256()
    for i in sorted(pcrs):
        h.update(b"%d:" % i + pcrs[i].encode())
    compuesta = h.hexdigest()

    # PCR7 mide el estado del arranque seguro. Todo ceros = ese registro nunca se extendio.
    pcr7 = pcrs.get(7, "")
    arranque_medido = bool(pcr7) and set(pcr7) != {"0"}

    clase, firmantes, motivo_clase = _clase_medida(dev)
    rec["clase"] = clase
    rec["claves_de_firma_en_el_aparato"] = ([hex(h) for h in firmantes] if firmantes else [])
    rec["clase_motivo"] = motivo_clase

    # Con clave de atestacion: producir el quote y verificarlo A BORDO. Si algo no cuadra,
    # la clase se queda en DECLARADO con el detalle a la vista: la lectura de PCR nunca cae
    # por culpa de la firma, y ATESTADO no se concede sin quote PRODUCIDO Y VERIFICADO.
    quote_ok, quote_detalle = (False, None)
    if firmantes:
        quote_ok, quote_detalle = _atestar(dev, firmantes[0], pcrs)
        crudo = (quote_detalle or {}).pop("_crudo", None)   # el registro no carga con el blob
        rec["quote"] = quote_detalle
        if quote_ok and crudo:
            # Publicacion para pares (la sirve el panel en /attest/tpm, ruta publica por diseno,
            # como /attest): fichero de ULTIMO ESTADO, no registro — el historial de digestos ya
            # queda en este .jsonl. tmp+replace para que un lector nunca vea el fichero a medias.
            try:
                pub = {"svc": "tpm_attest", "ts": ahora, "ak": quote_detalle["ak"],
                       "pcr_digest": quote_detalle["pcr_digest_del_quote"],
                       "nota": ("quote TPM2 del ultimo ciclo con nonce propio del nodo: un par "
                                "verifica firma, estructura y pcrDigest, y vigila la continuidad "
                                "del AK; la frescura es la del ciclo (ts)")}
                pub.update(crudo)
                ruta = os.path.join(DATA, "tpm", "quote_publico.json")
                os.makedirs(os.path.dirname(ruta), exist_ok=True)   # 1er ciclo de un nodo virgen:
                tmp = ruta + ".tmp"                                  # _emit aun no creo el dir
                with open(tmp, "w") as f:
                    json.dump(pub, f, ensure_ascii=False)
                os.replace(tmp, ruta)
            except Exception:
                pass                                        # publicar es best-effort, atestar no
        if quote_ok:
            rec["clase"] = "ATESTADO"
            rec["clase_motivo"] = ("quote TPM2 sobre PCR 0-7 con nonce fresco, firmado por "
                                   "%s y verificado a bordo: estructura, nonce, pcrDigest y "
                                   "firma ECDSA contra la publica releida, con el control "
                                   "negativo pasado" % quote_detalle["ak"])
            rec["nota"] = ("quote producido y verificado a bordo: prueba que el aparato de "
                           "ESTA maquina firmo estos PCR ahora. El valor ante un tercero "
                           "llega cuando un par lo verifique desde fuera (federacion)")

    rec.update({
        "veredicto": "PCR_LEIDOS",
        "contador_actualizacion": contador,
        "pcr_leidos": len(pcrs),
        "pcr": pcrs,
        "huella_compuesta": compuesta,
        "arranque_seguro_medido": arranque_medido,
        "quote_firmado": bool(quote_ok),
        "apto_para_voto_ponderado": False,
        "motivo_no_apto": (("la atestacion ya existe y esta verificada a bordo; la politica "
                            "exige ademas Trust Manifest, y esa pieza no la mide este servicio")
                           if quote_ok else
                           ("la politica exige atestacion, y una lectura sin quote verificado "
                            "no lo es"))})
    _emit(rec)
    return 0


def main():
    try:
        return cmd_cycle()
    except Exception as e:
        _emit({"svc": "tpm_attest", "ts": int(time.time()), "veredicto": "ERROR_INTERNO",
               "error": str(e)[:200]})
        return 0


if __name__ == "__main__":
    sys.exit(main())
