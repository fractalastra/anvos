#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""llave_local — el nodo habla con la llave física que tiene puesta, sin depender de nadie.

POR QUÉ (decisión del operador, 2026-08-02 · ITD-017)

Ningún nodo del sistema propio debe depender de otra máquina para firmar con su llave. Hoy no
podía: no hay herramientas de tarjeta en el nodo y el núcleo **no soporta usbfs** —medido: no
figura en /proc/filesystems y el montaje se rechaza—, así que la vía de tarjeta inteligente
está cerrada sin recompilar el núcleo.

Lo que sí hay, y estaba delante: el núcleo enumera la llave como dispositivo de interfaz humana,
y ese camino se recorre **con biblioteca estándar y sin añadir un solo binario**. Medido antes de
escribir esto: la llave negocia canal desde el propio nodo, CTAP 2, firmware 5.7.4.

  OJO CON LAS DOS INTERFACES: el núcleo enumera dos para la MISMA llave y solo una habla este
  protocolo. Probando solo con la primera se concluye que la llave no sirve — y sirve. Por eso
  aquí se prueban todas y se dice cuál respondió.

QUÉ HACE Y QUÉ NO

  informar   pregunta a la llave qué es y qué sabe hacer. NO pide toque, no escribe en ella.
  verificar  comprueba una firma contra la parte pública de la credencial. NO pide toque.
  crear      crea una credencial del nodo en la llave.     EXIGE TOQUE FÍSICO.
  firmar     firma un reto con esa credencial.             EXIGE TOQUE FÍSICO.

El toque no es un estorbo: es la prueba de que hay una persona presente. Un nodo que pudiera
firmar sin él tendría una llave que en realidad no protege nada.

AÑADIDO EL 2-ago CON EL OPERADOR DELANTE, y es lo que convierte esto en una prueba: `crear` guarda
ahora la CLAVE PÚBLICA que la llave devuelve —antes se descartaba— y `verificar` comprueba la firma
contra ella. Sin eso, el nodo firmaba y **nadie podía confirmar ni refutar** el resultado: no era una
firma, era un fichero con forma de firma. La comprobación de la curva P-256 va en biblioteca estándar
porque la forma sellada no trae criptografía y la regla del núcleo único prohíbe añadirla; verificar no
maneja secretos, así que la privada sigue sin salir de la llave.
Validado antes de desplegar contra vectores publicados: 2G y 3G de la curva, el vector ECDSA de
FIPS 186-4 en su caso bueno, y TRES casos malos —huella alterada, firma alterada y punto fuera de la
curva— que deben fallar y fallan.

LÍMITE DECLARADO, y conviene no disimularlo: esto produce firmas del formato de la llave, que
**no es el formato que el ecosistema usa hoy** para sus artefactos. Sirve para que el nodo
acredite actos suyos ante quien acepte ese formato; no convierte al nodo en autoridad del reino,
y eso es correcto: la autoridad local de un nodo no es la raíz.

Solo biblioteca estándar.

Manifest: llave_local.py|0|llave/llave_local.jsonl
Uso: llave_local.py informar | crear <id_nodo> | firmar <fichero> | verificar <fichero>
"""
import glob
import hashlib
import json
import os
import select
import struct
import sys
import time

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
SALIDA = os.path.join(DATA, "llave", "llave_local.jsonl")
# Pista de en que interfaz respondio la llave la ultima vez (ITV-069). Es solo eso: una
# pista para no repetir la espera, nunca una condicion para dejar de buscar.
RECUERDO = os.path.join(DATA, "llave", "ultima_interfaz")
CRED = os.path.join(DATA, "llave", "credencial_nodo.json")
BROADCAST = 0xFFFFFFFF
CMD_INIT, CMD_MSG, CMD_ERROR, CMD_KEEPALIVE = 0x86, 0x90, 0xBF, 0xBB
RP = "anvos.local"          # a quién pertenece la credencial, desde el punto de vista de la llave


# ─── el mínimo de CBOR que hace falta, y nada más ────────────────────────────────────────────
def _cbor_lee(b, i=0):
    m, v = b[i] >> 5, b[i] & 0x1F
    i += 1
    if v == 24:
        v = b[i]; i += 1
    elif v == 25:
        v = struct.unpack(">H", b[i:i+2])[0]; i += 2
    elif v == 26:
        v = struct.unpack(">I", b[i:i+4])[0]; i += 4
    if m == 0:
        return v, i
    if m == 1:
        return -1 - v, i
    if m == 2:
        return b[i:i+v], i + v
    if m == 3:
        return b[i:i+v].decode("utf-8", "replace"), i + v
    if m in (4, 5):
        salida = [] if m == 4 else {}
        for _ in range(v):
            k, i = _cbor_lee(b, i)
            if m == 4:
                salida.append(k)
            else:
                val, i = _cbor_lee(b, i)
                salida[k if isinstance(k, (str, int)) else str(k)] = val
        return salida, i
    if m == 7:
        return {20: False, 21: True, 22: None}.get(v, v), i
    raise ValueError(f"CBOR: tipo {m} no soportado por este cliente mínimo")


def _cbor_escribe(o):
    def cab(m, v):
        if v < 24:
            return bytes([(m << 5) | v])
        if v < 256:
            return bytes([(m << 5) | 24, v])
        if v < 65536:
            return bytes([(m << 5) | 25]) + struct.pack(">H", v)
        return bytes([(m << 5) | 26]) + struct.pack(">I", v)
    if isinstance(o, bool):
        return bytes([0xF5 if o else 0xF4])
    if isinstance(o, int):
        return cab(0, o) if o >= 0 else cab(1, -1 - o)
    if isinstance(o, bytes):
        return cab(2, len(o)) + o
    if isinstance(o, str):
        d = o.encode()
        return cab(3, len(d)) + d
    if isinstance(o, list):
        return cab(4, len(o)) + b"".join(_cbor_escribe(x) for x in o)
    if isinstance(o, dict):
        # CTAP exige claves ordenadas de forma canónica
        cl = sorted(o, key=lambda k: (isinstance(k, str), k))
        return cab(5, len(o)) + b"".join(_cbor_escribe(k) + _cbor_escribe(o[k]) for k in cl)
    raise ValueError(f"CBOR: no sé escribir {type(o)}")


# ─── transporte con la llave ─────────────────────────────────────────────────────────────────
class Llave:
    def __init__(self, dev):
        self.dev = dev
        self.fd = os.open(dev, os.O_RDWR | os.O_NONBLOCK)
        self.cid = BROADCAST
        self.info = {}

    def cerrar(self):
        try:
            os.close(self.fd)
        except OSError:
            pass

    def _leer(self, plazo):
        listos, _, _ = select.select([self.fd], [], [], plazo)
        return os.read(self.fd, 64) if listos else None

    def _enviar(self, cmd, datos, plazo=3.0):
        paq = struct.pack(">IBH", self.cid, cmd, len(datos)) + datos[:57]
        os.write(self.fd, paq + b"\x00" * (64 - len(paq)))
        resto, seq = datos[57:], 0
        while resto:
            trozo = resto[:59]
            resto = resto[59:]
            p = struct.pack(">IB", self.cid, seq) + trozo
            os.write(self.fd, p + b"\x00" * (64 - len(p)))
            seq += 1
        # respuesta, tolerando los avisos de "sigo aquí" mientras se espera el toque
        fin = time.time() + plazo
        while time.time() < fin:
            r = self._leer(max(0.1, fin - time.time()))
            if r is None:
                continue
            if r[4] == CMD_KEEPALIVE:
                continue
            if r[4] == CMD_ERROR:
                raise OSError(f"la llave responde error 0x{r[7]:02x}")
            total = struct.unpack(">H", r[5:7])[0]
            cuerpo = r[7:7 + min(total, 57)]
            while len(cuerpo) < total:
                c = self._leer(max(0.1, fin - time.time()))
                if c is None:
                    break
                cuerpo += c[5:5 + min(total - len(cuerpo), 59)]
            return cuerpo
        raise TimeoutError(f"sin respuesta en {plazo}s")

    def abrir_canal(self):
        r = self._enviar(CMD_INIT, b"\x01\x02\x03\x04\x05\x06\x07\x08", plazo=2.0)
        if len(r) < 17 or r[:8] != b"\x01\x02\x03\x04\x05\x06\x07\x08":
            raise OSError("no habla este protocolo")
        self.cid = struct.unpack(">I", r[8:12])[0]
        self.info = {"ctap": r[12], "firmware": f"{r[13]}.{r[14]}.{r[15]}"}
        return self.info

    def ctap(self, cmd, params=None, plazo=3.0):
        cuerpo = bytes([cmd]) + (_cbor_escribe(params) if params else b"")
        r = self._enviar(CMD_MSG, cuerpo, plazo=plazo)
        if not r:
            raise OSError("respuesta vacía")
        if r[0] != 0:
            raise OSError(f"la llave rechaza la orden (estado 0x{r[0]:02x})")
        return _cbor_lee(r[1:])[0] if len(r) > 1 else {}


def _recordada():
    """Última interfaz que respondió, si se anotó. Devuelve None si no hay memoria."""
    try:
        with open(RECUERDO) as f:
            d = f.read().strip()
        return d if d.startswith("/dev/hidraw") else None
    except OSError:
        return None


def _recordar(dev):
    """Anota qué interfaz respondió. Es una pista, nunca una condición: si mañana la llave está
    en otra, el recorrido completo la encuentra igual."""
    try:
        os.makedirs(os.path.dirname(RECUERDO), exist_ok=True)
        with open(RECUERDO, "w") as f:
            f.write(dev)
    except OSError:
        pass


def _buscar(plazo=2.0):
    """Prueba TODAS las interfaces y dice cuál respondió. Concluir desde la primera es el error.

    ORDEN DE PRUEBA (ITV-069, medido el 2026-08-07)
    ------------------------------------------------
    Se recorrían las interfaces por orden alfabético, de modo que en este nodo se agotaban siempre
    los 2,0 s de plazo en /dev/hidraw0 —que no es la llave y nunca responde— antes de encontrarla en
    /dev/hidraw1. Medido: 2,10 s por pasada, de los cuales 2,00 s son esa espera. Con 15.191
    ejecuciones acumuladas son más de OCHO HORAS de espera, y una ventana de dos segundos abierta en
    cada pasada para que el supervisor —que corta a los 6 s— la interrumpa.
    """
    intentos = []
    # Se prueba PRIMERO la que respondió la última vez. No se descarta ninguna: si esa falla, el
    # recorrido completo sigue igual detrás. Es una pista para no volver a pagar la misma espera,
    # no una lista blanca: dar por hecho que la llave sigue donde estaba seria suponer, y aqui se
    # supone lo menos posible.
    orden = sorted(glob.glob("/dev/hidraw*"))
    prev = _recordada()
    if prev in orden:
        orden.remove(prev)
        orden.insert(0, prev)
    for dev in orden:
        try:
            k = Llave(dev)
        except OSError as e:
            intentos.append((dev, f"no se puede abrir ({e})"))
            continue
        try:
            k.abrir_canal()
            _recordar(dev)
            return k, intentos
        except Exception as e:
            intentos.append((dev, str(e)))
            k.cerrar()
    return None, intentos


def _anotar(rec):
    rec.update({"svc": "llave_local", "ts": int(time.time())})
    try:
        os.makedirs(os.path.dirname(SALIDA), exist_ok=True)
        with open(SALIDA, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        print(f"[aviso] NO_REGISTRADO ({e})", file=sys.stderr)


def cmd_informar():
    k, intentos = _buscar()
    if k is None:
        # NO HAY LLAVE NO ES UNA AVERIA DE ESTE SERVICIO (ITV-077, medido el 2026-08-07).
        #
        # Informar es lo que hace, y decir «aqui no hay llave» es informar correctamente. Devolvia 3,
        # el supervisor lo contaba como fallo y en un nodo sin llave fisica eso significa fallar
        # SIEMPRE: medido en el nodo de laboratorio, 120 fallos de 121 ejecuciones. Ese ruido tapa
        # una averia de verdad el dia que la haya, y ademas cuenta como deriva de salud del nodo.
        #
        # Es la tercera vez esta semana que el mismo malentendido aparece en tres servicios sin
        # relacion entre si: el antivirus salia con codigo 1 al ENCONTRAR algo y se leia como
        # servicio roto; el activador de la grafica fallaba siempre en una maquina sin esa grafica.
        # El patron es uno: confundir «el hecho que este servicio existe para constatar» con «este
        # servicio no ha podido funcionar». Un informador que informa ha terminado bien.
        #
        # Termina en 0 y lo DECLARA en su registro. Lo que si sigue siendo fallo es no poder ni
        # mirar —sin interfaces que probar—, porque entonces no informa: no puede.
        print("SIN_LLAVE — ninguna interfaz respondió:")
        for d, m in intentos:
            print(f"    {d}: {m}")
        _anotar({"orden": "informar", "resultado": "SIN_LLAVE", "intentos": len(intentos),
                 "nota": "ausencia de llave constatada; no es un fallo del servicio"})
        # NI SIQUIERA ESTO es un fallo, y mi primera version lo trataba como tal. Una maquina sin
        # interfaces de dispositivo humano —una maquina virtual, por ejemplo— no tiene donde haber
        # una llave: constatar que no hay es la respuesta correcta, no la imposibilidad de mirar.
        # Lo comprobo el nodo de laboratorio, que tiene CERO interfaces y seguia contando fallo.
        # El fallo de verdad seria no poder ejecutarse ni dejar constancia, y eso ya lo cubre el
        # tratamiento de excepciones de arriba.
        if not intentos:
            print("  sin interfaces de dispositivo humano en esta maquina: no hay donde haber llave")
        return 0
    try:
        info = k.ctap(0x04)   # pregunta qué es y qué sabe hacer. NO pide toque.
        versiones = info.get(1, [])
        exts = info.get(2, [])
        aaguid = info.get(3, b"")
        opciones = info.get(4, {})
        print(f"LLAVE PRESENTE en {k.dev}")
        print(f"  canal negociado, protocolo CTAP {k.info['ctap']}, firmware {k.info['firmware']}")
        print(f"  versiones      : {', '.join(versiones) if versiones else 'no declaradas'}")
        print(f"  extensiones    : {', '.join(exts) if exts else 'ninguna'}")
        print(f"  identificador  : {aaguid.hex() if isinstance(aaguid, bytes) else aaguid}")
        print(f"  presencia física exigida: {opciones.get('up', 'no declarado')}")
        print(f"  puede residir credencial: {opciones.get('rk', 'no declarado')}")
        for d, m in intentos:
            print(f"  (nota: {d} no respondió — {m})")
        _anotar({"orden": "informar", "resultado": "OK", "dev": k.dev,
                 "ctap": k.info["ctap"], "firmware": k.info["firmware"],
                 "versiones": versiones})
        return 0
    except Exception as e:
        print(f"LLAVE_NO_INTERROGABLE — el canal se abrió pero no contesta a la consulta: {e}")
        _anotar({"orden": "informar", "resultado": "NO_INTERROGABLE", "motivo": str(e)})
        return 3
    finally:
        k.cerrar()


def cmd_crear(node_id):
    k, _ = _buscar()
    if k is None:
        print("SIN_LLAVE — no hay ninguna llave que responda en este nodo")
        return 3
    try:
        reto = hashlib.sha256(f"anvos-cred-{node_id}".encode()).digest()
        params = {1: reto,
                  2: {"id": RP, "name": "AstraNova nodo soberano"},
                  3: {"id": node_id.encode(), "name": node_id},
                  4: [{"alg": -7, "type": "public-key"}]}
        print("TOCA LA LLAVE cuando parpadee (60 s)...", flush=True)
        r = k.ctap(0x01, params, plazo=60.0)
        datos = r.get(2, b"")
        if not isinstance(datos, bytes) or len(datos) < 55:
            print("CREDENCIAL_NO_CREADA — la llave respondió algo que no sé interpretar")
            return 3
        largo = struct.unpack(">H", datos[53:55])[0]
        cred_id = datos[55:55 + largo]

        # DEFECTO MEDIDO Y SUBSANADO (2-ago-2026, con el operador delante del nodo). La primera
        # versión se detenía justo aquí: extraía el identificador de la credencial y **tiraba la
        # clave pública**, que viene inmediatamente después en estos mismos bytes.
        #
        # Consecuencia exacta, comprobada sobre una firma real: el nodo firmaba con su llave y su
        # toque, el fichero salía bien formado… y **nadie podía confirmar ni refutar esa firma**,
        # porque la mitad pública no existía en ninguna parte. No era una firma: era un fichero con
        # forma de firma. Es el patrón que esta casa ya sabe nombrar —*el artefacto existe, el
        # consumidor no*— aparecido justo en la pieza que debía cerrar la fase.
        pub = {}
        try:
            cose, _ = _cbor_lee(datos, 55 + largo)
            x, y = cose.get(-2), cose.get(-3)
            if isinstance(x, bytes) and isinstance(y, bytes) and len(x) == 32 == len(y):
                pub = {"crv": "P-256", "alg": cose.get(3), "x": x.hex(), "y": y.hex()}
        except Exception:
            pub = {}
        if not pub:
            # Fail-closed: sin parte pública la credencial NO sirve para acreditar nada, así que no
            # se guarda a medias fingiendo que sí. Mejor repetir el toque que quedarse con una
            # credencial que solo parece útil.
            print("CREDENCIAL_NO_CREADA — la llave no devolvió una clave pública utilizable.\n"
                  "  No se guarda nada: una credencial sin parte pública no puede verificarse y "
                  "sería un artefacto que solo aparenta servir.")
            _anotar({"orden": "crear", "resultado": "SIN_PUBLICA"})
            return 3

        os.makedirs(os.path.dirname(CRED), exist_ok=True)
        with open(CRED, "w") as f:
            json.dump({"nodo": node_id, "rp": RP, "cred_id": cred_id.hex(),
                       "publica": pub, "ts": int(time.time())}, f, indent=1)
        os.chmod(CRED, 0o600)
        print(f"CREDENCIAL CREADA para «{node_id}» — identificador {cred_id.hex()[:24]}…")
        print(f"  guardada en {CRED}. La clave privada NO sale de la llave: eso es el punto.")
        _anotar({"orden": "crear", "nodo": node_id, "cred": cred_id.hex()[:24]})
        return 0
    except TimeoutError:
        print("SIN_TOQUE — nadie tocó la llave. No se creó nada, y es lo correcto: sin persona "
              "presente no hay credencial.")
        _anotar({"orden": "crear", "resultado": "SIN_TOQUE"})
        return 4
    except Exception as e:
        print(f"CREDENCIAL_NO_CREADA — {e}")
        _anotar({"orden": "crear", "resultado": "ERROR", "motivo": str(e)})
        return 3
    finally:
        k.cerrar()


def cmd_firmar(fichero):
    if not os.path.isfile(fichero):
        print(f"NO_FIRMADO — no existe {fichero}")
        return 2
    if not os.path.isfile(CRED):
        print(f"SIN_CREDENCIAL — este nodo aún no tiene credencial en la llave ({CRED}). "
              "Créala primero con «crear».")
        return 3
    cred = json.load(open(CRED))
    k, _ = _buscar()
    if k is None:
        print("SIN_LLAVE — no hay ninguna llave que responda en este nodo")
        return 3
    try:
        huella = hashlib.sha256(open(fichero, "rb").read()).digest()
        params = {1: RP, 2: huella,
                  3: [{"id": bytes.fromhex(cred["cred_id"]), "type": "public-key"}]}
        print("TOCA LA LLAVE para firmar (60 s)...", flush=True)
        r = k.ctap(0x02, params, plazo=60.0)
        firma = r.get(3, b"")
        if not firma:
            print("NO_FIRMADO — la llave no devolvió firma")
            return 3
        destino = fichero + ".llave"
        with open(destino, "w") as f:
            json.dump({"typ": "ANVOS-FIRMA-LLAVE-v1", "fichero": os.path.basename(fichero),
                       "sha256": huella.hex(), "firma": firma.hex(),
                       "datos_autenticador": r.get(2, b"").hex() if isinstance(r.get(2), bytes) else "",
                       "cred_id": cred["cred_id"], "nodo": cred["nodo"],
                       "ts": int(time.time())}, f, indent=1)
        print(f"FIRMADO POR LA LLAVE DEL NODO — {destino}")
        print("  ninguna otra máquina ha participado: el reto se calculó aquí y la firma la "
              "hizo la llave puesta en este nodo, con toque.")
        _anotar({"orden": "firmar", "fichero": os.path.basename(fichero),
                 "sha256": huella.hex()[:16], "resultado": "OK"})
        return 0
    except TimeoutError:
        print("SIN_TOQUE — nadie tocó la llave. No hay firma, y es lo correcto.")
        _anotar({"orden": "firmar", "resultado": "SIN_TOQUE"})
        return 4
    except Exception as e:
        print(f"NO_FIRMADO — {e}")
        _anotar({"orden": "firmar", "resultado": "ERROR", "motivo": str(e)})
        return 3
    finally:
        k.cerrar()


# ─── P-256, lo justo para COMPROBAR una firma (nunca para hacerla) ───────────────────────────
# Se implementa aquí porque la forma sellada no trae biblioteca de criptografía y la regla del
# núcleo único prohíbe añadirla. Es solo aritmética modular: **verificar** no maneja ningún
# secreto. La clave privada sigue sin salir de la llave, que es el punto de todo esto.
_P256_P = 2**256 - 2**224 + 2**192 + 2**96 - 1
_P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
_P256_A = _P256_P - 3
_P256_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
           0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def _pt_suma(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % _P256_P == 0:
        return None
    if P == Q:
        l = (3 * x1 * x1 + _P256_A) * pow(2 * y1, -1, _P256_P) % _P256_P
    else:
        l = (y2 - y1) * pow(x2 - x1, -1, _P256_P) % _P256_P
    x3 = (l * l - x1 - x2) % _P256_P
    return (x3, (l * (x1 - x3) - y1) % _P256_P)


def _pt_mul(k, P):
    R = None
    while k:
        if k & 1:
            R = _pt_suma(R, P)
        P = _pt_suma(P, P)
        k >>= 1
    return R


def _der_rs(firma):
    """(r, s) de una firma DER. Se valida la forma: una firma mal formada NO es una firma."""
    if len(firma) < 8 or firma[0] != 0x30:
        raise ValueError("no es una secuencia DER")
    i = 2 if firma[1] < 0x80 else 3
    out = []
    for _ in range(2):
        if firma[i] != 0x02:
            raise ValueError("falta un entero DER")
        n = firma[i + 1]
        out.append(int.from_bytes(firma[i + 2:i + 2 + n], "big"))
        i += 2 + n
    return out[0], out[1]


def _ecdsa_ok(x, y, e, r, s):
    if not (1 <= r < _P256_N and 1 <= s < _P256_N):
        return False
    if (y * y - (x * x * x + _P256_A * x + 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)) % _P256_P:
        return False          # el punto ni siquiera está en la curva
    w = pow(s, -1, _P256_N)
    R = _pt_suma(_pt_mul(e * w % _P256_N, _P256_G), _pt_mul(r * w % _P256_N, (x, y)))
    return R is not None and R[0] % _P256_N == r


def cmd_verificar(fichero):
    """Comprueba una firma de la llave contra la parte pública de la credencial del nodo."""
    sello = fichero if fichero.endswith(".llave") else fichero + ".llave"
    origen = sello[:-6]
    if not os.path.isfile(sello):
        print(f"SIN_FIRMA — no existe {sello}")
        return 2
    if not os.path.isfile(CRED):
        print(f"SIN_CREDENCIAL — no hay credencial del nodo en {CRED}")
        return 3
    cred = json.load(open(CRED))
    pub = cred.get("publica") or {}
    if not pub.get("x"):
        print("NO_VERIFICABLE — la credencial de este nodo NO guarda su parte pública.\n"
              "  Esto NO significa que la firma sea falsa: significa que no se puede comprobar,\n"
              "  y no haber podido comprobar algo no es haberlo comprobado. Vuelve a crear la\n"
              "  credencial con «crear» para que quede guardada.")
        _anotar({"orden": "verificar", "resultado": "NO_VERIFICABLE_SIN_PUBLICA"})
        return 5
    d = json.load(open(sello))
    try:
        # El autenticador firma sobre sus propios datos SEGUIDOS del reto, y el reto aquí es la
        # huella del fichero. Por eso se recalcula del fichero EN DISCO: si alguien lo alteró
        # después de firmarlo, la huella cambia y la comprobación tiene que fallar.
        huella = hashlib.sha256(open(origen, "rb").read()).digest() if os.path.isfile(origen) \
            else bytes.fromhex(d["sha256"])
        mensaje = bytes.fromhex(d["datos_autenticador"]) + huella
        e = int.from_bytes(hashlib.sha256(mensaje).digest(), "big")
        r, s = _der_rs(bytes.fromhex(d["firma"]))
        ok = _ecdsa_ok(int(pub["x"], 16), int(pub["y"], 16), e, r, s)
    except Exception as ex:
        print(f"NO_VERIFICABLE — {ex}")
        _anotar({"orden": "verificar", "resultado": "ERROR", "motivo": str(ex)})
        return 5
    if ok and huella.hex() != d["sha256"]:
        # No debería ocurrir —la firma cubre la huella—, pero si ocurriera se dice, no se calla.
        print("INCOHERENTE — la firma valida pero la huella declarada no es la del fichero")
        return 1
    if ok:
        print(f"FIRMA VÁLIDA — «{d['fichero']}» firmado por la llave del nodo «{d['nodo']}»")
        print(f"  huella del fichero en disco: {huella.hex()[:32]}…")
        print(f"  comprobado contra la parte pública de la credencial {d['cred_id'][:24]}…")
        _anotar({"orden": "verificar", "fichero": d["fichero"], "resultado": "VALIDA"})
        return 0
    print(f"FIRMA NO VÁLIDA — «{d['fichero']}» no corresponde a esta credencial, o el fichero "
          f"cambió después de firmarse")
    _anotar({"orden": "verificar", "fichero": d["fichero"], "resultado": "NO_VALIDA"})
    return 1


def main():
    a = sys.argv[1:]
    if not a or a[0] == "informar":
        return cmd_informar()
    if a[0] == "crear" and len(a) > 1:
        return cmd_crear(a[1])
    if a[0] == "firmar" and len(a) > 1:
        return cmd_firmar(a[1])
    if a[0] == "verificar" and len(a) > 1:
        return cmd_verificar(a[1])
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
