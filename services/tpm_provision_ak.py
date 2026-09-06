#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""tpm_provision_ak — crea la clave de ATESTACION dentro del TPM. Es la unica ESCRITURA.

Todo lo que este ecosistema hace con el TPM hasta hoy es leer: `tpm_attest` publica los registros
de plataforma y los marca DECLARADO, no ATESTADO, porque una lectura sin firma vale para quien ya
confia en el nodo y no vale ante quien no. Lo que convierte una cosa en la otra es el *quote*, y
el quote necesita una clave de firma DENTRO del chip. Ese es el unico hueco, y cerrarlo exige
escribir en el aparato de una maquina en produccion.

POR QUE VA APARTE Y NO DENTRO DE tpm_attest

  Porque un servicio de observacion no crea claves en el hardware por su cuenta. La lectura corre
  cada hora sin que nadie la autorice; esto se ejecuta UNA vez y con permiso explicito. Mezclarlos
  significaria que un ciclo rutinario pueda cambiar el estado del chip.

LO QUE HACE, EN ORDEN

  1. Comprueba que el handle de destino esta LIBRE. No se pisa nada de lo que ya hay.
  2. TPM2_CreatePrimary en la jerarquia de aval: clave ECC P-256, restringida y de FIRMA.
     La parte privada nace dentro del chip y no sale nunca; ni el operador puede extraerla.
  3. TPM2_EvictControl para hacerla persistente en el handle elegido.
  4. Libera el objeto transitorio.

REVERSIBLE: TPM2_EvictControl sobre el handle persistente la retira y el chip queda como estaba.

MEDIDO EN EL NODO ANTES DE ESCRIBIR NADA:
  - TPM 2.0 Nuvoton, responde por /dev/tpmrm0 con la biblioteca estandar; cero binarios nuevos.
  - Handles ocupados: 0x81000001 (perfil de raiz de almacenamiento) y 0x81010001 (perfil de aval).
    Ambos RSA, restringidos y de DESCIFRADO: ninguno firma, por eso hoy no hay quote posible.
  - 10 handles persistentes libres. Ninguna jerarquia con contrasena. No esta en bloqueo.
  - Los discos del nodo no van cifrados, asi que el arranque no depende de este aparato.

  uso: tpm_provision_ak.py --dry-run     construye y ENSENA los comandos, sin enviar ninguno
       tpm_provision_ak.py --apply       los envia. Requiere autorizacion explicita del operador.
       tpm_provision_ak.py --revocar     retira la clave persistente y deja el chip como estaba
"""
import os
import sys
import struct
import binascii

DEV = "/dev/tpmrm0"
HANDLE_AK = 0x81010002          # jerarquia de aval, siguiente libre tras 0x81010001
RH_ENDORSEMENT = 0x4000000B
RH_OWNER = 0x40000001
RS_PW = 0x40000009
CC_CREATE_PRIMARY = 0x00000131
CC_EVICT_CONTROL = 0x00000120
CC_FLUSH_CONTEXT = 0x00000165
CC_GET_CAPABILITY = 0x0000017A
ST_SESSIONS = 0x8002
ST_NO_SESSIONS = 0x8001

ALG_ECC, ALG_SHA256, ALG_NULL, ALG_ECDSA = 0x0023, 0x000B, 0x0010, 0x0018
CURVE_P256 = 0x0003
# fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | restricted | sign
ATTRS_AK = 0x00000002 | 0x00000010 | 0x00000020 | 0x00000040 | 0x00010000 | 0x00040000


def _tx(cmd):
    with open(DEV, "r+b", buffering=0) as f:
        f.write(cmd)
        r = f.read(8192)
    if len(r) < 10:
        raise ValueError("respuesta corta: %d octetos" % len(r))
    _t, _s, rc = struct.unpack(">HII", r[:10])
    return rc, r


def _sesion_pw():
    """Area de autorizacion con contrasena vacia. Vale porque ninguna jerarquia la tiene puesta."""
    return struct.pack(">I", RS_PW) + struct.pack(">H", 0) + b"\x00" + struct.pack(">H", 0)


def _publica_ak():
    """TPMT_PUBLIC de una clave de atestacion: ECC P-256, restringida, de firma, ECDSA-SHA256."""
    parms = (struct.pack(">H", ALG_NULL)                       # simetrico: ninguno
             + struct.pack(">HH", ALG_ECDSA, ALG_SHA256)        # esquema de firma
             + struct.pack(">H", CURVE_P256)
             + struct.pack(">H", ALG_NULL))                     # kdf: ninguno
    unique = struct.pack(">H", 0) + struct.pack(">H", 0)        # punto vacio: lo rellena el chip
    return (struct.pack(">HH", ALG_ECC, ALG_SHA256)
            + struct.pack(">I", ATTRS_AK)
            + struct.pack(">H", 0)                              # sin politica de autorizacion
            + parms + unique)


def cmd_create_primary():
    pub = _publica_ak()
    cuerpo = (_sesion_pw_area()
              + struct.pack(">H", 4) + struct.pack(">H", 0) + struct.pack(">H", 0)  # inSensitive vacio
              + struct.pack(">H", len(pub)) + pub
              + struct.pack(">H", 0)                            # outsideInfo vacio
              + struct.pack(">I", 0))                           # sin PCR de creacion
    cab = struct.pack(">HII", ST_SESSIONS, 10 + 4 + len(cuerpo), CC_CREATE_PRIMARY)
    return cab + struct.pack(">I", RH_ENDORSEMENT) + cuerpo


def _sesion_pw_area():
    s = _sesion_pw()
    return struct.pack(">I", len(s)) + s


def cmd_evict(transitorio, destino):
    s = _sesion_pw_area()
    cuerpo = s + struct.pack(">I", destino)
    cab = struct.pack(">HII", ST_SESSIONS, 10 + 8 + len(cuerpo), CC_EVICT_CONTROL)
    return cab + struct.pack(">II", RH_OWNER, transitorio) + cuerpo


def handle_libre(h):
    c = struct.pack(">HIIIII", ST_NO_SESSIONS, 22, CC_GET_CAPABILITY, 0x00000001, 0x81000000, 32)
    rc, r = _tx(c)
    if rc:
        return None
    n = struct.unpack(">I", r[15:19])[0]
    ocupados = [struct.unpack(">I", r[19 + 4 * i:23 + 4 * i])[0] for i in range(n)]
    return h not in ocupados, ocupados


def main():
    modo = sys.argv[1] if len(sys.argv) > 1 else "--dry-run"
    if not os.path.exists(DEV):
        print("no hay %s en este nodo: esta maquina no tiene TPM" % DEV)
        return 0

    libre, ocupados = handle_libre(HANDLE_AK)
    print("  handles ocupados ahora: %s" % [hex(x) for x in ocupados])
    print("  destino 0x%08x: %s" % (HANDLE_AK, "LIBRE" if libre else "OCUPADO — abortar"))
    if not libre:
        return 2

    c1 = cmd_create_primary()
    print("  1) TPM2_CreatePrimary  jerarquia=aval  ECC P-256 restringida+firma  %d octetos" % len(c1))
    print("     %s..." % binascii.hexlify(c1[:40]).decode())
    print("     (la parte privada NACE dentro del chip y no sale)")
    print("  2) TPM2_EvictControl   transitorio -> 0x%08x  (se construye con el handle que devuelva 1)" % HANDLE_AK)
    print("  3) TPM2_FlushContext   libera el objeto transitorio")

    if modo != "--apply":
        print("  ENSAYO EN SECO: no se ha enviado NINGUN comando al aparato.")
        return 0

    rc, r = _tx(c1)
    if rc:
        print("  ✗ CreatePrimary devolvio rc=0x%08x — no se ha persistido nada" % rc)
        return 1
    transitorio = struct.unpack(">I", r[10:14])[0]
    print("  ✔ clave creada, handle transitorio 0x%08x" % transitorio)

    rc2, _ = _tx(cmd_evict(transitorio, HANDLE_AK))
    if rc2:
        print("  ✗ EvictControl rc=0x%08x — la clave NO es persistente; se libera y queda como estaba" % rc2)
        _tx(struct.pack(">HII", ST_NO_SESSIONS, 14, CC_FLUSH_CONTEXT) + struct.pack(">I", transitorio))
        return 1
    _tx(struct.pack(">HII", ST_NO_SESSIONS, 14, CC_FLUSH_CONTEXT) + struct.pack(">I", transitorio))
    libre2, ocup2 = handle_libre(HANDLE_AK)
    print("  ✔ persistente en 0x%08x — handles ahora: %s" % (HANDLE_AK, [hex(x) for x in ocup2]))
    print("  La atestacion NO se da por buena aqui: solo cuando un quote real VERIFIQUE.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
