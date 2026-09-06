#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""anv_zstd — descompresor zstd para ANVOS con SOLO stdlib + ctypes, enlazando la libzstd.so.1
que YA viene embarcada en la capa python firmada (/run/pl/pylayer/lib). Habilita a un nodo
busybox (sin binario zstd ni módulo python-zstandard) a consumir los batches AFHTR-CS del
ecosistema (anv-batch-pack comprime con zstd). No añade binarios: reutiliza lo ya presente.
API: decompress_bytes(data)->bytes ; decompress_file(src,dst) . CLI: anv_zstd.py <in.zst> <out>"""
import os
import sys
import ctypes
import glob

# ZSTD_getFrameContentSize devuelve estos centinelas (como unsigned 64):
_UNKNOWN = (1 << 64) - 1   # ZSTD_CONTENTSIZE_UNKNOWN = -1
_ERROR = (1 << 64) - 2     # ZSTD_CONTENTSIZE_ERROR   = -2

_CANDIDATES = [
    "/run/pl/pylayer/lib/libzstd.so.1",
    "/persist/anvos-staging/pylayer-verify/libzstd.so.1",
]


def _find_lib():
    for p in _CANDIDATES:
        if os.path.exists(p):
            return p
    # búsqueda de respaldo en la capa activa
    for base in ("/run/pl/pylayer/lib", "/run/pl/pylayer/lib64"):
        for p in glob.glob(os.path.join(base, "libzstd.so*")):
            return p
    return "libzstd.so.1"   # último recurso: que el loader lo resuelva


class _Z:
    _lib = None

    @classmethod
    def lib(cls):
        if cls._lib is None:
            z = ctypes.CDLL(_find_lib())
            z.ZSTD_getFrameContentSize.restype = ctypes.c_ulonglong
            z.ZSTD_getFrameContentSize.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            z.ZSTD_decompress.restype = ctypes.c_size_t
            z.ZSTD_decompress.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                          ctypes.c_void_p, ctypes.c_size_t]
            z.ZSTD_isError.restype = ctypes.c_uint
            z.ZSTD_isError.argtypes = [ctypes.c_size_t]
            cls._lib = z
        return cls._lib


def decompress_bytes(data, max_size=None):
    """Descomprime un frame zstd completo. max_size (del manifest) acota el destino si el
    frame no lleva content-size. Devuelve bytes. Lanza si el frame es inválido."""
    z = _Z.lib()
    src = ctypes.create_string_buffer(bytes(data), len(data))
    csize = z.ZSTD_getFrameContentSize(src, len(data))
    if csize == _ERROR:
        raise ValueError("zstd: frame inválido")
    if csize == _UNKNOWN:
        if not max_size:
            raise ValueError("zstd: content-size desconocido y sin max_size")
        cap = int(max_size)
    else:
        cap = int(csize)
        if max_size and cap > int(max_size):
            raise ValueError("zstd: content-size (%d) excede max_size (%d)" % (cap, int(max_size)))
    dst = ctypes.create_string_buffer(cap if cap > 0 else 1)
    r = z.ZSTD_decompress(dst, cap, src, len(data))
    if z.ZSTD_isError(r):
        raise ValueError("zstd: error al descomprimir (code=%d)" % r)
    return dst.raw[:r]


def decompress_file(src, dst, max_size=None):
    with open(src, "rb") as f:
        data = f.read()
    out = decompress_bytes(data, max_size=max_size)
    with open(dst, "wb") as f:
        f.write(out)
    return len(out)


def main():
    if len(sys.argv) < 3:
        print("uso: anv_zstd.py <in.zst> <out> [max_size]", file=sys.stderr)
        return 2
    ms = int(sys.argv[3]) if len(sys.argv) > 3 else None
    n = decompress_file(sys.argv[1], sys.argv[2], max_size=ms)
    print("OK descomprimido %d bytes -> %s" % (n, sys.argv[2]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
