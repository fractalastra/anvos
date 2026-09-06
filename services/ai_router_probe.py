#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""ai_router_probe — presencia del enrutador de IA local en la capa autónoma.
Single-shot: sondea un endpoint de modelos local (Ollama 127.0.0.1:11434). Si existe,
reporta modelos disponibles y estado 'router-ready' (degradación elegante: la capacidad
de IA se ACTIVA sola cuando hay motor; si no, queda 'en espera' sin fallar).
Solo stdlib (urllib), timeout corto, sin dependencias externas."""
import json, time, os
import urllib.request
import urllib.error

ENDPOINT = "http://127.0.0.1:11434/api/tags"
TIMEOUT = 2.5

def _machine_id():
    try:
        with open('/etc/machine-id') as f:
            return f.read().strip() or 'unknown'
    except OSError:
        return 'unknown'

def _probe():
    try:
        with urllib.request.urlopen(ENDPOINT, timeout=TIMEOUT) as r:
            data = json.loads(r.read().decode('utf-8', 'replace'))
        models = [m.get("name") for m in data.get("models", []) if m.get("name")]
        return ("router-ready", models, None)
    except urllib.error.URLError as e:
        return ("en-espera", [], f"sin endpoint local ({getattr(e, 'reason', e)})")
    except Exception as e:
        return ("en-espera", [], str(e))

def main():
    status, models, note = _probe()
    rec = {
        "svc": "ai_router_probe",
        "ts": int(time.time()),
        "node": _machine_id(),
        "status": status,
        "endpoint": ENDPOINT,
        "models": models,
        "n_models": len(models),
        "note": note,
    }
    print(json.dumps(rec, ensure_ascii=False))

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(json.dumps({"svc": "ai_router_probe", "ts": int(time.time()),
                          "error": str(e)}, ensure_ascii=False))
