#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""mod_edu_identity — MÓDULO OPCIONAL de dominio (educación) de la capa ANVOS.

Porta el núcleo de anv-mod-edu-identity a la capa: identidades de aprendizaje por organización,
sesiones firmadas (HMAC-SHA256, sin libs externas) y credenciales de compleción. Es un MÓDULO opcional
— solo corre si el PERFIL FIRMADO del nodo lo habilita (etiqueta 'edu-identity'; layerd gatea). Se
añade/retira sin tocar el núcleo. Node-local, stdlib, servidor residente con apagado limpio. Fail-safe.

Endpoints (HTTP :7793):
  GET  /                         estado
  POST /learner {org,learner_id,name}       alta de alumno
  GET  /learner?org=&id=                    perfil
  POST /session {org,learner_id}            token de sesión firmado (HMAC)
  POST /verify  {token}                     valida el token -> payload
  POST /credential {org,learner_id,course,result}   credencial de compleción
El HMAC es SOBERANO del nodo (clave local, no la del vault); el nodo NO firma con la identidad del master."""
import os
import sys
import json
import time
import hmac
import base64
import hashlib
import secrets
import signal
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread, Lock

DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
BASE = os.path.join(DATA, "modules", "edu_identity")
REC = os.path.join(BASE, "edu_identity.jsonl")            # latido/eventos del módulo (ledger del svc)
ACCESS_LOG = os.path.join(BASE, "access.log")             # RGPD: log de acceso a datos de alumno
KEYFILE = os.path.join(BASE, ".hmac_secret")              # clave HMAC soberana del nodo (600)
HOST = os.environ.get("ANV_EDU_ID_HOST", "0.0.0.0")
PORT = int(os.environ.get("ANV_EDU_ID_PORT", "7793"))
SESSION_TTL = int(os.environ.get("ANV_EDU_ID_SESSION_TTL", "86400"))  # 24h
# Privacidad (RGPD/menores): por defecto NO se guarda el nombre en claro (pseudonimización máxima).
STORE_NAME = os.environ.get("ANV_EDU_STORE_NAME", "0") == "1"   # base legal explícita para activarlo
DEFAULT_RETENTION_DAYS = int(os.environ.get("ANV_EDU_RETENTION_DAYS", "1825"))  # 5 años
_LOCK = Lock()
_STATS = {"learners": 0, "sessions": 0, "credentials": 0, "forgotten": 0}


def _node_id():
    for p in ("/persist/anvos-node.id", "/etc/anvos-node.id"):
        try:
            v = open(p).read().strip()
            if v:
                return v
        except Exception:
            pass
    return socket.gethostname() or "anvos-node"


NODE = _node_id()


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _secret():
    try:
        return open(KEYFILE, "rb").read()
    except Exception:
        os.makedirs(BASE, exist_ok=True)
        s = secrets.token_bytes(32)
        with open(KEYFILE, "wb") as f:
            f.write(s)
        try:
            os.chmod(KEYFILE, 0o600)
        except Exception:
            pass
        return s


def _b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_token(payload):
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    mac = _b64(hmac.new(_secret(), body.encode(), hashlib.sha256).digest())
    return body + "." + mac


def verify_token(token):
    try:
        body, mac = token.split(".", 1)
        exp = _b64(hmac.new(_secret(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(mac, exp):
            return None
        p = json.loads(_b64d(body))
        if p.get("exp", 0) < time.time():
            return None
        return p
    except Exception:
        return None


def _rec(rec):
    try:
        os.makedirs(BASE, exist_ok=True)
        with open(REC, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        # ITB-079 clase A: el fallo de registro deja huella por stderr en vez de callar.
        print("REG_FAIL mod_edu_identity._rec: %r" % (e,), file=sys.stderr, flush=True)


def _org_dir(org):
    d = os.path.join(BASE, "orgs", "".join(c for c in str(org) if c.isalnum() or c in "-_") or "org")
    os.makedirs(d, exist_ok=True)
    return d


def _pseudo(org, lid):
    """Pseudónimo estable del alumno = HMAC(secreto_nodo, org|learner_id). El sistema de ficheros NO
    revela el learner_id real (minimización de PII / pseudonimización RGPD)."""
    return hmac.new(_secret(), ("%s|%s" % (org, lid)).encode(), hashlib.sha256).hexdigest()[:24]


def _learner_path(org, lid):
    return os.path.join(_org_dir(org), _pseudo(org, lid) + ".json")


def _access(action, org, lid, src=""):
    """RGPD: registra el acceso a datos de alumno (quién/qué/cuándo)."""
    try:
        os.makedirs(BASE, exist_ok=True)
        with open(ACCESS_LOG, "a") as f:
            f.write("%s action=%s org=%s learner=%s src=%s\n" % (_now(), action, org, _pseudo(org, lid), src))
    except Exception:
        pass


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        try:
            self.wfile.write(b)
        except Exception:
            pass

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n).decode("utf-8", "replace")) if n else {}
        except Exception:
            return {}

    def do_GET(self):
        if self.path.startswith("/learner"):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            org = (q.get("org") or [""])[0]
            lid = (q.get("id") or [""])[0]
            _access("read", org, lid, self.client_address[0])   # RGPD: log de acceso a datos
            try:
                p = json.load(open(_learner_path(org, lid)))
                return self._send(200, {"ok": True, "learner": p})
            except Exception:
                return self._send(404, {"ok": False, "error": "no encontrado"})
        self._send(200, {"svc": "mod_edu_identity", "node": NODE, "status": "ok",
                         "stats": _STATS, "endpoint": "%s:%d" % (HOST, PORT)})

    def do_POST(self):
        d = self._body()
        with _LOCK:
            if self.path == "/learner":
                org, lid = d.get("org"), d.get("learner_id")
                if not (org and lid):
                    return self._send(400, {"ok": False, "error": "org y learner_id requeridos"})
                ret = int(d.get("retention_days", DEFAULT_RETENTION_DAYS))
                # PSEUDONIMIZACIÓN: NO se guarda el learner_id real; solo su pseudónimo + metadatos RGPD.
                prof = {"org": org, "pseudo": _pseudo(org, lid), "created": _now(), "node": NODE,
                        "consent": d.get("consent", "no-declarado"),
                        "retention_until": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + ret * 86400))}
                if STORE_NAME and d.get("name"):
                    prof["name"] = d.get("name")   # nombre en claro SOLO con base legal (ANV_EDU_STORE_NAME=1)
                json.dump(prof, open(_learner_path(org, lid), "w"), ensure_ascii=False)
                _STATS["learners"] += 1
                _access("register", org, lid, self.client_address[0])
                _rec({"svc": "mod_edu_identity", "ts": int(time.time()), "event": "learner_registered",
                      "org": org, "pseudo": prof["pseudo"], "consent": prof["consent"]})
                return self._send(200, {"ok": True, "learner": prof})
            if self.path == "/forget":
                # RGPD art.17 (derecho de supresión): borra el alumno y sus credenciales.
                org, lid = d.get("org"), d.get("learner_id")
                removed = False
                try:
                    lp = _learner_path(org, lid)
                    if os.path.exists(lp):
                        os.remove(lp)
                        removed = True
                except Exception:
                    pass
                _STATS["forgotten"] += 1
                _access("forget", org, lid, self.client_address[0])
                _rec({"svc": "mod_edu_identity", "ts": int(time.time()), "event": "learner_forgotten",
                      "org": org, "pseudo": _pseudo(org, lid)})
                return self._send(200, {"ok": True, "removed": removed, "note": "derecho de supresión RGPD art.17"})
            if self.path == "/session":
                org, lid = d.get("org"), d.get("learner_id")
                if not os.path.exists(_learner_path(org, lid)):
                    return self._send(404, {"ok": False, "error": "alumno no registrado"})
                payload = {"org": org, "learner_id": lid, "iat": int(time.time()),
                           "exp": int(time.time()) + SESSION_TTL, "node": NODE}
                _STATS["sessions"] += 1
                return self._send(200, {"ok": True, "token": sign_token(payload), "exp": payload["exp"]})
            if self.path == "/verify":
                p = verify_token(d.get("token", ""))
                return self._send(200, {"ok": bool(p), "payload": p})
            if self.path == "/credential":
                org, lid = d.get("org"), d.get("learner_id")
                if not os.path.exists(_learner_path(org, lid)):
                    return self._send(404, {"ok": False, "error": "alumno no registrado"})
                cred = {"org": org, "learner_id": lid, "course": d.get("course", ""),
                        "result": d.get("result", ""), "issued": _now(), "node": NODE}
                cf = os.path.join(_org_dir(org), "credentials.jsonl")
                with open(cf, "a") as f:
                    f.write(json.dumps(cred, ensure_ascii=False) + "\n")
                _STATS["credentials"] += 1
                _rec({"svc": "mod_edu_identity", "ts": int(time.time()), "event": "credential_issued",
                      "org": org, "learner_id": lid, "course": cred["course"]})
                return self._send(200, {"ok": True, "credential": cred})
        self._send(404, {"ok": False, "error": "ruta desconocida"})


def main():
    try:
        _secret()  # asegura la clave HMAC soberana
        try:
            srv = HTTPServer((HOST, PORT), Handler)
        except OSError as e:
            print(json.dumps({"svc": "mod_edu_identity", "ok": False, "fatal": "bind %s:%d: %s" % (HOST, PORT, e)},
                             ensure_ascii=False), flush=True)
            return 0
        t = Thread(target=srv.serve_forever, daemon=True)
        t.start()
        print(json.dumps({"svc": "mod_edu_identity", "node": NODE, "status": "listening",
                          "endpoint": "%s:%d" % (HOST, PORT), "mode": "module",
                          "note": "MÓDULO opcional (perfil): identidades/credenciales educativas"}, ensure_ascii=False), flush=True)
        _rec({"svc": "mod_edu_identity", "ts": int(time.time()), "node": NODE, "status": "listening", "port": PORT})
        stop = {"v": False}

        def _sig(*_):
            stop["v"] = True
            try:
                srv.shutdown()
            except Exception:
                pass
        signal.signal(signal.SIGTERM, _sig)
        signal.signal(signal.SIGINT, _sig)
        last = 0
        while not stop["v"]:
            time.sleep(1)
            now = int(time.time())
            if now - last >= 60:
                _rec({"svc": "mod_edu_identity", "ts": now, "node": NODE, "status": "listening", "stats": _STATS})
                last = now
        print(json.dumps({"svc": "mod_edu_identity", "node": NODE, "status": "stopped"}, ensure_ascii=False), flush=True)
        return 0
    except Exception as e:
        print(json.dumps({"svc": "mod_edu_identity", "ok": False, "fatal": str(e)}, ensure_ascii=False), flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
