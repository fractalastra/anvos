#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Fajardo — proyecto AstraNova / fractalastra
# This file is part of the AstraNova ANVOS node layer. See LICENSE (AGPLv3).
# Dual licensing: a commercial license is available (see NOTICE).
# Patent pending: ES P202631174, ES P202631188 (see NOTICE).
"""codegen_nodo — circuito de generacion de codigo EN el nodo (ITE-014).

El nodo genera con su modelo local (llama-server 127.0.0.1:8090), prueba en su
banco (con preparacion de ficheros y entorno), y FIRMA LA AUTORIA con la clave
nacida a bordo, atada al genesis por certificado firmado con node_host.key.

INVARIANTES:
- La firma de autoria dice QUIEN ESCRIBIO. NO otorga ejecucion: la capa sigue
  exigiendo la clave de release para correr cualquier pieza (admision).
- Sin clave de autoria o sin certificado -> NO se procesa nada (fail-closed).
- Nunca borra: tareas procesadas van a tasks/.hechas/, jamas rm.
- Ledger encadenado por hash (prev+hash), verificable desde el master.
"""
import json, os, re, sys, time, hashlib, subprocess, urllib.request

STAGING = os.environ.get("ANVOS_STAGING", "/persist/anvos-staging")
DATA = os.environ.get("ANVOS_DATA", "/persist/anvos-data")
ROOT = os.path.join(DATA, "codegen")
TASKS = os.path.join(ROOT, "tasks")
HECHAS = os.path.join(TASKS, ".hechas")
WS = os.path.join(ROOT, "workspaces")
PEND = os.path.join(ROOT, "pending_admision")
LEDGER = os.path.join(ROOT, "codegen_ledger.jsonl")
# ── Eslabón de POLÍTICA (F1a, sobre de autonomía del nodo) ──────────────────────────────
# Tras banco OK y ANTES de firmar autoría: G-policy-surface veta que la propuesta toque una
# superficie prohibida (capa_genesis/llave propia, red a malla, gobernanza, borrado…). Es la
# MISMA garantía que en la autoridad; propose-only siempre (la admisión sigue siendo la clave de release).
# Subprocess fail-closed (mismo patrón que gate_compila): sin gate o REJECT → NO se firma.
GATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "G-policy-surface.py")
# TOPOLOGÍA DURABLE DEL SOBRE (F1b, criterio de revisor-b dueño del pipeline): el sobre vive en
# pylayer/ — el patrón canónico de config de capa firmada (donde vive authority.json), porque
# el sobre ES "el authority.json del dominio código". Así no depende de que ring_promote
# replique .json (solo mueve .py) ni hay que tocar ring_promote (pieza Set-B crítica).
# Respaldo: junto al script, para el master/lab donde no hay pylayer/.
_PYLAYER = os.path.join(STAGING, "pylayer", "code_policy_origo.json")
_LOCAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "code_policy_origo.json")
CODE_POLICY = _PYLAYER if os.path.isfile(_PYLAYER) else _LOCAL
AUTH = os.path.join(DATA, "authorship")
AUTH_KEY = os.path.join(AUTH, "authorship.key")
AUTH_PUB = os.path.join(AUTH, "authorship.pub")
CERT = os.path.join(AUTH, "authorship_cert.json")
MS = os.path.join(STAGING, "pylayer-verify")
LD = os.path.join(MS, "ld-linux-x86-64.so.2")
PYEXE = os.environ.get("ANVOS_PY", "/usr/bin/anvos-python3")
MODEL_URL = os.environ.get("ANV_MODEL_URL", "http://127.0.0.1:8090/v1/chat/completions")
MODEL_NAME = os.environ.get("ANV_MODEL_NAME", "local")
ATTEMPTS = int(os.environ.get("ANV_CODEGEN_ATTEMPTS", "2"))
POLL = int(os.environ.get("ANV_CODEGEN_POLL", "60"))


def log(**kw):
    kw.setdefault("svc", "codegen_nodo")
    kw.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    print(json.dumps(kw, ensure_ascii=False), flush=True)


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(65536), b""):
            h.update(b)
    return h.hexdigest()


def identidad():
    """Carga la identidad de autoria. None si falta algo (fail-closed)."""
    try:
        cert = json.load(open(CERT))
        if not (os.path.isfile(AUTH_KEY) and os.path.isfile(AUTH_PUB)
                and os.path.isfile(CERT + ".minisig")):
            return None
        return cert
    except Exception:
        return None


def modelo(prompt_sys, prompt_user, max_tokens=1200):
    req = urllib.request.Request(MODEL_URL, method="POST",
        headers={"Content-Type": "application/json"},
        data=json.dumps({"messages": [{"role": "system", "content": prompt_sys},
                                       {"role": "user", "content": prompt_user}],
                         "temperature": 0.15, "max_tokens": max_tokens}).encode())
    with urllib.request.urlopen(req, timeout=900) as r:
        d = json.loads(r.read())
    return d["choices"][0]["message"]["content"]


def extraer_codigo(texto):
    texto = re.sub(r"<think>.*?</think>", "", texto, flags=re.S)
    m = re.findall(r"```[a-zA-Z]*\n(.*?)```", texto, flags=re.S)
    return (m[-1] if m else texto).strip() + "\n"


def gate_compila(path, lang):
    if lang == "python":
        r = subprocess.run([PYEXE, "-m", "py_compile", path],
                           capture_output=True, timeout=30)
    else:
        r = subprocess.run(["/bin/sh", "-n", path], capture_output=True, timeout=30)
    return r.returncode == 0, (r.stderr or b"").decode(errors="replace")[-400:]


def banco(task, ws, artefacto, lang):
    """Banco de pruebas. Prepara files{} y env{} ANTES de cada caso (leccion medida:
    sin esto una tarea correcta paso de 1/5 a 5/5 sin tocar el modelo)."""
    resultados = []
    for t in task.get("tests", []):
        for rel, contenido in (t.get("files") or {}).items():
            dst = rel if os.path.isabs(rel) else os.path.join(ws, rel)
            os.makedirs(os.path.dirname(dst) or ws, exist_ok=True)
            if isinstance(contenido, list):
                contenido = "\n".join(contenido) + "\n"
            open(dst, "w").write(contenido)
        env = dict(os.environ)
        env.update({k: str(v) for k, v in (t.get("env") or {}).items()})
        cmd = ([PYEXE, artefacto] if lang == "python"
               else ["/bin/sh", artefacto]) + [str(a) for a in t.get("args", [])]
        try:
            r = subprocess.run(cmd, cwd=ws, env=env, capture_output=True,
                               input=(t.get("stdin") or "").encode() or None,
                               timeout=int(t.get("timeout", 30)))
            out = r.stdout.decode(errors="replace")
            ok = True
            if "expect_exit" in t and r.returncode != t["expect_exit"]:
                ok = False
            if t.get("expect_exit_nonzero") and r.returncode == 0:
                ok = False
            if "expect_stdout_contains" in t and t["expect_stdout_contains"] not in out:
                ok = False
            if "expect_stdout_matches" in t and not re.search(t["expect_stdout_matches"], out):
                ok = False
        except subprocess.TimeoutExpired:
            ok, out = False, "TIMEOUT"
        resultados.append({"name": t.get("name", "?"), "ok": ok})
    total = len(resultados)
    return (total > 0 and all(r["ok"] for r in resultados)), resultados


def _py_wrapper():
    """Intérprete para invocar el gate: en ANVOS, anvos-python3 (wrapper con el ld correcto);
    sys.executable NO sirve (apunta a un binario sin /lib64/ld). Fuera de ANVOS cae a python3.
    Lección medir-ANVOS-con-sus-herramientas: código portado del master adapta el intérprete."""
    import shutil
    # obs red-team (REV-F1A-PORT): endurecido — se prefieren rutas ABSOLUTAS canónicas del nodo
    # antes que el PATH (que un entorno manipulado podría desviar). El PATH queda de respaldo.
    for cand in ("/usr/bin/anvos-python3", "/bin/anvos-python3", "/usr/bin/python3"):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    for c in ("anvos-python3", "python3"):
        w = shutil.which(c)
        if w:
            return w
    return sys.executable


def gate_policy(path):
    """Eslabón de política (F1a): invoca G-policy-surface por SUBPROCESS con el sobre del
    nodo. Fail-closed en TODO camino de error (gate ausente, excepción, verdict != PASS).
    Adaptado a ANVOS: intérprete = anvos-python3 (sys.executable no corre en el nodo). El
    gate resuelve el minisign del bundle POR SÍ MISMO (no se le pasa por env — cierre del
    vector ANVOS_MINISIGN, diana red-team REV-F1A-PORT)."""
    if not (os.path.isfile(GATE) and os.path.isfile(CODE_POLICY)):
        return False, "gate o sobre ausente -> fail-closed"
    try:
        r = subprocess.run([_py_wrapper(), GATE, path, "--policy", CODE_POLICY,
                            "--dest", os.path.join(PEND, os.path.basename(path)), "--json"],
                           capture_output=True, text=True, timeout=30)
        out = json.loads(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else {}
        return out.get("verdict") == "PASS", out.get("verdict", "SIN_VEREDICTO")
    except Exception as e:
        return False, "excepcion gate: %s" % str(e)[:80]


def firmar_autoria(path, cert, task, digest):
    """Firma de AUTORIA con la clave de a bordo y VERIFICACION inmediata contra la
    publica local. Verificar contra la publica que uno elige no prueba admision:
    esto solo atestigua autoria; la admision la contrafirma el master con 653C."""
    tc = ("autoria nodo=%s genesis=%s clave=%s modelo=%s tarea=%s sha256=%s"
          % (cert["nodo"], cert["genesis_key_id"], cert["authorship_key_id"],
             MODEL_NAME, task["id"], digest))
    sig = path + ".autoria.minisig"
    r = subprocess.run([LD, "--library-path", MS, os.path.join(MS, "minisign"),
                        "-S", "-s", AUTH_KEY, "-t", tc, "-m", path, "-x", sig],
                       capture_output=True, input=b"\n", timeout=30)
    if r.returncode != 0:
        return None
    v = subprocess.run([LD, "--library-path", MS, os.path.join(MS, "minisign"),
                        "-Vm", path, "-x", sig, "-p", AUTH_PUB],
                       capture_output=True, timeout=30)
    return sig if v.returncode == 0 else None


def ledger_append(entry):
    prev = "GENESIS"
    try:
        with open(LEDGER, "rb") as f:
            lines = f.read().strip().splitlines()
        if lines:
            prev = json.loads(lines[-1]).get("hash", "GENESIS")
    except FileNotFoundError:
        pass
    entry["prev"] = prev
    entry["hash"] = hashlib.sha256(
        json.dumps(entry, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    with open(LEDGER, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def procesar(tf, cert):
    task = json.load(open(tf))
    tid = task["id"]
    lang = task.get("language", "python")
    ws = os.path.join(WS, tid)
    os.makedirs(ws, exist_ok=True)
    artefacto = os.path.join(ws, task["filename"])
    prompt_sys = ("Eres un generador de codigo. Responde SOLO con el codigo pedido, "
                  "en un unico bloque, sin explicaciones. /no_think")
    prompt_user = ("Lenguaje: %s\nFichero: %s\nProposito: %s\nCriterio de aceptacion: %s\n%s"
                   % (lang, task["filename"], task["intent"], task.get("acceptance", ""),
                      "\n".join(task.get("constraints", []))))
    resultado = {"task": tid, "estado": "FALLO", "intentos": 0}
    for intento in range(1, ATTEMPTS + 1):
        resultado["intentos"] = intento
        try:
            code = extraer_codigo(modelo(prompt_sys, prompt_user))
        except Exception as e:
            log(event="modelo_error", task=tid, err=str(e)[:200])
            continue
        open(artefacto, "w").write(code)
        ok_c, err_c = gate_compila(artefacto, lang)
        if not ok_c:
            log(event="no_compila", task=tid, intento=intento, err=err_c)
            continue
        ok_b, casos = banco(task, ws, artefacto, lang)
        log(event="banco", task=tid, intento=intento, ok=ok_b, casos=casos)
        if not ok_b:
            continue
        # ESLABÓN DE POLÍTICA (F1a): la propuesta NO se firma como autoría si toca una
        # superficie vetada del sobre del nodo. Fail-closed. Propose-only intacto.
        ok_p, verdict_p = gate_policy(artefacto)
        log(event="policy", task=tid, intento=intento, ok=ok_p, verdict=verdict_p)
        if not ok_p:
            continue
        digest = sha256_file(artefacto)
        sig = firmar_autoria(artefacto, cert, task, digest)
        if not sig:
            log(event="fallo_firma_autoria", task=tid)
            break
        contrato = {"id": "CHG-" + tid, "task": task, "artefacto": artefacto,
                    "sha256": digest, "bench": casos,
                    "autoria": {"nodo": cert["nodo"],
                                "genesis_key_id": cert["genesis_key_id"],
                                "authorship_key_id": cert["authorship_key_id"],
                                "cert": CERT, "sig": sig, "modelo": MODEL_NAME},
                    "admision": {"estado": "pendiente_contrafirma_653C"},
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        os.makedirs(PEND, exist_ok=True)
        cpath = os.path.join(PEND, "CHG-%s.json" % tid)
        open(cpath, "w").write(json.dumps(contrato, ensure_ascii=False, indent=1))
        resultado.update(estado="GENERADO_Y_FIRMADA_AUTORIA", sha256=digest,
                         contrato=cpath, autoria_sig=sig)
        break
    ledger_append({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "nodo": cert["nodo"], "modelo": MODEL_NAME, **resultado})
    os.makedirs(HECHAS, exist_ok=True)
    os.rename(tf, os.path.join(HECHAS, os.path.basename(tf)))
    return resultado["estado"]


def main():
    for d in (TASKS, HECHAS, WS, PEND):
        os.makedirs(d, exist_ok=True)
    once = "--once" in sys.argv
    while True:
        cert = identidad()
        if cert is None:
            log(event="SIN_AUTORIA", detalle="falta clave/cert de autoria; no se procesa (fail-closed)")
        else:
            for tf in sorted(os.listdir(TASKS)):
                if tf.endswith(".json") and os.path.isfile(os.path.join(TASKS, tf)):
                    try:
                        est = procesar(os.path.join(TASKS, tf), cert)
                        log(event="tarea", fichero=tf, estado=est)
                    except Exception as e:
                        log(event="error_tarea", fichero=tf, err=str(e)[:300])
        if once:
            break
        time.sleep(POLL)


if __name__ == "__main__":
    main()
