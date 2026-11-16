#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Templates pushed to microvm-sbxd at run time (PUT /templates/NAME), the
# way the control plane pushes them: the daemon fetches the image over plain
# HTTP, checks its size and SHA-256, boots it once and snapshots it. Served
# here by a small HTTP server of our own, which also misbehaves on request.
#
#   sbxd_templates.py URL API_KEY DIR SMALL.erofs BIG.erofs [DELTA.erofs]
#
# URL is a daemon started with no --template, DIR its --dir; SMALL and BIG
# two EROFS images with /bin/sh (alpine and python, say). DELTA, if given,
# is a layer on SMALL (microvm-mkrootfs --lower SMALL) that adds /hello.txt
# ("hi from the delta") and sets FOO=bar: pushed as a template in layers.
import base64
import hashlib
import http.client
import http.server
import json
import os
import struct
import sys
import threading
import time
import urllib.parse

URL, KEY, DIR, SMALL, BIG = sys.argv[1:6]
DELTA = sys.argv[6] if len(sys.argv) > 6 else None
u = urllib.parse.urlparse(URL)
HOST, PORT = u.hostname, u.port or 80
fails = 0


def check(ok, what):
    global fails
    print(f"  {what:<72} {'ok' if ok else 'FAIL'}", flush=True)
    if not ok:
        fails += 1


def api(method, path, body=None, key=KEY):
    c = http.client.HTTPConnection(HOST, PORT, timeout=120)
    h = {"X-API-KEY": key}
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    c.request(method, path, data, h)
    r = c.getresponse()
    raw = r.read()
    c.close()
    try:
        return r.status, json.loads(raw) if raw else None
    except ValueError:
        return r.status, raw


def sh(info, cmd):
    """Runs cmd with /bin/sh in the sandbox: (exit code, stdout)."""
    c = http.client.HTTPConnection(HOST, PORT, timeout=60)
    h = {"E2b-Sandbox-Id": info["sandboxID"], "E2b-Sandbox-Port": "49983", "Connect-Protocol-Version": "1",
         "Content-Type": "application/connect+json"}
    if info.get("envdAccessToken"):
        h["X-Access-Token"] = info["envdAccessToken"]
    body = json.dumps({"process": {"cmd": "/bin/sh", "args": ["-c", cmd]}}).encode()
    c.request("POST", "/process.Process/Start", struct.pack(">BI", 0, len(body)) + body, h)
    r = c.getresponse()
    out, code = b"", None
    while True:
        hd = r.read(5)
        if len(hd) < 5:
            break
        flags, n = struct.unpack(">BI", hd)
        m = json.loads(r.read(n))
        if flags & 2:
            break
        ev = m.get("event", {})
        out += base64.b64decode(ev.get("data", {}).get("stdout", ""))
        if "end" in ev:
            code = ev["end"].get("exitCode", 0)
    c.close()
    return code, out


# --- the image server ----------------------------------------------------------

def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while b := f.read(1 << 20):
            h.update(b)
    return h.hexdigest(), os.path.getsize(path)


hits = {}  # path -> requests


class Images(http.server.BaseHTTPRequestHandler):
    files = {}  # path -> (file, mode)

    def log_message(self, *a):
        pass

    def do_GET(self):
        hits[self.path] = hits.get(self.path, 0) + 1
        f = self.files.get(self.path)
        if not f:
            self.send_error(404)
            return
        path, mode = f
        size = os.path.getsize(path)
        if mode == "slow":
            time.sleep(1.5)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size + (1 if mode == "long" else 0)))
        self.end_headers()
        try:
            self.body(path, size, mode)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the daemon stopped reading: a check it made failed

    def body(self, path, size, mode):
        with open(path, "rb") as fh:
            sent = 0
            while b := fh.read(1 << 20):
                if mode == "short" and sent + len(b) >= size:
                    b = b[:max(0, size - sent - 4096)]
                    self.wfile.write(b)
                    break
                if mode == "flip" and sent == 0:
                    b = bytes([b[0] ^ 1]) + b[1:]
                self.wfile.write(b)
                sent += len(b)
            if mode == "long":
                self.wfile.write(b"x")


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Images)
SRV = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()
Images.files = {"/small": (SMALL, ""), "/big": (BIG, "slow"), "/flip": (SMALL, "flip"),
                "/short": (SMALL, "short"), "/long": (SMALL, "long")}
SSHA, SSIZE = digest(SMALL)
BSHA, BSIZE = digest(BIG)
if DELTA:
    Images.files["/delta"] = (DELTA, "")
    DSHA, DSIZE = digest(DELTA)


def spec(path="/small", sha=None, size=None, **kw):
    d = {"url": SRV + path, "sha256": sha or SSHA, "sizeBytes": SSIZE if size is None else size, "memoryMB": 256}
    d.update(kw)
    return d


def wait_state(name, want=("ready", "failed"), limit=120):
    end = time.monotonic() + limit
    while time.monotonic() < end:
        s, lst = api("GET", "/templates")
        t = next((x for x in lst if x["templateID"] == name), None) if s == 200 else None
        if t and t["state"] in want:
            return t
        time.sleep(0.05)
    return t


def image(sha):
    return os.path.join(DIR, "images", sha + ".erofs")


def layers():
    print("a template in layers:")
    lower = [{"url": SRV + "/small", "sha256": SSHA, "sizeBytes": SSIZE}]
    def lspec(**kw):
        return dict({"url": SRV + "/delta", "sha256": DSHA, "sizeBytes": DSIZE, "memoryMB": 256, "layers": lower}, **kw)
    for bad, what in [(lspec(layers={}), "layers not an array"), (lspec(layers=[{"url": SRV}]), "a layer without sha256"),
                      (lspec(layers=lower * 2), "a layer twice"),
                      (lspec(layers=[dict(lower[0], sha256=DSHA)]), "the image as its own layer"),
                      (lspec(layers=lower * 8), "8 layers below")]:
        s, j = api("PUT", "/templates/x", bad)
        check(s == 400, f"PUT {what}: 400 ({j.get('message') if isinstance(j, dict) else j})")
    hits.clear()
    had = os.path.exists(image(SSHA))  # the base: here already, from the tests before?
    s, j = api("PUT", "/templates/layered", lspec())
    check(s == 202 and j.get("layers") == [SSHA], f"PUT: 202, its layers listed ({j.get('layers')})")
    s2, j2 = api("PUT", "/templates/layered-too", lspec(memoryMB=320))
    t = wait_state("layered")
    t2 = wait_state("layered-too")
    check(t["state"] == "ready" and t2["state"] == "ready", f"both ready ({t.get('error')}, {t2.get('error')})")
    check(hits.get("/small", 0) == (0 if had else 1) and hits.get("/delta") == 1,
          f"each layer fetched once, the base only if it wasn't here ({hits})")
    check(os.path.exists(image(SSHA)) and os.path.exists(image(DSHA)), "both layers in images/, by sha256")
    s, info = api("POST", "/v2/sandboxes", {"templateID": "layered"})
    check(s == 201, f"create: 201 ({s})")
    if s == 201:
        code, out = sh(info, "cat /hello.txt; echo $FOO; test -e /etc/alpine-release && echo base")
        check(code == 0 and out == b"hi from the delta\nbar\nbase\n", f"the delta over the base ({out!r})")
        s, d = api("GET", f"/sandboxes/{info['sandboxID']}")
        mb = (SSIZE + DSIZE + (1 << 20) - 1) >> 20
        check(d.get("diskSizeMB") == mb, f"diskSizeMB counts both layers ({d.get('diskSizeMB')}, {mb})")
        s, _ = api("POST", f"/sandboxes/{info['sandboxID']}/pause", {})
        check(s == 204, f"pause: 204 ({s})")
        s, _ = api("POST", f"/sandboxes/{info['sandboxID']}/resume", {})
        check(s in (200, 201), f"resume: {s}")
        code, out = sh(info, "cat /hello.txt")
        check(code == 0 and out == b"hi from the delta\n", "after a pause and resume (a restore on the layers)")
        api("DELETE", f"/sandboxes/{info['sandboxID']}")
    # The plain template on the same base layer: no fetch, the same file.
    s, j = api("PUT", "/templates/plain", spec())
    t = wait_state("plain")
    check(t["state"] == "ready" and hits.get("/small", 0) == (0 if had else 1),
          "a template of the base alone: ready, no fetch")
    api("DELETE", "/templates/layered")
    api("DELETE", "/templates/layered-too")
    end = time.monotonic() + 5
    while os.path.exists(image(DSHA)) and time.monotonic() < end:
        time.sleep(0.1)
    check(not os.path.exists(image(DSHA)), "unused, the delta goes")
    check(os.path.exists(image(SSHA)), "the base stays: plain uses it")
    api("DELETE", "/templates/plain")


def main():
    print("validation:")
    s, lst = api("GET", "/templates")
    check(s == 200 and lst == [], "GET /templates: none yet")
    s, _ = api("PUT", "/templates/x", spec(), key="nope")
    check(s == 401, "a wrong API key: 401")
    for bad, what in [(spec(url=None), "no url"), (spec(sha="ab" * 31), "a short sha256"),
                      (spec(sha=SSHA.upper()), "an upper-case sha256"), (spec(size=0), "sizeBytes 0"),
                      (spec(size=17 << 30), "sizeBytes over 16 GiB"), (spec(memoryMB=32), "memoryMB 32"),
                      (spec(cpuCount=9), "cpuCount 9"), (spec(user="Root!"), "a bad user"),
                      (spec(internet="yes"), "internet not a bool"), (b"[1]", "not an object")]:
        s, j = api("PUT", "/templates/x", bad)
        check(s == 400, f"PUT {what}: 400 ({j.get('message') if isinstance(j, dict) else j})")
    for name in ("UPPER", "a" * 64, "sl%2Fash", "a b"):
        s, _ = api("PUT", "/templates/" + urllib.parse.quote(name, safe="%"), spec())
        check(s in (400, 404), f"PUT a bad name {name[:12]!r}: rejected ({s})")

    print("failures are reported, not served:")
    s, j = api("PUT", "/templates/byname", spec(url="http://localhost:1/small"))
    check(s == 202 and j["state"] == "failed" and "address" in j.get("error", ""),
          "a host name, not an address: failed at once")
    for path, what in [("/flip", "one flipped bit"), ("/short", "a short body"), ("/long", "a long body"),
                       ("/nope", "a 404")]:
        name = "bad" + path[1:]
        s, j = api("PUT", f"/templates/{name}", spec(path))
        t = wait_state(name)
        check(s == 202 and t and t["state"] == "failed" and t.get("error"),
              f"{what}: failed ({t.get('error') if t else None})")
    check(not os.path.exists(image(SSHA)), "no image kept from them")
    check(not [f for f in os.listdir(os.path.join(DIR, "images")) if f.endswith(".part")], "no .part left behind")
    s, j = api("POST", "/v2/sandboxes", {"templateID": "badflip"})
    check(s == 503, f"create from a failed template: 503 ({s})")

    print("push, fetch, boot:")
    hits.clear()
    t0 = time.monotonic()
    s, j = api("PUT", "/templates/small", spec())
    check(s == 202 and j["state"] == "fetching" and j["sha256"] == SSHA, "PUT: 202 fetching")
    s2, j2 = api("PUT", "/templates/small-too", spec(memoryMB=384))
    t = wait_state("small")
    dt = time.monotonic() - t0
    check(t and t["state"] == "ready", f"ready ({dt * 1000:.0f} ms for {SSIZE >> 20} MiB)")
    check(wait_state("small-too")["state"] == "ready", "a second name of the same image: ready")
    check(hits.get("/small") == 1, f"one fetch for both ({hits.get('/small')})")
    check(os.path.exists(image(SSHA)) and (os.stat(image(SSHA)).st_mode & 0o777) == 0o444,
          "kept as images/SHA.erofs, read-only")
    s, j = api("PUT", "/templates/small", spec())
    check(s == 200 and j["state"] == "ready", "the same PUT again: 200, nothing done")
    check(hits.get("/small") == 1, "no fetch for it")
    s, info = api("POST", "/v2/sandboxes", {"templateID": "small"})
    check(s == 201 and info.get("templateID") == "small", "create from it: 201")
    old = info if s == 201 else None
    if old:
        code, out = sh(old, "echo hi; cat /proc/meminfo | head -1")
        check(code == 0 and out.startswith(b"hi\n"), "runs a command")
        s, d = api("GET", f"/sandboxes/{old['sandboxID']}")
        check(s == 200 and d["memoryMB"] == 256, f"memoryMB 256 ({d.get('memoryMB')})")

    print("a create waits for a template still fetching:")
    t0 = time.monotonic()
    s, j = api("PUT", "/templates/big", {"url": SRV + "/big", "sha256": BSHA, "sizeBytes": BSIZE, "memoryMB": 512})
    check(s == 202 and j["state"] == "fetching", "PUT big: 202 fetching (the server waits 1.5 s)")
    s, info = api("POST", "/v2/sandboxes", {"templateID": "big"})
    dt = time.monotonic() - t0
    check(s == 201 and dt > 1.5, f"create: 201 once it was ready ({dt * 1000:.0f} ms)")
    if s == 201:
        code, out = sh(info, "echo big")
        check(code == 0 and out == b"big\n", "runs a command")
        api("DELETE", f"/sandboxes/{info['sandboxID']}")

    print("replace and delete:")
    s, j = api("PUT", "/templates/small", spec(memoryMB=320))
    check(s == 202 and j["memoryMB"] == 320, "PUT other settings: 202, a new version")
    t = wait_state("small")
    check(t["state"] == "ready" and hits.get("/small") == 1, "ready from the image already here, no fetch")
    s, info = api("POST", "/v2/sandboxes", {"templateID": "small"})
    check(s == 201, "create from the new version: 201")
    if s == 201:
        s, d = api("GET", f"/sandboxes/{info['sandboxID']}")
        check(d.get("memoryMB") == 320, f"memoryMB 320 ({d.get('memoryMB')})")
        api("DELETE", f"/sandboxes/{info['sandboxID']}")
    if old:
        code, out = sh(old, "echo still")
        check(code == 0 and out == b"still\n", "a sandbox of the old version still runs")
    s, _ = api("DELETE", "/templates/small")
    check(s == 204, "DELETE: 204")
    s, lst = api("GET", "/templates")
    check(not any(x["templateID"] == "small" for x in lst), "not listed")
    s, _ = api("POST", "/v2/sandboxes", {"templateID": "small"})
    check(s == 404, "create from it: 404")
    s, _ = api("DELETE", "/templates/small")
    check(s == 404, "DELETE again: 404")
    if old:
        code, out = sh(old, "echo alive")
        check(code == 0 and out == b"alive\n", "its old sandbox still runs")
        api("DELETE", f"/sandboxes/{old['sandboxID']}")
    time.sleep(1.5)
    check(os.path.exists(image(SSHA)), "the image stays while small-too uses it")
    api("DELETE", "/templates/small-too")
    end = time.monotonic() + 5
    while os.path.exists(image(SSHA)) and time.monotonic() < end:
        time.sleep(0.1)
    check(not os.path.exists(image(SSHA)), "unused, the image goes")
    s, j = api("PUT", "/templates/small", spec())
    t = wait_state("small")
    check(t["state"] == "ready" and hits.get("/small") == 2, "pushed again: fetched again, ready")

    print("start and ready commands:")
    for bad, what in [(spec(startCmd=""), "an empty startCmd"), (spec(readyCmd=7), "a readyCmd not a string"),
                      (spec(workdir="rel"), "a relative workdir")]:
        s, j = api("PUT", "/templates/x", bad)
        check(s == 400, f"PUT {what}: 400")
    svc = spec(startCmd="pwd > /tmp/cwd; sleep 1; echo up > /tmp/ready; exec sleep 100000",
               readyCmd="[ -f /tmp/ready ]", workdir="/etc")
    t0 = time.monotonic()
    s, j = api("PUT", "/templates/svc", svc)
    t = wait_state("svc")
    took = time.monotonic() - t0
    check(s == 202 and t["state"] == "ready" and t.get("startCmd") == svc["startCmd"] and
          t.get("readyCmd") == svc["readyCmd"] and t.get("workdir") == "/etc", "with both: ready, and listed")
    check(took >= 1.0, f"ready only once the ready command succeeded ({took:.2f} s)")
    s, j = api("PUT", "/templates/svc", svc)
    check(s == 200, "the same again: 200")
    s, j = api("PUT", "/templates/svc", dict(svc, readyCmd="[ -f /tmp/ready ] && true"))
    check(s == 202, "another readyCmd: 202, a new version")
    wait_state("svc")
    s, info = api("POST", "/v2/sandboxes", {"templateID": "svc"})
    check(s == 201, "a sandbox from it")
    if s == 201:
        code, out = sh(info, "cat /tmp/cwd /tmp/ready; pgrep -f 'sleep 100000' >/dev/null && echo running")
        check(code == 0 and out == b"/etc\nup\nrunning\n", "in it: the start command still runs, from workdir")
        code, out = sh(info, "pwd")
        check(code == 0 and out == b"/etc\n", f"a command without a cwd runs in workdir ({code}, {out!r})")
        api("DELETE", f"/sandboxes/{info['sandboxID']}")
    s, j = api("PUT", "/templates/nouser", spec(startCmd="true", user="nosuchuser"))
    t = wait_state("nouser")
    check(t["state"] == "failed" and "start command" in t.get("error", ""),
          f"a start command that can't start: failed ({t.get('error')})")
    s, j = api("PUT", "/templates/readyonly", spec(readyCmd="test -d /etc"))
    t = wait_state("readyonly")
    check(t["state"] == "ready", "a ready command alone")
    for n in ("svc", "nouser", "readyonly"):
        api("DELETE", f"/templates/{n}")

    if DELTA:
        layers()

    print("PASS" if not fails else f"{fails} FAILED")
    return 1 if fails else 0


sys.exit(main())
