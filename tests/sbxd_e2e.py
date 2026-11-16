#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# End-to-end test of microvm-sbxd, speaking the wire protocol the e2b SDKs
# speak (control plane REST, envd Connect+JSON, /files), with the standard
# library only.
#
#   sbxd_e2e.py URL API_KEY TEMPLATE [--domain DOMAIN] [--net-template NAME]
#               [--smp-template NAME:CPUS] [--pool NAME:CPUS]
#
# URL is the daemon (http://127.0.0.1:3000); TEMPLATE an image with bash
# and python3 (for the port test) and a "user" account, or without them
# (those checks are skipped). --smp-template: a template of CPUS vCPUs
# (cpus=CPUS), with python3: cpuCount, nproc, and a CPU-bound job spread
# over them, before and after a pause. --pool: the daemon has --cgroup;
# sandboxes of a team share its vCPUs and memory (NAME: a template of CPUS
# vCPUs with python3, 512 MiB or more).
import base64
import gzip
import http.client
import json
import struct
import sys
import time
import urllib.parse

URL, KEY, TEMPLATE = sys.argv[1], sys.argv[2], sys.argv[3]
DOMAIN = sys.argv[sys.argv.index("--domain") + 1] if "--domain" in sys.argv else "sbx.test"
u = urllib.parse.urlparse(URL)
HOST, PORT = u.hostname, u.port or 80
fails = 0


def check(ok, what):
    global fails
    print(f"  {what:<70} {'ok' if ok else 'FAIL'}", flush=True)
    if not ok:
        fails += 1


def conn():
    return http.client.HTTPConnection(HOST, PORT, timeout=60)


def api(method, path, body=None, key=KEY):
    c = conn()
    h = {"X-API-KEY": key, "User-Agent": "e2b-python-sdk/2.63.0"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    c.request(method, path, data, h)
    r = c.getresponse()
    raw = r.read()
    c.close()
    try:
        j = json.loads(raw) if raw else None
    except ValueError:
        j = raw
    return r.status, j, r


class Sbx:
    def __init__(self, info):
        self.id = info["sandboxID"]
        self.token = info.get("envdAccessToken")
        self.c = conn()

    def headers(self, user=None, extra=None):
        h = {"E2b-Sandbox-Id": self.id, "E2b-Sandbox-Port": "49983", "Connect-Protocol-Version": "1"}
        if self.token:
            h["X-Access-Token"] = self.token
        if user is not None:
            h["Authorization"] = "Basic " + base64.b64encode(f"{user}:".encode()).decode()
        if extra:
            h.update(extra)
        return h

    def unary(self, method, msg, user=None, token=None):
        h = self.headers(user)
        if token is not None:
            h["X-Access-Token"] = token
        h["Content-Type"] = "application/json"
        self.c.request("POST", "/" + method, json.dumps(msg).encode(), h)
        r = self.c.getresponse()
        raw = r.read()
        return r.status, json.loads(raw) if raw else None

    def stream(self, method, msg, user=None, limit=None, chunked=True):
        """A server stream: returns (status, [messages], end) or yields."""
        c = conn()
        h = self.headers(user, {"Content-Type": "application/connect+json", "Keepalive-Ping-Interval": "50"})
        body = json.dumps(msg).encode()
        env = struct.pack(">BI", 0, len(body)) + body
        if chunked:  # the Python SDK sends streaming bodies chunked
            c.putrequest("POST", "/" + method)
            for k, v in h.items():
                c.putheader(k, v)
            c.putheader("Transfer-Encoding", "chunked")
            c.endheaders()
            c.send(b"%x\r\n%s\r\n0\r\n\r\n" % (len(env), env))
        else:
            c.request("POST", "/" + method, env, h)
        r = c.getresponse()
        return c, r

    def files_get(self, path, user=None):
        q = {"path": path}
        if user:
            q["username"] = user
        self.c.request("GET", "/files?" + urllib.parse.urlencode(q), headers=self.headers())
        r = self.c.getresponse()
        return r.status, r.read()

    def files_put_multipart(self, files, path=None, user=None):
        b = "XyZb0undary"
        body = b""
        for name, data in files:
            body += (f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
                     f"Content-Type: application/octet-stream\r\n\r\n").encode() + data + b"\r\n"
        body += f"--{b}--\r\n".encode()
        q = {}
        if path:
            q["path"] = path
        if user:
            q["username"] = user
        h = self.headers(extra={"Content-Type": f"multipart/form-data; boundary={b}"})
        self.c.request("POST", "/files?" + urllib.parse.urlencode(q), body, h)
        r = self.c.getresponse()
        raw = r.read()
        return r.status, json.loads(raw) if raw else None

    def files_put_octet(self, path, data, gz=False):
        h = self.headers(extra={"Content-Type": "application/octet-stream"})
        if gz:
            h["Content-Encoding"] = "gzip"
            data = gzip.compress(data)
        self.c.request("POST", "/files?" + urllib.parse.urlencode({"path": path}), data, h)
        r = self.c.getresponse()
        raw = r.read()
        return r.status, json.loads(raw) if raw else None


def read_stream(r, stop=None, until_end=True):
    """Envelopes from a streaming response: (messages, end)."""
    msgs, end = [], None
    while True:
        hd = r.read(5)
        if len(hd) < 5:
            break
        flags, n = struct.unpack(">BI", hd)
        payload = json.loads(r.read(n))
        if flags & 2:
            end = payload
            break
        msgs.append(payload)
        if stop and stop(payload):
            break
    return msgs, end


def run(sbx, cmd, user=None, envs=None, cwd=None, stdin=False, tag=None):
    p = {"cmd": "/bin/bash", "args": ["-l", "-c", cmd]}
    if envs:
        p["envs"] = envs
    if cwd:
        p["cwd"] = cwd
    msg = {"process": p, "stdin": stdin}
    if tag:
        msg["tag"] = tag
    c, r = sbx.stream("process.Process/Start", msg, user)
    msgs, end = read_stream(r)
    c.close()
    out = b"".join(base64.b64decode(m["event"]["data"].get("stdout", "")) for m in msgs if "data" in m.get("event", {}))
    err = b"".join(base64.b64decode(m["event"]["data"].get("stderr", "")) for m in msgs if "data" in m.get("event", {}))
    ends = [m["event"]["end"] for m in msgs if "end" in m.get("event", {})]
    first = msgs[0] if msgs else {}
    return {"status": r.status, "ctype": r.getheader("Content-Type"), "first": first, "out": out, "err": err,
            "end": ends[0] if ends else None, "endframe": end}


def main():
    print("control plane:")
    s, j, _ = api("POST", "/v2/sandboxes", {"templateID": TEMPLATE, "metadata": {}, "envVars": {}}, key="")
    check(s == 401 and j == {"code": 401, "message": "invalid API key"} or s == 401, "no API key: 401 {code,message}")
    t0 = time.monotonic()
    s, info, _ = api("POST", "/v2/sandboxes",
                     {"templateID": TEMPLATE, "timeout": 120, "metadata": {"who": "e2e"}, "envVars": {"GREETING": "hej"}})
    dt = (time.monotonic() - t0) * 1000
    check(s == 201 and all(k in info for k in ("templateID", "sandboxID", "clientID", "envdVersion")),
          f"create: 201 with the required fields ({dt:.1f} ms)")
    if s != 201:
        print(info)
        return
    sbx = Sbx(info)
    s, d, _ = api("GET", f"/sandboxes/{sbx.id}")
    need = ("templateID", "sandboxID", "clientID", "startedAt", "endAt", "envdVersion", "cpuCount", "memoryMB",
            "diskSizeMB", "state")
    check(s == 200 and all(k in d for k in need) and d["state"] == "running" and d["metadata"] == {"who": "e2e"},
          "get_info: every required field, running, metadata")
    s, lst, _ = api("GET", "/v2/sandboxes")
    check(s == 200 and any(x["sandboxID"] == sbx.id for x in lst), "list: has it")
    s, _, _ = api("GET", "/sandboxes/nosuchsandbox")
    check(s == 404, "get_info of an unknown sandbox: 404")

    print("envd:")
    sbx.c.request("GET", "/health", headers=sbx.headers())
    r = sbx.c.getresponse()
    r.read()
    check(r.status == 204, "/health: 204")
    s, j = sbx.unary("filesystem.Filesystem/Stat", {"path": "/"}, token="wrong")
    check(s == 401 and j.get("code") == "unauthenticated", "a wrong access token: unauthenticated")

    t0 = time.monotonic()
    x = run(sbx, "echo out; echo err >&2; exit 3")
    dt = (time.monotonic() - t0) * 1000
    check(x["status"] == 200 and x["ctype"] == "application/connect+json", "Start: 200 application/connect+json")
    check("start" in x["first"].get("event", {}) and x["first"]["event"]["start"].get("pid", 0) > 0,
          "Start: the first event is start with a pid")
    check(x["out"] == b"out\n" and x["err"] == b"err\n", "stdout and stderr")
    check(x["end"] and x["end"].get("exitCode") == 3 and x["endframe"] == {}, f"end: exitCode 3, end-stream {{}} ({dt:.1f} ms)")
    x = run(sbx, "exit 0")
    check(x["end"] is not None and "exitCode" not in x["end"] and x["end"].get("exited") is True,
          "exit 0: exitCode omitted (proto3 zero)")
    x = run(sbx, 'echo "$GREETING $FOO"; pwd', envs={"FOO": "bar"}, cwd="/tmp")
    check(x["out"] == b"hej bar\n/tmp\n", "envVars from create, envs and cwd of the call")
    x = run(sbx, "id -un", user="root")
    check(x["out"] == b"root\n", "Authorization: Basic root")
    x = run(sbx, "kill -9 $$")
    check(x["end"] and x["end"].get("exitCode") == -1 and "killed" in x["end"].get("status", ""),
          "killed by a signal: exitCode -1, status 'signal: killed'")
    c, r = sbx.stream("process.Process/Start", {"process": {"cmd": "/no/such/thing"}})
    msgs, end = read_stream(r)
    c.close()
    check(r.status == 200 and end and end.get("error", {}).get("code") == "not_found",
          "a missing command: HTTP 200, the error in the end-stream frame")

    # Background process, List, Connect, SendSignal.
    c, r = sbx.stream("process.Process/Start",
                      {"process": {"cmd": "/bin/bash", "args": ["-l", "-c", "sleep 30"]}, "tag": "bg"})
    msgs, _ = read_stream(r, stop=lambda m: "start" in m.get("event", {}))
    pid = msgs[0]["event"]["start"]["pid"]
    c.close()
    s, j = sbx.unary("process.Process/List", {})
    procs = j.get("processes", []) if s == 200 else []
    mine = [p for p in procs if p.get("pid") == pid]
    check(s == 200 and mine and mine[0].get("tag") == "bg" and mine[0]["config"]["cmd"] == "/bin/bash",
          "List: the background process, its tag and config")
    c, r = sbx.stream("process.Process/Connect", {"process": {"pid": pid}})
    first, _ = read_stream(r, stop=lambda m: True)
    s, j = sbx.unary("process.Process/SendSignal", {"process": {"pid": pid}, "signal": "SIGNAL_SIGKILL"})
    msgs, end = read_stream(r)
    c.close()
    ends = [m for m in msgs if "end" in m.get("event", {})]
    check(first and first[0]["event"].get("start", {}).get("pid") == pid and s == 200 and ends and end == {},
          "Connect: start, then SendSignal SIGKILL ends it")
    s, j = sbx.unary("process.Process/SendSignal", {"process": {"pid": 999999}, "signal": "SIGNAL_SIGKILL"})
    check(s == 404 and j.get("code") == "not_found", "SendSignal to no process: not_found")

    # stdin: SendInput, CloseStdin.
    c, r = sbx.stream("process.Process/Start", {"process": {"cmd": "/bin/bash", "args": ["-l", "-c", "cat"]},
                                                "stdin": True})
    msgs, _ = read_stream(r, stop=lambda m: "start" in m.get("event", {}))
    pid = msgs[0]["event"]["start"]["pid"]
    s1, _ = sbx.unary("process.Process/SendInput",
                      {"process": {"pid": pid}, "input": {"stdin": base64.b64encode(b"hello stdin\n").decode()}})
    s2, _ = sbx.unary("process.Process/CloseStdin", {"process": {"pid": pid}})
    msgs, end = read_stream(r)
    c.close()
    out = b"".join(base64.b64decode(m["event"]["data"]["stdout"]) for m in msgs if "data" in m.get("event", {}))
    check(s1 == 200 and s2 == 200 and out == b"hello stdin\n", "SendInput, CloseStdin: cat echoes and ends")

    # StreamInput (client streaming, chunked).
    c, r = sbx.stream("process.Process/Start", {"process": {"cmd": "/bin/bash", "args": ["-l", "-c", "cat"]},
                                                "stdin": True})
    msgs, _ = read_stream(r, stop=lambda m: "start" in m.get("event", {}))
    pid = msgs[0]["event"]["start"]["pid"]
    ic = conn()
    ic.putrequest("POST", "/process.Process/StreamInput")
    for k, v in sbx.headers(extra={"Content-Type": "application/connect+json"}).items():
        ic.putheader(k, v)
    ic.putheader("Transfer-Encoding", "chunked")
    ic.endheaders()

    def env(m):
        b = json.dumps(m).encode()
        e = struct.pack(">BI", 0, len(b)) + b
        ic.send(b"%x\r\n%s\r\n" % (len(e), e))
    env({"start": {"process": {"pid": pid}}})
    for i in range(3):
        env({"data": {"input": {"stdin": base64.b64encode(f"line {i}\n".encode()).decode()}}})
    env({"keepalive": {}})
    ic.send(b"0\r\n\r\n")
    ir = ic.getresponse()
    imsgs, iend = read_stream(ir)
    ic.close()
    sbx.unary("process.Process/CloseStdin", {"process": {"pid": pid}})
    msgs, end = read_stream(r)
    c.close()
    out = b"".join(base64.b64decode(m["event"]["data"]["stdout"]) for m in msgs if "data" in m.get("event", {}))
    check(ir.status == 200 and imsgs == [{}] and iend == {} and out == b"line 0\nline 1\nline 2\n",
          "StreamInput: one {} then the end; the input arrived in order")

    # A terminal.
    c, r = sbx.stream("process.Process/Start",
                      {"process": {"cmd": "/bin/bash", "args": ["-i", "-l"], "envs": {"TERM": "xterm-256color"}},
                       "pty": {"size": {"cols": 100, "rows": 30}}})
    msgs, _ = read_stream(r, stop=lambda m: "start" in m.get("event", {}))
    pid = msgs[0]["event"]["start"]["pid"]
    s1, _ = sbx.unary("process.Process/Update", {"process": {"pid": pid}, "pty": {"size": {"cols": 120, "rows": 40}}})
    s2, _ = sbx.unary("process.Process/SendInput", {"process": {"pid": pid}, "input": {
        "pty": base64.b64encode(b"echo $((6*7)) $(stty size)\rexit\r").decode()}})
    msgs, end = read_stream(r)
    c.close()
    out = b"".join(base64.b64decode(m["event"]["data"].get("pty", "")) for m in msgs if "data" in m.get("event", {}))
    check(s1 == 200 and s2 == 200 and b"42 40 120" in out, "a terminal: Update resizes, pty input and output")

    print("files:")
    s, j = sbx.files_put_multipart([("/tmp/e2e/a.txt", b"alpha\n")], path="/tmp/e2e/a.txt")
    check(s == 200 and j == [{"name": "a.txt", "type": "file", "path": "/tmp/e2e/a.txt"}],
          "write (multipart, one file): 200 [{name,type,path}]")
    s, data = sbx.files_get("/tmp/e2e/a.txt")
    check(s == 200 and data == b"alpha\n", "read it back")
    big = bytes(range(256)) * 20000  # 5 MB
    s, j = sbx.files_put_multipart([("/tmp/e2e/b.bin", big), ("rel/c.txt", b"gamma")])
    check(s == 200 and len(j) == 2 and j[1]["path"].endswith("/rel/c.txt"), "write two files (5 MB + relative path)")
    s, data = sbx.files_get("/tmp/e2e/b.bin")
    check(s == 200 and data == big, "read back 5 MB intact")
    # Again, on the same keep-alive connection: an upload that paused
    # reading (backpressure) must leave the connection readable.
    ok = True
    for i in range(6):
        s, j = sbx.files_put_multipart([(f"/tmp/e2e/r{i}.bin", big)])
        s2, data = sbx.files_get(f"/tmp/e2e/r{i}.bin")
        ok &= s == 200 and s2 == 200 and data == big
    check(ok, "6 more 5 MB round trips on one connection")
    s, j = sbx.files_put_octet("/tmp/e2e/d.txt", b"delta" * 1000, gz=True)
    s2, data = sbx.files_get("/tmp/e2e/d.txt")
    check(s == 200 and s2 == 200 and data == b"delta" * 1000, "octet-stream + gzip upload")
    s, j = sbx.files_get("/tmp/e2e/nope")
    check(s == 404 and json.loads(j).get("code") == 404, "read a missing file: 404 {code,message}")
    s, j = sbx.unary("filesystem.Filesystem/Stat", {"path": "/tmp/e2e/a.txt"})
    e = j.get("entry", {}) if s == 200 else {}
    check(e.get("name") == "a.txt" and e.get("type") == "FILE_TYPE_FILE" and e.get("size") in ("6", 6) and
          e.get("permissions", "").startswith("-") and "modifiedTime" in e, "Stat: an EntryInfo")
    s, j = sbx.unary("filesystem.Filesystem/MakeDir", {"path": "/tmp/e2e/sub/deep"})
    s2, j2 = sbx.unary("filesystem.Filesystem/MakeDir", {"path": "/tmp/e2e/sub/deep"})
    check(s == 200 and s2 == 409 and j2.get("code") == "already_exists", "MakeDir, then already_exists")
    s, j = sbx.unary("filesystem.Filesystem/Move", {"source": "/tmp/e2e/a.txt", "destination": "/tmp/e2e/sub/a2.txt"})
    check(s == 200 and j["entry"]["path"] == "/tmp/e2e/sub/a2.txt", "Move")
    s, j = sbx.unary("filesystem.Filesystem/ListDir", {"path": "/tmp/e2e", "depth": 2})
    names = sorted(x["path"] for x in j.get("entries", [])) if s == 200 else []
    check("/tmp/e2e/sub/a2.txt" in names and "/tmp/e2e/sub/deep" in names, "ListDir depth 2")
    s, j = sbx.unary("filesystem.Filesystem/Remove", {"path": "/tmp/e2e/sub"})
    s2, j2 = sbx.unary("filesystem.Filesystem/Stat", {"path": "/tmp/e2e/sub"})
    check(s == 200 and s2 == 404 and j2.get("code") == "not_found", "Remove, then Stat: not_found")

    # Watching: the stream (JS, async Python) and the polling API (sync Python).
    c, r = sbx.stream("filesystem.Filesystem/WatchDir", {"path": "/tmp/e2e", "recursive": True})
    first, _ = read_stream(r, stop=lambda m: True)
    run(sbx, "echo x > /tmp/e2e/w1.txt")
    msgs, _ = read_stream(r, stop=lambda m: "filesystem" in m and m["filesystem"]["name"] == "w1.txt" and
                          m["filesystem"]["type"] == "EVENT_TYPE_WRITE")
    c.close()
    check(first == [{"start": {}}] and msgs and msgs[-1]["filesystem"]["type"] == "EVENT_TYPE_WRITE",
          "WatchDir: start, then the events")
    s, j = sbx.unary("filesystem.Filesystem/CreateWatcher", {"path": "/tmp/e2e", "includeEntry": True})
    wid = j.get("watcherId") if s == 200 else None
    run(sbx, "touch /tmp/e2e/w2.txt")
    time.sleep(0.05)
    s, j = sbx.unary("filesystem.Filesystem/GetWatcherEvents", {"watcherId": wid})
    evs = j.get("events", []) if s == 200 else []
    s2, _ = sbx.unary("filesystem.Filesystem/RemoveWatcher", {"watcherId": wid})
    check(wid and any(e["name"] == "w2.txt" and e["type"] == "EVENT_TYPE_CREATE" and "entry" in e for e in evs)
          and s2 == 200, "CreateWatcher, GetWatcherEvents (with entries), RemoveWatcher")

    print("ports:")
    x = run(sbx, "command -v python3")
    if x["end"] and "exitCode" not in x["end"]:
        c, r = sbx.stream("process.Process/Start", {"process": {"cmd": "/bin/bash", "args": [
            "-l", "-c", "cd /tmp/e2e && exec python3 -m http.server 8000 --bind 127.0.0.1"]}, "tag": "web"})
        read_stream(r, stop=lambda m: "start" in m.get("event", {}))
        ok = False
        for _ in range(100):
            pc = conn()
            try:
                pc.request("GET", "/w1.txt", headers={"Host": f"8000-{sbx.id}.{DOMAIN}"})
                pr = pc.getresponse()
                body = pr.read()
                if pr.status == 200 and body == b"x\n":
                    ok = True
                    break
            except (ConnectionError, http.client.HTTPException):
                pass
            finally:
                pc.close()
            time.sleep(0.05)
        check(ok, "GET http://8000-ID.domain/w1.txt reaches the sandbox's server")
        c.close()
    else:
        print("  (no python3 in the image: port test skipped)")
    pc = conn()
    pc.request("GET", "/", headers={"Host": f"9-{sbx.id}.{DOMAIN}"})
    pr = pc.getresponse()
    body = pr.read()
    pc.close()
    check(pr.status == 502 and b"port is not open" in body, "a closed port: 502 'port is not open'")

    print("pause and resume:")
    run(sbx, "echo kept > /tmp/kept.txt")
    c, r = sbx.stream("process.Process/Start", {"process": {"cmd": "/bin/bash", "args": [
        "-l", "-c", "for i in $(seq 1 50); do sleep 0.1; done; echo survived"]}, "tag": "survivor"})
    read_stream(r, stop=lambda m: "start" in m.get("event", {}))
    c.close()
    t0 = time.monotonic()
    s, _, _ = api("POST", f"/sandboxes/{sbx.id}/pause", {})
    dt = (time.monotonic() - t0) * 1000
    s2, d, _ = api("GET", f"/sandboxes/{sbx.id}")
    check(s == 204 and s2 == 200 and d["state"] == "paused", f"pause: 204, state paused ({dt:.1f} ms)")
    s, _, _ = api("POST", f"/sandboxes/{sbx.id}/pause", {})
    check(s == 409, "pause again: 409")
    sbx.c = conn()
    sbx.c.request("GET", "/health", headers=sbx.headers())
    r = sbx.c.getresponse()
    r.read()
    check(r.status == 502, "/health while paused: 502")
    t0 = time.monotonic()
    s, j, _ = api("POST", f"/v2/sandboxes/{sbx.id}/connect", {"timeout": 60})
    dt = (time.monotonic() - t0) * 1000
    check(s in (200, 201) and j["sandboxID"] == sbx.id, f"connect resumes it ({dt:.1f} ms)")
    sbx.token = j.get("envdAccessToken", sbx.token)
    x = run(sbx, "cat /tmp/kept.txt; echo $GREETING")
    check(x["out"] == b"kept\nhej\n", "files and the environment survive")
    c, r = sbx.stream("process.Process/Connect", {"process": {"tag": "survivor"}})
    msgs, end = read_stream(r)
    c.close()
    out = b"".join(base64.b64decode(m["event"]["data"].get("stdout", "")) for m in msgs if "data" in m.get("event", {}))
    check(out == b"survived\n", "a process from before the pause goes on")
    s, _, _ = api("POST", f"/sandboxes/{sbx.id}/pause", {})
    s2, j, _ = api("POST", f"/v2/sandboxes/{sbx.id}/connect", {})
    x = run(sbx, "cat /tmp/kept.txt")
    check(s == 204 and s2 in (200, 201) and x["out"] == b"kept\n", "a second pause and resume")

    print("timeouts and kill:")
    s, _, _ = api("POST", f"/sandboxes/{sbx.id}/timeout", {"timeout": 300})
    check(s == 204, "set_timeout: 204")
    s, _, _ = api("DELETE", f"/sandboxes/{sbx.id}")
    s2, _, _ = api("GET", f"/sandboxes/{sbx.id}")
    s3, _, _ = api("DELETE", f"/sandboxes/{sbx.id}")
    check(s == 204 and s2 == 404 and s3 == 404, "kill: 204, then 404")
    s, info, _ = api("POST", "/v2/sandboxes", {"templateID": TEMPLATE, "timeout": 1, "metadata": {}, "envVars": {}})
    time.sleep(2.5)
    s2, _, _ = api("GET", f"/sandboxes/{info['sandboxID']}")
    check(s == 201 and s2 == 404, "a sandbox past its timeout is gone")

    if "--net-template" in sys.argv:
        print("network (allow_internet_access):")
        nt = sys.argv[sys.argv.index("--net-template") + 1]
        probe = "python3 -c \"import socket; socket.getaddrinfo('debian.org', 443); print('resolved')\""
        for allow in (True, False):
            s, info, _ = api("POST", "/v2/sandboxes", {"templateID": nt, "metadata": {}, "envVars": {},
                                                       "allow_internet_access": allow})
            if s != 201:
                check(False, f"create with allow_internet_access={allow}")
                continue
            nb = Sbx(info)
            x = run(nb, probe)
            s2, d, _ = api("GET", f"/sandboxes/{nb.id}")
            if not isinstance(d, dict):
                check(False, f"get_info is JSON: {d!r:.300}")
                d = {}
            if allow:
                check(x["out"] == b"resolved\n" and d.get("allowInternetAccess") is True,
                      "allowed: a name resolves through the host's resolver")
            else:
                check(x["out"] == b"" and x["end"].get("exitCode", 0) != 0 and d.get("allowInternetAccess") is False,
                      "allow_internet_access=false: not even DNS gets out")
            api("DELETE", f"/sandboxes/{nb.id}")
        # E2B's egress rules aren't done here: refused, never quietly ignored.
        s, _, _ = api("POST", "/v2/sandboxes", {"templateID": nt, "network": {"denyOut": ["0.0.0.0/0"]}})
        check(s == 400, f"network.denyOut (E2B's egress rules): 400 ({s})")
        s, info, _ = api("POST", "/v2/sandboxes", {"templateID": nt, "network": {"allowPublicTraffic": True}})
        check(s == 201, f"network.allowPublicTraffic true (what sandboxes have): 201 ({s})")
        if s == 201:
            api("DELETE", f"/sandboxes/{info['sandboxID']}")

    if "--smp-template" in sys.argv:
        name, n = sys.argv[sys.argv.index("--smp-template") + 1].split(":")
        n = int(n)
        print(f"several vCPUs ({name}, {n}):")
        s, info, _ = api("POST", "/v2/sandboxes", {"templateID": name, "metadata": {}, "envVars": {}})
        if s != 201:
            check(False, f"create from {name}: {s} {info}")
        else:
            sb = Sbx(info)
            s, d, _ = api("GET", f"/sandboxes/{sb.id}")
            x = run(sb, "nproc")
            check(s == 200 and d.get("cpuCount") == n and x["out"] == f"{n}\n".encode(),
                  f"get_info cpuCount {n}, nproc {n}")
            # n forked processes of the same CPU-bound loop: on n vCPUs,
            # about as long as one alone.
            job = ("python3 -c \"import time,os\n"
                   "def f(): sum(i*i for i in range(3_000_000))\n"
                   "t=time.perf_counter(); f(); one=time.perf_counter()-t\n"
                   "t=time.perf_counter()\n"
                   f"for _ in range({n}):\n"
                   " if os.fork()==0: f(); os._exit(0)\n"
                   f"for _ in range({n}): os.wait()\n"
                   "print(f'{(time.perf_counter()-t)/one:.2f}')\"")
            for when in ("booted", "after a pause"):
                x = run(sb, job)
                try:
                    ratio = float(x["out"])
                except ValueError:
                    ratio = 99.0
                    print(x)
                check(ratio < 1.8, f"{when}: {n} processes take {ratio:.2f}x one alone (in parallel)")
                if when == "booted":
                    s, _, _ = api("POST", f"/sandboxes/{sb.id}/pause", {})
                    s2, j, _ = api("POST", f"/v2/sandboxes/{sb.id}/connect", {})
                    sb.token = j.get("envdAccessToken", sb.token) if isinstance(j, dict) else sb.token
                    x = run(sb, "nproc")
                    check(s == 204 and s2 in (200, 201) and x["out"] == f"{n}\n".encode(),
                          f"paused and resumed: still {n} CPUs")
            api("DELETE", f"/sandboxes/{sb.id}")

    if "--pool" in sys.argv:
        # The daemon has --cgroup: a team's sandboxes share its pool.
        name, n = sys.argv[sys.argv.index("--pool") + 1].split(":")
        n = int(n)
        print(f"team pools (--cgroup; {name}, {n} vCPUs):")
        team = f"e2e-{int(time.time())}"

        def pool_of(t):
            s, p, _ = api("GET", "/pools")
            return next((x for x in p if x.get("team") == t), None) if s == 200 and isinstance(p, list) else None

        for bad in ({"team": "Bad Name"}, {"team": "x", "vcpus": 0}, {"team": "x", "memoryMB": 1}, {"team": "x", "y": 1},
                    {"vcpus": 1}, "t"):
            s, _, _ = api("POST", "/v2/sandboxes", {"templateID": name, "pool": bad})
            check(s == 400, f"pool {json.dumps(bad)}: 400 ({s})")
        # One vCPU for the team: n busy processes get one vCPU's time.
        s, info, _ = api("POST", "/v2/sandboxes", {"templateID": name, "pool": {"team": team, "vcpus": 1, "memoryMB": 1024}})
        if s != 201:
            check(False, f"create in a pool: {s} {info}")
        else:
            sb = Sbx(info)
            p0 = pool_of(team)
            check(p0 is not None and p0["running"] == 1 and p0["memoryBytes"] > 1 << 20,
                  f"GET /pools: the team, 1 running, its memory ({p0})")
            burn = (f"python3 -c \"import os,time\nt=time.time()\nfor _ in range({n}):\n"
                    " if os.fork()==0:\n  while time.time()-t<3: pass\n  os._exit(0)\n"
                    f"for _ in range({n}): os.wait()\"")
            c0, t0 = (p0 or {}).get("cpuUsec", 0), time.monotonic()
            run(sb, burn)
            p1 = pool_of(team) or {}
            used = (p1.get("cpuUsec", 0) - c0) / 1e6 / (time.monotonic() - t0)
            check(used < 1.25, f"{n} busy processes, a pool of 1 vCPU: {used:.2f} vCPUs used")
            # Paused: its snapshot is the team's storage, its memory is free.
            s, _, _ = api("POST", f"/sandboxes/{sb.id}/pause", {})
            for _ in range(40):  # the VMM exits just after the pause is answered
                p2 = pool_of(team) or {}
                if p2.get("memoryBytes") == 0:
                    break
                time.sleep(0.05)
            check(s == 204 and p2.get("paused") == 1 and p2.get("running") == 0 and p2.get("snapshotBytes", 0) > 0
                  and p2.get("memoryBytes") == 0, f"paused: its snapshot counted, no memory ({p2})")
            s, j, _ = api("POST", f"/v2/sandboxes/{sb.id}/connect", {})
            sb.token = j.get("envdAccessToken", sb.token) if isinstance(j, dict) else sb.token
            x = run(sb, "echo back")
            check(s in (200, 201) and x["out"] == b"back\n" and (pool_of(team) or {}).get("running") == 1,
                  "resumed, in its team's cgroup again")
            api("DELETE", f"/sandboxes/{sb.id}")
        # The team's memory: past it, the kernel stops the VMM using the most.
        s, info, _ = api("POST", "/v2/sandboxes", {"templateID": name, "pool": {"team": team, "memoryMB": 256}})
        if s != 201:
            check(False, f"create with a 256 MiB pool: {s} {info}")
        else:
            sb = Sbx(info)
            run(sb, "python3 -c \"b = bytearray(400 << 20); print(len(b))\"")
            gone = False
            for _ in range(50):
                s, _, _ = api("GET", f"/sandboxes/{sb.id}")
                if s == 404:
                    gone = True
                    break
                time.sleep(0.1)
            check(gone, "touching 400 MiB in a 256 MiB pool: the sandbox is stopped")
            api("DELETE", f"/sandboxes/{sb.id}")
        time.sleep(0.2)
        check(pool_of(team) is None, "the team's last sandbox gone: so is its pool")
        # Longer than a day (the daemon's --max-timeout none).
        s, info, _ = api("POST", "/v2/sandboxes", {"templateID": TEMPLATE, "timeout": 30 * 86400})
        if s == 201:
            s2, d, _ = api("GET", f"/sandboxes/{info['sandboxID']}")
            check(s2 == 200 and d.get("endAt", "") > time.strftime("%Y-%m-%d", time.gmtime(time.time() + 29 * 86400)),
                  f"a 30-day timeout ({d.get('endAt')})")
            api("DELETE", f"/sandboxes/{info['sandboxID']}")
        else:
            check(False, f"create with a 30-day timeout: {s}")

    # Many at once.
    t0 = time.monotonic()
    ids = []
    for _ in range(8):
        s, info, _ = api("POST", "/v2/sandboxes", {"templateID": TEMPLATE, "metadata": {}, "envVars": {}})
        if s == 201:
            ids.append(info["sandboxID"])
    dt = (time.monotonic() - t0) * 1000
    check(len(ids) == 8, f"8 sandboxes one after another ({dt / 8:.1f} ms each)")
    for i in ids:
        api("DELETE", f"/sandboxes/{i}")

    print("FAIL" if fails else "ok", f"({fails} failed)")
    sys.exit(1 if fails else 0)


main()
