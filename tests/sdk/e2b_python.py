# SPDX-License-Identifier: MIT
# The unmodified e2b Python SDK against microvm-sbxd (SANDBOX.md).
#
#   E2B_API_URL=http://127.0.0.1:3917 E2B_SANDBOX_URL=http://127.0.0.1:3917 \
#   E2B_API_KEY=... E2B_DOMAIN=sbx.test PYTHONPATH=SDK python3 e2b_python.py TEMPLATE [NET_TEMPLATE]
#
# Each check prints ok or FAIL (with the exception); the exit status is the
# number of failures. Not part of ctest: it needs the SDK (pip install e2b).
import asyncio
import http.client
import os
import sys
import time
import traceback

from e2b import (AsyncSandbox, CommandExitException, FileType, FilesystemEventType, NotFoundException, PtySize,
                 Sandbox, SandboxQuery, SandboxState)
from e2b.sandbox.filesystem.filesystem import WriteEntry

TEMPLATE = sys.argv[1] if len(sys.argv) > 1 else "base"
NET_TEMPLATE = sys.argv[2] if len(sys.argv) > 2 else None
fails = 0


def check(name, fn):
    global fails
    t0 = time.monotonic()
    try:
        r = fn()
        ok = r is None or r is True
        detail = "" if ok else f": {r!r}"
    except Exception as e:  # noqa: BLE001
        ok, detail = False, f": {type(e).__name__}: {e}"
        if os.getenv("VERBOSE"):
            traceback.print_exc()
    dt = (time.monotonic() - t0) * 1000
    fails += not ok
    print(f"  {name + f' ({dt:.1f} ms)':66} {'ok' if ok else 'FAIL' + detail}", flush=True)


def proxied_get(host, path):
    """What a client of get_host() does, with the wildcard DNS replaced by the Host header."""
    u = os.environ["E2B_SANDBOX_URL"].split("//", 1)[1]
    c = http.client.HTTPConnection(u, timeout=10)
    c.request("GET", path, headers={"Host": host})
    r = c.getresponse()
    body = r.read()
    c.close()
    return r.status, body


def main():
    print(f"e2b Python SDK, template {TEMPLATE}:")
    sbx = {}

    def create():
        sbx["s"] = Sandbox.create(TEMPLATE, timeout=120, metadata={"suite": "py"}, envs={"FROM_CREATE": "yes"})
        return bool(sbx["s"].sandbox_id)

    check("Sandbox.create", create)
    s = sbx["s"]

    # Commands.
    check("commands.run: stdout, exit 0", lambda: s.commands.run("echo hello").stdout == "hello\n")

    def exit_code():
        try:
            s.commands.run("echo out; echo err >&2; exit 3")
        except CommandExitException as e:
            return e.exit_code == 3 and e.stdout == "out\n" and e.stderr == "err\n"
        return "no exception"

    check("commands.run: a failing command raises, with its output", exit_code)
    check("envs from create and per call, cwd",
          lambda: s.commands.run("echo $FROM_CREATE $X; pwd", envs={"X": "1"}, cwd="/tmp").stdout == "yes 1\n/tmp\n")
    check("user=root", lambda: s.commands.run("id -u", user="root").stdout == "0\n")

    got = []
    check("on_stdout streaming", lambda: (s.commands.run("for i in 1 2 3; do echo $i; done",
                                                         on_stdout=lambda d: got.append(d)), "".join(got))[1] == "1\n2\n3\n")

    def background():
        h = s.commands.run("sleep 30", background=True)
        pids = [p.pid for p in s.commands.list()]
        killed = s.commands.kill(h.pid)
        res = None
        try:
            res = h.wait()
        except CommandExitException as e:
            res = e
        return h.pid in pids and killed and res.exit_code != 0

    check("background, list, kill", background)

    def stdin():
        h = s.commands.run("head -n 2", background=True, stdin=True)
        s.commands.send_stdin(h.pid, "a\n")
        s.commands.send_stdin(h.pid, "b\n")
        return h.wait().stdout == "a\nb\n"

    check("send_stdin", stdin)

    def connect():
        h = s.commands.run("sleep 0.3; echo late", background=True)
        h2 = s.commands.connect(h.pid)
        return h2.wait().stdout.endswith("late\n")

    check("commands.connect", connect)

    # Files.
    check("files.write / read (text)", lambda: (s.files.write("/tmp/t/a.txt", "héllo"),
                                                s.files.read("/tmp/t/a.txt"))[1] == "héllo")
    big = os.urandom(3 << 20)
    check("files.write / read 3 MiB (bytes)", lambda: (s.files.write("/tmp/t/big.bin", big),
                                                      bytes(s.files.read("/tmp/t/big.bin", format="bytes")))[1] == big)
    check("files.write_files (two)", lambda: len(s.files.write_files([WriteEntry(path="/tmp/t/b.txt", data="b"),
                                                                      WriteEntry(path="/tmp/t/c.txt", data=b"c")])) == 2)
    check("files.write_files gzip", lambda: (s.files.write_files([WriteEntry(path="/tmp/t/g.txt", data="g" * 10000)], gzip=True),
                                             s.files.read("/tmp/t/g.txt"))[1] == "g" * 10000)
    check("files.list", lambda: {e.name for e in s.files.list("/tmp/t")} >= {"a.txt", "big.bin", "b.txt", "c.txt"})
    check("files.exists", lambda: s.files.exists("/tmp/t/a.txt") and not s.files.exists("/tmp/t/nope"))
    check("files.get_info", lambda: (lambda i: i.type == FileType.FILE and i.size == len(big))(s.files.get_info("/tmp/t/big.bin")))
    check("files.make_dir (new, then existing)", lambda: s.files.make_dir("/tmp/t/d/e") and not s.files.make_dir("/tmp/t/d/e"))
    check("files.rename", lambda: s.files.rename("/tmp/t/b.txt", "/tmp/t/d/b2.txt").path == "/tmp/t/d/b2.txt")

    def remove():
        s.files.remove("/tmp/t/d")
        return not s.files.exists("/tmp/t/d")

    check("files.remove", remove)

    def missing():
        try:
            s.files.read("/tmp/t/nope")
        except NotFoundException:
            return True
        return "no exception"

    check("reading a missing file raises NotFoundException", missing)

    def watch():
        w = s.files.watch_dir("/tmp/t", recursive=True)
        s.files.write("/tmp/t/new.txt", "x")
        s.commands.run("mkdir -p /tmp/t/sub && echo y > /tmp/t/sub/deep.txt")
        evs = []
        for _ in range(20):
            evs += w.get_new_events()
            names = {e.name for e in evs}
            if {"new.txt", "sub/deep.txt"} <= names:
                break
            time.sleep(0.05)
        w.stop()
        return {"new.txt", "sub/deep.txt"} <= {e.name for e in evs} and any(
            e.type == FilesystemEventType.CREATE for e in evs) or [(e.name, e.type) for e in evs]

    check("files.watch_dir (recursive)", watch)

    # A terminal.
    def pty():
        out = []
        h = s.pty.create(PtySize(rows=24, cols=80))
        s.pty.send_stdin(h.pid, b"stty size; exit\n")
        res = h.wait(on_pty=lambda d: out.append(bytes(d)))
        return b"24 80" in b"".join(out) or b"".join(out)[-200:]

    check("pty.create, send_stdin, stty size", pty)

    def pty_resize():
        out = []
        h = s.pty.create(PtySize(rows=24, cols=80))
        s.pty.resize(h.pid, PtySize(rows=40, cols=100))
        s.pty.send_stdin(h.pid, b"stty size; exit\n")
        h.wait(on_pty=lambda d: out.append(bytes(d)))
        return b"40 100" in b"".join(out) or b"".join(out)[-200:]

    check("pty.resize", pty_resize)

    # Ports.
    def port():
        s.files.write("/tmp/www/hi.txt", "from the sandbox")
        s.commands.run("cd /tmp/www && exec python3 -m http.server 8000", background=True)
        host = s.get_host(8000)
        for _ in range(100):
            try:
                st, body = proxied_get(host, "/hi.txt")
                if st == 200:
                    return body == b"from the sandbox" and host.startswith("8000-" + s.sandbox_id)
            except OSError:
                pass
            time.sleep(0.05)
        return f"no answer from {host}"

    if s.commands.run("command -v python3 || true").stdout:
        check("get_host(8000): a server in the sandbox", port)

    # The control plane.
    check("get_info", lambda: (lambda i: i.sandbox_id == s.sandbox_id and i.metadata.get("suite") == "py"
                               and i.state == SandboxState.RUNNING)(s.get_info()))
    check("Sandbox.list", lambda: s.sandbox_id in [x.sandbox_id for x in Sandbox.list(
        query=SandboxQuery(metadata={"suite": "py"})).next_items()])
    check("set_timeout", lambda: s.set_timeout(300))
    check("is_running", lambda: s.is_running())

    def pause_resume():
        s.files.write("/tmp/keep.txt", "kept")
        bg = s.commands.run("sleep 1000", background=True)
        t0 = time.monotonic()
        s.pause()
        tp = (time.monotonic() - t0) * 1000
        st = Sandbox.get_info(s.sandbox_id).state
        t0 = time.monotonic()
        s2 = Sandbox.connect(s.sandbox_id)
        tr = (time.monotonic() - t0) * 1000
        print(f"    pause {tp:.0f} ms, connect-resume {tr:.1f} ms")
        sbx["s"] = s2
        return st == SandboxState.PAUSED and s2.files.read("/tmp/keep.txt") == "kept" and bg.pid in [
            p.pid for p in s2.commands.list()]

    check("pause, Sandbox.connect resumes (files, processes)", pause_resume)
    s = sbx["s"]
    check("commands after resume", lambda: s.commands.run("echo again").stdout == "again\n")

    def kill():
        sid = s.sandbox_id
        s.kill()
        try:
            Sandbox.get_info(sid)
        except NotFoundException:
            return True
        return "still there"

    check("kill, then get_info raises NotFoundException", kill)

    # The async SDK.
    async def async_suite():
        a = await AsyncSandbox.create(TEMPLATE, timeout=60)
        try:
            r = await a.commands.run("echo async")
            await a.files.write("/tmp/x", "y")
            ok = r.stdout == "async\n" and await a.files.read("/tmp/x") == "y"
            hs = await asyncio.gather(*[a.commands.run(f"echo {i}") for i in range(10)])
            return ok and [h.stdout for h in hs] == [f"{i}\n" for i in range(10)]
        finally:
            await a.kill()

    check("AsyncSandbox: run, files, 10 concurrent commands", lambda: asyncio.run(async_suite()))

    # Creates in a row.
    def many():
        t0 = time.monotonic()
        xs = [Sandbox.create(TEMPLATE, timeout=60) for _ in range(5)]
        dt = (time.monotonic() - t0) * 1000 / 5
        ok = all(x.commands.run("echo $((1+1))").stdout == "2\n" for x in xs)
        for x in xs:
            x.kill()
        print(f"    {dt:.1f} ms per Sandbox.create")
        return ok

    check("5 sandboxes, each runs a command", many)

    if NET_TEMPLATE:
        probe = "python3 -c \"import socket; socket.getaddrinfo('debian.org', 443); print('ok')\""

        def net(allow):
            x = Sandbox.create(NET_TEMPLATE, timeout=60, allow_internet_access=allow)
            try:
                try:
                    out = x.commands.run(probe).stdout
                except CommandExitException:
                    out = "refused"
                return out == ("ok\n" if allow else "refused")
            finally:
                x.kill()

        check("allow_internet_access=True: DNS works", lambda: net(True))
        check("allow_internet_access=False: nothing gets out", lambda: net(False))

    print("FAIL" if fails else "ok", f"({fails} failed)")
    sys.exit(min(fails, 100))


main()
