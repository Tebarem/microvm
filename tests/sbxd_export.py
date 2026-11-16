#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# microvm-sbxd's GET /sandboxes/ID/export (image builds): a sandbox's root
# filesystem changes as a tar layer, whiteouts included; microvm-mkrootfs
# makes an image of it on top of the base, and a sandbox from that image
# sees the changes.
#
#   sbxd_export.py URL KEY MKROOTFS OCI_DIR WORK
#
# URL and KEY: a microvm-sbxd with an "alpine" template made from OCI_DIR;
# WORK: an empty directory for the layer and the image.
import base64
import hashlib
import http.client
import http.server
import io
import json
import os
import struct
import subprocess
import sys
import tarfile
import threading
import time
import urllib.parse

URL, KEY, MKROOTFS, OCI, WORK = sys.argv[1:6]
u = urllib.parse.urlparse(URL)
HOST, PORT = u.hostname, u.port or 80
fails = 0


def check(ok, what):
    global fails
    print(f"  {what:<72} {'ok' if ok else 'FAIL'}", flush=True)
    if not ok:
        fails += 1


def api(method, path, body=None):
    c = http.client.HTTPConnection(HOST, PORT, timeout=120)
    h = {"X-API-KEY": KEY}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    c.request(method, path, data, h)
    r = c.getresponse()
    raw = r.read()
    c.close()
    try:
        return r.status, json.loads(raw) if raw else None
    except ValueError:
        return r.status, raw


def sh(info, cmd, user="root"):
    c = http.client.HTTPConnection(HOST, PORT, timeout=120)
    h = {"E2b-Sandbox-Id": info["sandboxID"], "E2b-Sandbox-Port": "49983", "Connect-Protocol-Version": "1",
         "Content-Type": "application/connect+json",
         "Authorization": "Basic " + base64.b64encode(f"{user}:".encode()).decode()}
    if info.get("envdAccessToken"):
        h["X-Access-Token"] = info["envdAccessToken"]
    body = json.dumps({"process": {"cmd": "/bin/sh", "args": ["-c", cmd]}}).encode()
    c.request("POST", "/process.Process/Start", struct.pack(">BI", 0, len(body)) + body, h)
    r = c.getresponse()
    out, err, code = b"", b"", None
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
        err += base64.b64decode(ev.get("data", {}).get("stderr", ""))
        if "end" in ev:
            code = ev["end"].get("exitCode", 0)
    c.close()
    if code:
        print("    stderr:", err.decode(errors="replace")[-400:])
    return code, out


def export(info):
    """(status, tar bytes, whether the chunked stream ended properly)."""
    c = http.client.HTTPConnection(HOST, PORT, timeout=120)
    c.request("GET", f"/sandboxes/{info['sandboxID']}/export", headers={"X-API-KEY": KEY})
    r = c.getresponse()
    try:
        data, whole = r.read(), True
    except http.client.IncompleteRead as e:
        data, whole = e.partial, False
    ct = r.getheader("content-type")
    c.close()
    return r.status, data, whole, ct


LONG = "/opt/" + "d" * 60 + "/" + "e" * 60
CHANGES = f"""set -e
mkdir -p /opt/new/sub
echo hello > /opt/new/sub/file
chown 1234:5678 /opt/new/sub/file
chmod 0640 /opt/new/sub/file
mkdir -p {LONG}
echo long > {LONG}/f
echo changed >> /etc/motd
rm /etc/issue
rm -rf /etc/apk
mkdir /etc/apk
echo only > /etc/apk/only
ln /opt/new/sub/file /opt/new/hard
ln -s /opt/new/sub/file /opt/new/sym
ln -s {LONG}/f /opt/new/longsym
mkfifo /opt/new/fifo
head -c 3000000 /dev/urandom > /opt/new/big
mknod /opt/new/null c 1 3
sha256sum /opt/new/big | cut -d' ' -f1
"""


def main():
    print("export:")
    s, info = api("POST", "/sandboxes", {"templateID": "alpine", "timeout": 300})
    check(s == 201, "a sandbox from alpine")
    if s != 201:
        return
    rc, out = sh(info, CHANGES)
    big_sha = out.decode().strip()
    check(rc == 0 and len(big_sha) == 64, "files added, changed, removed, linked in it")

    t0 = time.monotonic()
    st, data, whole, ct = export(info)
    ms = (time.monotonic() - t0) * 1000
    check(st == 200 and whole and ct == "application/x-tar", f"exported: {len(data)} bytes in {ms:.0f} ms")
    check(len(data) % 512 == 0 and data[-1024:] == bytes(1024), "a whole tar, with its end blocks")
    tf = tarfile.open(fileobj=io.BytesIO(data), format=tarfile.PAX_FORMAT)
    m = {x.name: x for x in tf.getmembers()}

    def content(name):
        x = m.get(name)
        return tf.extractfile(x).read() if x and x.isfile() else None

    pair = [m.get("opt/new/sub/file"), m.get("opt/new/hard")]
    f = next((x for x in pair if x and x.isfile()), None)  # the other is a link to it
    check(f and content(f.name) == b"hello\n", "a new file")
    check(f and f.uid == 1234 and f.gid == 5678 and f.mode == 0o640, "its owner and mode")
    links = [x for x in pair if x and x.islnk()]
    check(len(links) == 1 and f and links[0].linkname == f.name, "a hard link stays one")
    check(content(LONG[1:] + "/f") == b"long\n", "a path over 100 bytes (pax)")
    check(m.get("opt/new/sym") and m["opt/new/sym"].issym() and m["opt/new/sym"].linkname == "/opt/new/sub/file",
          "a symlink")
    check(m.get("opt/new/longsym") and m["opt/new/longsym"].linkname == LONG + "/f", "a symlink target over 100 bytes")
    check(m.get("opt/new/fifo") and m["opt/new/fifo"].isfifo(), "a fifo")
    check("opt/new/null" not in m, "a device node: left out")
    big = content("opt/new/big")
    check(big and hashlib.sha256(big).hexdigest() == big_sha, "a 3 MB file, byte for byte")
    check((content("etc/motd") or b"").endswith(b"changed\n"), "a changed file (copied up) whole")
    check("etc/.wh.issue" in m, "a removed file: a whiteout")
    check("etc/apk/.wh..wh..opq" in m and content("etc/apk/only") == b"only\n",
          "a directory removed and made again: opaque, with its new file")
    check(not any(x.name.startswith(("/", "../")) or "/../" in x.name for x in m.values()), "relative paths only")
    check("bin/busybox" not in m and "etc/passwd" not in m, "nothing that didn't change")
    check(not {"etc/hostname", "etc/hosts", "etc/resolv.conf"} & m.keys(), "not the sandbox's own /etc files")

    rc, out = sh(info, "echo still here")
    check(rc == 0 and out == b"still here\n", "the sandbox goes on afterwards")
    st2, data2, whole2, _ = export(info)
    check(st2 == 200 and whole2 and len(data2) == len(data), "a second export: the same")

    layer = os.path.join(WORK, "layer.tar")
    with open(layer, "wb") as fh:
        fh.write(data)
    img = os.path.join(WORK, "built.erofs")
    r = subprocess.run([MKROOTFS, "--oci", OCI, "--add-layer", layer, img], capture_output=True, text=True)
    check(r.returncode == 0, "microvm-mkrootfs: base + the layer")
    if r.returncode:
        print(r.stderr[-800:])
        return
    api("DELETE", f"/sandboxes/{info['sandboxID']}")

    # Boot it: the image server below, a template of it.
    h = hashlib.sha256()
    with open(img, "rb") as fh:
        while b := fh.read(1 << 20):
            h.update(b)

    class Srv(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(os.path.getsize(img)))
            self.end_headers()
            with open(img, "rb") as fh:
                while b := fh.read(1 << 20):
                    self.wfile.write(b)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Srv)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    spec = {"url": f"http://127.0.0.1:{srv.server_address[1]}/i", "sha256": h.hexdigest(),
            "sizeBytes": os.path.getsize(img), "memoryMB": 256}
    s, _ = api("PUT", "/templates/built", spec)
    end = time.monotonic() + 120
    t = None
    while time.monotonic() < end:
        _, lst = api("GET", "/templates")
        t = next((x for x in lst if x["templateID"] == "built"), None)
        if t and t["state"] in ("ready", "failed"):
            break
        time.sleep(0.1)
    check(s in (200, 202) and t and t["state"] == "ready", "a template of the built image")
    s, info = api("POST", "/sandboxes", {"templateID": "built", "timeout": 120})
    check(s == 201, "a sandbox from it")
    if s != 201:
        return
    q = "; ".join([
        "cat /opt/new/sub/file", "stat -c '%u:%g %a' /opt/new/sub/file",
        "stat -c %i /opt/new/sub/file /opt/new/hard | uniq | wc -l",
        f"cat {LONG}/f", "readlink /opt/new/longsym", "test -p /opt/new/fifo && echo fifo",
        "sha256sum /opt/new/big | cut -d' ' -f1", "tail -1 /etc/motd",
        "test -e /etc/issue || echo no-issue", "ls /etc/apk", "test -e /etc/hostname && echo hostname",
    ])
    rc, out = sh(info, q)
    want = (f"hello\n1234:5678 640\n1\nlong\n{LONG}/f\nfifo\n{big_sha}\nchanged\nno-issue\nonly\nhostname\n")
    check(rc == 0 and out.decode() == want, "in it: the changes, and the base")
    if out.decode() != want:
        print(out.decode())
    api("DELETE", f"/sandboxes/{info['sandboxID']}")
    api("DELETE", "/templates/built")
    srv.shutdown()


main()
print("FAILED" if fails else "all passed", f"({fails} failed)" if fails else "")
sys.exit(1 if fails else 0)
