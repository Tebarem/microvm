# SPDX-License-Identifier: MIT
"""Python function runtime for the microvm guest agent (src/agent/proto.h).

    /init agent run python3 /opt/microvm/runtime.py [--no-snapshot] MODULE.py [FUNCTION]

Warm-up imports MODULE.py (its top level runs once: load models, open
pools, import what it needs), calls its init() if it has one, and then
sends READY, which asks for the snapshot unless --no-snapshot. Every VM
restored from that snapshot starts here, already warm.

Each invocation calls FUNCTION (default: handler) as handler(event, ctx):
  event  the payload, bytes
  ctx    .args (list of str), .env (dict), .deadline_ms, .id, .count (the
         invocations this VM served before this one)
It returns bytes, str, None (empty result), or anything else, which is
sent as JSON. An exception prints its traceback to stderr and returns
status 1. What it prints during the invocation goes to that invocation.

A snapshot copies the process, random number generators included, into
every VM restored from it. The kernel's is reseeded by the agent before
this process runs again, so os.urandom, secrets and uuid.uuid4 are unique
per VM. Before a VM's first invocation this runtime also reseeds the
random module and, if the process has OpenSSL's libcrypto loaded (the ssl
module and anything else linked to it), OpenSSL's generator, and then
calls MODULE's after_restore() if it has one: that is where a function
reseeds generators of its own (numpy.random, random.Random instances, a
library with its own copy of OpenSSL). If after_restore() raises, the
runtime exits: a VM in an unknown state is never reused. What stays
shared: the str/bytes hash seed (PYTHONHASHSEED), fixed at start-up.
SECURITY.md has the measurements.
"""
import gc
import importlib.util
import json
import os
import random
import struct
import sys
import traceback

MAGIC, VERSION = 0x4641564D, 1
RESULT, DONE, INVOKE, READY = 4, 5, 0x10, 0x20
READY_SNAPSHOT = 1
HDR = struct.Struct("<IBBHII")
CHUNK = 64 << 10


def read_full(n):
    b = bytearray()
    while len(b) < n:
        r = os.read(0, n - len(b))
        if not r:
            os._exit(0)  # the agent is gone
        b += r
    return bytes(b)


def write_full(b):
    v = memoryview(b)
    while v:
        v = v[os.write(3, v):]


def frame(typ, fid, body=b""):
    write_full(HDR.pack(MAGIC, VERSION, typ, 0, fid, len(body)) + body)


class Context:
    __slots__ = ("id", "args", "env", "deadline_ms", "count")


def parse_invoke(body):
    deadline, _max_result, _max_output, nargs, nenv, plen = struct.unpack_from("<IIIHHI", body, 0)
    off, strs = 20, []
    for _ in range(nargs + nenv):
        (n,) = struct.unpack_from("<I", body, off)
        strs.append(body[off + 4:off + 4 + n].decode("utf-8", "surrogateescape"))
        off += 4 + n
    env = dict(s.split("=", 1) if "=" in s else (s, "") for s in strs[nargs:])
    return deadline, strs[:nargs], env, body[off:off + plen]


def libcrypto_loaded():
    try:
        with open("/proc/self/maps") as f:
            return any("libcrypto" in line for line in f)
    except OSError:
        return True  # can't tell: reseed anyway


def reseed(mod):
    """This VM's own random state, not the snapshot's."""
    random.seed()
    if libcrypto_loaded():
        import ssl  # already imported if it is in use; cheap otherwise
        # Mixed into OpenSSL's primary DRBG as a reseed; the per-thread
        # DRBGs that RAND_bytes uses reseed from it on their next call.
        ssl.RAND_add(os.urandom(48), 48.0)
    hook = getattr(mod, "after_restore", None)
    if callable(hook):
        hook()


def main():
    argv = sys.argv[1:]
    snap = True
    if argv[:1] == ["--no-snapshot"]:
        snap, argv = False, argv[1:]
    if not argv:
        sys.stderr.write("usage: runtime.py [--no-snapshot] MODULE.py [FUNCTION]\n")
        return 2
    path, name = argv[0], (argv[1] if len(argv) > 1 else "handler")
    sys.path.insert(0, os.path.dirname(os.path.abspath(path)))
    spec = importlib.util.spec_from_file_location("handler_module", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["handler_module"] = mod
    spec.loader.exec_module(mod)
    fn = getattr(mod, name)
    if callable(getattr(mod, "init", None)):
        mod.init()
    # Keep what warm-up made out of the collector's way: restored VMs then
    # share those pages instead of each copying them on the first GC.
    gc.collect()
    gc.freeze()
    sys.stdout.flush()
    sys.stderr.flush()
    frame(READY, 0, struct.pack("<I", READY_SNAPSHOT if snap else 0))

    count = 0
    while True:
        magic, ver, typ, _flags, fid, n = HDR.unpack(read_full(HDR.size))
        body = read_full(n)
        if magic != MAGIC or ver != VERSION or typ != INVOKE:
            os._exit(3)
        if count == 0:
            try:
                reseed(mod)
            except BaseException:
                traceback.print_exc()
                sys.stderr.flush()
                os._exit(1)
        ctx = Context()
        ctx.deadline_ms, ctx.args, ctx.env, event = parse_invoke(body)
        ctx.id, ctx.count = fid, count
        status = 0
        try:
            r = fn(event, ctx)
            if r is None:
                out = b""
            elif isinstance(r, (bytes, bytearray, memoryview)):
                out = bytes(r)
            elif isinstance(r, str):
                out = r.encode()
            else:
                out = json.dumps(r).encode()
        except Exception:
            traceback.print_exc()
            out, status = b"", 1
        sys.stdout.flush()
        sys.stderr.flush()
        for i in range(0, len(out), CHUNK):
            frame(RESULT, fid, out[i:i + CHUNK])
        frame(DONE, fid, struct.pack("<IiII", 0, status, 0, 0))
        count += 1


if __name__ == "__main__":
    sys.exit(main())
