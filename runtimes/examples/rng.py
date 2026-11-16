# SPDX-License-Identifier: MIT
# Every random source a Python function might use, each one used during
# warm-up so its state is in the snapshot: VMs restored from one snapshot
# must still all answer differently (tools/fn-images.sh checks).
import os
import random
import secrets
import ssl
import sys
import uuid

random.random()
ssl.RAND_bytes(16)
uuid.uuid4()


def handler(event, ctx):
    # output belongs to its invocation (fn-images.sh checks)
    print("stdout of", event.decode().strip())
    print("stderr of", event.decode().strip(), file=sys.stderr)
    return {
        "urandom": os.urandom(8).hex(),
        "random": random.random(),
        "uuid4": str(uuid.uuid4()),
        "secrets": secrets.token_hex(8),
        "ssl.RAND_bytes": ssl.RAND_bytes(8).hex(),
        "hash": hash("microvm"),
        "count": ctx.count,
        "event": event.decode(),
    }
