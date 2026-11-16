# Agent sandboxes

An agent sandbox is a long-lived VM that an AI agent creates, then runs
commands in, reads and writes files in, and reaches servers in, the way
E2B's sandboxes work. The goal is E2B compatibility: the unmodified `e2b`
Python and JS SDKs, and the agent frameworks built on them, work against
microvm when `E2B_API_URL` and `E2B_SANDBOX_URL` point at it.

```
 e2b SDK ──HTTP/1.1──► microvm-sbxd ──vsock──► /init sandbox ──► processes, files, ports
            (REST API,       (host)     (src/sbx/proto.h)   (guest/init/sbx.c)
             Connect+JSON)
```

- **In the guest**, `/init sandbox` (`guest/init/sbx.c`) plays the part of
  E2B's envd. It stays pid 1 and serves a small binary protocol over vsock:
  one operation per connection.
- **On the host**, `microvm-sbxd` (`src/sbxd/`) speaks E2B's API to the SDKs and
  turns each call into guest operations. All HTTP, JSON and Connect parsing
  happens on the host, where the input comes from the API's clients. What
  the guest sends back is hostile, so it is parsed only by a strict reader
  of fixed binary frames (`src/sbx/wire.c`).

## Starting a sandbox

```sh
microvm --kernel vmlinux --rootfs image.erofs --vsock /run/sbx/a.sock --mem 512 --append sandbox
```

The guest enters the image (EROFS root with a tmpfs overlay, as for
`--rootfs`) and brings up the loopback interface. It then listens on vsock
port 53 and prints `microvm-init: sandbox: ready`. A host connects through
the VMM's socket (`CONNECT 53\n`, then `OK <port>\n`), and the agent
answers with HELLO.

## The guest protocol (`src/sbx/proto.h`)

The frames are length-prefixed: magic, version, type, flags (always 0),
then the body length.

| Operation | What it does |
|---|---|
| `START` | Starts a process: argv (with a PATH lookup), user, cwd, environment, tag; pipes or a terminal of a given size; stdin open or not. Streams `P_START` (pid), then stdout/stderr/terminal data, then `P_END` (wait status). |
| `CONNECT` | Attaches to a running process by pid or tag: its output from then on, and its end. |
| `PS` | Lists running processes with their tag, cwd, argv and env. |
| `INPUT`, `CLOSE_STDIN`, `SIGNAL`, `RESIZE` | Act on a process selected by pid or tag. `SIGNAL` goes to the process group, so it reaches what the command started. |
| `STAT`, `MKDIR`, `MOVE`, `LIST`, `REMOVE` | Entries carry mode, uid/gid with their names, size, mtime and symlink target. `MKDIR` makes parents. `LIST` takes a depth. `REMOVE` is recursive. |
| `READ`, `WRITE` | Stream a file in 64 KiB `DATA` frames, then `DONE`. A write makes the file's directories and gives them to the user. |
| `WATCH` | inotify, optionally recursive (new subdirectories are watched as they appear). Events carry the path relative to the watched directory and, when the entry still exists, its entry. |
| `PORT_CONNECT` | After `OK`, the connection is a TCP connection to `127.0.0.1:PORT` in the guest, both ways, with half-close. |
| `SET_ENV` | The default environment of new processes (E2B's `envVars`). |
| `EXPORT` | Image builds: the root filesystem's changes as an OCI layer, a tar in `DATA` frames, then `OK` with its length. Added and changed files (pax records for long names, hard links kept), `.wh.NAME` for what was removed (overlayfs's whiteouts), `.wh..wh..opq` in a directory made again over one from the image (its opaque xattr). Device nodes, sockets and the sandbox's own `/etc/hostname`, `/etc/hosts` and `/etc/resolv.conf` are left out. Other processes are stopped while it walks. |
| `SNAPSHOT` | Pause: every other process is stopped, and the VMM saves the VM (`--snapshot FILE`) and exits. Each VM restored from the file continues with the RNG reseeded and the clock set before anything else runs, and then the processes continue. |

**Users.** Users are looked up by name in the image's `/etc/passwd`, and
supplementary groups come from `/etc/group`. An empty name means root, as
does `root` when the image has no passwd entry for it. Relative paths and
`~` start at the user's home. A process with no cwd starts in the home, or
in `/` if the image lacks that directory. As in envd, file operations run
as root and give what they create to the user.

**Backpressure.** The agent has one thread and never blocks on the host.
Output for a connection is held up to 1 MiB. Past that, the process, file
or port feeding it is no longer read until the host catches up, so a
stalled reader stalls only its own producer. Output that no connection is
attached to is dropped. When a process exits, what is left in its pipes is
passed on first, then `P_END`.

## What it costs (KVM box, p50 of one run)

| Measure | Time |
|---|---|
| Boot → the agent answers (wall clock, VMM process start included) | 12.5–13 ms |
| Restore a paused sandbox → the agent answers | 2.3–2.5 ms |
| 8 MiB of process output to the host | 5 ms |

`mvm_sbx_tests` (ctest `sbx`) checks everything in the table above
end-to-end on KVM: processes, users, the environment, stdin, a terminal,
background processes, signals, files, watching, ports, and pause and
resume.

## E2B compatibility: what `microvm-sbxd` must speak

From E2B's SDK sources (Python and JS SDK 2.63):

- **Transport.** HTTP/1.1 is enough, because both SDKs use HTTP/2 only over
  TLS. Request bodies may be chunked, since streaming RPCs send them that
  way.
- **The control plane** is REST with `X-API-KEY`.
  - `POST /v2/sandboxes` creates a sandbox and returns 201 with
    `sandboxID`, `templateID`, `clientID`, `envdVersion`,
    `envdAccessToken` and `domain`.
  - `POST /v2/sandboxes/{id}/connect` connects to (or resumes) one.
  - Kill, set-timeout and pause return 204. Pause returns 409 if the
    sandbox is already paused.
  - Get-info and list return `startedAt`, `endAt`, `cpuCount`, `memoryMB`,
    `diskSizeMB` and `state`.
  - Every error is JSON `{"code": N, "message": "..."}`.
- **envd** is Connect with JSON, without compression.
  - Unary calls are `POST /process.Process/Start`-style requests with
    `application/json`.
  - Streams are `application/connect+json` with 5-byte envelopes and an
    end-stream frame. A stream error goes in that frame with HTTP 200.
  - Values are ProtoJSON: camelCase keys, zero values omitted, int64 as
    strings, bytes as base64, enums by name.
  - The sandbox is named by the `E2b-Sandbox-Id` header,
    `X-Access-Token` carries `envdAccessToken`, and the user travels as
    `Authorization: Basic base64("user:")`.
  - `/files` handles multipart uploads and downloads, and `/health`
    answers 204.
- **envd version.** Reporting envdVersion `0.6.4` turns on every SDK code
  path.
- **How the SDK maps onto guest operations:**
  - `commands.run` is `Start` with `/bin/bash -l -c CMD`, which becomes
    `START`.
  - `send_stdin` becomes `INPUT`, and `kill` (SIGKILL) becomes `SIGNAL`.
  - `pty.create` becomes `START` with a terminal.
  - `files.*` become the file operations.
  - `watch_dir` becomes `WATCH`. Python's sync SDK polls watchers instead
    of streaming, so the daemon keeps a `WATCH` stream for each watcher.
  - `get_host(port)` is served through `PORT_CONNECT`.
  - Pause and resume become `SNAPSHOT` and `--restore`.

## The host daemon: `microvm-sbxd`

```sh
microvm-sbxd --vmm out/microvm --kernel vmlinux-kvm --kernel-smp vmlinux-smp-kvm --dir /var/lib/sbxd   --template base=python.erofs,mem=512 --template alpine=alpine.erofs,mem=256   --template net=python.erofs,net --template big=python.erofs,mem=2048,cpus=4   --api-key-file /etc/sbxd.key --domain sbx.example.com --listen 127.0.0.1:3000   [--jail out/microvm-jail] [--max-sandboxes 64] [--verbose]   [--net-deny-port PORT|none]... [--net-flow-rate N] [--net-max-dests N] [--net-tx-rate BYTES]   [--cgroup DIR] [--max-timeout SECONDS|none]
```

Then point the SDKs at it:

```sh
E2B_API_URL=http://127.0.0.1:3000 E2B_SANDBOX_URL=http://127.0.0.1:3000 E2B_API_KEY=$(cat /etc/sbxd.key) E2B_DOMAIN=sbx.example.com python agent.py
```

**Process model.** The daemon has one thread with an epoll loop and no root.
Each sandbox is its own VMM process, started with `posix_spawn` and an
empty environment, and watched through a pidfd. The VMM's console goes to
`DIR/sbx/<id>/console.log`.

**Templates.** At start-up every `--template NAME=IMAGE[,mem=MIB][,cpus=N][,user=NAME][,net]`
boots once, and its agent saves a snapshot (`SNAPSHOT`, then the VMM
exits). A sandbox is a `--restore` of that snapshot with the image
attached, so creating one costs about as much as a resume.

- `cpus=` is the number of vCPUs, 1–8 (default 1), which `cpuCount`
  reports. Above 1 the template boots the SMP kernel, `--kernel-smp`
  (`VARIANT=smp guest/kernel/build.sh`; pre-patch it with
  `tools/prepatch-alternatives.sh -c 2`). Its sandboxes restore with the
  same count.
- `user=` is the default user of commands and files when the SDK doesn't
  name one; the default is root inside the guest.
- `net` gives the template a network (the rootless NAT, under its default
  policy). A sandbox created with `allow_internet_access: false` on such a
  template restores with `--net-deny-all`, which refuses every flow,
  DNS included.
- **The network's limits** (SECURITY.md, the egress policy). Every sandbox
  with the internet is denied the mail ports, 25, 465 and 587 (or the
  `--net-deny-port` ports given; `none` for none). It also gets the
  daemon's `--net-flow-rate`, `--net-max-dests` and `--net-tx-rate`, if
  given. A create request may set its own with
  `"netLimits": {"txRate": BYTES, "flowRate": N, "maxDests": N}`: the
  control plane gives each team its plan's. E2B's own `"network"` (egress
  allow and deny lists, private URLs) isn't done here: a create that asks
  for any of it is refused with 400, so a rule that would deny something
  is never quietly ignored.
- **`GET /stats`** lists each running sandbox with a network, with its
  VMM's counters since it last started (the `--stats` file):
  `[{"sandboxID", "cpuCount", "internet", "startedAt", "cpuNs",
  "txBytes", "rxBytes", "flows", "refused", "denied", "limited"}]`.
  A resume starts them again from zero.
- **Team pools** (`--cgroup DIR`, a cgroup v2 directory delegated to the
  daemon, with the cpu and memory controllers). A create with
  `"pool": {"team": NAME, "vcpus": N, "memoryMB": N}` (from the control
  plane; NAME a-z, 0-9 and -, each number optional: no cap) runs the
  sandbox's VMM in `DIR/t-NAME`, jailed in a cgroup of its own under it.
  That cgroup's `cpu.max` and `memory.max` are the pool's, with
  `memory.swap.max` 0: the team's sandboxes on the node share N vCPUs of
  CPU time, and past its memory the kernel's OOM killer stops the VMM
  using the most. What counts is memory in use, which the balloon's free
  page reports keep honest, not each sandbox's size. A pool's cgroup is
  removed with its team's last VMM; a pause ends the VMM, so a paused
  sandbox takes no memory. Without `--cgroup`, a create with a pool is
  refused (400). Under systemd: `Delegate=yes`, `DelegateSubgroup=sbxd`,
  and `--cgroup` a directory beside that subgroup.
- **`GET /pools`** lists each team with a sandbox on the node:
  `[{"team", "running", "paused", "memoryBytes", "cpuUsec", "oomKills",
  "snapshotBytes"}]`: the cgroup's `memory.current`, `cpu.stat`
  usage_usec and `memory.events` oom_kill (from zero when the cgroup was
  made again), and the disk its paused sandboxes' snapshots take.
- **`--max-timeout`**: the longest timeout a sandbox may be given
  (default 86400, a day; `none`: no limit). The control plane holds each
  team to its plan's.
- `"base"` (the SDK's default template) means the only template, when
  there is just one.

**Templates pushed at run time.** With no `--template`, a node gets its
templates from the control plane, which sends the same settings plus where
to fetch the image:

```
PUT /templates/NAME   {"url": "http://files.example.com:3900/...", "sha256": "…", "sizeBytes": N,
                       "memoryMB": 512, "cpuCount": 1, "user": "user", "internet": true,
                       "startCmd"?: "npm start", "readyCmd"?: "curl -sf localhost:3000", "workdir"?: "/app",
                       "layers"?: [{"url", "sha256", "sizeBytes"}, ...]}
GET /templates        [{"templateID", "sha256", "layers"?, "state", "memoryMB", "cpuCount", "internet",
                        "startCmd"?, "readyCmd"?, "workdir"?, "error"?}]
DELETE /templates/NAME
```

- **Fetching.** The daemon fetches the URL over plain HTTP from an address,
  never a name, so there is no DNS and no TLS code in it. A presigned URL
  from the regional store holds no credential that outlives it.
  - The image streams to `DIR/images/SHA.part`.
  - The status must be 200, the Content-Length `sizeBytes`, and the SHA-256
    the one asked for. Only then is it renamed to `DIR/images/SHA.erofs`,
    read-only. The hash is what makes the image trusted, not the network.
  - At most 4 fetches run at once, and a connection silent for 30 s is
    dropped.
- **Content addressing.** There is one fetch per image, however many names
  use it. An image already in `images/` is not fetched again: a `PUT` with
  other settings boots it at once.
- **Layers.** An image may be the top layer of several: `layers` lists the
  ones below it, bottom first, at most 7 (`microvm-mkrootfs --lower` made
  the image on them; IMAGES.md). Each is fetched and checked like the
  image, once, and kept by its hash in `images/`, so every template built
  on the same base shares that base's file. The VMM maps each layer read
  only (`--rootfs` once per layer), so their pages are shared in the host's
  page cache by every VM of every such template, and `/init` stacks them
  under the VM's writable tmpfs. A template boots once all of its layers
  are here; one that fails to fetch fails it. Jailed, layer K is bound at
  `/layerK`.
- **States.** A template goes `fetching` → `preparing` (its boot and
  snapshot) → `ready`, or `failed` with an `error`.
  - A create against a template that is still fetching or preparing waits
    for it.
  - A create against a failed template gets 503.
- **Replacing and deleting.**
  - The same `PUT` again is a no-op (200). Any other `PUT` makes a new
    version (202).
  - A replaced or deleted template takes no new sandboxes, but its running
    and paused ones keep their snapshot and image. It is freed once the last
    of them is gone, and each of its layers is unlinked once no template
    uses it.
- **Start and ready commands** (E2B's `set_start_cmd`): before the
  snapshot, `startCmd` is started with `/bin/sh -c` as the template's user
  in `workdir` and left running, and `readyCmd` is run the same way every
  100 ms until it exits 0. Then the snapshot is taken, so every sandbox
  begins with the started process already up. A command that can't start
  fails the template at once ("the start command: no such user"); one that
  never gets ready fails it after 300 s. Either can come alone. `workdir`
  is also where a sandbox's commands run when they name no `cwd`, as in
  E2B (otherwise: the user's home).
- **Names.** A static `--template` name can't be pushed over (409).
- **Tests.** `tests/sbxd_templates.py` drives all of this against an image
  server that misbehaves on purpose: a flipped bit, short and long bodies,
  404s, a slow store.

**Export** (image builds): `GET /sandboxes/ID/export` streams the agent's
`EXPORT`, the sandbox's root filesystem changes, as `application/x-tar`.
`microvm-mkrootfs --oci BASE --add-layer layer.tar` makes an image of it.
An error after the stream began cuts it: a client must see the chunked
body end properly. `tests/sbxd_export.py` makes every kind of change,
checks the tar, and boots a template of the image made from it.

**Pause and resume.** Pause asks the agent for `SNAPSHOT`. The VMM saves
the VM and exits, and the sandbox is paused. A connect or resume restores
it. A restored VMM keeps the file it came from mapped, so each sandbox
alternates between two files (`a.snap`, `b.snap`), and the one it no
longer needs is removed. With `autoPause`, a sandbox past its timeout is
paused instead of killed.

- **A pause writes only what the sandbox changed.** Sandbox VMMs run with
  `--snapshot-diff`: the file is a diff against the template's snapshot,
  holding only the pages written since the restore (`/proc/self/pagemap`
  tells which ones are no longer the file's). A resume maps the template,
  then the diff over it (`--base`). The next pause saves a diff of the
  template again, so there is never a chain of diffs.
- **Freed memory goes back to the host** (`--balloon`, on for every
  sandbox VMM). The guest kernel reports the memory it has free through
  virtio-balloon's free page reporting, a single page at a time and up
  to 2 s after it was freed. The VMM discards each reported range
  (`MADV_DONTNEED`), so the range stops being the sandbox's memory. A
  running sandbox shrinks: 10 s after a process wrote and freed 200 MB,
  the VMM held 30 MiB instead of 225. Before a pause, `/init` makes the
  kernel report everything free at once (kernel patch 0040,
  `vm.page_reporting_flush`), so a diff holds only memory in use.
- **A pause ends when the snapshot is whole, not when the VMM has
  exited.** Tearing down a KVM VM takes the host kernel ~40 ms (an RCU
  barrier in KVM's MMU). The VMM writes the snapshot's header last, and
  the daemon watches the sandbox's directory (inotify). When the VMM
  closes the file and the header is in it, the sandbox is paused; the
  exiting process is reaped later. A resume can start a new VMM at once.

**With `--jail`**, every VMM runs under `microvm-jail`:

- with `--uid/--gid 65534` when the daemon is root;
- binding only the image (`/rootfs`), the sandbox's own directory
  (`/work`, writable), the kernel (template boots only) and the
  template's snapshot (read-only: restored, or a pause's base).

The VMM then sees one sandbox's files and nothing else of the host.

**What it speaks:**

- **The control plane:**
  - create (`/sandboxes`, `/v2/sandboxes`), list (with a state filter),
    get-info, kill;
  - set-timeout (`--max-timeout`, a day by default), pause, connect and resume;
  - `/metrics` (empty) and `/health`.
- **envd:**
  - `process.Process`: Start, Connect, List, SendInput, StreamInput,
    CloseStdin, SendSignal, Update.
  - `filesystem.Filesystem`: Stat, MakeDir, Move, ListDir, Remove,
    WatchDir, CreateWatcher, GetWatcherEvents, RemoveWatcher.
  - `GET` and `POST /files`: multipart, raw octet-stream, gzip.
  - `/health`.
  - Streams send keepalives at the client's `Keepalive-Ping-Interval`.
- **Ports.** A request whose Host is `PORT-ID.DOMAIN` becomes a raw
  tunnel to that port in the guest (`PORT_CONNECT`). The tunnel carries
  bytes both ways, so upgrades such as WebSockets pass through it.
  `49983-ID.DOMAIN` is envd itself, as in E2B. `get_host(port)` hands
  out these names, so a deployment points the wildcard `*.DOMAIN` at the
  daemon (or a proxy in front of it).

**Not supported:**

- signed file URLs (`secure` sandboxes' `files.download_url`);
- file metadata;
- `/metrics` data;
- template building through the API (templates are images on the host).

**`tests/sbxd_e2e.py`** (stdlib Python, the SDK's requests by hand)
checks 51 things against a running daemon:

- the control plane;
- every process call, including StreamInput and a terminal;
- files, including 5 MB, two files at once, and gzip, then 6 more 5 MB
  round trips on one keep-alive connection;
- watching and ports;
- pause and resume twice, with a process and files surviving;
- timeouts and kill;
- the network policy;
- with `--smp-template NAME:N`, a template of N vCPUs: `cpuCount`,
  `nproc`, and N CPU-bound processes running in parallel, before and after
  a pause;
- with `--pool NAME:N` (a daemon with `--cgroup`): bad pools refused, a
  pool's vCPUs holding N busy processes to one, a paused sandbox's
  snapshot counted and its memory freed, a sandbox past its pool's memory
  stopped, the cgroup gone with the team's last sandbox, and a 30-day
  timeout.

It passes on the python and alpine images, with and without `--jail`, and
with the daemon built under ASan + UBSan. Alpine has no bash, so the
agent runs `/bin/sh` when the SDK asks for `/bin/bash` and the image has
none.

**Measured on the KVM box** (python image, 512 MiB, one run each):

| Measure | Time |
|---|---|
| A template's first boot, to the snapshot saved | 60–100 ms |
| A template's snapshot on disk | 11–15 MiB |
| Create (HTTP request to 201) | 2.1–3 ms; 3.5 ms jailed |
| `commands.run` of a short command, to its end | 12 ms |
| Pause, after a few commands (13 MiB changed) | 10 ms |
| Pause, after a process wrote and freed 200 MB (16 MiB changed) | 11–22 ms |
| Pause, after writing 64 MB to `/tmp` (78 MiB changed) | 36–40 ms |
| Pause on alpine (256 MiB; 3 MiB changed) | 3.2–3.4 ms |
| Resume | 3–5 ms |

Pause and resume are through the Python SDK (`pause()`, then
`Sandbox.connect()`), jailed or not. A pause costs about 0.5 ms per MiB
the sandbox changed: copying those pages into the file is most of it.
Before diffs, a pause wrote all of the guest's memory and waited for the
VMM to exit: 160–220 ms on the python image. Before free page reporting,
the 200 MB a process had freed was saved too: 210 MiB in 100–110 ms, and
after a few commands 21 MiB.

## With the real SDKs

`tests/sdk/` runs the unmodified `e2b` SDKs against the daemon: the
Python SDK (sync and async) in `e2b_python.py`, and the JS SDK in
`e2b_js.mjs`. They are not part of ctest, because they need the SDKs:

```sh
E2B_API_URL=http://127.0.0.1:3000 E2B_SANDBOX_URL=http://127.0.0.1:3000 \
E2B_API_KEY=... E2B_DOMAIN=sbx.example.com PYTHONPATH=SDK \
python3 tests/sdk/e2b_python.py TEMPLATE [NET_TEMPLATE]
```

They cover what agent frameworks use:

- `commands.run` with streaming output, exit codes and their exceptions,
  envs, cwd and user;
- background commands, `list`, `kill`, `send_stdin` and `connect`;
- every `files` call, including 3 MiB, gzip, `watch_dir` and the
  not-found errors;
- `pty` create, input and resize;
- `get_host` reaching a server in the sandbox;
- `get_info`, `list` with a metadata query, `set_timeout`, `pause` and
  `connect` (resume, with files and a process surviving), and `kill`;
- 10 concurrent commands, and 5 creates in a row;
- `allow_internet_access` both ways.

With SDK 2.63.0 (Python and JS), every check passes on the python and
alpine images and on a python template with `cpus=4`, with and without
`--jail`, and with the daemon under ASan + UBSan. Through the SDK, a create takes 2.5–3.6 ms, a resume 4–9
ms and a pause about 20 ms (in the test, after a background process and
some files).

- Plain `http://` URLs get HTTP/1.1 from both SDKs. The Python SDK
  defaults to HTTP/2, but only negotiates it over TLS, so
  `E2B_HTTP_VERSION` needn't be set.
- The SDKs on the test box came from npm and PyPI. npm verified the
  registry signatures and provenance (`npm audit signatures`), and the
  install ran without lifecycle scripts. The Python wheels' hashes were
  checked against PyPI and their provenance read where published. The
  e2b wheels have none, so they were diffed against the `e2b@2.63.0` tag
  on GitHub: byte-identical.

**Without internet access, lookups fail at once.** A sandbox created with
`allow_internet_access: false` has the network device and
`--net-deny-all`. A DNS query gets NXDOMAIN straight from the NAT, and
any other datagram an ICMP "administratively prohibited" (SECURITY.md,
the egress policy). A name lookup then fails in milliseconds with glibc
and musl alike, instead of waiting out the resolver's 10 s timeout.

## Still to do

