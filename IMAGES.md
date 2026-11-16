# Container images

`microvm-mkrootfs` turns a container image into the read-only EROFS root
filesystem that `microvm --rootfs` boots. Input forms:

```bash
microvm-mkrootfs --oci DIR app.erofs                 # an OCI image layout
microvm-mkrootfs --docker-archive app.tar app.erofs  # docker save / podman save
microvm-mkrootfs app.erofs base.tar.gz app.tar       # bare layers, bottom first
```

- **`--oci DIR`** reads an [OCI image layout] (`oci-layout`, `index.json`,
  `blobs/sha256/`), as written by `skopeo copy ... oci:DIR` or
  `podman save --format oci-dir`.
- **`--docker-archive FILE`** reads a tar of an image's files: either the
  legacy `docker save` layout (`manifest.json`, `<hex>.json`,
  `<id>/layer.tar`), or an OCI layout in a tar (`docker save` since
  Docker 25, `podman save --format oci-archive`). It reads the tar in place,
  without extracting it. Symlinks between members (Docker's way of storing
  a repeated layer once) are followed inside the archive.
- **`--add-layer FILE`** (repeatable, with `--oci` or `--docker-archive`)
  puts a layer of the caller's on top of the image: tar, or gzip or zstd
  compressed tar. It is a Dockerfile's `COPY` without a build: a
  function's code, a runtime adapter (`runtimes/`, below). Added layers are
  parsed like the image's own, whiteouts included, and come before the
  config is resolved, so a user they add to `/etc/passwd` can be the
  image's `User`. A whiteout hides an image path, as a Dockerfile's
  `RUN rm -rf` would: `tools/whiteouts.py OCI_DIR LAYER_DIR PATTERN...`
  writes them for every image path that matches a pattern, such as
  `usr/local/lib/python3.*/site-packages/pip-*.dist-info` (wildcards
  match within one path segment).
- **`--ref NAME`** picks an image when there are several. It matches a tag
  in `manifest.json`, or the `org.opencontainers.image.ref.name` or
  `io.containerd.image.name` annotation in an index.
- **`--copy FILE SRC DEST OWNER MODE`** (repeatable, in order with
  `--add-layer`) is a Dockerfile `COPY` from FILE, a tar (or gzip or zstd
  tar) of the build context's files, as image builds upload them:
  - SRC is a path in the context, or a glob (`*`, `?`, `[...]` within a
    component, as Go's `filepath.Match`); `.` is the whole context.
  - Docker's rules: a directory's contents go into DEST; a file goes to
    DEST, or into it when DEST ends in `/`, is a directory in the image
    already, or more than one thing matched.
  - Directories merge into those already there; anything else replaces
    what is there. Symlinks on the way to DEST are followed inside the
    image.
  - Everything copied is root's, or OWNER's (`--chown`, `user[:group]`,
    names from the image as it is at that point); MODE (`--chmod`, octal)
    sets the permission bits. Either may be `""`.
  - The context is parsed with the same rules as any layer, and nothing
    outside DEST is touched.
- **`--env NAME=VALUE`** (repeatable), **`--workdir PATH`** and
  **`--user USER`** change the image's config the way a Dockerfile's
  `ENV`, `WORKDIR` and `USER` do (image builds use them). An `--env` of a
  name the image has replaces it in its place; new names come after the
  image's, and the last `--env` of a name wins. The user is resolved after
  the `--add-layer` layers, so one a build added with `useradd` works.
- **Other options:**
  - `--config FILE` also writes the image config file (below) next to the
    image;
  - `--max-size N[KMG]` caps the decompressed size of all layers together
    (default 16 GiB);
  - `--max-ratio N` caps a compressed layer's decompressed-to-compressed
    ratio (default 200);
  - `--stats` prints the times and sizes;
  - `--no-sandbox` is for debugging.

The converter never contacts a registry. See
[Pulling from a registry](#pulling-from-a-registry) for how that could be
added.

[OCI image layout]: https://github.com/opencontainers/image-spec/blob/main/image-layout.md

## What it does with an image

Images are untrusted. The code is `src/image/oci.c`, and SECURITY.md has
the threat model.

1. **Pick the image.** The converter walks `index.json`, nesting at most 4
   deep. OCI indexes and Docker manifest lists both work. With `--ref`, it
   looks only at entries with that name. It takes the first linux/amd64
   entry, as containerd does.
   - Entries for another platform are skipped. So are BuildKit's
     attestation manifests (`unknown/unknown`) and artifacts that aren't
     images.
   - An entry with no platform is used only when nothing matches. Two such
     entries are an error ("pick one with `--ref`"), not a guess.
2. **Verify each blob before using it.** For the manifest, the config and
   every layer, the converter checks the size against the descriptor first,
   then the sha256 digest. Only `sha256:` and 64 lowercase hex digits are
   accepted. A docker-archive has no descriptors. There, the config is
   verified by its name (`<hex>.json` or `blobs/sha256/<hex>`), which must
   be its digest.
3. **Check the config.** It needs `os` linux, `architecture` amd64,
   `rootfs.type` layers, and one `diff_id` per layer.
4. **Check each layer's diff_id** (the sha256 of its uncompressed tar)
   *before* the layer is parsed:
   - an uncompressed layer is hashed;
   - a compressed (gzip or zstd) layer is decompressed once just to hash
     it. That pass also gives its exact decompressed size, so the size cap
     and the ratio cap are enforced before any tar parsing.
5. **Apply the layers in order** into an in-memory tree (`src/image/tar.c`,
   with the same path rules as bare tar layers):
   - `.wh.NAME` removes `NAME` from the layers below;
   - `.wh..wh..opq` empties its directory of lower-layer entries;
   - nothing is extracted to the host. A compressed layer streams through
     its decoder a second time.
6. **Apply the `--add-layer` layers**, in order, the same way. They have no
   digests to check. Their sha256 goes into the config file.
7. **Add the image config file** at `/.microvm/image-config`, as one more
   top layer. It replaces anything the image or an added layer put there.
8. **Write the EROFS image.** File data is copied straight from the layers.
   It is laid out in layer order, so each compressed layer is decoded a
   third and last time, front to back.

Media types accepted for layers:
- OCI `tar`, `tar+gzip`, `tar+zstd`, and the nondistributable variants;
- Docker `diff.tar.gzip` and its foreign variant, and containerd's
  `diff.tar.zstd`. A foreign layer's blob must be in the layout: its `urls`
  are never fetched.
- A layer's bytes must match its media type: zstd bytes behind a gzip or
  tar media type, or gzip behind zstd, are errors. Docker-archive layers
  and bare layers have no media type, and are told apart by their first
  bytes.

One image can mix them, as images built on a gzip base with zstd layers on
top do.

### Gzip and DEFLATE (`src/image/inflate.c`)

This is our own inflater, held to zlib's strictness:
- stored blocks must have a valid `NLEN`;
- Huffman codes may not be over-subscribed. An incomplete code is allowed
  only for a single 1-bit code, as in zlib, and never for the code-length
  code;
- distances may not reach back past the start of the output;
- an unused code is fine, but using a symbol it doesn't define is an error.

For gzip it checks the header flags, length-limits `FEXTRA`, `FNAME` and
`FCOMMENT`, checks `FHCRC`, the CRC-32 and `ISIZE`, and refuses bytes after
the last member. Several members are allowed.

Bomb limits:
- a total output cap: `--max-size`, enforced as it inflates;
- a ratio cap: output may not exceed `max-ratio × input + 64 MiB`;
- a cap on runs of tiny dynamic blocks, which cost header decoding but
  produce almost no output.

Throughput is 550–1080 MB/s of output on real `gzip -6` layers, about twice
GNU gzip's. Numbers are in [BENCH.md](BENCH.md#container-image-conversion).

### Zstandard (`src/image/zstd.c`)

Our own decoder for RFC 8878, with no dictionary support, held to
libzstd's strictness:
- **frame headers:** reserved bits must be clear. A frame that needs a
  dictionary is refused (id 0 means none), and so is a window over
  128 MiB. That is libzstd's own default limit; `zstd --long=31` output
  is over it.
- **blocks:** reserved block types are refused, and a block may not exceed
  the block maximum (the smaller of the window and 128 KiB), compressed or
  decompressed.
- **literals:** Huffman weights must be valid. The implied last weight must
  complete a power of two. Each of the 1 or 4 streams must be consumed
  exactly, and a block may reuse the previous tree only if there is one.
- **FSE tables:** normalized counts must sum exactly to the table size,
  and symbols and accuracy logs must stay within each table's limits. A
  repeated table must exist.
- **sequences:** the bitstream must be consumed exactly. Literal and match
  lengths stay inside the block, and an offset (repeat offsets included)
  may reach back neither past the window nor past the frame's output so
  far.
- **frame ends:** the content size must match when the frame gives one,
  and so must the XXH64 checksum.
- **what follows:** skippable frames are skipped, and concatenated frames
  are decoded in turn. Anything else after the last frame is an error.

Bomb limits are the gzip ones, plus two of zstd's own:
- **output caps:** `--max-size`, and `--max-ratio`, which covers RLE
  blocks too: 4 bytes of input can make 128 KiB.
- **memory:** the window buffer grows with the output and never exceeds
  twice the window plus a block, or the frame's content size plus a block
  if that is smaller. A frame that claims a 128 MiB window but makes 10 KB
  costs 128 KiB.
- **work:** at most 4096 table builds (Huffman or FSE) plus one per KiB of
  output, so tiny blocks with fresh tables can't make it work for nothing.

Throughput is in [BENCH.md](BENCH.md#container-image-conversion).

### JSON (`src/image/json.c`)

A strict RFC 8259 parser:
- **size limits:** 4 MiB for an index or manifest, 16 MiB for a config,
  and at most 1M values;
- **nesting:** at most 64 levels;
- **strings:** valid UTF-8 only, with escapes and surrogate pairs checked;
  `json_cstr()` refuses a string with a NUL in it;
- **objects:** a duplicate key is an error, never "last one wins";
- trailing bytes after the document are rejected.

## Images in layers

An image can be a layer on others, so that images built on the same base
share it: one copy on disk and in every node's store, one copy in the
host's page cache for all of their VMs.

```
microvm-mkrootfs --oci base-layout base.erofs                    a whole image
microvm-mkrootfs --lower base.erofs --add-layer run.tar \
                 --copy ctx.tar . /app "" "" --env K=V --user app  app.erofs
microvm --rootfs base.erofs --rootfs app.erofs                    stacked: base at the bottom
```

- **What a layer holds.** `--lower` (repeatable, bottom first) reads the
  images below, as this tool writes them, into the in-memory tree. The
  options (`--add-layer`, `--copy`, `--env`, `--workdir`, `--user`) then
  apply as they would to a whole image. OUT gets only what changed:
  - new and changed entries;
  - every directory on the way to them, with its metadata as it is now;
  - for each name that went away, a whiteout: a 0/0 character device,
    overlayfs's own. A directory that replaced another gets one whiteout
    per old name, not an opaque xattr: the image format has no xattrs.
  - A hard link to a file below becomes a copy of it in the layer.
- **Its config.** `/.microvm/image-config` is always in the layer. It is the
  lower images' config with the options applied: `added-layer` records
  accumulate, and the user is resolved again in the image as it now is.
- **Reading the lower images.** Only this tool's own format is accepted:
  4 KiB blocks, 64-byte extended inodes, flat data, no xattrs, no
  compression, no features. Anything else is refused. Every offset and
  size is checked against the file before it is used. A directory reached
  twice (a loop) is refused, as is nesting deeper than 2048. A layer that
  comes back from storage is checked by its hash first, but the reader
  doesn't count on that; `fuzz_erofs` fuzzes it.
- **In the guest.** The VMM maps layer K at its own guest-physical range,
  2 MiB-aligned with a hole after it, as e820 persistent memory. The
  guest's kernel makes `/dev/pmemK` from it. With more than one layer, the
  VMM passes `layersN` to `/init`, which makes the device nodes from
  `/proc/partitions` (the kernel registers them asynchronously, so their
  minors needn't follow their names) and mounts each as EROFS under
  `/lower/K`. It then mounts overlayfs with `lowerdir` top first, under the
  usual tmpfs upper. One layer is mounted as before: no `/proc` lookup.
  - Up to 8 layers in all; their sizes together at most 64 GiB.
  - Multiple layers are Linux only (the Windows VMM maps one image).
- **Snapshots** record each layer's size. A restore needs the same layers
  in the same order. Snapshots from before layers record one image.

## The image config file

The image keeps the runtime parts of its config in `/.microvm/image-config`
(mode 0444, root-owned), so whatever starts the command doesn't need the
OCI JSON. `--config FILE` writes the same bytes to the host too.

The format is a sequence of NUL-terminated strings: a header, then
key/value pairs, in this order:

```
microvm-image-config\0  1\0                      header, format version 1
config-digest\0   sha256:<hex>\0                 the image config blob
manifest-digest\0 sha256:<hex>\0                 OCI layouts only
added-layer\0     sha256:<hex>\0                 one per --add-layer, in order
entrypoint\0 <arg>\0      (one pair per element, in order; may be absent)
cmd\0        <arg>\0      (one per element)
env\0        NAME=value\0 (one per element, as the image lists them)
workdir\0    <path>\0     (absent when empty)
user\0       <the image's User string>\0  (absent when empty)
uid\0        <decimal>\0  (always present)
gid\0        <decimal>\0  (always present)
group\0      <decimal>\0  (one per supplementary group)
```

Readers must ignore keys they don't know. `oci_config_walk()` parses the
file, and `mvm_oci_tests --check-sample IMG CFG` prints it. Values never
contain a NUL, because the converter refuses images whose config strings
do.

### How the guest runs an image

`microvm --rootfs app.erofs` with no command runs what the image says;
`microvm --rootfs app.erofs -- ARG...` replaces its Cmd, as `docker run IMAGE
ARG...` does. The same goes for function runtimes (`--append agent`). The
guest's `/init` does it (`guest/init/image.c`), after it has entered the
image, in the command's own process:

1. **argv** is `entrypoint` followed by the caller's arguments. With no
   arguments, it is `entrypoint` followed by `cmd`. If both are empty, it is
   an error (status 125). A name without a `/` is looked up in the image's
   own `PATH`.
2. **Environment:** the `env` entries in order, then the caller's
   (`--env-file` and `-e`, below) on top. If none sets `PATH`, add
   `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`;
   if none sets `HOSTNAME`, add `HOSTNAME=microvm`; if none sets `HOME`, add
   the user's home from the image's `/etc/passwd`, or `/`.
3. **Working directory:** `workdir`, or `/`. It is created (by root, mode
   0755) if the image lacks it, as Docker does, and then entered as the
   image's user.
4. **User:** `setgroups(group...)`, then `setresgid(gid)`, then
   `setresuid(uid)`, after everything that still needs root.

An image without the file (bare tar layers, the test image) runs the
caller's command as root in `/`, and needs one. Its environment is `PATH`,
`HOSTNAME` and `HOME=/root` as above, with the caller's on top.

**The caller's environment**, as `docker run -e` and `--env-file` give it:

```sh
microvm --kernel vmlinux --rootfs app.erofs --env-file app.env -e LOG_LEVEL=debug -e TZ
```

- `-e NAME=VALUE` (or `--env`) sets `NAME`, replacing the image's.
- `-e NAME` takes the VMM process's own `NAME`. If the process has none,
  it removes `NAME`, the image's included. Under `microvm-jail` the VMM's
  environment is empty, so give values.
- `--env-file FILE` holds one `NAME=VALUE` or `NAME` a line, as Docker's:
  leading blanks are dropped, blank lines and lines starting with `#` are
  skipped, a CR before the newline is dropped, and the value is taken as it
  is, quotes and all. A name with a blank in it is an error.
- The files go first, then `-e`, each in order; a later `NAME` wins.
- A value may hold anything but a NUL: spaces, quotes, `=`, newlines.
  At most 4096 strings and 1 MiB in all.
- They need `--rootfs`, and don't apply to `--restore`: a restored VM's
  command already has its environment, saved in the snapshot. Give each
  invocation its own with `microvm-invoke --env` (the agent protocol's).

The strings never touch the kernel command line, which any process in the
guest can read (`/proc/cmdline`) and the console prints. `/init` reads them
from the VMM over its control port (0x707) before anything else runs, and
only the command's process gets them. In a VM started with `--snapshot`
they are in guest memory, so in the snapshot file.

The root the command sees:
- **The image, writable:** an overlay of a tmpfs on the read-only image.
  Changes live in guest RAM and vanish with the VM.
- **`/proc`**, and **`/sys` read-only** if the kernel has sysfs (the
  default kernel doesn't: BENCH.md).
- **A `/dev` of its own:** null, zero, full, random, urandom, tty, ptmx
  with a private devpts, `/dev/shm`, and the `fd`, `stdin`, `stdout` and
  `stderr` links.
- **`/tmp`** (mode 1777) if the image has none.
- **`/etc/hostname` and `/etc/hosts`** for the hostname `microvm`, and with
  `--net`, **`/etc/resolv.conf`** naming the VMM's resolver (10.0.2.3). The
  guest kernel's `ip=` autoconfiguration hands it over in `/proc/net/pnp`.
  These replace the image's own copies, as Docker's bind mounts do.

`/init` stays pid 1: it reaps orphaned processes, and the VM ends when the
command exits, even if a process it started still holds its output open.

**What a non-root `User` means here.** The converter has already resolved
the User string with Docker's rules (`user`, `uid`, `user:group`,
`uid:gid`, and mixed forms), against the image's own `/etc/passwd` and
`/etc/group`. A name that isn't there is a conversion error. A numeric uid
that isn't in passwd is allowed and gets gid 0, as in Docker.
Supplementary groups are the groups in `/etc/group` that list the user.

These ids exist only inside the guest kernel. They have no relation to
host uids: the VMM is already unprivileged (`nobody` under `setpriv`, or
the jail's per-VM uid), and the guest kernel is the only thing that checks
them. Dropping to them in the guest is defence in depth inside the VM, for
example so a compromised app can't remount or read root-only files in its
own image. It doesn't change the host boundary, which is the VMM sandbox
and the jail either way. Files in the image keep the owners from the layer
tars, so an image built for `User: 1000` with files owned by 1000 works
unchanged.

### Functions on public runtime images (`runtimes/`)

`runtimes/` has function runtimes for the guest agent (SECURITY.md,
"Function invocations") in the languages' own code, for their official
images:
- `python/microvm_runtime.py`, for Python 3;
- `js/microvm_runtime.mjs`, for Bun and Node.

A function image is the public image plus one layer with the adapter and
the function:

```bash
skopeo copy docker://docker.io/library/python@sha256:<digest> oci:python   # pin by digest
mkdir -p fn/opt/microvm fn/app
cp runtimes/python/microvm_runtime.py fn/opt/microvm/runtime.py
cp handler.py fn/app/
tar --create --owner=0 --group=0 -f fn.tar -C fn opt app
microvm-mkrootfs --oci python --add-layer fn.tar fn.erofs
microvm --kernel vmlinux --rootfs fn.erofs --vsock fn.sock --append agent \
    --snapshot fn.snap -- python3 /opt/microvm/runtime.py /app/handler.py
microvm --restore fn.snap --rootfs fn.erofs --vsock vm1.sock &   # one per VM
echo '{"x": 1}' | microvm-invoke vm1.sock --payload -
```

The function is `handler(event, ctx)` in Python, or the exported `handler`
(or default export) in JS, possibly async. `event` is the payload as bytes
or a `Uint8Array`. `ctx` has the invocation's arguments, environment strings,
deadline, id, and how many invocations the VM served before. The function
returns bytes, a string, nothing, or a value that is sent as JSON. Its
module's top level, and an `init()` if it has one, is the warm-up that the
snapshot keeps. The image's Entrypoint still comes first, as for any
command (`docker-entrypoint.sh` for node and bun, which execs the rest).

Every runtime asks for the snapshot by default (`--no-snapshot` turns that
off). A restored VM reseeds every random number generator before its first
invocation, or it would repeat the snapshot's in every VM (SECURITY.md,
"Language runtimes and snapshots"). For Node that needs `reseed.node` next
to `runtime.mjs`, built from `runtimes/js/reseed.c` with any C compiler:

```sh
cc -std=c2x -O2 -shared -fPIC -nostdlib -fno-stack-protector -o reseed.node runtimes/js/reseed.c
```

Without it Node takes no snapshot, and says so on stderr. `tools/fn-images.sh` builds the
function images, takes the snapshots, checks them, and times them
(BENCH.md).

The official Python images delete every `.pyc` file to save space (0 of
1098 modules in python:3-slim have one), and the image is read-only, so a
cold start compiles every module it imports, every time. That was most of
Python's cold start. `tools/pyc-layer.sh` gives an image its bytecode back
as one more layer:

```sh
tools/pyc-layer.sh build vmlinux fn.erofs pyc.tar /app        # compile in a VM
microvm-mkrootfs --oci python --add-layer fn.tar --add-layer pyc.tar fn.erofs
```

- It boots the image and runs `runtimes/python/precompile.py` there (it
  must be at `/opt/microvm/precompile.py`). The image's own interpreter
  compiles every directory on `sys.path` and the given directories of the
  function's code, so the bytecode matches its version and its sources.
  The VM's console carries the `.pyc` files back as a tar.
- The layer goes last, over everything it was compiled from. Like any
  layer, `microvm-mkrootfs` parses it as untrusted input.
- The `.pyc` files are hash-based (PEP 552): they don't depend on file
  times, and the same image gives the same layer, byte for byte. By default
  each import checks the source's hash, so a source changed under the
  layer is compiled again rather than run stale; `--unchecked` skips that
  check, for no measurable gain (BENCH.md).
- `fn-images.sh` builds it for Python functions (`PYC=0` leaves it out).
  It made cold boot → first response 2.3 times faster, and `import json,
  ssl` 92 → 43 ms.

### Scanning images for known vulnerabilities

`tools/scan-images.sh DIR OCI_DIR...` scans OCI layouts with Anchore's
grype. Grype isn't part of microvm, so the script fetches a pinned release
into `DIR` and checks it before running it:
- the digests GitHub recorded for the release;
- the release's checksums file;
- a Sigstore signature on that file, whose certificate names Anchore's
  release workflow and chains to Sigstore's Fulcio CA.

It installs nothing outside `DIR`. `WRAP` runs the scans as another user.
Grype reads Debian's and Alpine's package databases, language packages
(npm, pip) and the runtime binaries themselves: it identifies
`python3.15`, `node` and `bun` by version.

The four images the function benchmarks use, on 2026-11-05 (grype
0.121.0, database built 2026-11-04). The tags still pointed at the
digests pinned in BENCH.md, so these are the current images:

| image | findings | with a fix released |
|---|---|---|
| alpine 3.24.3 | 3 Medium | none |
| python:3-slim (Debian 13.7, Python 3.15.2) | 60 High, 63 Medium, 12 Low, 46 Negligible | 1 Low, in Python: fixed in 3.16.0 |
| oven/bun:slim (Debian 13.7, Bun 1.4.4) | 59 High, 62 Medium, 11 Low, 46 Negligible | none |
| node:lts-slim (Debian 13.7, Node 26.13.0) | 67 High, 77 Medium, 12 Low, 46 Negligible | 19, all in npm's own dependencies |

- **The Debian findings have no fix to take.** Debian marks every one
  "won't fix" (minor issues it doesn't ship security updates for) or "not
  fixed" yet. They are the same in all three images: glibc, util-linux,
  ncurses, gcc's runtime libraries, sqlite, perl-base, zlib and acl. A
  newer image can't remove them until Debian fixes them. Most are only
  reachable through programs a function doesn't run (`mount`, `login`,
  `perl`).
- **The fixable Node findings are all in npm**: `undici`,
  `brace-expansion`, `ip-address`, `glob`, `minimatch` and
  `postcss-selector-parser` under `/usr/local/lib/node_modules/npm`. The
  function runtime never loads npm. Node's own `fetch` uses the `undici`
  built into the binary, not this copy; grype can't see that one's
  version, so Node's releases are what covers it.
- **No findings for the runtimes' current releases**: Node 26.13.0, Bun 1.4.4,
  and Python 3.15.2 but for one Low.

**Function images leave the package managers out.** A function runs its
code, not `npm install` or `pip install`. So `tools/fn-images.sh` hides
them with whiteouts in the function's added layer (`tools/whiteouts.py`):
- Node: `npm`, `npx` and `/usr/local/lib/node_modules/npm`;
- Python: `pip`, `pip3`, `pip3.15`, `site-packages/pip` and its
  `dist-info`, and `ensurepip`, which carries a copy of pip of its own.
  Without it, `python -m venv` makes environments only with
  `--without-pip`.

Bun's `bunx` is the `bun` binary itself, so there is nothing to hide. The
script boots each function image and checks that nothing matching the
patterns is left. Scanned the same way, as an OCI layout of the image's
layers and the function's (`mvm-mkoci`):

| function image | findings | with a fix released |
|---|---|---|
| python + function | 60 High, 63 Medium, 12 Low, 46 Negligible | 1 Low, in Python |
| node + function | 61 High, 65 Medium, 11 Low, 46 Negligible | **none** (19 before) |
| bun + function | 59 High, 62 Medium, 11 Low, 46 Negligible | none |

pip had no known vulnerabilities to remove, but a function shouldn't be
able to install packages either way. What is left is the Debian findings
above, which have no fix to take.

## Limits

| what | limit |
|---|---|
| decompressed size of all layers | `--max-size`, 16 GiB |
| compression ratio (gzip, zstd) | `--max-ratio` 200, plus 64 MiB slack |
| zstd window | 128 MiB |
| layers | 512 |
| index, manifest | 4 MiB each |
| image config | 16 MiB |
| nested indexes | 4 |
| JSON nesting | 64 levels |
| inodes in an image | 2^24 |
| `/etc/passwd`, `/etc/group` read for User | 1 MiB each |
| supplementary groups | 32 |

## Follow-ups

- **zstd dictionaries.** Frames that need one are refused. Image layers
  don't use them: the OCI spec has no way to name one.
- **One inflate pass fewer.** A compressed layer is decoded three times:
  verify, import, write. Hashing the decompressed bytes during the import
  pass would save about a third of the OCI conversion time. The cost is
  that the tar parser would see a layer before its diff_id is known to
  match. That parser already treats every layer as hostile, and it runs in
  the sandbox, so this is a policy choice, not a safety one. For now the
  code verifies first.
- **Pinning the top digest.** An OCI layout's `index.json` is the one
  unverified file: it is the root of trust. A `--digest sha256:...` option
  should require the manifest or index it leads to. This is needed before
  a fetcher (below) is trusted with anything.
- **Other architectures** (arm64) need only a platform option, once there
  is a guest kernel for them.

## Pulling from a registry

There is no registry client, by design for now. Pulling is plain HTTPS:

- `GET /v2/<name>/manifests/<ref>`, with an `Accept` header listing the
  index and manifest media types;
- a token from the realm in the `WWW-Authenticate: Bearer` challenge,
  anonymous or with credentials;
- `GET /v2/<name>/blobs/<digest>`, which usually redirects to a CDN or
  object store on another host;
- with redirects, `Range` resumes and rate limits to handle.

Everything fetched is content-addressed, so integrity doesn't depend on the
transport. Pin the image by digest (`name@sha256:...`) and check every
blob, as the converter already does. Then TLS only protects credentials,
privacy and availability, and stops a network attacker from substituting a
different image when a pull is by tag.

There are three ways to get there. **This is the user's decision; nothing
is built yet.**

1. **Our own TLS client, in C, with no dependencies.**
   - What it takes:
     - a TLS 1.3 client: X25519, AES-GCM and ChaCha20-Poly1305, SHA-384,
       and HKDF;
     - X.509 parsing and chain validation against the system CA bundle,
       with ECDSA and RSA verification;
     - hostname checks;
     - an HTTP/1.1 client with redirects and chunked encoding.
   - For: it fits the project's no-dependency rule, gives one static
     binary, and is fully under our control and fuzzable.
   - Against:
     - it is the largest piece of this whole feature (several thousand
       lines);
     - the crypto has to be constant-time;
     - certificate validation is where most from-scratch TLS clients have
       failed;
     - we would own every future CVE.
   - The client could run in the same kind of sandbox as the converter:
     one socket, no files.
2. **The OS TLS stack.** On Debian that means OpenSSL or GnuTLS (or
   libcurl on top); on Windows, SChannel.
   - For: audited, maintained, and patched by the distribution.
   - Against:
     - it is a third-party dependency, so we either link dynamically or
       give up the static-binary deployment;
     - the HTTP and registry protocol is still ours to write;
     - OpenSSL inside our process enlarges what the sandbox has to allow
       (file reads for the CA store, more syscalls).
3. **A sidecar fetcher that writes an OCI layout.** A separate,
   unprivileged process does the network side. It could be an existing tool
   such as `skopeo copy docker://... oci:DIR` or `crane`, or a small program
   of our own later. It writes an OCI layout, and `microvm-mkrootfs --oci`
   converts it unchanged, verifying everything again.
   - For:
     - no TLS in our code at all;
     - the parts that need the network and the parts that parse images
       stay in separate processes: the fetcher has network but parses
       nothing that matters, and the converter parses everything but has
       no network;
     - registry auth, mirrors, proxies and caching become operations
       concerns;
     - it works today.
   - Against:
     - one more component on the service hosts (a Go binary in the case of
       skopeo or crane);
     - its own update cadence;
     - the fetcher must be given the pinned digest. Today index.json is
       taken on trust (see Follow-ups).

For the hosted service, option 3, with a digest pin added to the converter,
is the least code to own for the same guarantees. Options 1 and 2 matter if
the VMM host itself must pull, with no other process.
