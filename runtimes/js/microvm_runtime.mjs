// SPDX-License-Identifier: MIT
// JavaScript function runtime for the microvm guest agent (src/agent/proto.h),
// for Bun and Node:
//
//   /init agent run bun /opt/microvm/runtime.mjs [--no-snapshot] MODULE [FUNCTION]
//   /init agent run node /opt/microvm/runtime.mjs [--no-snapshot] MODULE [FUNCTION]
//
// Warm-up imports MODULE (its top level runs once), awaits its init() if it
// exports one, and sends READY, asking for a snapshot unless --no-snapshot.
//
// A snapshot copies the process, random number generators included, into
// every VM restored from it. Before a restored VM's first invocation they
// are all made fresh (SECURITY.md has the measurements):
// - the guest kernel has been reseeded from the host and has emptied every
//   MADV_WIPEONFORK page (/init, kernel patch 0039), so BoringSSL (Bun's
//   crypto) reseeds itself as it would after a fork;
// - Node's OpenSSL is reseeded through reseed.node (reseed.c), next to this
//   file. Without it Node takes no snapshot;
// - Math.random is this adapter's own generator (xoshiro128**), reseeded:
//   neither engine can reseed its own;
// - Node's randomUUID and randomInt caches of random bytes are used up, so
//   they refill from the reseeded DRBG.
// Then MODULE's afterRestore() runs, for state of its own; if it throws,
// the runtime exits.
//
// Each invocation calls FUNCTION (default: the export named handler, or the
// default export) as `await handler(event, ctx)`:
//   event  the payload, a Uint8Array
//   ctx    { args, env, deadlineMs, id, count }
// It returns a Uint8Array, a string, undefined (empty result), or anything
// else, sent as JSON. A throw prints the error to stderr and returns status
// 1. What it prints during the invocation goes to that invocation.
//
// Between invocations the runtime blocks reading the next one: timers and
// promises the handler left behind wait until then, as on Lambda.
// SECURITY.md says what a snapshot shares between the VMs restored from it.
import crypto from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

const MAGIC = 0x4641564d, VERSION = 1;
const RESULT = 4, DONE = 5, INVOKE = 0x10, READY = 0x20;
const READY_SNAPSHOT = 1, CHUNK = 64 << 10;
const nap = new Int32Array(new SharedArrayBuffer(4));

function readFull(n) {
  const b = Buffer.allocUnsafe(n);
  for (let off = 0; off < n;) {
    let r;
    try {
      r = fs.readSync(0, b, off, n - off, null);
    } catch (e) {
      if (e.code === "EAGAIN" || e.code === "EINTR") {
        Atomics.wait(nap, 0, 0, 1);
        continue;
      }
      if (e.code === "EOF") process.exit(0);
      throw e;
    }
    if (r === 0) process.exit(0); // the agent is gone
    off += r;
  }
  return b;
}

function writeFull(b) {
  for (let off = 0; off < b.length;) {
    try {
      off += fs.writeSync(3, b, off, b.length - off);
    } catch (e) {
      if (e.code !== "EAGAIN" && e.code !== "EINTR") throw e;
      Atomics.wait(nap, 0, 0, 1);
    }
  }
}

function frame(type, id, body = Buffer.alloc(0)) {
  const h = Buffer.alloc(16);
  h.writeUInt32LE(MAGIC, 0);
  h[4] = VERSION;
  h[5] = type;
  h.writeUInt32LE(id, 8);
  h.writeUInt32LE(body.length, 12);
  writeFull(Buffer.concat([h, body]));
}

function parseInvoke(b) {
  const deadlineMs = b.readUInt32LE(0), nargs = b.readUInt16LE(12), nenv = b.readUInt16LE(14);
  const plen = b.readUInt32LE(16);
  let off = 20;
  const strs = [];
  for (let i = 0; i < nargs + nenv; i++) {
    const n = b.readUInt32LE(off);
    strs.push(b.toString("utf8", off + 4, off + 4 + n));
    off += 4 + n;
  }
  const env = {};
  for (const s of strs.slice(nargs)) {
    const k = s.indexOf("=");
    if (k < 0) env[s] = "";
    else env[s.slice(0, k)] = s.slice(k + 1);
  }
  return { deadlineMs, args: strs.slice(0, nargs), env, event: new Uint8Array(b.buffer, b.byteOffset + off, plen) };
}

// ---- random state after a restore -------------------------------------
const urandom = fs.openSync("/dev/urandom", "r"); // the guest kernel's, reseeded by /init
function fresh(n) {
  const b = Buffer.alloc(n);
  for (let off = 0; off < n;) off += fs.readSync(urandom, b, off, n - off, null);
  return b;
}

// Math.random: xoshiro128** (not a CSPRNG, as the engines' own aren't).
const rs = new Uint32Array(4);
const rotl = (x, k) => (x << k) | (x >>> (32 - k));
function next32() {
  const r = Math.imul(rotl(Math.imul(rs[1], 5), 7), 9) >>> 0;
  const t = rs[1] << 9;
  rs[2] ^= rs[0];
  rs[3] ^= rs[1];
  rs[1] ^= rs[2];
  rs[0] ^= rs[3];
  rs[2] ^= t;
  rs[3] = rotl(rs[3], 11);
  return r;
}
function seedMathRandom(b) {
  for (let i = 0; i < 4; i++) rs[i] = b.readUInt32LE(4 * i);
  if (!(rs[0] | rs[1] | rs[2] | rs[3])) rs[0] = 1;
}
function random() {
  return ((next32() >>> 5) * 67108864 + (next32() >>> 6)) / 9007199254740992;
}

// Node's OpenSSL: reseed.node, if it is there.
let openssl = null;
if (!globalThis.Bun && process.versions.openssl) {
  try {
    openssl = createRequire(import.meta.url)("./reseed.node");
  } catch (e) {
    process.stderr.write(`runtime.mjs: no snapshot: can't load reseed.node (${e.message})\n`);
  }
}

function reseedAll() {
  const b = fresh(64);
  if (openssl && !openssl.reseed(b.subarray(0, 48))) throw new Error("OpenSSL didn't reseed");
  seedMathRandom(b.subarray(48));
  // Node's caches: 128 UUIDs' worth, and 6 KiB for randomInt (6 bytes a
  // call). Using them up makes them refill from the reseeded DRBG.
  for (let i = 0; i < 128; i++) crypto.randomUUID();
  for (let i = 0; i < 1024; i++) crypto.randomInt(281474976710655);
}

const argv = process.argv.slice(2);
const noSnap = argv[0] === "--no-snapshot";
if (noSnap) argv.shift();
const snap = !noSnap && (globalThis.Bun !== undefined || openssl !== null);
const [file, name = "handler"] = argv;
if (!file) {
  process.stderr.write("usage: runtime.mjs [--no-snapshot] MODULE [FUNCTION]\n");
  process.exit(2);
}
if (snap) {
  seedMathRandom(fresh(16));
  Object.defineProperty(Math, "random", { value: random, writable: true, configurable: true, enumerable: false });
}
const mod = await import(pathToFileURL(path.resolve(file)).href);
const fn = mod[name] ?? (name === "handler" ? mod.default : undefined);
if (typeof fn !== "function") {
  process.stderr.write(`runtime.mjs: ${file} exports no function ${name}\n`);
  process.exit(2);
}
if (typeof mod.init === "function") await mod.init();
globalThis.Bun?.gc(true);
globalThis.gc?.();
frame(READY, 0, Buffer.from([snap ? READY_SNAPSHOT : 0, 0, 0, 0]));

for (let count = 0; ; count++) {
  const h = readFull(16);
  const body = readFull(h.readUInt32LE(12));
  if (h.readUInt32LE(0) !== MAGIC || h[4] !== VERSION || h[5] !== INVOKE) process.exit(3);
  if (count === 0 && snap) {
    try {
      reseedAll();
      if (typeof mod.afterRestore === "function") await mod.afterRestore();
    } catch (e) {
      process.stderr.write(`afterRestore: ${e?.stack ?? e}\n`);
      process.exit(1);
    }
  }
  const id = h.readUInt32LE(8);
  const { deadlineMs, args, env, event } = parseInvoke(body);
  let out = Buffer.alloc(0), status = 0;
  try {
    const r = await fn(event, { args, env, deadlineMs, id, count });
    if (r === undefined || r === null) out = Buffer.alloc(0);
    else if (r instanceof Uint8Array) out = Buffer.from(r.buffer, r.byteOffset, r.byteLength);
    else if (typeof r === "string") out = Buffer.from(r);
    else out = Buffer.from(JSON.stringify(r));
  } catch (e) {
    process.stderr.write(`${e?.stack ?? e}\n`);
    status = 1;
  }
  for (let i = 0; i < out.length; i += CHUNK) frame(RESULT, id, out.subarray(i, i + CHUNK));
  const d = Buffer.alloc(16);
  d.writeInt32LE(status, 4);
  frame(DONE, id, d);
}
