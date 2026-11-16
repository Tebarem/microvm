// SPDX-License-Identifier: MIT
// Every random source a JavaScript function might use, each one used during
// warm-up so its state is in the snapshot: VMs restored from one snapshot
// must still all answer differently (tools/fn-images.sh checks).
import crypto from "node:crypto";

crypto.randomBytes(16);
crypto.randomUUID();
crypto.getRandomValues(new Uint8Array(16));
crypto.randomInt(1000);
crypto.generateKeyPairSync("x25519");
Math.random();

export function handler(event, ctx) {
  // output belongs to its invocation (fn-images.sh checks)
  const tag = new TextDecoder().decode(event).trim();
  console.log("stdout of", tag);
  console.error("stderr of", tag);
  return {
    randomBytes: crypto.randomBytes(8).toString("hex"),
    randomUUID: crypto.randomUUID(),
    getRandomValues: Buffer.from(crypto.getRandomValues(new Uint8Array(8))).toString("hex"),
    randomInt: crypto.randomInt(281474976710655),
    "x25519 key": crypto.generateKeyPairSync("x25519").publicKey.export({ type: "spki", format: "der" }).toString("hex").slice(-16),
    "Math.random": Math.random(),
    count: ctx.count,
    event: new TextDecoder().decode(event),
    runtime: globalThis.Bun ? `bun ${Bun.version}` : `node ${process.version}`,
  };
}
