// SPDX-License-Identifier: MIT
// The function-invocation protocol between the host and the guest agent
// (guest/init/agent.c), and between the agent and the function runtime it
// starts. Shared by the host library (src/agent/), the agent and the demo
// runtime, so this header needs nothing but <stdint.h> (the guest side is
// freestanding).
//
// One stream of frames each way, little-endian:
//
//   off 0  u32 magic    MVA_MAGIC
//       4  u8  version  MVA_VERSION
//       5  u8  type     enum mva_type
//       6  u16 flags    0
//       8  u32 id       the invocation (0 in HELLO and READY)
//      12  u32 len      body bytes that follow
//
// Host <-> agent, over vsock: the host connects to the guest's port
// MVA_PORT (through the VMM's Unix socket: "CONNECT 52\n"). The agent
// answers with HELLO, then serves one invocation at a time:
//
//   host -> guest  INVOKE id  (body below)
//   guest -> host  any number of STDOUT / STDERR / RESULT id (data, at most
//                  MVA_MAX_CHUNK each), then exactly one DONE id.
//
// The host may send INVOKE before it has read HELLO. A second INVOKE before
// DONE is a protocol error. The guest sends nothing between DONE and the
// next INVOKE. A DONE with MVA_DONE_VM_ENDS set is the last frame: the VM
// stops after it (the runtime died, overran its deadline, or broke the
// protocol). The host then shuts its side down; the agent waits for that
// (up to 1 s) before it stops the VM, so the VMM has passed everything on.
// A malformed INVOKE whose length is sane is answered with DONE
// MVA_REFUSED; one whose header is unusable closes the connection. A host must treat everything the guest sends as hostile:
// src/agent/parse.c checks every field below.
//
// Agent <-> runtime, inside the guest, over pipes: the runtime reads INVOKE
// frames (forwarded as the host sent them) on fd 0, and writes READY, then
// RESULT and DONE frames (kind MVA_RETURNED) on fd 3. Its stdout (fd 1)
// and stderr (fd 2) are pipes to the agent: what it writes there during an
// invocation becomes that invocation's STDOUT / STDERR, the rest goes to
// the VM's console.
#pragma once

#include <stdint.h>

enum : uint32_t {
    MVA_MAGIC = 0x4641564du, // "MVAF"
    MVA_VERSION = 1,
    MVA_HDR = 16,
    MVA_PORT = 52, // the agent's vsock port in the guest

    // Limits. The host chooses per invocation the result and output caps
    // (up to these), and enforces them; the agent truncates to them.
    MVA_MAX_CHUNK = 64u << 10,    // body of a STDOUT / STDERR / RESULT frame
    MVA_MAX_PAYLOAD = 6u << 20,   // INVOKE payload
    MVA_MAX_RESULT = 6u << 20,    // RESULT bytes per invocation
    MVA_MAX_OUTPUT = 1u << 20,    // STDOUT, and STDERR, bytes per invocation
    MVA_MAX_STRINGS = 256,        // arguments and environment strings each
    MVA_MAX_STRING = 4096,        // bytes in one string (no NUL bytes)
    MVA_MAX_STRING_BYTES = 64u << 10, // all strings of one INVOKE together
    MVA_MAX_DEADLINE_MS = 15 * 60 * 1000,
    MVA_INVOKE_FIXED = 20,
    MVA_MAX_INVOKE = MVA_INVOKE_FIXED + 2 * MVA_MAX_STRINGS * 4 + MVA_MAX_STRING_BYTES + MVA_MAX_PAYLOAD,
};

enum mva_type : uint8_t {
    MVA_HELLO = 1,  // guest -> host, first frame of a connection; body 16
    MVA_STDOUT = 2, // guest -> host, data
    MVA_STDERR = 3, // guest -> host, data
    MVA_RESULT = 4, // guest -> host and runtime -> agent, data
    MVA_DONE = 5,   // guest -> host and runtime -> agent; body 16
    MVA_INVOKE = 0x10, // host -> guest -> runtime
    MVA_READY = 0x20,  // runtime -> agent, once: body 4 (u32 flags)
};

// HELLO body: u32 protocol (MVA_VERSION), u32 invocations this VM has
// already served (0 for a fresh restore), u32 0, u32 0.
//
// INVOKE body:
//   off 0  u32 deadline_ms  1..MVA_MAX_DEADLINE_MS, from when the agent
//                           has read this fixed part
//       4  u32 max_result   <= MVA_MAX_RESULT
//       8  u32 max_output   <= MVA_MAX_OUTPUT, for stdout and stderr each
//      12  u16 nargs        <= MVA_MAX_STRINGS
//      14  u16 nenv         <= MVA_MAX_STRINGS
//      16  u32 payload_len  <= MVA_MAX_PAYLOAD
//      20  nargs + nenv strings: u32 length, then that many bytes
//          then the payload; the body ends exactly there.
//
// DONE body: u32 kind, i32 status, u32 flags, u32 duration_us (as the
// agent measured it: INVOKE read to DONE). From the runtime: kind
// MVA_RETURNED and its status; flags and duration 0.
enum mva_kind : uint32_t {
    MVA_RETURNED = 0, // the runtime finished it: status is the runtime's
    MVA_EXITED = 1,   // the runtime exited: status is its exit code
    MVA_SIGNALED = 2, // the runtime was killed: status is the signal
    MVA_TIMEOUT = 3,  // past the deadline: the agent killed the runtime
    MVA_REFUSED = 4,  // a malformed INVOKE; the VM keeps serving
    MVA_FAULT = 5,    // the runtime broke the protocol: killed
    MVA_KIND_MAX = MVA_FAULT,
};

enum : uint32_t {
    MVA_DONE_TRUNC_RESULT = 1u << 0, // the agent dropped result bytes past max_result
    MVA_DONE_TRUNC_STDOUT = 1u << 1,
    MVA_DONE_TRUNC_STDERR = 1u << 2,
    MVA_DONE_VM_ENDS = 1u << 3, // the last frame: the VM is stopping
    MVA_DONE_FLAGS = 0xf,

    MVA_READY_SNAPSHOT = 1u << 0, // take the snapshot now (with --snapshot)
};
