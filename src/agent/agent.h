// SPDX-License-Identifier: MIT
// Host side of the function-invocation protocol (src/agent/proto.h):
// encode an INVOKE, parse what the guest sends back, and (POSIX) a client
// that drives one VM's agent through the VMM's vsock Unix socket.
//
//   mva_client c;
//   mva_connect(&c, "/run/vm-17/v.sock", 2000);   // waits for the VM
//   mva_response rs = {};
//   mva_invoke(&c, &(mva_request){.deadline_ms = 1000, ...}, &rs, 500);
//   ... rs.result, rs.out, rs.err, rs.kind, rs.status ...
//   mva_response_free(&rs);
//   mva_close(&c);
//
// Everything the guest sends is hostile: the parser checks every header
// and body field, holds each invocation to the caps the host chose, and
// any violation ends the connection for good (the host should then kill
// the VM).
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "proto.h"

typedef struct {
    uint8_t *data;
    size_t len, cap;
} mva_buf;

typedef struct {
    mva_buf result, out, err;
    uint32_t kind; // enum mva_kind
    int32_t status;
    uint32_t flags; // MVA_DONE_*
    uint32_t duration_us;
    bool done; // a DONE arrived: the fields above are final
} mva_response;

typedef struct {
    uint32_t deadline_ms;
    uint32_t max_result, max_output; // 0: the protocol's maximum
    const char *const *argv;
    size_t nargs;
    const char *const *envp;
    size_t nenv;
    const void *payload;
    size_t payload_len;
} mva_request;

// ---- encoding and parsing (portable) ------------------------------------------

// The INVOKE frame for rq as invocation `id`, in a malloc'd buffer. nullptr
// if rq breaks a protocol limit (a string with a NUL byte, too many, too
// long...) or on allocation failure.
uint8_t *mva_encode_invoke(const mva_request *rq, uint32_t id, size_t *len);

typedef struct {
    uint8_t hdr[MVA_HDR];
    uint8_t small[16]; // a HELLO or DONE body
    uint32_t have;     // bytes of hdr (or of small, in such a body)
    bool in_body;
    uint8_t type;
    uint32_t body, got; // the current frame's body length, bytes seen
    bool hello, inflight;
    uint32_t id, max_result, max_output;
    uint32_t served; // from HELLO
    const char *error; // set once; sticky
} mva_parser;

void mva_parser_init(mva_parser *p);
// The host has sent INVOKE `id` with these caps: expect its frames.
void mva_parser_expect(mva_parser *p, uint32_t id, uint32_t max_result, uint32_t max_output);
// Parse `n` bytes from the guest into rs. Returns the bytes consumed. It
// stops early after a DONE (rs->done; the invocation is over and any more
// bytes are a protocol error until the next expect) or on an error
// (p->error).
size_t mva_parse(mva_parser *p, const uint8_t *buf, size_t n, mva_response *rs);

void mva_response_free(mva_response *rs);

// ---- the client (POSIX) -------------------------------------------------------

typedef struct {
    int fd;
    mva_parser p;
    uint32_t next_id;
    bool dead; // the VM ended or broke the protocol: no more invocations
    const char *error;
    size_t blen; // bytes in buf not parsed yet
    uint8_t buf[64 << 10];
} mva_client;

// Connect to the agent through the VMM's vsock socket at uds_path,
// retrying until timeout_ms has passed (the VMM and the agent may still be
// starting). 0, or -1 with c->error set.
int mva_connect(mva_client *c, const char *uds_path, int timeout_ms);
// Wait for the agent's HELLO (mva_invoke doesn't need it first).
int mva_hello(mva_client *c, int timeout_ms);
// One invocation: send it, collect everything until DONE. Waits at most
// the deadline plus grace_ms. 0 with rs complete (rs->kind etc.), or -1
// with c->error set: the VM should be killed. Either way, c->dead tells
// whether the VM can take another invocation.
int mva_invoke(mva_client *c, const mva_request *rq, mva_response *rs, int grace_ms);
void mva_close(mva_client *c);
