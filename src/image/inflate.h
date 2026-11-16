// SPDX-License-Identifier: MIT
// DEFLATE (RFC 1951) and gzip (RFC 1952) decompression for image layers,
// which are untrusted input.
//
// Strict: every block type is validated as zlib does (stored LEN/NLEN,
// over-subscribed or incomplete Huffman codes, a missing end-of-block code,
// symbols 286/287 and distances 30/31, repeats with nothing to repeat or
// past the end, distances before the start of the stream), and gzip headers
// (reserved flags, the header CRC) and trailers (CRC-32 and size of every
// member) are checked. Concatenated gzip members are accepted; anything
// else after the last member is an error.
//
// Bomb limits: a cap on the total output, a cap on the ratio of output to
// input (with some slack for small inputs), and a cap on Huffman blocks
// that produce almost nothing (each one costs a table build).
#pragma once

#include "../common.h"

typedef struct {
    uint64_t max_out;     // total decompressed bytes; 0: no cap
    uint32_t max_ratio;   // output <= max_ratio * input + ratio_slack; 0: no cap
    uint64_t ratio_slack;
} inflate_limits;

typedef enum { INFLATE_RAW, INFLATE_GZIP } inflate_format;

// Compressed input, pulled as needed: up to cap bytes into buf, *got = 0 at
// the end. Returns 0, or -1 on a read error.
typedef int (*inflate_pull)(void *ctx, uint8_t *buf, size_t cap, size_t *got);

typedef struct inflate_stream inflate_stream;

[[nodiscard]] inflate_stream *inflate_new(inflate_format fmt, const inflate_limits *lim);
void inflate_free(inflate_stream *s);
// (Re)start decompressing an input from its beginning.
void inflate_start(inflate_stream *s, inflate_pull pull, void *ctx);
// The decompressed bytes not consumed yet: *n = 0 only at the end of the
// stream. Returns 0, or -1 (inflate_error() says why; errors are sticky).
[[nodiscard]] int inflate_peek(inflate_stream *s, const uint8_t **p, size_t *n);
void inflate_consume(inflate_stream *s, size_t n); // n <= what peek returned
// Copy out up to len bytes; *got < len only at the end of the stream.
[[nodiscard]] int inflate_read(inflate_stream *s, void *dst, size_t len, size_t *got);
const char *inflate_error(const inflate_stream *s);
uint64_t inflate_total_in(const inflate_stream *s);  // compressed bytes pulled
uint64_t inflate_total_out(const inflate_stream *s); // decompressed bytes produced

// One shot, for tests and fuzzing: *out is malloc'ed (free it), even when
// empty. Returns 0 or -1 with *err set.
[[nodiscard]] int inflate_mem(inflate_format fmt, const void *in, size_t inlen,
                              const inflate_limits *lim, uint8_t **out, size_t *outlen,
                              const char **err);

uint32_t crc32_update(uint32_t crc, const void *data, size_t len); // crc32_update(0, ...) to start
