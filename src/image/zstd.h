// SPDX-License-Identifier: MIT
// Zstandard (RFC 8878) decompression for image layers (`tar+zstd`), which
// are untrusted input. The interface is inflate.h's: input is pulled,
// output is peeked and consumed.
//
// Strict, as libzstd's decoder is:
// - every frame and block header field is checked: reserved bits, block
//   types, sizes against Block_Maximum_Size;
// - literals and their Huffman trees: weights, the implied last weight, and
//   each stream consumed exactly;
// - FSE tables: normalized counts must sum to the table size, and symbols
//   and accuracy logs stay within their limits;
// - sequences: the bitstream is consumed exactly, literal and match lengths
//   stay inside the block, and offsets stay inside both the window and the
//   output so far;
// - the frame content size and the XXH64 checksum, when present.
// Skippable frames are skipped, and concatenated frames are accepted.
// Frames that need a dictionary are refused, as is anything after the last
// frame.
//
// Bomb limits are inflate_limits' (a total output cap, and an
// output-to-input ratio cap with slack), plus:
// - a window cap, so a frame header can't make the decoder allocate more
//   than ZSTD_MAX_WINDOW;
// - a cap on Huffman and FSE table builds per byte of output, so tiny
//   blocks can't make it work hard for nothing.
#pragma once

#include "inflate.h"

// libzstd's default decoding limit (ZSTD_WINDOWLOG_LIMIT_DEFAULT, 2^27).
// zstd --long=31 output needs more and is refused.
constexpr uint64_t ZSTD_MAX_WINDOW = 128 * MiB;

typedef struct zstd_stream zstd_stream;

[[nodiscard]] zstd_stream *zstd_new(const inflate_limits *lim);
void zstd_free(zstd_stream *s);
// (Re)start decompressing an input from its beginning.
void zstd_start(zstd_stream *s, inflate_pull pull, void *ctx);
// The decompressed bytes not consumed yet: *n = 0 only at the end. Returns
// 0, or -1 (zstd_error() says why; errors are sticky).
[[nodiscard]] int zstd_peek(zstd_stream *s, const uint8_t **p, size_t *n);
void zstd_consume(zstd_stream *s, size_t n); // n <= what peek returned
// Copy out up to len bytes; *got < len only at the end.
[[nodiscard]] int zstd_read(zstd_stream *s, void *dst, size_t len, size_t *got);
const char *zstd_error(const zstd_stream *s);
uint64_t zstd_total_in(const zstd_stream *s);
uint64_t zstd_total_out(const zstd_stream *s);

// One shot, for tests and fuzzing: *out is malloc'ed (free it), even when
// empty. Returns 0 or -1 with *err set.
[[nodiscard]] int zstd_mem(const void *in, size_t inlen, const inflate_limits *lim, uint8_t **out,
                           size_t *outlen, const char **err);

// XXH64 (the frame checksum's hash), exposed for tests.
uint64_t zstd_xxh64(const void *p, size_t n, uint64_t seed);
