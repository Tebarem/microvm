// SPDX-License-Identifier: MIT
// A strict, small JSON (RFC 8259) parser for image manifests, indexes and
// configs, which are untrusted input.
//
// Strict: one value and nothing but whitespace after it; no BOM, comments,
// trailing commas, NaN, leading zeros or bare control characters; strings
// must be valid UTF-8 and escapes valid (no lone surrogates). Duplicate
// keys are rejected in every object, so no two readers of one document can
// disagree about what it says. Bounded: input size, nesting depth and the
// number of values all have caps, checked before anything is allocated
// for them.
#pragma once

#include "../common.h"

typedef enum : uint8_t {
    JSON_NULL,
    JSON_FALSE,
    JSON_TRUE,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT,
} json_type;

typedef struct json_value json_value;
struct json_value {
    json_type type;
    uint32_t len;           // string, number: bytes; array, object: members
    const char *str;        // string: decoded, NUL-terminated (a \u0000 is in len); number: its text
    const char *key;        // a member of an object: its key (decoded, NUL-terminated)
    uint32_t klen;
    const json_value *kids; // array, object: len values, in document order
};

typedef struct {
    size_t max_size;    // bytes of input
    unsigned max_depth; // nested arrays/objects
    size_t max_values;
} json_limits;

constexpr json_limits JSON_DEFAULT_LIMITS = {4 * 1024 * 1024, 64, 1u << 20};

typedef struct json_doc json_doc;

// Returns the document (json_free() it), or nullptr with *err set.
[[nodiscard]] json_doc *json_parse(const void *text, size_t len, const json_limits *lim,
                                   const char **err);
void json_free(json_doc *d);
const json_value *json_root(const json_doc *d);

// obj's member `key`, or nullptr (also when obj isn't an object).
const json_value *json_get(const json_value *obj, const char *key);
// A string without NUL bytes: its text, or nullptr.
const char *json_cstr(const json_value *v);
// A non-negative integer (no sign, fraction or exponent) that fits.
bool json_u64(const json_value *v, uint64_t *out);
