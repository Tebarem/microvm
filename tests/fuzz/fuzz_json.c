// SPDX-License-Identifier: MIT
// Fuzz the JSON parser: manifests, indexes and configs are untrusted.
//
// Invariants on every accepted document: printed back out canonically, it
// parses again to the same canonical text; every object's keys are unique;
// strings without NULs are what json_cstr() returns; depth stays capped.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"
#include "image/json.h"

typedef struct {
    char *p;
    size_t n, cap;
} out;

static void put(out *o, const void *s, size_t n)
{
    if (o->n + n + 1 > o->cap) {
        size_t c = o->cap ? o->cap : 256;
        while (c < o->n + n + 1)
            c *= 2;
        if (!(o->p = realloc(o->p, c)))
            abort();
        o->cap = c;
    }
    memcpy(o->p + o->n, s, n);
    o->n += n;
    o->p[o->n] = 0;
}

static void put_str(out *o, const char *s, size_t n)
{
    put(o, "\"", 1);
    for (size_t i = 0; i < n; i++) {
        const unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            put(o, "\\", 1);
            put(o, &s[i], 1);
        } else if (c < 0x20) {
            char e[8];
            snprintf(e, sizeof e, "\\u%04x", c);
            put(o, e, 6);
        } else {
            put(o, &s[i], 1);
        }
    }
    put(o, "\"", 1);
}

static void print(out *o, const json_value *v, unsigned depth)
{
    FUZZ_ASSERT(depth <= JSON_DEFAULT_LIMITS.max_depth);
    switch (v->type) {
    case JSON_NULL: put(o, "null", 4); break;
    case JSON_TRUE: put(o, "true", 4); break;
    case JSON_FALSE: put(o, "false", 5); break;
    case JSON_NUMBER: put(o, v->str, v->len); break;
    case JSON_STRING:
        FUZZ_ASSERT((json_cstr(v) != nullptr) == (strlen(v->str) == v->len));
        put_str(o, v->str, v->len);
        break;
    case JSON_ARRAY:
    case JSON_OBJECT:
        put(o, v->type == JSON_ARRAY ? "[" : "{", 1);
        for (uint32_t i = 0; i < v->len; i++) {
            if (i)
                put(o, ",", 1);
            if (v->type == JSON_OBJECT) {
                for (uint32_t j = 0; j < i; j++) // keys are unique
                    FUZZ_ASSERT(v->kids[j].klen != v->kids[i].klen ||
                                memcmp(v->kids[j].key, v->kids[i].key, v->kids[i].klen));
                put_str(o, v->kids[i].key, v->kids[i].klen);
                put(o, ":", 1);
                if (strlen(v->kids[i].key) == v->kids[i].klen) {
                    char k[64];
                    if (v->kids[i].klen < sizeof k) { // lookup by key finds it
                        memcpy(k, v->kids[i].key, v->kids[i].klen + 1);
                        FUZZ_ASSERT(json_get(v, k) == &v->kids[i]);
                    }
                }
            }
            print(o, &v->kids[i], depth + 1);
        }
        put(o, v->type == JSON_ARRAY ? "]" : "}", 1);
        break;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const char *err = nullptr;
    json_doc *d = json_parse(data, size, nullptr, &err);
    if (!d) {
        FUZZ_ASSERT(err != nullptr);
        return 0;
    }
    out a = {0}, b = {0};
    print(&a, json_root(d), 0);
    json_doc *d2 = json_parse(a.p, a.n, nullptr, &err);
    FUZZ_ASSERT(d2 != nullptr);
    print(&b, json_root(d2), 0);
    FUZZ_ASSERT(a.n == b.n && !memcmp(a.p, b.p, a.n));
    json_free(d);
    json_free(d2);
    free(a.p);
    free(b.p);
    return 0;
}

static const char *const docs[] = {
    "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":"
    "[{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"size\":528,"
    "\"platform\":{\"architecture\":\"amd64\",\"os\":\"linux\"},\"annotations\":"
    "{\"org.opencontainers.image.ref.name\":\"latest\"}}]}",
    "{\"architecture\":\"amd64\",\"os\":\"linux\",\"config\":{\"User\":\"1000:1000\",\"Env\":"
    "[\"PATH=/usr/local/sbin:/usr/local/bin\",\"LANG=C.UTF-8\"],\"Entrypoint\":null,\"Cmd\":"
    "[\"/bin/sh\",\"-c\",\"echo \\\"hi\\\"\\n\"],\"WorkingDir\":\"/\"},\"rootfs\":{\"type\":"
    "\"layers\",\"diff_ids\":[]},\"history\":[{\"created\":\"2024-01-01T00:00:00Z\"}]}",
    "[1, -0.5e10, 1E+2, true, false, null, \"\\u00e9\\ud83d\\ude00\\/\\b\\f\\r\\t\", {}, [], [[{}]]]",
    "{\"a\":{\"a\":{\"a\":\"\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80\"}},\"b\":\"\\u0000\"}",
};
static fuzz_seed seeds[MVM_ARRAY_LEN(docs)];

const fuzz_seed *fuzz_seeds(size_t *n)
{
    for (size_t i = 0; i < MVM_ARRAY_LEN(docs); i++)
        seeds[i] = (fuzz_seed){(const uint8_t *)docs[i], strlen(docs[i])};
    *n = MVM_ARRAY_LEN(docs);
    return seeds;
}
