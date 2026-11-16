// SPDX-License-Identifier: MIT
// Strict JSON parser (see json.h): recursive descent, bounded depth. Values
// are built on a scratch stack and copied, once complete, into arena chunks
// owned by the document, so every array's or object's members are one
// contiguous block.
#include "json.h"

#include <stdlib.h>

typedef struct chunk chunk;
struct chunk {
    chunk *next;
    size_t used, cap;
    alignas(16) uint8_t data[];
};

struct json_doc {
    chunk *chunks;
    json_value root;
};

typedef struct {
    const uint8_t *p, *end;
    json_doc *doc;
    json_limits lim;
    unsigned depth;
    size_t values;
    json_value *stack; // members of the arrays/objects being parsed
    size_t sn, scap;
    const char *err;
} parser;

static void *arena(json_doc *d, size_t n)
{
    n = (n + 15) & ~(size_t)15;
    chunk *c = d->chunks;
    if (!c || c->cap - c->used < n) {
        const size_t cap = n > 60 * 1024 ? n : 60 * 1024;
        c = malloc(sizeof *c + cap);
        if (!c)
            return nullptr;
        c->cap = cap;
        c->used = 0;
        c->next = d->chunks;
        d->chunks = c;
    }
    void *r = c->data + c->used;
    c->used += n;
    return r;
}

static bool err(parser *ps, const char *why)
{
    if (!ps->err)
        ps->err = why;
    return false;
}

static void ws(parser *ps)
{
    while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r'))
        ps->p++;
}

static bool lit(parser *ps, const char *word, json_type t, json_value *v)
{
    const size_t n = strlen(word);
    if ((size_t)(ps->end - ps->p) < n || memcmp(ps->p, word, n))
        return err(ps, "an invalid literal");
    ps->p += n;
    v->type = t;
    return true;
}

static int hex4(const uint8_t *p)
{
    int v = 0;
    for (int i = 0; i < 4; i++) {
        const uint8_t c = p[i];
        int d;
        if (c >= '0' && c <= '9')
            d = c - '0';
        else if (c >= 'a' && c <= 'f')
            d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            d = c - 'A' + 10;
        else
            return -1;
        v = v << 4 | d;
    }
    return v;
}

// Length of the valid UTF-8 sequence at p (Unicode scalar values only), or 0.
static size_t utf8_len(const uint8_t *p, const uint8_t *end)
{
    const uint8_t c = p[0];
    size_t n;
    uint32_t cp;
    if (c < 0x80)
        return 1;
    if (c >= 0xc2 && c <= 0xdf)
        n = 2, cp = c & 0x1f;
    else if (c >= 0xe0 && c <= 0xef)
        n = 3, cp = c & 0x0f;
    else if (c >= 0xf0 && c <= 0xf4)
        n = 4, cp = c & 0x07;
    else
        return 0;
    if ((size_t)(end - p) < n)
        return 0;
    for (size_t i = 1; i < n; i++) {
        if ((p[i] & 0xc0) != 0x80)
            return 0;
        cp = cp << 6 | (p[i] & 0x3f);
    }
    if ((n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10ffff)) ||
        (cp >= 0xd800 && cp <= 0xdfff))
        return 0; // overlong, out of range, or a surrogate
    return n;
}

static size_t put_utf8(char *o, uint32_t cp)
{
    if (cp < 0x80) {
        o[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        o[0] = (char)(0xc0 | cp >> 6);
        o[1] = (char)(0x80 | (cp & 0x3f));
        return 2;
    }
    if (cp < 0x10000) {
        o[0] = (char)(0xe0 | cp >> 12);
        o[1] = (char)(0x80 | ((cp >> 6) & 0x3f));
        o[2] = (char)(0x80 | (cp & 0x3f));
        return 3;
    }
    o[0] = (char)(0xf0 | cp >> 18);
    o[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
    o[2] = (char)(0x80 | ((cp >> 6) & 0x3f));
    o[3] = (char)(0x80 | (cp & 0x3f));
    return 4;
}

// At the opening quote. Decodes into the arena (never longer than the text).
static bool string(parser *ps, const char **out, uint32_t *outlen)
{
    const uint8_t *s = ++ps->p, *q = s;
    while (q < ps->end && *q != '"') {
        if (*q == '\\' && ps->end - q < 2)
            break;
        q += *q == '\\' ? 2 : 1;
    }
    if (q >= ps->end || *q != '"')
        return err(ps, "an unterminated string");
    if ((size_t)(q - s) > UINT32_MAX - 1)
        return err(ps, "an over-long string");
    char *o = arena(ps->doc, (size_t)(q - s) + 1);
    if (!o)
        return err(ps, "out of memory");
    size_t n = 0;
    const uint8_t *p = s;
    while (p < q) {
        const uint8_t c = *p;
        if (c < 0x20)
            return err(ps, "a control character in a string");
        if (c != '\\') {
            const size_t l = utf8_len(p, q);
            if (!l)
                return err(ps, "invalid UTF-8 in a string");
            memcpy(o + n, p, l);
            n += l, p += l;
            continue;
        }
        const uint8_t e = p[1]; // p + 1 < q: the scan above skipped it
        p += 2;
        switch (e) {
        case '"': o[n++] = '"'; break;
        case '\\': o[n++] = '\\'; break;
        case '/': o[n++] = '/'; break;
        case 'b': o[n++] = '\b'; break;
        case 'f': o[n++] = '\f'; break;
        case 'n': o[n++] = '\n'; break;
        case 'r': o[n++] = '\r'; break;
        case 't': o[n++] = '\t'; break;
        case 'u': {
            int u = q - p >= 4 ? hex4(p) : -1;
            if (u < 0)
                return err(ps, "an invalid \\u escape");
            p += 4;
            uint32_t cp = (uint32_t)u;
            if (cp >= 0xdc00 && cp <= 0xdfff)
                return err(ps, "a lone low surrogate");
            if (cp >= 0xd800 && cp <= 0xdbff) {
                const int lo = q - p >= 6 && p[0] == '\\' && p[1] == 'u' ? hex4(p + 2) : -1;
                if (lo < 0xdc00 || lo > 0xdfff)
                    return err(ps, "a lone high surrogate");
                p += 6;
                cp = 0x10000 + ((cp - 0xd800) << 10) + ((uint32_t)lo - 0xdc00);
            }
            n += put_utf8(o + n, cp);
            break;
        }
        default:
            return err(ps, "an invalid escape");
        }
    }
    o[n] = 0;
    ps->p = q + 1;
    *out = o;
    *outlen = (uint32_t)n;
    return true;
}

static bool digits(parser *ps)
{
    const uint8_t *s = ps->p;
    while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9')
        ps->p++;
    return ps->p > s;
}

static bool number(parser *ps, json_value *v)
{
    const uint8_t *s = ps->p;
    if (ps->p < ps->end && *ps->p == '-')
        ps->p++;
    if (ps->p < ps->end && *ps->p == '0')
        ps->p++;
    else if (!digits(ps))
        return err(ps, "an invalid number");
    if (ps->p < ps->end && *ps->p == '.') {
        ps->p++;
        if (!digits(ps))
            return err(ps, "an invalid number");
    }
    if (ps->p < ps->end && (*ps->p == 'e' || *ps->p == 'E')) {
        ps->p++;
        if (ps->p < ps->end && (*ps->p == '+' || *ps->p == '-'))
            ps->p++;
        if (!digits(ps))
            return err(ps, "an invalid number");
    }
    const size_t n = (size_t)(ps->p - s);
    char *o = arena(ps->doc, n + 1);
    if (!o)
        return err(ps, "out of memory");
    memcpy(o, s, n);
    o[n] = 0;
    v->type = JSON_NUMBER;
    v->str = o;
    v->len = (uint32_t)n;
    return true;
}

static bool push(parser *ps, const json_value *v)
{
    if (ps->sn == ps->scap) {
        const size_t c = ps->scap ? ps->scap * 2 : 64;
        json_value *ns = realloc(ps->stack, c * sizeof *ns);
        if (!ns)
            return err(ps, "out of memory");
        ps->stack = ns;
        ps->scap = c;
    }
    ps->stack[ps->sn++] = *v;
    return true;
}

static int key_cmp(const void *a, const void *b)
{
    const json_value *x = *(const json_value *const *)a, *y = *(const json_value *const *)b;
    const uint32_t n = x->klen < y->klen ? x->klen : y->klen;
    const int c = memcmp(x->key, y->key, n);
    return c ? c : (x->klen > y->klen) - (x->klen < y->klen);
}

static bool value(parser *ps, json_value *v);

// The members since `base` on the stack become v's kids.
static bool finish(parser *ps, json_value *v, size_t base, json_type t)
{
    const size_t n = ps->sn - base;
    json_value *kids = n ? arena(ps->doc, n * sizeof *kids) : nullptr;
    if (n && !kids)
        return err(ps, "out of memory");
    if (n)
        memcpy(kids, ps->stack + base, n * sizeof *kids);
    ps->sn = base;
    v->type = t;
    v->len = (uint32_t)n;
    v->kids = kids;
    if (t == JSON_OBJECT && n > 1) {
        const json_value **byk = malloc(n * sizeof *byk);
        if (!byk)
            return err(ps, "out of memory");
        for (size_t i = 0; i < n; i++)
            byk[i] = &kids[i];
        qsort(byk, n, sizeof *byk, key_cmp);
        bool dup = false;
        for (size_t i = 1; i < n && !dup; i++)
            dup = !key_cmp(&byk[i - 1], &byk[i]);
        free(byk);
        if (dup)
            return err(ps, "a duplicate key in an object");
    }
    return true;
}

static bool container(parser *ps, json_value *v, bool obj)
{
    if (++ps->depth > ps->lim.max_depth)
        return err(ps, "nested too deeply");
    ps->p++;
    const size_t base = ps->sn;
    const uint8_t closer = obj ? '}' : ']';
    ws(ps);
    if (ps->p < ps->end && *ps->p == closer) {
        ps->p++;
    } else {
        for (;;) {
            json_value m = {0};
            ws(ps);
            if (obj) {
                if (ps->p >= ps->end || *ps->p != '"')
                    return err(ps, "expected a key");
                if (!string(ps, &m.key, &m.klen))
                    return false;
                ws(ps);
                if (ps->p >= ps->end || *ps->p != ':')
                    return err(ps, "expected ':'");
                ps->p++;
            }
            const char *k = m.key;
            const uint32_t kl = m.klen;
            if (!value(ps, &m))
                return false;
            m.key = k, m.klen = kl;
            if (!push(ps, &m))
                return false;
            ws(ps);
            if (ps->p < ps->end && *ps->p == ',') {
                ps->p++;
                continue;
            }
            if (ps->p < ps->end && *ps->p == closer) {
                ps->p++;
                break;
            }
            return err(ps, obj ? "expected ',' or '}'" : "expected ',' or ']'");
        }
    }
    ps->depth--;
    return finish(ps, v, base, obj ? JSON_OBJECT : JSON_ARRAY);
}

static bool value(parser *ps, json_value *v)
{
    if (++ps->values > ps->lim.max_values)
        return err(ps, "too many values");
    ws(ps);
    if (ps->p >= ps->end)
        return err(ps, "expected a value");
    *v = (json_value){0};
    switch (*ps->p) {
    case '{': return container(ps, v, true);
    case '[': return container(ps, v, false);
    case '"':
        v->type = JSON_STRING;
        return string(ps, &v->str, &v->len);
    case 't': return lit(ps, "true", JSON_TRUE, v);
    case 'f': return lit(ps, "false", JSON_FALSE, v);
    case 'n': return lit(ps, "null", JSON_NULL, v);
    default:
        if (*ps->p == '-' || (*ps->p >= '0' && *ps->p <= '9'))
            return number(ps, v);
        return err(ps, "expected a value");
    }
}

void json_free(json_doc *d)
{
    if (!d)
        return;
    for (chunk *c = d->chunks, *n; c; c = n) {
        n = c->next;
        free(c);
    }
    free(d);
}

json_doc *json_parse(const void *text, size_t len, const json_limits *lim, const char **errp)
{
    parser ps = {.p = text, .end = (const uint8_t *)text + len,
                 .lim = lim ? *lim : JSON_DEFAULT_LIMITS};
    if (len > ps.lim.max_size) {
        *errp = "the document is too big";
        return nullptr;
    }
    if (!(ps.doc = calloc(1, sizeof *ps.doc))) {
        *errp = "out of memory";
        return nullptr;
    }
    bool ok = value(&ps, &ps.doc->root);
    if (ok) {
        ws(&ps);
        if (ps.p != ps.end)
            ok = err(&ps, "data after the document");
    }
    free(ps.stack);
    if (!ok) {
        *errp = ps.err ? ps.err : "invalid JSON";
        json_free(ps.doc);
        return nullptr;
    }
    return ps.doc;
}

const json_value *json_root(const json_doc *d) { return &d->root; }

const json_value *json_get(const json_value *obj, const char *key)
{
    if (!obj || obj->type != JSON_OBJECT)
        return nullptr;
    const size_t kl = strlen(key);
    for (uint32_t i = 0; i < obj->len; i++)
        if (obj->kids[i].klen == kl && !memcmp(obj->kids[i].key, key, kl))
            return &obj->kids[i];
    return nullptr;
}

const char *json_cstr(const json_value *v)
{
    if (!v || v->type != JSON_STRING || strlen(v->str) != v->len)
        return nullptr;
    return v->str;
}

bool json_u64(const json_value *v, uint64_t *out)
{
    if (!v || v->type != JSON_NUMBER)
        return false;
    uint64_t r = 0;
    for (uint32_t i = 0; i < v->len; i++) {
        const char c = v->str[i];
        if (c < '0' || c > '9' || ckd_mul(&r, r, 10) || ckd_add(&r, r, (uint64_t)(c - '0')))
            return false;
    }
    *out = r;
    return v->len > 0;
}
