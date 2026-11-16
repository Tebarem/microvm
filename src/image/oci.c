// SPDX-License-Identifier: MIT
// OCI image layouts and docker-archives to an fs_tree (see oci.h).
#include "oci.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "inflate.h"
#include "json.h"
#include "sha256.h"
#include "zstd.h"

enum {
    MAX_LAYERS = 512,
    MAX_NEST = 4,          // indexes inside indexes
    MAX_STARTS = 64,       // decompression restarts of one layer
    MAX_ETC = 1 << 20,     // /etc/passwd, /etc/group
    MAX_GROUPS = 32,
    MAX_JSON = 4 << 20,    // index, manifest
    MAX_CONFIG = 16 << 20, // image config
};

typedef enum { C_ANY, C_TAR, C_GZIP, C_ZSTD } comp;

typedef struct layer {
    oci_image *im;
    fs_source raw;  // the blob: compressed or not
    comp c;
    uint64_t usize; // decompressed size (checked before use)
    uint64_t pos, rawpos;
    unsigned starts;
    size_t index;
} layer;

struct oci_image {
    oci_opts o;
    // Decompressors, shared by the layers that need them: layers are read
    // one at a time, and z_owner is the one whose stream is current.
    inflate_stream *z;
    zstd_stream *zs;
    layer *z_owner;
    layer **layers;
    size_t nlayers;
    uint64_t used;
    json_doc *config;  // the image config, until it is serialized
    char cfg_digest[72], man_digest[72]; // "sha256:<hex>"
    char (*add_digest)[72];              // of each o.add layer's bytes
    uint8_t *cfg, *cfgtar;
    size_t cfglen, cfgtarlen;
    uint8_t *lower_cfg; // oci_build_on: the lower image's config file, or nullptr
    size_t lower_cfglen;
    struct mem {
        const uint8_t *p;
        size_t n;
    } cfgmem;
};

static char ebuf[512];

[[gnu::format(gnu_printf, 1, 2)]] static const char *ef(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(ebuf, sizeof ebuf, fmt, ap);
    va_end(ap);
    return ebuf;
}

static int fail(const char **err, const char *msg)
{
    *err = msg;
    return -1;
}

// ---- sources ----------------------------------------------------------------------
static int mem_read(void *ctx, void *buf, size_t len, uint64_t off)
{
    const struct mem *m = ctx;
    if (off > m->n || len > m->n - off)
        return -1;
    memcpy(buf, m->p + off, len);
    return 0;
}

static int read_all(const fs_source *s, size_t max, uint8_t **out)
{
    if (s->size > max)
        return -1;
    uint8_t *b = malloc((size_t)s->size + 1);
    if (!b || (s->size && s->read(s->ctx, b, (size_t)s->size, 0))) {
        free(b);
        return -1;
    }
    b[s->size] = 0;
    *out = b;
    return 0;
}

static int hash_source(const fs_source *s, uint8_t d[32])
{
    enum { CHUNK = 1 << 20 };
    uint8_t *b = malloc(CHUNK);
    if (!b)
        return -1;
    sha256_ctx h;
    sha256_init(&h);
    for (uint64_t off = 0; off < s->size;) {
        const size_t k = s->size - off < CHUNK ? (size_t)(s->size - off) : CHUNK;
        if (s->read(s->ctx, b, k, off)) {
            free(b);
            return -1;
        }
        sha256_update(&h, b, k);
        off += k;
    }
    free(b);
    sha256_final(&h, d);
    return 0;
}

static bool is_hex64(const char *s)
{
    for (int i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return s[64] == 0;
}

// "sha256:<64 lowercase hex>" -> the hex part.
static const char *digest_hex(const char *d, const char **err)
{
    if (!d)
        return *err = "a descriptor has no digest", nullptr;
    if (strncmp(d, "sha256:", 7)) {
        const char *colon = strchr(d, ':');
        *err = colon ? ef("unsupported digest algorithm '%.*s' (only sha256)", (int)(colon - d > 32 ? 32 : colon - d), d)
                     : "a malformed digest";
        return nullptr;
    }
    if (!is_hex64(d + 7))
        return *err = "a malformed sha256 digest", nullptr;
    return d + 7;
}

// ---- layers ---------------------------------------------------------------------
static int gz_pull(void *ctx, uint8_t *buf, size_t cap, size_t *got)
{
    layer *L = ctx;
    const uint64_t left = L->raw.size - L->rawpos;
    const size_t k = left < cap ? (size_t)left : cap;
    if (k && L->raw.read(L->raw.ctx, buf, k, L->rawpos))
        return -1;
    L->rawpos += k;
    *got = k;
    return 0;
}

static int gz_start(layer *L)
{
    if (++L->starts > MAX_STARTS)
        return -1;
    L->rawpos = 0;
    L->pos = 0;
    if (L->c == C_ZSTD)
        zstd_start(L->im->zs, gz_pull, L);
    else
        inflate_start(L->im->z, gz_pull, L);
    L->im->z_owner = L;
    return 0;
}

// The layer's decompressor (gzip or zstd), which share an interface.
static int dec_peek(layer *L, const uint8_t **p, size_t *n)
{
    return L->c == C_ZSTD ? zstd_peek(L->im->zs, p, n) : inflate_peek(L->im->z, p, n);
}

static void dec_consume(layer *L, size_t n)
{
    if (L->c == C_ZSTD)
        zstd_consume(L->im->zs, n);
    else
        inflate_consume(L->im->z, n);
}

static int dec_read(layer *L, void *buf, size_t len, size_t *got)
{
    return L->c == C_ZSTD ? zstd_read(L->im->zs, buf, len, got) : inflate_read(L->im->z, buf, len, got);
}

static const char *dec_error(const layer *L)
{
    return L->c == C_ZSTD ? zstd_error(L->im->zs) : inflate_error(L->im->z);
}

// fs_source.read for a compressed layer: forward only; reading backwards
// (or after another layer was read) starts the stream over.
static int gz_read(void *ctx, void *buf, size_t len, uint64_t off)
{
    layer *L = ctx;
    if (off > L->usize || len > L->usize - off)
        return -1;
    if ((L->im->z_owner != L || off < L->pos) && gz_start(L))
        return -1;
    while (L->pos < off) {
        const uint8_t *p;
        size_t n;
        if (dec_peek(L, &p, &n) || !n)
            return -1;
        if (n > off - L->pos)
            n = (size_t)(off - L->pos);
        dec_consume(L, n);
        L->pos += n;
    }
    size_t got;
    if (dec_read(L, buf, len, &got) || got != len)
        return -1;
    L->pos += len;
    return 0;
}

static comp sniff(const fs_source *raw)
{
    uint8_t m[4];
    if (raw->size >= 4 && !raw->read(raw->ctx, m, 4, 0)) {
        if (m[0] == 0x1f && m[1] == 0x8b)
            return C_GZIP;
        if (m[0] == 0x28 && m[1] == 0xb5 && m[2] == 0x2f && m[3] == 0xfd)
            return C_ZSTD;
    }
    return C_TAR;
}

static const char *comp_name(comp c)
{
    return c == C_GZIP ? "gzip" : c == C_ZSTD ? "zstd" : "uncompressed tar";
}

// One layer on top of the tree. raw_hex: the blob's verified digest, if
// known; diff_hex: what the uncompressed layer's digest must be, if known.
static int copy_owner(fs_tree *t, const char *owner, uint32_t *uid, uint32_t *gid, const char **err);

static int add_layer_as(oci_image *im, fs_tree *t, const fs_source *raw, comp hint, const char *raw_hex,
                        const char *diff_hex, const struct oci_copy *cp, const char **err);

static int add_layer(oci_image *im, fs_tree *t, const fs_source *raw, comp hint,
                     const char *raw_hex, const char *diff_hex, const char **err)
{
    return add_layer_as(im, t, raw, hint, raw_hex, diff_hex, nullptr, err);
}

// One layer on top of the tree, or (cp) a COPY from a tar of a build
// context's files.
static int add_layer_as(oci_image *im, fs_tree *t, const fs_source *raw, comp hint, const char *raw_hex,
                        const char *diff_hex, const struct oci_copy *cp, const char **err)
{
    const size_t idx = im->nlayers + 1;
    if (im->nlayers >= MAX_LAYERS)
        return fail(err, "too many layers");
    layer **ls = realloc(im->layers, (im->nlayers + 1) * sizeof *ls);
    if (!ls)
        return fail(err, "out of memory");
    im->layers = ls;
    layer *L = calloc(1, sizeof *L);
    if (!L)
        return fail(err, "out of memory");
    im->layers[im->nlayers++] = L;
    *L = (layer){.im = im, .raw = *raw, .index = idx};
    L->c = sniff(raw);
    if (hint != C_ANY && hint != L->c)
        return fail(err, ef("layer %zu: its media type says %s but it is %s", idx, comp_name(hint),
                            comp_name(L->c)));
    const uint64_t cap = im->o.max_bytes;
    fs_source src = *raw;
    if (L->c == C_TAR) {
        if (diff_hex) {
            char hex[65];
            if (raw_hex) {
                memcpy(hex, raw_hex, 65);
            } else {
                uint8_t d[32];
                if (hash_source(raw, d))
                    return fail(err, ef("layer %zu: cannot read it", idx));
                sha256_hex(d, hex);
            }
            if (strcmp(hex, diff_hex))
                return fail(err, ef("layer %zu: its digest is sha256:%s, but the config's diff_id "
                                    "says sha256:%s", idx, hex, diff_hex));
        }
        L->usize = raw->size;
    } else {
        const inflate_limits lim = {.max_out = cap, .max_ratio = im->o.max_ratio,
                                    .ratio_slack = 64 * MiB};
        if (L->c == C_ZSTD ? !im->zs && !(im->zs = zstd_new(&lim))
                           : !im->z && !(im->z = inflate_new(INFLATE_GZIP, &lim)))
            return fail(err, "out of memory");
        // Decompress it all once before anything parses it: the stream checks
        // out (CRCs or checksums, limits), and so does the diff_id.
        if (gz_start(L))
            return fail(err, "out of memory");
        sha256_ctx h;
        sha256_init(&h);
        uint64_t n = 0;
        for (;;) {
            const uint8_t *p;
            size_t k;
            if (dec_peek(L, &p, &k))
                return fail(err, ef("layer %zu: %s", idx, dec_error(L)));
            if (!k)
                break;
            n += k;
            if (n > cap - im->used)
                return fail(err, ef("layer %zu: the image's layers decompress to more than "
                                    "the cap (%llu bytes)", idx, (unsigned long long)cap));
            sha256_update(&h, p, k);
            dec_consume(L, k);
        }
        uint8_t d[32];
        char hex[65];
        sha256_final(&h, d);
        sha256_hex(d, hex);
        if (diff_hex && strcmp(hex, diff_hex))
            return fail(err, ef("layer %zu: it decompresses to sha256:%s, but the config's "
                                "diff_id says sha256:%s", idx, hex, diff_hex));
        L->usize = n;
        im->z_owner = nullptr;
        L->starts = 0;
        src = (fs_source){gz_read, L, n};
    }
    if (L->c == C_TAR && L->usize > cap - im->used)
        return fail(err, ef("layer %zu: the image's layers are bigger than the cap (%llu bytes)",
                            idx, (unsigned long long)cap));
    im->used += L->usize;
    if (cp) {
        fs_copy c = {.src = cp->src, .dest = cp->dest, .mode = cp->mode};
        if (cp->owner && *cp->owner) {
            if (copy_owner(t, cp->owner, &c.uid, &c.gid, err))
                return -1;
            c.chown = true;
        }
        if (fs_import_copy(t, &src, &c, err))
            return fail(err, ef("added layer %zu (COPY %s %s): %s", idx, cp->src, cp->dest, *err));
        return 0;
    }
    if (fs_import_tar(t, &src, err))
        return fail(err, ef("layer %zu: %s", idx, *err));
    return 0;
}

int oci_add_layer(oci_image *im, fs_tree *t, const fs_source *raw, const char **err)
{
    return add_layer(im, t, raw, C_ANY, nullptr, nullptr, err);
}

uint64_t oci_layer_bytes(const oci_image *im) { return im->used; }

// ---- blobs -------------------------------------------------------------------------
typedef struct {
    const char *media; // may be nullptr
    char hex[65];
    uint64_t size;
    const json_value *v;
} desc;

static int parse_desc(const json_value *v, desc *d, const char **err)
{
    if (!v || v->type != JSON_OBJECT)
        return fail(err, "a descriptor isn't an object");
    const json_value *mt = json_get(v, "mediaType");
    d->media = json_cstr(mt);
    if (mt && !d->media)
        return fail(err, "a descriptor's mediaType isn't a string");
    const char *hex = digest_hex(json_cstr(json_get(v, "digest")), err);
    if (!hex)
        return -1;
    memcpy(d->hex, hex, 65);
    if (!json_u64(json_get(v, "size"), &d->size))
        return fail(err, "a descriptor's size isn't a non-negative integer");
    d->v = v;
    return 0;
}

// A blob by digest, size and digest checked, parsed as JSON.
static json_doc *load_json(const oci_store *st, const desc *d, size_t max, const char *what,
                           const char **err)
{
    char path[96];
    snprintf(path, sizeof path, "blobs/sha256/%s", d->hex);
    fs_source s;
    if (st->open(st->ctx, path, &s))
        return *err = ef("the %s blob sha256:%s is missing", what, d->hex), nullptr;
    if (s.size != d->size)
        return *err = ef("the %s blob sha256:%s is %llu bytes, its descriptor says %llu", what,
                         d->hex, (unsigned long long)s.size, (unsigned long long)d->size), nullptr;
    if (d->size > max)
        return *err = ef("the %s blob is too big (%llu bytes)", what, (unsigned long long)d->size),
               nullptr;
    uint8_t *b;
    if (read_all(&s, max, &b))
        return *err = ef("cannot read the %s blob", what), nullptr;
    uint8_t dg[32];
    char hex[65];
    sha256(b, (size_t)s.size, dg);
    sha256_hex(dg, hex);
    if (strcmp(hex, d->hex)) {
        free(b);
        return *err = ef("the %s blob's digest is sha256:%s, not sha256:%s", what, hex, d->hex),
               nullptr;
    }
    json_limits lim = JSON_DEFAULT_LIMITS;
    lim.max_size = max;
    const char *jerr;
    json_doc *doc = json_parse(b, (size_t)s.size, &lim, &jerr);
    free(b);
    if (!doc)
        *err = ef("the %s: %s", what, jerr);
    return doc;
}

// A file by path (index.json, manifest.json...), parsed as JSON: no digest.
static json_doc *load_file(const oci_store *st, const char *path, const char **err)
{
    fs_source s;
    if (st->open(st->ctx, path, &s))
        return *err = ef("%s is missing", path), nullptr;
    uint8_t *b;
    if (read_all(&s, MAX_JSON, &b))
        return *err = ef("%s is too big or unreadable", path), nullptr;
    const char *jerr;
    json_doc *doc = json_parse(b, (size_t)s.size, nullptr, &jerr);
    free(b);
    if (!doc)
        *err = ef("%s: %s", path, jerr);
    return doc;
}

static bool media_is(const char *m, const char *const *set)
{
    for (; m && *set; set++)
        if (!strcmp(m, *set))
            return true;
    return false;
}

static const char *const INDEX_TYPES[] = {"application/vnd.oci.image.index.v1+json",
                                          "application/vnd.docker.distribution.manifest.list.v2+json",
                                          nullptr};
static const char *const MANIFEST_TYPES[] = {"application/vnd.oci.image.manifest.v1+json",
                                             "application/vnd.docker.distribution.manifest.v2+json",
                                             nullptr};
static const char *const CONFIG_TYPES[] = {"application/vnd.oci.image.config.v1+json",
                                           "application/vnd.docker.container.image.v1+json", nullptr};

static comp layer_comp(const char *m)
{
    static const char *const tar[] = {"application/vnd.oci.image.layer.v1.tar",
                                      "application/vnd.oci.image.layer.nondistributable.v1.tar",
                                      nullptr};
    static const char *const gz[] = {"application/vnd.oci.image.layer.v1.tar+gzip",
                                     "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
                                     "application/vnd.docker.image.rootfs.diff.tar.gzip",
                                     "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
                                     nullptr};
    static const char *const zst[] = {"application/vnd.oci.image.layer.v1.tar+zstd",
                                      "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
                                      "application/vnd.docker.image.rootfs.diff.tar.zstd",
                                      nullptr};
    if (media_is(m, tar))
        return C_TAR;
    if (media_is(m, gz))
        return C_GZIP;
    if (media_is(m, zst))
        return C_ZSTD;
    return C_ANY; // unknown
}

static bool str_eq(const json_value *v, const char *s)
{
    const char *c = json_cstr(v);
    return c && !strcmp(c, s);
}

// 1 if the descriptor's platform is linux/amd64, 0 if it is something else,
// -1 if it has none.
static int platform_match(const json_value *d)
{
    const json_value *p = json_get(d, "platform");
    if (!p)
        return -1;
    return str_eq(json_get(p, "os"), "linux") && str_eq(json_get(p, "architecture"), "amd64");
}

static bool ref_match(const json_value *d, const char *ref)
{
    const json_value *a = json_get(d, "annotations");
    return str_eq(json_get(a, "org.opencontainers.image.ref.name"), ref) ||
           str_eq(json_get(a, "io.containerd.image.name"), ref);
}

// From an index, the descriptor of the linux/amd64 image manifest.
static int pick_manifest(const oci_store *st, const json_value *index, int depth,
                         const char *ref, desc *out, const char **err)
{
    if (index->type != JSON_OBJECT)
        return fail(err, "an index isn't a JSON object");
    uint64_t sv;
    if (!json_u64(json_get(index, "schemaVersion"), &sv) || sv != 2)
        return fail(err, "an index's schemaVersion isn't 2");
    const json_value *ms = json_get(index, "manifests");
    if (!ms || ms->type != JSON_ARRAY)
        return fail(err, "an index has no manifests array");
    const json_value *best = nullptr, *unplatformed = nullptr;
    size_t nunplatformed = 0;
    for (uint32_t i = 0; i < ms->len; i++) {
        const json_value *d = &ms->kids[i];
        const char *mt = json_cstr(json_get(d, "mediaType"));
        if (!media_is(mt, INDEX_TYPES) && !media_is(mt, MANIFEST_TYPES))
            continue; // attestations, signatures, other artifacts
        if (ref && depth == 0 && !ref_match(d, ref))
            continue;
        const int pm = platform_match(d);
        if (pm == 1 && !best)
            best = d;
        if (pm == -1 && !nunplatformed++)
            unplatformed = d;
    }
    if (!best) {
        if (nunplatformed > 1)
            return fail(err, ref ? ef("several images are tagged '%s'", ref)
                                 : "the index holds several images; pick one with --ref");
        best = unplatformed;
    }
    if (!best)
        return fail(err, ref && depth == 0 ? ef("no linux/amd64 image is tagged '%s'", ref)
                                           : "the index has no linux/amd64 image");
    desc d;
    if (parse_desc(best, &d, err))
        return -1;
    if (media_is(d.media, MANIFEST_TYPES)) {
        *out = d;
        return 0;
    }
    if (depth + 1 >= MAX_NEST)
        return fail(err, "indexes are nested too deeply");
    json_doc *sub = load_json(st, &d, MAX_JSON, "index", err);
    if (!sub)
        return -1;
    const json_value *root = json_root(sub);
    const json_value *smt = json_get(root, "mediaType");
    int rc = smt && !str_eq(smt, d.media) ? fail(err, "an index's mediaType isn't its descriptor's")
                                          : pick_manifest(st, root, depth + 1, ref, out, err);
    if (rc == 0) // out->media points into sub: pin it to a static string
        for (const char *const *m = MANIFEST_TYPES; *m; m++)
            if (!strcmp(*m, out->media))
                out->media = *m;
    json_free(sub);
    return rc;
}

// ---- the image config ------------------------------------------------------------
typedef struct {
    uint8_t *p;
    size_t n, cap;
    bool oom;
} sbuf;

static void put(sbuf *b, const char *s)
{
    const size_t l = strlen(s) + 1;
    if (b->oom)
        return;
    if (b->n + l > b->cap) {
        size_t c = b->cap ? b->cap : 1024;
        while (c < b->n + l)
            c *= 2;
        uint8_t *np = realloc(b->p, c);
        if (!np) {
            b->oom = true;
            return;
        }
        b->p = np;
        b->cap = c;
    }
    memcpy(b->p + b->n, s, l);
    b->n += l;
}

static void put_kv(sbuf *b, const char *k, const char *v)
{
    put(b, k);
    put(b, v);
}

static void put_num(sbuf *b, const char *k, uint64_t v)
{
    char s[24];
    snprintf(s, sizeof s, "%llu", (unsigned long long)v);
    put_kv(b, k, s);
}

// The config's fields, from the image config (JSON) or from the lower
// image's serialized config (oci_build_on); the strings point into either.
typedef struct {
    const char **v;
    size_t n, cap;
} strv;

typedef struct {
    const char *cfg_digest, *man_digest; // nullptr: none
    strv added, ep, cmd, env;
    const char *workdir, *user;          // nullptr: none
    bool oom;
} cfg_fields;

static void strv_push(cfg_fields *f, strv *l, const char *x)
{
    if (f->oom)
        return;
    if (l->n == l->cap) {
        const size_t c = l->cap ? l->cap * 2 : 16;
        const char **nv = realloc(l->v, c * sizeof *nv);
        if (!nv) {
            f->oom = true;
            return;
        }
        l->v = nv;
        l->cap = c;
    }
    l->v[l->n++] = x;
}

static void fields_free(cfg_fields *f)
{
    free(f->added.v);
    free(f->ep.v);
    free(f->cmd.v);
    free(f->env.v);
}

// A string array (or null / absent): each element, NUL-free.
static int get_strv(cfg_fields *f, strv *l, const json_value *cfg, const char *field, const char **err)
{
    const json_value *v = json_get(cfg, field);
    if (!v || v->type == JSON_NULL)
        return 0;
    if (v->type != JSON_ARRAY)
        return fail(err, ef("the image config's %s isn't an array", field));
    for (uint32_t i = 0; i < v->len; i++) {
        const char *s = json_cstr(&v->kids[i]);
        if (!s)
            return fail(err, ef("the image config's %s holds a non-string (or a NUL byte)", field));
        strv_push(f, l, s);
    }
    return 0;
}

static int fields_from_json(const json_value *root, cfg_fields *f, const char **err)
{
    const json_value *c = json_get(root, "config");
    if (c && c->type != JSON_OBJECT && c->type != JSON_NULL)
        return fail(err, "the image config's config isn't an object");
    if (get_strv(f, &f->ep, c, "Entrypoint", err) || get_strv(f, &f->cmd, c, "Cmd", err) ||
        get_strv(f, &f->env, c, "Env", err))
        return -1;
    static const char *const strs[] = {"WorkingDir", "User"};
    for (size_t i = 0; i < MVM_ARRAY_LEN(strs); i++) {
        const json_value *v = json_get(c, strs[i]);
        const char *s = nullptr;
        if (v && v->type != JSON_NULL && !(s = json_cstr(v)))
            return fail(err, ef("the image config's %s isn't a string (or holds a NUL)", strs[i]));
        *(i ? &f->user : &f->workdir) = s;
    }
    return 0;
}

// oci_config_walk() callback: a lower image's serialized config. What
// the user resolves to (uid, gid, group) is worked out again, in the
// image as it is now.
static void lower_field(void *ctx, const char *k, const char *v)
{
    cfg_fields *f = ctx;
    if (!strcmp(k, "config-digest"))
        f->cfg_digest = v;
    else if (!strcmp(k, "manifest-digest"))
        f->man_digest = v;
    else if (!strcmp(k, "added-layer"))
        strv_push(f, &f->added, v);
    else if (!strcmp(k, "entrypoint"))
        strv_push(f, &f->ep, v);
    else if (!strcmp(k, "cmd"))
        strv_push(f, &f->cmd, v);
    else if (!strcmp(k, "env"))
        strv_push(f, &f->env, v);
    else if (!strcmp(k, "workdir"))
        f->workdir = v;
    else if (!strcmp(k, "user"))
        f->user = v;
}

static size_t env_name_len(const char *e)
{
    const char *eq = strchr(e, '=');
    return eq ? (size_t)(eq - e) : strlen(e);
}

// The image's Env, with the build's on top (oci_opts.env).
static void put_env(sbuf *b, const strv *img, const oci_opts *o)
{
    for (size_t i = 0; i < img->n; i++) {
        const char *s = img->v[i];
        const size_t nl = env_name_len(s);
        for (size_t k = o->nenv; k-- > 0;) // the last of the build's for this name
            if (env_name_len(o->env[k]) == nl && !memcmp(o->env[k], s, nl)) {
                s = o->env[k];
                break;
            }
        put_kv(b, "env", s);
    }
    for (size_t k = 0; k < o->nenv; k++) {
        const size_t nl = env_name_len(o->env[k]);
        bool seen = false;
        for (size_t i = 0; i < img->n && !seen; i++) // already put in the image's place
            seen = env_name_len(img->v[i]) == nl && !memcmp(img->v[i], o->env[k], nl);
        for (size_t l = k + 1; l < o->nenv && !seen; l++) // a later one of the build's wins
            seen = env_name_len(o->env[l]) == nl && !memcmp(o->env[l], o->env[k], nl);
        if (!seen)
            put_kv(b, "env", o->env[k]);
    }
}

static int read_text(fs_tree *t, const char *path, char **out)
{
    *out = nullptr;
    const fs_inode *ino = fs_lookup(t, path, true);
    if (!ino || (ino->mode & FS_IFMT) != FS_IFREG)
        return 0; // none
    if (ino->size > MAX_ETC)
        return -1;
    char *b = malloc((size_t)ino->size + 1);
    const fs_source *s = &t->src[ino->src];
    if (!b || (ino->size && s->read(s->ctx, b, (size_t)ino->size, ino->off))) {
        free(b);
        return -1;
    }
    b[ino->size] = 0;
    *out = b;
    return 0;
}

static bool parse_u32(const char *s, size_t n, uint32_t *v)
{
    uint64_t r = 0;
    if (!n || n > 10)
        return false;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return false;
        r = r * 10 + (uint64_t)(s[i] - '0');
    }
    if (r > UINT32_MAX)
        return false;
    *v = (uint32_t)r;
    return true;
}

// Field i (0-based) of a ':'-separated line [s, e).
static bool field(const char *s, const char *e, int i, const char **fs, size_t *fl)
{
    for (; i > 0; i--) {
        const char *c = memchr(s, ':', (size_t)(e - s));
        if (!c)
            return false;
        s = c + 1;
    }
    const char *c = memchr(s, ':', (size_t)(e - s));
    *fs = s;
    *fl = (size_t)((c ? c : e) - s);
    return true;
}

typedef bool (*line_fn)(void *ctx, const char *s, const char *e);

static void each_line(const char *text, line_fn fn, void *ctx)
{
    for (const char *p = text; p && *p;) {
        const char *nl = strchr(p, '\n');
        const char *e = nl ? nl : p + strlen(p);
        if (e > p && *p != '#' && fn(ctx, p, e))
            return;
        p = nl ? nl + 1 : nullptr;
    }
}

typedef struct {
    const char *name; // match by name, or
    uint32_t id;      // by id (name == nullptr)
    bool found;
    char found_name[256];
    uint32_t uid, gid;
} pw_q;

static bool pw_line(void *ctx, const char *s, const char *e)
{
    pw_q *q = ctx;
    const char *n, *u, *g;
    size_t nl, ul, gl;
    uint32_t uid, gid;
    if (!field(s, e, 0, &n, &nl) || !field(s, e, 2, &u, &ul) || !field(s, e, 3, &g, &gl) ||
        !parse_u32(u, ul, &uid) || !parse_u32(g, gl, &gid) || nl >= sizeof q->found_name)
        return false;
    if (q->name ? (strlen(q->name) == nl && !memcmp(q->name, n, nl)) : uid == q->id) {
        q->found = true;
        memcpy(q->found_name, n, nl);
        q->found_name[nl] = 0;
        q->uid = uid;
        q->gid = gid;
        return true;
    }
    return false;
}

typedef struct {
    const char *name; // group name to find, or
    const char *member; // user whose groups to collect
    bool found;
    uint32_t gid;
    uint32_t groups[MAX_GROUPS];
    size_t ngroups;
} gr_q;

static bool gr_line(void *ctx, const char *s, const char *e)
{
    gr_q *q = ctx;
    const char *n, *g, *m;
    size_t nl, gl, ml;
    uint32_t gid;
    if (!field(s, e, 0, &n, &nl) || !field(s, e, 2, &g, &gl) || !parse_u32(g, gl, &gid))
        return false;
    if (q->name) {
        if (strlen(q->name) == nl && !memcmp(q->name, n, nl)) {
            q->found = true;
            q->gid = gid;
            return true;
        }
        return false;
    }
    if (!field(s, e, 3, &m, &ml))
        return false;
    const size_t ul = strlen(q->member);
    for (const char *p = m, *end = m + ml; p < end;) {
        const char *c = memchr(p, ',', (size_t)(end - p));
        const char *ce = c ? c : end;
        if ((size_t)(ce - p) == ul && !memcmp(p, q->member, ul)) {
            bool dup = false;
            for (size_t i = 0; i < q->ngroups; i++)
                dup |= q->groups[i] == gid;
            if (!dup && q->ngroups < MAX_GROUPS)
                q->groups[q->ngroups++] = gid;
            break;
        }
        p = ce + 1;
    }
    return false;
}

// Docker's rules for User: "", "user", "uid", "user:group", "uid:gid" ...;
// names are looked up in the image's own /etc/passwd and /etc/group.
// what: the setting, for errors ("User"). b: where uid, gid and the
// supplementary groups go, or nullptr (then just *uid_out and *gid_out).
static int resolve_user(fs_tree *t, const char *user, sbuf *b, const char *what, uint32_t *uid_out,
                        uint32_t *gid_out, const char **err)
{
    if (!*user) {
        if (b) {
            put_num(b, "uid", 0);
            put_num(b, "gid", 0);
        }
        *uid_out = *gid_out = 0;
        return 0;
    }
    if (strlen(user) > 255)
        return fail(err, ef("the image's %s is too long", what));
    char *passwd, *group;
    if (read_text(t, "/etc/passwd", &passwd))
        return fail(err, "the image's /etc/passwd is too big or unreadable");
    if (read_text(t, "/etc/group", &group)) {
        free(passwd);
        return fail(err, "the image's /etc/group is too big or unreadable");
    }
    const char *colon = strchr(user, ':');
    char u[256], g[256] = "";
    const size_t ul = colon ? (size_t)(colon - user) : strlen(user);
    memcpy(u, user, ul);
    u[ul] = 0;
    if (colon)
        snprintf(g, sizeof g, "%s", colon + 1);
    int rc = -1;
    pw_q pq = {0};
    uint32_t uid, gid = 0;
    if (parse_u32(u, ul, &uid)) {
        pq.id = uid;
        each_line(passwd, pw_line, &pq);
        if (pq.found)
            gid = pq.gid;
    } else {
        pq.name = u;
        each_line(passwd, pw_line, &pq);
        if (!pq.found) {
            *err = ef("the image's %s '%s' isn't in its /etc/passwd", what, u);
            goto out;
        }
        uid = pq.uid;
        gid = pq.gid;
    }
    if (colon) {
        if (!parse_u32(g, strlen(g), &gid)) {
            gr_q gq = {.name = g};
            each_line(group, gr_line, &gq);
            if (!gq.found) {
                *err = ef("the image's %s group '%s' isn't in its /etc/group", what, g);
                goto out;
            }
            gid = gq.gid;
        }
    }
    *uid_out = uid;
    *gid_out = gid;
    if (!b) {
        rc = 0;
        goto out;
    }
    put_num(b, "uid", uid);
    put_num(b, "gid", gid);
    if (pq.found) { // supplementary groups: those that list the user
        gr_q gq = {.member = pq.found_name};
        each_line(group, gr_line, &gq);
        for (size_t i = 0; i < gq.ngroups; i++)
            if (gq.groups[i] != gid)
                put_num(b, "group", gq.groups[i]);
    }
    rc = 0;
out:
    free(passwd);
    free(group);
    return rc;
}

// COPY --chown's user[:group], in the image as it is so far.
static int copy_owner(fs_tree *t, const char *owner, uint32_t *uid, uint32_t *gid, const char **err)
{
    return resolve_user(t, owner, nullptr, "COPY --chown user", uid, gid, err);
}

static void oct(uint8_t *f, size_t w, uint64_t v)
{
    for (size_t i = w - 1; i-- > 0; v >>= 3)
        f[i] = (uint8_t)('0' + (v & 7));
    f[w - 1] = 0;
}

static void tar_hdr(uint8_t *h, const char *name, char type, unsigned mode, uint64_t size)
{
    memset(h, 0, 512);
    memcpy(h, name, strlen(name));
    oct(h + 100, 8, mode);
    oct(h + 108, 8, 0);
    oct(h + 116, 8, 0);
    oct(h + 124, 12, size);
    oct(h + 136, 12, 0);
    h[156] = (uint8_t)type;
    memcpy(h + 257, "ustar\0" "00", 8);
    memset(h + 148, ' ', 8);
    unsigned s = 0;
    for (int i = 0; i < 512; i++)
        s += h[i];
    oct(h + 148, 7, s);
}

// Serialize the config and add it to the tree as one more (top) layer.
static int write_config(oci_image *im, fs_tree *t, const char **err)
{
    cfg_fields f = {0};
    if (im->config) {
        if (fields_from_json(json_root(im->config), &f, err)) {
            fields_free(&f);
            return -1;
        }
        f.cfg_digest = im->cfg_digest;
        if (im->man_digest[0])
            f.man_digest = im->man_digest;
    } else if (im->lower_cfg && oci_config_walk(im->lower_cfg, im->lower_cfglen, lower_field, &f)) {
        fields_free(&f);
        return fail(err, "the lower image's " OCI_CONFIG_PATH " is malformed");
    }
    if (im->o.workdir)
        f.workdir = im->o.workdir;
    if (im->o.user)
        f.user = im->o.user;
    sbuf b = {0};
    put(&b, "microvm-image-config");
    put(&b, "1");
    if (f.cfg_digest)
        put_kv(&b, "config-digest", f.cfg_digest);
    if (f.man_digest)
        put_kv(&b, "manifest-digest", f.man_digest);
    for (size_t i = 0; i < f.added.n; i++)
        put_kv(&b, "added-layer", f.added.v[i]);
    for (size_t i = 0; i < im->o.nadd; i++)
        put_kv(&b, "added-layer", im->add_digest[i]);
    for (size_t i = 0; i < f.ep.n; i++)
        put_kv(&b, "entrypoint", f.ep.v[i]);
    for (size_t i = 0; i < f.cmd.n; i++)
        put_kv(&b, "cmd", f.cmd.v[i]);
    put_env(&b, &f.env, &im->o);
    if (f.workdir && *f.workdir)
        put_kv(&b, "workdir", f.workdir);
    const char *user = f.user ? f.user : "";
    if (*user)
        put_kv(&b, "user", user);
    uint32_t uid, gid;
    const bool oom = f.oom;
    const int rc = resolve_user(t, user, &b, "User", &uid, &gid, err);
    fields_free(&f);
    if (rc || b.oom || oom) {
        free(b.p);
        return rc ? -1 : fail(err, "out of memory");
    }
    im->cfg = b.p;
    im->cfglen = b.n;

    const size_t data = (b.n + 511) & ~(size_t)511;
    im->cfgtarlen = 512 + 512 + data + 1024;
    if (!(im->cfgtar = calloc(1, im->cfgtarlen)))
        return fail(err, "out of memory");
    tar_hdr(im->cfgtar, ".microvm/", '5', 0755, 0);
    tar_hdr(im->cfgtar + 512, ".microvm/image-config", '0', 0444, b.n);
    memcpy(im->cfgtar + 1024, b.p, b.n);
    im->cfgmem = (struct mem){im->cfgtar, im->cfgtarlen};
    const fs_source src = {mem_read, &im->cfgmem, im->cfgtarlen};
    if (fs_import_tar(t, &src, err))
        return fail(err, ef("adding the image config: %s", *err));
    return 0;
}

int oci_config_walk(const uint8_t *p, size_t n, void (*fn)(void *, const char *, const char *),
                    void *ctx)
{
    if (!n || p[n - 1] != 0)
        return -1;
    const char *s = (const char *)p, *end = s + n;
    if (strcmp(s, "microvm-image-config"))
        return -1;
    s += strlen(s) + 1;
    if (s >= end || strcmp(s, "1"))
        return -1;
    s += 2;
    while (s < end) {
        const char *k = s;
        s += strlen(s) + 1;
        if (s >= end)
            return -1;
        const char *v = s;
        s += strlen(s) + 1;
        fn(ctx, k, v);
    }
    return 0;
}

const uint8_t *oci_config(const oci_image *im, size_t *len)
{
    *len = im->cfglen;
    return im->cfg;
}

// Checks on the config every image needs; returns its diff_ids array.
static const json_value *check_config(const json_value *root, size_t nlayers, const char **err)
{
    if (root->type != JSON_OBJECT)
        return *err = "the image config isn't a JSON object", nullptr;
    const char *os = json_cstr(json_get(root, "os"));
    const char *arch = json_cstr(json_get(root, "architecture"));
    if (!os || strcmp(os, "linux"))
        return *err = ef("the image is for os '%.32s', not linux", os ? os : "?"), nullptr;
    if (!arch || strcmp(arch, "amd64"))
        return *err = ef("the image is for '%.32s', not amd64", arch ? arch : "?"), nullptr;
    const json_value *rf = json_get(root, "rootfs");
    if (!str_eq(json_get(rf, "type"), "layers"))
        return *err = "the image config's rootfs.type isn't \"layers\"", nullptr;
    const json_value *ids = json_get(rf, "diff_ids");
    if (!ids || ids->type != JSON_ARRAY)
        return *err = "the image config has no rootfs.diff_ids", nullptr;
    if (ids->len != nlayers)
        return *err = ef("the image has %zu layers but its config lists %u diff_ids", nlayers,
                         ids->len), nullptr;
    for (uint32_t i = 0; i < ids->len; i++)
        if (!digest_hex(json_cstr(&ids->kids[i]), err))
            return nullptr;
    return ids;
}

// ---- OCI image layout --------------------------------------------------------------
static int build_layout(oci_image *im, const oci_store *st, fs_tree *t, json_doc *index,
                        const char **err)
{
    json_doc *lay = load_file(st, "oci-layout", err);
    if (!lay)
        return -1;
    const bool ok = str_eq(json_get(json_root(lay), "imageLayoutVersion"), "1.0.0");
    json_free(lay);
    if (!ok)
        return fail(err, "oci-layout's imageLayoutVersion isn't 1.0.0");

    desc md;
    if (pick_manifest(st, json_root(index), 0, im->o.ref, &md, err))
        return -1;
    json_doc *man = load_json(st, &md, MAX_JSON, "manifest", err);
    if (!man)
        return -1;
    memcpy(im->man_digest, "sha256:", 7);
    memcpy(im->man_digest + 7, md.hex, 65);
    int rc = -1;
    const json_value *m = json_root(man);
    uint64_t sv;
    const json_value *mt = json_get(m, "mediaType");
    if (m->type != JSON_OBJECT || !json_u64(json_get(m, "schemaVersion"), &sv) || sv != 2) {
        *err = "the manifest isn't a schemaVersion 2 image manifest";
        goto out;
    }
    if (mt && !str_eq(mt, md.media)) {
        *err = "the manifest's mediaType isn't its descriptor's";
        goto out;
    }
    desc cd;
    if (parse_desc(json_get(m, "config"), &cd, err))
        goto out;
    if (cd.media && !media_is(cd.media, CONFIG_TYPES)) {
        *err = ef("the image config has media type '%.80s'", cd.media);
        goto out;
    }
    const json_value *ls = json_get(m, "layers");
    if (!ls || ls->type != JSON_ARRAY) {
        *err = "the manifest has no layers array";
        goto out;
    }
    if (!(im->config = load_json(st, &cd, MAX_CONFIG, "image config", err)))
        goto out;
    memcpy(im->cfg_digest, "sha256:", 7);
    memcpy(im->cfg_digest + 7, cd.hex, 65);
    const json_value *ids = check_config(json_root(im->config), ls->len, err);
    if (!ids)
        goto out;
    for (uint32_t i = 0; i < ls->len; i++) {
        desc ld;
        if (parse_desc(&ls->kids[i], &ld, err))
            goto out;
        const comp c = layer_comp(ld.media);
        if (c == C_ANY) {
            *err = ef("layer %u has unsupported media type '%.100s'", i + 1,
                      ld.media ? ld.media : "(none)");
            goto out;
        }
        char path[96];
        snprintf(path, sizeof path, "blobs/sha256/%s", ld.hex);
        fs_source raw;
        if (st->open(st->ctx, path, &raw)) {
            *err = ef("layer %u's blob sha256:%s is missing", i + 1, ld.hex);
            goto out;
        }
        if (raw.size != ld.size) {
            *err = ef("layer %u's blob is %llu bytes, its descriptor says %llu", i + 1,
                      (unsigned long long)raw.size, (unsigned long long)ld.size);
            goto out;
        }
        uint8_t d[32];
        char hex[65];
        if (hash_source(&raw, d)) {
            *err = ef("cannot read layer %u", i + 1);
            goto out;
        }
        sha256_hex(d, hex);
        if (strcmp(hex, ld.hex)) {
            *err = ef("layer %u's blob digest is sha256:%s, not sha256:%s", i + 1, hex, ld.hex);
            goto out;
        }
        const char *diff = json_cstr(&ids->kids[i]) + 7;
        if (add_layer(im, t, &raw, c, hex, diff, err))
            goto out;
    }
    rc = 0;
out:
    json_free(man);
    return rc;
}

// ---- docker-archive (manifest.json) ----------------------------------------------
// The config's digest, from its name: "<hex>.json" or "blobs/sha256/<hex>".
static bool name_digest(const char *path, char hex[65])
{
    const size_t n = strlen(path);
    const char *h = nullptr;
    if (n == 69 && !strcmp(path + 64, ".json"))
        h = path;
    else if (n == 77 && !strncmp(path, "blobs/sha256/", 13))
        h = path + 13;
    if (!h)
        return false;
    memcpy(hex, h, 64);
    hex[64] = 0;
    return is_hex64(hex);
}

static int build_docker(oci_image *im, const oci_store *st, fs_tree *t, json_doc *mf,
                        const char **err)
{
    const json_value *arr = json_root(mf);
    if (arr->type != JSON_ARRAY)
        return fail(err, "manifest.json isn't an array");
    const json_value *e = nullptr;
    const char *ref = im->o.ref;
    for (uint32_t i = 0; i < arr->len; i++) {
        const json_value *tags = json_get(&arr->kids[i], "RepoTags");
        bool hit = !ref;
        for (uint32_t j = 0; ref && tags && tags->type == JSON_ARRAY && j < tags->len; j++)
            hit |= str_eq(&tags->kids[j], ref);
        if (!hit)
            continue;
        if (e)
            return fail(err, ref ? ef("several images are tagged '%s'", ref)
                                 : "the archive holds several images; pick one with --ref");
        e = &arr->kids[i];
    }
    if (!e)
        return fail(err, ref ? ef("no image is tagged '%s'", ref) : "the archive holds no image");
    const char *cpath = json_cstr(json_get(e, "Config"));
    const json_value *ls = json_get(e, "Layers");
    if (!cpath || !ls || ls->type != JSON_ARRAY)
        return fail(err, "manifest.json's entry has no Config or Layers");
    desc cd = {0};
    if (!name_digest(cpath, cd.hex))
        return fail(err, "the image config's name isn't its digest, so it can't be verified");
    fs_source cs;
    if (st->open(st->ctx, cpath, &cs))
        return fail(err, ef("the image config %.100s is missing", cpath));
    cd.size = cs.size;
    // load_json opens it again by digest; in an archive the two names differ
    uint8_t *b;
    if (read_all(&cs, MAX_CONFIG, &b))
        return fail(err, "the image config is too big or unreadable");
    uint8_t dg[32];
    char hex[65];
    sha256(b, (size_t)cs.size, dg);
    sha256_hex(dg, hex);
    if (strcmp(hex, cd.hex)) {
        free(b);
        return fail(err, ef("the image config's digest is sha256:%s, not sha256:%s", hex, cd.hex));
    }
    json_limits lim = JSON_DEFAULT_LIMITS;
    lim.max_size = MAX_CONFIG;
    const char *jerr;
    im->config = json_parse(b, (size_t)cs.size, &lim, &jerr);
    free(b);
    if (!im->config)
        return fail(err, ef("the image config: %s", jerr));
    memcpy(im->cfg_digest, "sha256:", 7);
    memcpy(im->cfg_digest + 7, cd.hex, 65);
    const json_value *ids = check_config(json_root(im->config), ls->len, err);
    if (!ids)
        return -1;
    for (uint32_t i = 0; i < ls->len; i++) {
        const char *lp = json_cstr(&ls->kids[i]);
        fs_source raw;
        if (!lp || st->open(st->ctx, lp, &raw))
            return fail(err, ef("layer %u (%.100s) is missing", i + 1, lp ? lp : "?"));
        if (add_layer(im, t, &raw, C_ANY, nullptr, json_cstr(&ids->kids[i]) + 7, err))
            return -1;
    }
    return 0;
}

// The caller's layers (oci_opts.add) on top of the image, then its config.
static int add_and_config(oci_image *im, fs_tree *t, const char **err)
{
    if (im->o.nadd && !(im->add_digest = calloc(im->o.nadd, sizeof *im->add_digest)))
        return fail(err, "out of memory");
    for (size_t i = 0; i < im->o.nadd; i++) {
        uint8_t d[32];
        if (hash_source(&im->o.add[i], d))
            return fail(err, ef("added layer %zu: cannot read it", i + 1));
        memcpy(im->add_digest[i], "sha256:", 7);
        sha256_hex(d, im->add_digest[i] + 7);
        const struct oci_copy *cp = im->o.copy && im->o.copy[i].src ? &im->o.copy[i] : nullptr;
        if (add_layer_as(im, t, &im->o.add[i], C_ANY, nullptr, nullptr, cp, err))
            return -1;
    }
    return write_config(im, t, err);
}

int oci_build(oci_image *im, const oci_store *st, fs_tree *t, const char **err)
{
    const char *e1 = nullptr;
    fs_source probe;
    int rc;
    if (!st->open(st->ctx, "index.json", &probe)) {
        json_doc *index = load_file(st, "index.json", err);
        if (!index)
            return -1;
        rc = build_layout(im, st, t, index, err);
        json_free(index);
    } else if (!st->open(st->ctx, "manifest.json", &probe)) {
        json_doc *mf = load_file(st, "manifest.json", err);
        if (!mf)
            return -1;
        rc = build_docker(im, st, t, mf, err);
        json_free(mf);
    } else {
        return fail(err, "neither an OCI image layout (index.json) nor a docker-archive "
                         "(manifest.json)");
    }
    (void)e1;
    if (!rc)
        rc = add_and_config(im, t, err);
    json_free(im->config);
    im->config = nullptr;
    return rc;
}

int oci_build_on(oci_image *im, fs_tree *t, const char **err)
{
    // The lower image's config, if it has one (CONFIG_MAX in the guest's
    // /init is the same 4 MiB).
    const fs_inode *ino = fs_lookup(t, OCI_CONFIG_PATH, false);
    if (ino && (ino->mode & FS_IFMT) == FS_IFREG) {
        if (!ino->size || ino->size > MAX_JSON)
            return fail(err, "the lower image's " OCI_CONFIG_PATH " is empty or too big");
        const fs_source *s = &t->src[ino->src];
        if (!(im->lower_cfg = malloc((size_t)ino->size)))
            return fail(err, "out of memory");
        im->lower_cfglen = (size_t)ino->size;
        if (s->read(s->ctx, im->lower_cfg, im->lower_cfglen, ino->off))
            return fail(err, "cannot read the lower image's " OCI_CONFIG_PATH);
    }
    return add_and_config(im, t, err);
}

oci_image *oci_new(const oci_opts *o)
{
    oci_image *im = calloc(1, sizeof *im);
    if (!im)
        return nullptr;
    if (o)
        im->o = *o;
    if (!im->o.max_bytes)
        im->o.max_bytes = 16 * GiB;
    if (!im->o.max_ratio)
        im->o.max_ratio = 200;
    return im;
}

void oci_free(oci_image *im)
{
    if (!im)
        return;
    for (size_t i = 0; i < im->nlayers; i++)
        free(im->layers[i]);
    free(im->layers);
    inflate_free(im->z);
    zstd_free(im->zs);
    json_free(im->config);
    free(im->cfg);
    free(im->cfgtar);
    free(im->lower_cfg);
    free(im->add_digest);
    free(im);
}

// ---- docker-archive as a store ----------------------------------------------------
typedef struct {
    fs_source base;
    uint64_t off, size;
} slice;

struct oci_archive {
    fs_tree t;
    slice **sl;
    size_t nsl;
};

static int slice_read(void *ctx, void *buf, size_t len, uint64_t off)
{
    const slice *s = ctx;
    if (off > s->size || len > s->size - off)
        return -1;
    return s->base.read(s->base.ctx, buf, len, s->off + off);
}

static int archive_open(void *ctx, const char *path, fs_source *out)
{
    oci_archive *a = ctx;
    const fs_inode *ino = fs_lookup(&a->t, path, true);
    if (!ino || (ino->mode & FS_IFMT) != FS_IFREG)
        return -1;
    slice **sl = realloc(a->sl, (a->nsl + 1) * sizeof *sl);
    if (!sl)
        return -1;
    a->sl = sl;
    slice *s = malloc(sizeof *s);
    if (!s)
        return -1;
    *s = (slice){a->t.src[ino->src], ino->off, ino->size};
    a->sl[a->nsl++] = s;
    *out = (fs_source){slice_read, s, ino->size};
    return 0;
}

int oci_archive_open(oci_archive **out, const fs_source *tar, const char **err)
{
    oci_archive *a = calloc(1, sizeof *a);
    if (!a || fs_tree_init(&a->t)) {
        free(a);
        return fail(err, "out of memory");
    }
    if (fs_import_tar(&a->t, tar, err)) {
        oci_archive_free(a);
        return fail(err, ef("the archive: %s", *err));
    }
    *out = a;
    return 0;
}

oci_store oci_archive_store(oci_archive *a) { return (oci_store){archive_open, a}; }

void oci_archive_free(oci_archive *a)
{
    if (!a)
        return;
    for (size_t i = 0; i < a->nsl; i++)
        free(a->sl[i]);
    free(a->sl);
    fs_tree_free(&a->t);
    free(a);
}
