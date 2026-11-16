// SPDX-License-Identifier: MIT
// microvm-mkrootfs: container images to read-only EROFS root filesystems
// for `microvm --rootfs`.
//
//   microvm-mkrootfs [OPTIONS] OUT.erofs LAYER.tar[.gz]...   layers, bottom first
//   microvm-mkrootfs [OPTIONS] --oci DIR OUT.erofs            an OCI image layout
//   microvm-mkrootfs [OPTIONS] --docker-archive FILE OUT.erofs  `docker save` output
//   microvm-mkrootfs [OPTIONS] --lower LOWER.erofs... OUT.erofs  a layer on images
//
// --add-layer TAR puts a layer of the caller's on top of an image (a
// function's code, a runtime adapter), as a Dockerfile's COPY would.
//
// --lower makes a layer instead of a whole image: OUT holds only what the
// --add-layer, --copy, --env, --workdir and --user options change in the
// image the LOWER images (ours, bottom first) make together, with
// whiteouts for what they remove. `microvm --rootfs LOWER... --rootfs OUT`
// stacks them in the guest, so images built on the same base share its
// layer, on disk and in the host's page cache.
//
// Layers are parsed in memory and never extracted (src/image/). Images are
// untrusted: on Linux every input file is opened first, then the parsing
// runs in a forked child inside the same sandbox as the VMM (seccomp,
// Landlock, rlimits; see SECURITY.md), which can only read the open inputs
// and write the open outputs. The output appears (renamed from OUT.part)
// only if the child succeeds.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <dirent.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <sys/resource.h>
#  include <sys/stat.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

#include "clock.h"
#include "image/oci.h"
#include "sandbox.h"

static const char USAGE[] =
    "usage: microvm-mkrootfs [OPTIONS] OUT.erofs LAYER.tar[.gz]...\n"
    "       microvm-mkrootfs [OPTIONS] --oci DIR OUT.erofs\n"
    "       microvm-mkrootfs [OPTIONS] --docker-archive FILE.tar OUT.erofs\n"
    "       microvm-mkrootfs [OPTIONS] --lower LOWER.erofs [--lower ...] OUT.erofs\n"
    "  Layers are tar, gzip'ed or zstd'ed tar, the bottom one first. An OCI image layout\n"
    "  (skopeo copy ... oci:DIR, podman save --format oci-dir) or a docker-archive\n"
    "  (docker save, podman save) gives its linux/amd64 image, whose config goes\n"
    "  into the image at " OCI_CONFIG_PATH " (see IMAGES.md). With --lower, OUT is a\n"
    "  layer: what the options below change in the image the LOWER images (made by\n"
    "  this tool, bottom first) make, for microvm --rootfs LOWER... --rootfs OUT.\n"
    "options:\n"
    "  --ref NAME        the image to take when there are several (tag or ref name)\n"
    "  --config FILE     also write the image config to FILE\n"
    "  --add-layer FILE  a layer (tar, gzip'ed or zstd'ed tar) to put on top of the\n"
    "                    image, before its config is resolved (repeatable)\n"
    "  --copy FILE SRC DEST OWNER MODE\n"
    "                    a Dockerfile COPY from FILE, a tar of the build context's\n"
    "                    files, in order with --add-layer; OWNER (--chown) and MODE\n"
    "                    (--chmod, octal) may be \"\"\n"
    "  --env NAME=VALUE  set NAME in the image's Env, as ENV in a Dockerfile (repeatable)\n"
    "  --workdir PATH    replace the image's WorkingDir, as WORKDIR\n"
    "  --user USER       replace the image's User (resolved after --add-layer), as USER\n"
    "  --max-size N      cap on all layers' decompressed bytes (K/M/G; default 16G)\n"
    "  --max-ratio N     cap on a layer's compression ratio (default 200)\n"
    "  --stats           print times and sizes\n"
    "  --no-sandbox      parse in this process, unsandboxed (debugging)\n"
    "  --version         print the version and exit\n";

typedef struct {
    char name[96]; // path in the layout
    os_file f;
    uint64_t size;
} named;

typedef struct {
    enum { M_LAYERS, M_OCI, M_ARCHIVE, M_LOWER } mode;
    oci_opts opts;
    const char *out, *config, *input;
    char *out_part, *config_part;
    FILE *outf, *cfgf;
    named *files; // inputs: layers, the archive, or the layout's files
    size_t nfiles, cap;
    named *add;   // --add-layer files
    const char **env; // --env
    struct oci_copy *copy; // per add: --copy's, or src nullptr for --add-layer
    fs_source *add_src;
    size_t nadd;
    bool stats, sandbox;
    char sandbox_report[160];
} job;

static int file_read(void *ctx, void *buf, size_t len, uint64_t off)
{
    return os_file_pread(*(os_file *)ctx, buf, len, off);
}

typedef struct {
    FILE *f;
    uint64_t n;
} sink;

static int file_write(void *ctx, const void *buf, size_t len)
{
    sink *s = ctx;
    s->n += len;
    return fwrite(buf, 1, len, s->f) == len ? 0 : -1;
}

static int layout_open(void *ctx, const char *path, fs_source *out)
{
    job *j = ctx;
    for (size_t i = 0; i < j->nfiles; i++) {
        if (!strcmp(j->files[i].name, path)) {
            *out = (fs_source){file_read, &j->files[i].f, j->files[i].size};
            return 0;
        }
    }
    return -1;
}

// Open a regular file read-only; not through a symlink (POSIX).
static int open_input(const char *path, os_file *f, uint64_t *size)
{
#if defined(_WIN32)
    return os_file_open_ro(path, f) || os_file_size(*f, size) ? -1 : 0;
#else
    const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
    struct stat st;
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }
    f->h = fd;
    *size = (uint64_t)st.st_size;
    return 0;
#endif
}

static int add_file(job *j, const char *name, const char *path)
{
    if (j->nfiles == j->cap) {
        const size_t c = j->cap ? j->cap * 2 : 16;
        named *v = realloc(j->files, c * sizeof *v);
        if (!v)
            return -1;
        j->files = v;
        j->cap = c;
    }
    named *n = &j->files[j->nfiles];
    snprintf(n->name, sizeof n->name, "%s", name);
    if (open_input(path, &n->f, &n->size))
        return -1;
    j->nfiles++;
    return 0;
}

static bool is_hex64(const char *s)
{
    size_t i = 0;
    for (; s[i]; i++)
        if (i >= 64 || !((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return i == 64;
}

// An OCI layout: oci-layout, index.json and every blobs/sha256/<hex> file,
// all opened now, before anything is parsed (the parser can't open files).
static int open_layout(job *j, const char *dir)
{
    char path[4096];
    for (int i = 0; i < 2; i++) {
        const char *n = i ? "index.json" : "oci-layout";
        snprintf(path, sizeof path, "%.4000s/%s", dir, n);
        if (add_file(j, n, path) && i == 1) {
            fprintf(stderr, "microvm-mkrootfs: cannot open '%s'\n", path);
            return -1;
        }
    }
    char bdir[4096];
    snprintf(bdir, sizeof bdir, "%.4000s/blobs/sha256", dir);
#if defined(_WIN32)
    char pat[4200];
    snprintf(pat, sizeof pat, "%.4100s/*", bdir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return 0; // no blobs: the build reports what is missing
    do {
        if (!is_hex64(fd.cFileName) || (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            continue;
        char name[96];
        snprintf(name, sizeof name, "blobs/sha256/%.64s", fd.cFileName);
        snprintf(path, sizeof path, "%.4000s/%.64s", bdir, fd.cFileName);
        if (add_file(j, name, path)) {
            fprintf(stderr, "microvm-mkrootfs: cannot open '%s'\n", path);
            FindClose(h);
            return -1;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(bdir);
    if (!d)
        return 0;
    struct rlimit rl;
    size_t want = 0;
    for (struct dirent *e; (e = readdir(d));)
        want += is_hex64(e->d_name);
    // one fd per blob: raise the soft limit if it's too low
    if (!getrlimit(RLIMIT_NOFILE, &rl) && rl.rlim_cur < want + 64 && rl.rlim_max != rl.rlim_cur) {
        rl.rlim_cur = want + 64 < rl.rlim_max ? want + 64 : rl.rlim_max;
        (void)setrlimit(RLIMIT_NOFILE, &rl);
    }
    rewinddir(d);
    for (struct dirent *e; (e = readdir(d));) {
        if (!is_hex64(e->d_name))
            continue;
        char name[96];
        snprintf(name, sizeof name, "blobs/sha256/%.64s", e->d_name);
        snprintf(path, sizeof path, "%.4000s/%.64s", bdir, e->d_name);
        if (add_file(j, name, path)) {
            fprintf(stderr, "microvm-mkrootfs: cannot open '%s': %s\n", path, strerror(errno));
            closedir(d);
            return -1;
        }
    }
    closedir(d);
#endif
    return 0;
}

// The untrusted part: parse the inputs, write the outputs. Runs in the
// sandboxed child on Linux. Returns the exit status.
static int convert(job *j)
{
    const uint64_t t0 = mvm_now_ns();
    for (size_t k = 0; k < j->nadd; k++)
        j->add_src[k] = (fs_source){file_read, &j->add[k].f, j->add[k].size};
    j->opts.add = j->add_src;
    j->opts.nadd = j->nadd;
    j->opts.copy = j->copy;
    fs_tree t;
    oci_image *im = oci_new(&j->opts);
    if (!im || fs_tree_init(&t)) {
        fprintf(stderr, "microvm-mkrootfs: out of memory\n");
        return 1;
    }
    const char *err = "";
    int rc = 0;
    oci_archive *a = nullptr;
    fs_tree delta = {0};
    fs_tree *img = &t; // what is written
    if (j->mode == M_LOWER) {
        // The image the lower layers make, then the changes; only those
        // are written.
        for (size_t i = 0; i < j->nfiles && !rc; i++) {
            const fs_source src = {file_read, &j->files[i].f, j->files[i].size};
            if ((rc = fs_import_erofs(&t, &src, &err)))
                fprintf(stderr, "microvm-mkrootfs: %s: %s\n", j->files[i].name, err);
        }
        fs_mark mk = {0};
        if (!rc && (rc = fs_tree_mark(&t, &mk)))
            fprintf(stderr, "microvm-mkrootfs: out of memory\n");
        if (!rc && (rc = oci_build_on(im, &t, &err)))
            fprintf(stderr, "microvm-mkrootfs: %s\n", err);
        if (!rc && (rc = fs_tree_diff(&t, &mk, &delta, &err)))
            fprintf(stderr, "microvm-mkrootfs: %s\n", err);
        fs_mark_free(&mk);
        img = &delta;
    } else if (j->mode == M_LAYERS) {
        for (size_t i = 0; i < j->nfiles && !rc; i++) {
            const fs_source src = {file_read, &j->files[i].f, j->files[i].size};
            if ((rc = oci_add_layer(im, &t, &src, &err)))
                fprintf(stderr, "microvm-mkrootfs: %s: %s\n", j->files[i].name, err);
        }
    } else {
        oci_store st = {layout_open, j};
        if (j->mode == M_ARCHIVE) {
            const fs_source src = {file_read, &j->files[0].f, j->files[0].size};
            rc = oci_archive_open(&a, &src, &err);
            if (!rc)
                st = oci_archive_store(a);
        }
        if (!rc)
            rc = oci_build(im, &st, &t, &err);
        if (rc)
            fprintf(stderr, "microvm-mkrootfs: %s: %s\n", j->input, err);
    }
    const uint64_t t1 = mvm_now_ns();
    sink out = {j->outf, 0};
    if (!rc) {
        err = "";
        rc = erofs_write(img, &(fs_sink){file_write, &out}, &err);
        if (fflush(j->outf))
            rc = -1;
        if (rc)
            fprintf(stderr, "microvm-mkrootfs: %s: %s\n", j->out, err[0] ? err : "write failed");
    }
    if (!rc && j->cfgf) {
        size_t n;
        const uint8_t *c = oci_config(im, &n);
        if (fwrite(c, 1, n, j->cfgf) != n || fflush(j->cfgf)) {
            fprintf(stderr, "microvm-mkrootfs: %s: write failed\n", j->config);
            rc = -1;
        }
    }
    const uint64_t t2 = mvm_now_ns();
    if (!rc && j->stats) {
        size_t files = img->n;
        fprintf(stderr,
                "microvm-mkrootfs: %zu inodes, layers %.1f MB decompressed, image %.1f MB\n"
                "  read layers: %.3f s   write image: %.3f s   total: %.3f s\n%s%s",
                files, (double)oci_layer_bytes(im) / 1e6, (double)out.n / 1e6, (double)(t1 - t0) / 1e9,
                (double)(t2 - t1) / 1e9, (double)(t2 - t0) / 1e9, j->sandbox_report,
                j->sandbox_report[0] ? "\n" : "");
    }
    oci_archive_free(a);
    oci_free(im);
    fs_tree_free(&delta);
    fs_tree_free(&t);
    return rc ? 1 : 0;
}

static bool parse_size(const char *s, uint64_t *v)
{
    char *end;
    const unsigned long long n = strtoull(s, &end, 10);
    uint64_t m = 1;
    if (end == s)
        return false;
    if (*end == 'K' || *end == 'k')
        m = KiB, end++;
    else if (*end == 'M' || *end == 'm')
        m = MiB, end++;
    else if (*end == 'G' || *end == 'g')
        m = GiB, end++;
    return !*end && !ckd_mul(v, (uint64_t)n, m) && *v;
}

static char *part_name(const char *path)
{
    const size_t n = strlen(path);
    char *p = malloc(n + 6);
    if (p)
        memcpy(p, path, n), memcpy(p + n, ".part", 6);
    return p;
}

static int finish_file(const char *part, const char *final, bool keep)
{
    if (!keep) {
        remove(part);
        return 0;
    }
#if defined(_WIN32)
    if (!MoveFileExA(part, final, MOVEFILE_REPLACE_EXISTING))
        return -1;
#else
    if (rename(part, final))
        return -1;
#endif
    return 0;
}

int main(int argc, char **argv)
{
    job j = {.sandbox = true};
    const char *oci = nullptr, *archive = nullptr;
    const char **lower = calloc((size_t)argc, sizeof *lower);
    size_t nlower = 0;
    if (!lower) {
        fprintf(stderr, "microvm-mkrootfs: out of memory\n");
        return 1;
    }
    int i = 1;
    for (; i < argc && argv[i][0] == '-' && argv[i][1] == '-'; i++) {
        const char *o = argv[i];
        if (!strcmp(o, "--version")) {
            printf("microvm-mkrootfs %s\n", MICROVM_VERSION);
            return 0;
        }
        const bool has_arg = i + 1 < argc;
        if (!strcmp(o, "--oci") && has_arg)
            oci = argv[++i];
        else if (!strcmp(o, "--docker-archive") && has_arg)
            archive = argv[++i];
        else if (!strcmp(o, "--lower") && has_arg)
            lower[nlower++] = argv[++i];
        else if (!strcmp(o, "--ref") && has_arg)
            j.opts.ref = argv[++i];
        else if (!strcmp(o, "--config") && has_arg)
            j.config = argv[++i];
        else if ((!strcmp(o, "--add-layer") && has_arg) || (!strcmp(o, "--copy") && i + 5 < argc)) {
            const bool copy = o[2] == 'c';
            const char *f = argv[++i];
            struct oci_copy cp = {.mode = -1};
            if (copy) {
                cp.src = argv[++i], cp.dest = argv[++i], cp.owner = argv[++i];
                const char *m = argv[++i];
                char *end;
                const long v = *m ? strtol(m, &end, 8) : -1;
                if (cp.dest[0] != '/' || (*m && (*end || v < 0 || v > 07777))) {
                    fprintf(stderr, "microvm-mkrootfs: --copy wants an absolute DEST and an octal MODE (or \"\")\n");
                    return 2;
                }
                cp.mode = (int32_t)v;
            }
            struct oci_copy *cv = realloc(j.copy, (j.nadd + 1) * sizeof *cv);
            if (!cv) {
                fprintf(stderr, "microvm-mkrootfs: out of memory\n");
                return 1;
            }
            j.copy = cv;
            j.copy[j.nadd] = cp;
            named *v = realloc(j.add, (j.nadd + 1) * sizeof *v);
            if (v)
                j.add = v;
            fs_source *src = v ? realloc(j.add_src, (j.nadd + 1) * sizeof *src) : nullptr;
            if (src)
                j.add_src = src;
            if (!v || !src) {
                fprintf(stderr, "microvm-mkrootfs: out of memory\n");
                return 1;
            }
            snprintf(j.add[j.nadd].name, sizeof j.add[j.nadd].name, "%s", f);
            if (open_input(f, &j.add[j.nadd].f, &j.add[j.nadd].size)) {
                fprintf(stderr, "microvm-mkrootfs: cannot open '%s'\n", f);
                return 1;
            }
            j.nadd++;
        }
        else if (!strcmp(o, "--env") && has_arg) {
            const char *e = argv[++i];
            if (e[0] == '=' || !strchr(e, '=')) {
                fprintf(stderr, "microvm-mkrootfs: --env wants NAME=VALUE\n");
                return 2;
            }
            const char **v = realloc(j.env, (j.opts.nenv + 1) * sizeof *v);
            if (!v) {
                fprintf(stderr, "microvm-mkrootfs: out of memory\n");
                return 1;
            }
            v[j.opts.nenv++] = e;
            j.env = v;
            j.opts.env = v;
        } else if (!strcmp(o, "--workdir") && has_arg && argv[i + 1][0] == '/')
            j.opts.workdir = argv[++i];
        else if (!strcmp(o, "--user") && has_arg)
            j.opts.user = argv[++i];
        else if (!strcmp(o, "--max-size") && has_arg && parse_size(argv[i + 1], &j.opts.max_bytes))
            i++;
        else if (!strcmp(o, "--max-ratio") && has_arg) {
            uint64_t r;
            if (!parse_size(argv[++i], &r) || r > UINT32_MAX)
                break;
            j.opts.max_ratio = (uint32_t)r;
        } else if (!strcmp(o, "--stats"))
            j.stats = true;
        else if (!strcmp(o, "--no-sandbox"))
            j.sandbox = false;
        else
            break;
    }
    const int rest = argc - i;
    const int inputs = !!oci + !!archive + !!nlower;
    if (inputs > 1 || (inputs ? rest != 1 : rest < 2) || (i < argc && argv[i][0] == '-' && argv[i][1] == '-') ||
        ((j.config || j.nadd) && !inputs)) {
        fputs(USAGE, stderr);
        return 2;
    }
    j.out = argv[i];
    if (oci) {
        j.mode = M_OCI;
        j.input = oci;
        if (open_layout(&j, oci))
            return 1;
    } else if (nlower) {
        j.mode = M_LOWER;
        j.input = lower[0];
        for (size_t k = 0; k < nlower; k++)
            if (add_file(&j, lower[k], lower[k])) {
                fprintf(stderr, "microvm-mkrootfs: cannot open '%s'\n", lower[k]);
                return 1;
            }
    } else if (archive) {
        j.mode = M_ARCHIVE;
        j.input = archive;
        if (add_file(&j, archive, archive)) {
            fprintf(stderr, "microvm-mkrootfs: cannot open '%s'\n", archive);
            return 1;
        }
    } else {
        for (int k = i + 1; k < argc; k++) {
            if (add_file(&j, argv[k], argv[k])) {
                fprintf(stderr, "microvm-mkrootfs: cannot open '%s'\n", argv[k]);
                return 1;
            }
        }
    }
    j.out_part = part_name(j.out);
    j.config_part = j.config ? part_name(j.config) : nullptr;
    if (!j.out_part || (j.config && !j.config_part)) {
        fprintf(stderr, "microvm-mkrootfs: out of memory\n");
        return 1;
    }
    if (!(j.outf = fopen(j.out_part, "wb"))) {
        fprintf(stderr, "microvm-mkrootfs: cannot create '%s'\n", j.out_part);
        return 1;
    }
    setvbuf(j.outf, nullptr, _IOFBF, 1 << 20);
    if (j.config && !(j.cfgf = fopen(j.config_part, "wb"))) {
        fprintf(stderr, "microvm-mkrootfs: cannot create '%s'\n", j.config_part);
        fclose(j.outf);
        remove(j.out_part);
        return 1;
    }

    int rc;
#if defined(_WIN32)
    rc = convert(&j); // Windows is for development only: no sandboxed helper
#else
    if (!j.sandbox) {
        rc = convert(&j);
    } else {
        fflush(stderr);
        const pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "microvm-mkrootfs: fork: %s\n", strerror(errno));
            rc = 1;
        } else if (pid == 0) {
            if (sandbox_enter(&(sandbox_cfg){.mem_headroom = 4 * GiB}, j.sandbox_report,
                              sizeof j.sandbox_report)) {
                fprintf(stderr, "microvm-mkrootfs: cannot enter the sandbox: %s\n", strerror(errno));
                _exit(1);
            }
            const int c = convert(&j);
            fflush(stderr);
            _exit(c);
        } else {
            int st;
            while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
                ;
            if (WIFEXITED(st)) {
                rc = WEXITSTATUS(st);
            } else {
                fprintf(stderr, "microvm-mkrootfs: the sandboxed converter was killed by signal %d\n",
                        WIFSIGNALED(st) ? WTERMSIG(st) : -1);
                rc = 1;
            }
        }
    }
#endif
    // The child wrote through its own copies; ours hold nothing buffered.
    fclose(j.outf);
    if (j.cfgf)
        fclose(j.cfgf);
    if (finish_file(j.out_part, j.out, rc == 0) ||
        (j.config_part && finish_file(j.config_part, j.config, rc == 0))) {
        fprintf(stderr, "microvm-mkrootfs: cannot rename '%s' to '%s'\n", j.out_part, j.out);
        rc = 1;
    }
    for (size_t k = 0; k < j.nfiles; k++)
        os_file_close(j.files[k].f);
    for (size_t k = 0; k < j.nadd; k++)
        os_file_close(j.add[k].f);
    free(j.files);
    free(lower);
    free(j.add);
    free(j.add_src);
    free(j.out_part);
    free(j.config_part);
    return rc;
}
