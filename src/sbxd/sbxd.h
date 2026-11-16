// SPDX-License-Identifier: MIT
// microvm-sbxd: E2B-compatible agent sandboxes on microvm (SANDBOX.md).
//
// One thread, one epoll loop. Three kinds of connection:
//   hconn  an HTTP/1.1 client: the control plane (REST), envd's API
//          (Connect + JSON, /files, /health), or a port tunnel;
//   gconn  one guest operation: a connection to a sandbox's agent through
//          its VMM's vsock socket (CONNECT 53), speaking src/sbx/proto.h;
//   pidfd  a VMM process, to learn when it exits;
// and an inotify fd: a VMM closing its snapshot (a pause, done before the
// VMM has exited).
// Objects are freed only between events (the graveyard), so a callback
// may close anything, including the connection it was called for.
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "sbx/sbx.h"
#include "sbxd/http.h"

typedef struct hconn hconn;
typedef struct gconn gconn;
typedef struct sandbox sandbox;
typedef struct tmpl tmpl;
typedef struct watcher watcher;

enum { EV_LISTEN = 1, EV_HTTP, EV_GUEST, EV_PIDFD, EV_NOTIFY, EV_REAP, EV_FETCH };

typedef struct {
    int kind;
} ev_head;

// --- configuration ---------------------------------------------------------------

enum { TMPL_MAX_LOWER = 7 }; // with the image: the VMM's 8 --rootfs layers

// A layer of a template's image below its top one (tmpl.image), pushed
// with it: content-addressed like it (DIR/images/SHA256.erofs), so
// templates built on the same base share that layer's file, and the host's
// page cache of it.
typedef struct {
    char path[512];
    char sha256[65];
    uint64_t size;
} tmpl_layer;

struct tmpl {
    char name[64];
    char image[512]; // EROFS root filesystem: its top layer, or all of it
    uint32_t nlower; // layers below it, bottom first (microvm --rootfs, in order)
    tmpl_layer lower[TMPL_MAX_LOWER];
    uint64_t size;   // the image's bytes (pushed templates)
    char user[64];   // the default user ("" = root)
    uint32_t mem_mib;
    uint32_t cpus; // vCPUs; above 1, booted with --kernel-smp
    bool net;
    // Prepared at start-up: booted once, snapshotted when the agent is up.
    char snap[640];
    int state; // T_PREPARING, T_READY, T_FAILED, T_FETCHING
    sandbox *boot;
    // Pushed at run time (PUT /templates/NAME, api.c): the image is
    // content-addressed, DIR/images/SHA256.erofs, fetched and checked first
    // (fetch.c). Replaced or deleted, a template is retired: no new
    // sandboxes, and freed once none of its sandboxes is left (they map its
    // snapshot and image).
    bool dynamic, retired;
    char sha256[65];
    // E2B's start and ready commands (/bin/sh -c, as user, in workdir):
    // before the snapshot the start command is left running and the ready
    // command is run until it succeeds. nullptr: none.
    char *start_cmd, *ready_cmd, *workdir;
    char why[160]; // why it failed
    tmpl *next;
};
enum { T_PREPARING, T_READY, T_FAILED, T_FETCHING };

typedef struct {
    const char *vmm, *jail, *kernel, *kernel_smp, *dir, *domain;
    char api_key[256]; // "" = any key is accepted
    tmpl tmpl[16];
    int ntmpl;
    int max_sandboxes;
    int max_conns;
    bool verbose;
    // Every sandbox with the internet: ports refused (default: mail, 25, 465
    // and 587) and limits (0: none), unless its create request says.
    uint16_t net_deny[16];
    int nnet_deny; // -1: --net-deny-port none
    uint32_t net_flow_rate, net_max_dests;
    uint64_t net_tx_rate;
    // Team pools (create's "pool"): a cgroup v2 directory this daemon may
    // write (delegated to it), with a cgroup per team in it. nullptr: none.
    const char *cgroup;
    int64_t max_timeout_s; // the longest timeout a sandbox may have
} config;

extern config C;

// --- the loop ----------------------------------------------------------------------

int64_t now_ms(void);
void ev_set(int fd, void *obj, bool in, bool out); // add or change interest
void ev_del(int fd);
void graveyard_add(void *p, void (*fn)(void *)); // freed after this event
[[gnu::format(printf, 1, 2)]] void logf_(const char *fmt, ...);
#define VLOG(...) (C.verbose ? logf_(__VA_ARGS__) : (void)0)

// --- guest connections --------------------------------------------------------

typedef struct {
    void (*ready)(gconn *g);                            // HELLO arrived
    void (*frame)(gconn *g, const mvs_frame *f);        // a frame (not in raw mode)
    void (*raw)(gconn *g, const uint8_t *p, size_t n);  // raw mode (a port)
    void (*end)(gconn *g, const char *why);             // over: why nullptr at a clean EOF
    void (*drained)(gconn *g);                          // the output went below the low mark
} gconn_ops;

enum { G_CONNECTING, G_LINE, G_HELLO, G_OPEN, G_RAW, G_DEAD };

struct gconn {
    int kind; // EV_GUEST
    int fd;
    int st;
    const gconn_ops *ops;
    void *ctx;
    char line[32];
    size_t nline;
    mvs_reader r;
    mvs_buf out;
    size_t out_off;
    bool paused, was_full, read_eof, want_shut;
    bool was_open; // got as far as HELLO
    uint32_t resumes;
};

enum : size_t { G_HIGH = 1u << 20, G_LOW = 256u << 10 };

// Connects to the sandbox's agent: nullptr if the VMM's socket refuses
// (*retry true when it may work soon: the VMM is still starting).
gconn *g_open(const sandbox *sb, const gconn_ops *ops, void *ctx, bool *retry);
void g_send(gconn *g, mvs_buf *b); // queues b's frames (and frees b)
void g_send_raw(gconn *g, const void *p, size_t n);
void g_shutdown_write(gconn *g); // raw mode: the client is done sending
void g_close(gconn *g);          // no more callbacks
void g_pause(gconn *g, bool on); // stop/restart reading
size_t g_pending(const gconn *g);
void g_raw_mode(gconn *g); // after a PORT_CONNECT's OK: bytes, not frames

// --- sandboxes -------------------------------------------------------------------

enum { SB_STARTING, SB_RUNNING, SB_PAUSING, SB_PAUSED, SB_DEAD };

struct sandbox {
    int kind; // EV_PIDFD
    char id[24];
    char token[40];
    tmpl *t;
    bool is_template;
    int st;
    pid_t pid;
    int pidfd;
    char sock[600], log[600], snap[2][600];
    int gen;          // the snapshot file the running VMM saves to: snap[gen & 1]
    int wd;           // the inotify watch on its directory (0: none)
    bool restored;    // started from a snapshot (pause file or template)
    int64_t started_ms, started_unix, end_unix; // end_unix: the timeout
    int64_t retry_at; // connecting to the agent: next try
    int64_t give_up_at;
    bool auto_pause, internet;
    // Its team's pool (create's "pool"): its VMM runs in the cgroup
    // --cgroup/t-TEAM, whose cpu.max and memory.max are the pool's. "": none.
    char team[68];
    uint32_t pool_cpus; // 0: no cap
    uint64_t pool_mem;  // bytes; 0: no cap
    // Its network limits (create's "netLimits"; 0: the daemon's --net-* default).
    uint32_t net_flow_rate, net_max_dests;
    uint64_t net_tx_rate;
    char stats[600]; // the VMM's --stats file (with a network)
    bool env_set;     // SET_ENV done (it stays in the agent, and in snapshots)
    char *metadata;   // JSON object text ("{}")
    char **envs;      // NAME=VALUE, for SET_ENV after each start
    size_t nenv;
    gconn *ctl;       // the start-up (HELLO, SET_ENV) or SNAPSHOT operation
    int tphase;       // a template's boot: start and ready commands (api.c)
    hconn *waiters;   // requests waiting for RUNNING or PAUSED
    watcher *watchers;
    sandbox *next;
};

extern sandbox *sandboxes;
sandbox *sb_find(const char *id);
int sb_count(void);

// --- HTTP connections ------------------------------------------------------------

enum { H_HEAD, H_BODY, H_TUNNEL, H_DEAD };

// What the current request is (its state lives in rq).
enum {
    RQ_NONE,
    RQ_SIMPLE,     // answered from the daemon
    RQ_WAIT_SB,    // control plane: waiting for a sandbox to run or pause
    RQ_UNARY,      // envd: one guest operation, one JSON answer
    RQ_STREAM,     // envd: a server stream (Start, Connect, WatchDir)
    RQ_INPUT,      // envd: StreamInput (client stream)
    RQ_FILES_GET,
    RQ_FILES_PUT,
    RQ_TUNNEL,
};

typedef struct {
    int kind;
    int method;          // envd: which RPC (envd.c)
    bool envd;           // an envd request whose body is still coming
    sandbox *sb;
    char user[64];
    // RQ_UNARY / RQ_STREAM
    sbuf acc;            // answer under construction (List, ListDir, PS)
    bool first;          // nothing written to acc yet
    bool started;        // a stream's first event is out
    bool include_entry;
    uint32_t sel_kind, sel_pid;
    char sel_tag[256];
    int keepalive_s;
    int64_t last_out;
    // RQ_INPUT: frames not decoded yet, input not sent yet
    sbuf inbuf, pend;
    bool in_pty, input_busy, in_started, body_over;
    // RQ_FILES_PUT
    mp_reader mp;
    bool multipart, gzip, part_open, part_ok;
    char path[4096];
    int nfiles;
    sbuf gz;             // a gzip body, whole
    void *inf, *src;     // its inflate stream, and where it pulls from
    // RQ_WAIT_SB: what to answer when the sandbox gets there
    int want;            // SB_RUNNING or SB_PAUSED
    int ok_status;       // 200, 201, 204
} reqstate;

struct hconn {
    int kind; // EV_HTTP
    int fd;
    int st;
    uint8_t *in;
    size_t in_len, in_cap;
    sbuf out;
    size_t out_off;
    bool read_paused, peer_eof;
    bool busy;          // inside h_process
    int64_t deadline;   // the head must arrive by then (or idle keep-alive ends)
    http_req req;
    bool have_req;
    // the request body
    bool body_chunked, body_done;
    int64_t body_left;
    http_chunked ck;
    sbuf body;          // whole bodies (the default)
    size_t body_max;
    bool body_stream;   // body bytes go to the request's consumer instead
    // the response
    bool resp_chunked, resp_done, close_after;
    reqstate rq;
    gconn *g;           // the request's guest operation
    hconn *wnext;       // in a sandbox's waiters
    hconn *next, *prev; // all connections
};

// Responses.
void h_respond(hconn *h, int status, const char *ctype, const void *body, size_t n, const char *extra_headers);
void h_json(hconn *h, int status, const sbuf *b);
void h_api_error(hconn *h, int status, const char *msg);      // {"code":N,"message":".."}
void h_stream_begin(hconn *h, int status, const char *ctype); // chunked
void h_chunk(hconn *h, const void *p, size_t n);
void h_stream_end(hconn *h);
size_t h_pending(const hconn *h);
void h_pause_read(hconn *h, bool on);
void h_close(hconn *h);
void h_body_more(hconn *h); // a consumer that paused is ready for more body

// Connect + JSON (envd.c).
void connect_error(hconn *h, bool stream, const char *code, const char *msg);
void envd_request(hconn *h, sandbox *sb);
void envd_body(hconn *h, const uint8_t *p, size_t n); // body_stream requests
void envd_body_end(hconn *h);
void envd_abort(hconn *h); // the client went away
void envd_tick(hconn *h, int64_t now);
void envd_rq_free(reqstate *q); // what a request's state holds
void envd_export(hconn *h, sandbox *sb); // GET /sandboxes/ID/export
void watchers_close(sandbox *sb);

// The control plane and the VMs (api.c).
void api_request(hconn *h);
void api_abort(hconn *h);
void sb_waiters_wake(sandbox *sb);
void sb_vmm_exited(sandbox *sb);
// Pausing without waiting for VMMs to exit: false if inotify isn't there
// (pauses then end when the VMM does).
bool sb_notify_start(void);
void sb_notify_readable(void);
void sb_reaped(void *reaper); // a VMM that saved a pause has exited
void sb_tick(int64_t now);
int64_t sb_next_deadline(void);
void templates_prepare(void);
tmpl *tmpl_find(const char *name); // a template new sandboxes may use
void tmpl_tick(void);              // retired templates no sandbox uses go
void tmpl_fetched(const char *sha256, bool ok, const char *why);

// Template images (fetch.c).
bool fetch_sha_ok(const char *sha256); // 64 lower-case hex digits
// Fetches the image (once, however many ask) and calls tmpl_fetched(),
// later. False, with *why: it can't start (a bad URL).
bool fetch_start(const char *sha256, const char *url, uint64_t size, const char **why);
void fetch_event(void *f, uint32_t events);
void fetch_tick(int64_t now);

// Requests that name a sandbox that is going away forget it (main.c).
void h_forget_sandbox(sandbox *sb);

// The port tunnel (main.c).
void tunnel_start(hconn *h, sandbox *sb, uint32_t port);
