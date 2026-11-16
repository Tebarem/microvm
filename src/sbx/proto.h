// SPDX-License-Identifier: MIT
// The sandbox protocol between the host (microvm-sbxd, src/sbx/) and the
// guest's sandbox agent (guest/init/sbx.c, `init sandbox`): what a host
// needs to run E2B-style agent sandboxes (SANDBOX.md). The guest side is
// freestanding, so this header needs nothing but <stdint.h>.
//
// One operation per connection. The host connects to the guest's vsock
// port MVS_PORT (through the VMM's Unix socket: "CONNECT 53\n"); the agent
// says HELLO; the host sends one request frame; the agent answers with
// frames, and the connection ends when the operation does. Frames, both
// ways, little-endian:
//
//   off 0  u32 magic    MVS_MAGIC
//       4  u8  version  MVS_VERSION
//       5  u8  type     enum mvs_type
//       6  u16 flags    0
//       8  u32 len      body bytes that follow, at most MVS_MAX_BODY
//
// Strings in bodies are "str": u32 length, then that many bytes, no NUL
// bytes inside. A request's body is its fixed part, then its strings, and
// ends exactly there.
//
// Answers. Every operation ends with exactly one OK (body: its result, if
// any) or ERROR (body: u32 enum mvs_err, i32 errno or 0, str message),
// except the streams, which end when the connection does:
//
//   START, CONNECT  P_START (u32 pid), then P_STDOUT / P_STDERR / P_PTY
//                   data, then P_END; or ERROR.
//   WATCH           OK, then W_EVENT frames; or ERROR.
//   PORT            OK, then raw bytes both ways (the connection is a TCP
//                   connection to 127.0.0.1:port in the guest); or ERROR.
//   READ            OK (u64 size), then DATA frames (the file), then DONE.
//   WRITE           the host sends DATA frames, then DONE; the agent
//                   answers OK (an ENTRY body) or ERROR.
//   LIST            ENTRY frames, then OK. PS: PROC frames, then OK.
//
// While an operation's process is running, the host may close the
// connection: the process goes on (a background command). The agent never
// waits for the host: output to a host that doesn't read is held up to
// MVS_MAX_BUFFER per connection, then the process's output stops being read
// until the host catches up (so a stalled reader stalls the process, not
// the agent). Output nobody is connected for is dropped.
//
// Everything the guest sends is hostile to the host: src/sbx/parse.c
// checks every field.
#pragma once

#include <stdint.h>

enum : uint32_t {
    MVS_MAGIC = 0x4253564du, // "MVSB"
    MVS_VERSION = 1,
    MVS_HDR = 12,
    MVS_PORT = 53,

    MVS_MAX_BODY = 1u << 20,       // any frame
    MVS_MAX_CHUNK = 64u << 10,     // a data frame's body
    MVS_MAX_STRING = 64u << 10,    // one string (paths: PATH_MAX in the guest)
    MVS_MAX_STRINGS = 1024,        // arguments + environment of a START
    MVS_MAX_BUFFER = 1u << 20,     // output held per connection
    MVS_MAX_PROCS = 1024,          // processes the agent tracks at once
    MVS_MAX_DEPTH = 64,            // LIST depth, WATCH recursion
};

enum mvs_type : uint8_t {
    // guest -> host
    MVS_HELLO = 1,    // first frame of every connection: u32 version, u32 boot id
    MVS_OK = 2,
    MVS_ERROR = 3,
    MVS_P_START = 4,  // u32 pid
    MVS_P_STDOUT = 5, // data
    MVS_P_STDERR = 6, // data
    MVS_P_PTY = 7,    // data
    MVS_P_END = 8,    // u32 wait status (as wait4 gives it), u32 0
    MVS_ENTRY = 9,    // a file's entry, below
    MVS_PROC = 10,    // u32 pid, u32 flags (START's), u16 nargs, u16 nenv, then strs: tag, cwd,
                      // nargs args (args[0] the command), nenv envs (the START's own)
    MVS_W_EVENT = 11, // u32 enum mvs_event, u32 flags, str name (relative to the watched
                      // directory), then an ENTRY body unless flags has MVS_W_NOENTRY
    // both ways
    MVS_DATA = 12,    // file bytes (READ, WRITE)
    MVS_DONE = 13,    // end of DATA

    // host -> guest: requests
    MVS_START = 0x20,   // below
    MVS_CONNECT = 0x21, // selector
    MVS_PS = 0x22,      // nothing
    MVS_INPUT = 0x23,   // selector, u32 flags (MVS_IN_PTY), str data
    MVS_CLOSE_STDIN = 0x24, // selector
    MVS_SIGNAL = 0x25,  // selector, u32 signal (9 or 15)
    MVS_RESIZE = 0x26,  // selector, u16 cols, u16 rows
    MVS_STAT = 0x30,    // str user, str path
    MVS_MKDIR = 0x31,   // str user, str path: and its parents; ERROR EXIST if it is there
    MVS_MOVE = 0x32,    // str user, str from, str to
    MVS_LIST = 0x33,    // u32 depth (1..MVS_MAX_DEPTH), str user, str path
    MVS_REMOVE = 0x34,  // str user, str path: recursively
    MVS_WATCH = 0x35,   // u32 flags (MVS_W_RECURSIVE), str user, str path
    MVS_READ = 0x36,    // str user, str path
    MVS_WRITE = 0x37,   // str user, str path; then DATA..., DONE
    MVS_PORT_CONNECT = 0x38, // u32 port
    MVS_SET_ENV = 0x40, // u16 nenv, then nenv strs NAME=VALUE: default environment of processes
    MVS_SNAPSHOT = 0x41, // stop everything and ask the VMM for a snapshot; OK in VMs that continue
    MVS_EXPORT = 0x42,   // no body: the root filesystem's changes as an OCI layer
                         // (a tar, whiteouts included) in DATA frames, then
                         // OK (u64 tar bytes) or ERROR; processes are stopped meanwhile
};

// A selector: u32 kind (0 pid, 1 tag), u32 pid, str tag (empty for pid).
enum : uint32_t { MVS_SEL_PID = 0, MVS_SEL_TAG = 1 };

// START: u32 flags, u16 cols, u16 rows, u16 nargs, u16 nenv, then strs:
// user, cwd (empty: the user's home), tag (with MVS_S_TAG), then nargs
// args (args[0] is the command: a name without '/' is looked up in PATH),
// then nenv NAME=VALUE environment strings, over the defaults.
enum : uint32_t {
    MVS_S_PTY = 1u << 0,   // a terminal of cols x rows instead of pipes
    MVS_S_STDIN = 1u << 1, // keep stdin open for INPUT (else /dev/null)
    MVS_S_TAG = 1u << 2,
    MVS_S_FLAGS = 7,

    MVS_IN_PTY = 1u << 0,  // INPUT goes to the terminal

    MVS_W_RECURSIVE = 1u << 0,
    MVS_W_NOENTRY = 1u << 31, // in W_EVENT: the entry is gone; only its name follows
};

// ENTRY: u32 mode (st_mode: type and permission bits), u32 uid, u32 gid,
// u32 flags (MVS_E_SYMLINK: the path is a symlink, and mode is its
// target's, or 0 if that is dangling), u64 size, i64 mtime_sec, u32
// mtime_nsec, then strs: path (absolute), owner name, group name (empty
// when unknown), symlink target (empty when not a symlink).
enum : uint32_t { MVS_E_SYMLINK = 1u << 0, MVS_ENTRY_FIXED = 36 };

enum mvs_event : uint32_t {
    MVS_EV_CREATE = 1, MVS_EV_WRITE = 2, MVS_EV_REMOVE = 3, MVS_EV_RENAME = 4, MVS_EV_CHMOD = 5,
};

enum mvs_err : uint32_t {
    MVS_E_INVALID = 1,   // a malformed or impossible request
    MVS_E_NOTFOUND = 2,  // no such file, process or user
    MVS_E_EXIST = 3,     // already there
    MVS_E_DENIED = 4,
    MVS_E_FAILED = 5,    // anything else (errno says)
    MVS_E_LIMIT = 6,     // too many processes or watches
};
