// SPDX-License-Identifier: MIT
// virtio-vsock (device 19): stream sockets between the guest (CID 3) and
// the host, which reaches them through one Unix socket, as with
// Firecracker:
//
//   connect(PATH); write "CONNECT <port>\n"   -> the guest's port <port>
//   read "OK <n>\n"                           -> connected; then raw bytes
//
// The connection closes if the guest refuses it. For the guest to connect
// to the host's port P (below 2^30), the host opens connections ahead of
// time:
//
//   connect(PATH); write "LISTEN <port>\n"   -> waits for the guest
//   read "OK <n>\n"                          -> the guest connected from
//                                              its port n; then raw bytes
//
// Each guest connection takes one waiting LISTEN connection (oldest
// first); with none waiting, the guest's connect is refused. A host that
// wants a backlog keeps several open. At most 128 connections in all.
//
// The device runs on its own I/O thread (started before the sandbox goes
// on), which owns the host sockets; the vCPU thread only handles the guest's
// transmit queue when the guest kicks it. Linux hosts only for now.
#pragma once

#include "virtio.h"

typedef struct vsock vsock;

constexpr uint64_t VSOCK_GUEST_CID = 3;

// Listen on a new Unix socket at uds_path (which must not exist). nullptr
// on error, logged.
vsock *vsock_create(const char *uds_path, const guest_mem *mem, ioapic *irq, unsigned pin);
virtio_dev *vsock_dev(vsock *s);
// Start the I/O thread, which runs vsock_poll(s, -1) forever.
[[nodiscard]] int vsock_start(vsock *s);
// One pass of the I/O loop: wait up to timeout_ms (-1: no limit) for host
// sockets or the guest, then move what can move. (Tests and fuzzing call
// it directly, with no I/O thread.)
void vsock_poll(vsock *s, int timeout_ms);
// For the sandbox: the listening socket, which the I/O thread accepts on.
int vsock_listen_fd(const vsock *s);
// An eventfd that the guest's queue kicks may signal directly (KVM_IOEVENTFD
// on the notify register): the I/O thread then checks every queue itself.
int vsock_doorbell_fd(const vsock *s);
// Most fds the device will have open at once (for RLIMIT_NOFILE).
unsigned vsock_max_fds(void);
