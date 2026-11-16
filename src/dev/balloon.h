// SPDX-License-Identifier: MIT
// virtio-balloon (device 5), for free page reporting only
// (VIRTIO_BALLOON_F_REPORTING, virtio 1.2 section 5.5.6.7): the guest
// hands over ranges of memory it has free, and the device discards them.
// A page of anonymous memory becomes demand-zero again; a page of a
// copy-on-write file view (a restored snapshot) becomes the file's again.
// Either way it stops being this VM's private memory: the VMM's resident
// set shrinks, and a diff snapshot leaves the page out. The guest never
// relies on a reported page's contents.
//
// The balloon itself never inflates: num_pages stays 0, and buffers on
// the inflate and deflate queues are handed back untouched. Everything
// runs on the vCPU thread, when the guest kicks a queue.
#pragma once

#include "virtio.h"

typedef struct balloon balloon;

// The smallest free block the guest reports: 2^ORDER pages (its kernel
// command line; the kernel's own default is 9, 2 MiB). Single pages: a
// paused sandbox's diff was 13 MiB instead of 21 (order 9) after a few
// commands, and 16 instead of 30 after 200 MB was written and freed. A
// guest loop that writes and frees memory ran as fast at 0 as at 9 or
// with no balloon (BENCH.md).
constexpr int BALLOON_REPORT_ORDER = 0;

balloon *balloon_create(const guest_mem *mem, ioapic *irq, unsigned pin);
virtio_dev *balloon_dev(balloon *b);
// Bytes discarded so far.
uint64_t balloon_discarded(const balloon *b);
