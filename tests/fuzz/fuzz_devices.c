// SPDX-License-Identifier: MIT
// Fuzz the device model with arbitrary guest port-I/O, MMIO and MSR
// sequences: every one of these is a guest-controlled VM exit.
//
// Input: 6-byte records {kind, port_lo, port_hi, size, value, value2}.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"
#include "vm.h"

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <unistd.h>
#endif

// The UART writes guest output straight to fd 1 / STD_OUTPUT_HANDLE.
static void silence_stdout(void)
{
#if defined(_WIN32)
    HANDLE nul = CreateFileA("NUL", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (nul != INVALID_HANDLE_VALUE)
        SetStdHandle(STD_OUTPUT_HANDLE, nul);
#else
    const int fd = open("/dev/null", O_WRONLY);
    if (fd >= 0) {
        dup2(fd, 1);
        close(fd);
    }
#endif
}

// Ports the device model actually implements, so most records hit them.
static const uint16_t PORTS[] = {
    0x3f8, 0x3f9, 0x3fa, 0x3fb, 0x3fc, 0x3fd, 0x3fe, 0x3ff, // COM1
    0x70,  0x71,                                           // CMOS
    0x60,  0x61,  0x64,                                    // i8042
    0x20,  0x21,  0xa0,  0xa1, 0x80,                       // PIC, POST
    MVM_PORT_MARK, MVM_PORT_EXIT,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static vm v;
    static bool once;
    if (!once) {
        silence_stdout();
        once = true;
    }
    memset(&v, 0, sizeof v);
    uart_init(&v.com1);
    for (size_t i = 0; i + 6 <= size; i += 6) {
        const uint8_t *r = data + i;
        const uint8_t size_b = (uint8_t)(1u << (r[3] % 3)); // 1, 2, 4
        const bool write = r[0] & 1;
        switch ((r[0] >> 1) % 4) {
        case 0:
        case 1: { // port I/O, mostly to implemented ports
            const uint16_t port = (r[0] >> 1) % 4 == 0 ? PORTS[r[1] % (sizeof PORTS / 2)]
                                                       : (uint16_t)(r[1] | r[2] << 8);
            uint32_t val = (uint32_t)r[4] | (uint32_t)r[5] << 8 | (uint32_t)r[4] << 16 |
                           (uint32_t)r[5] << 24;
            const bool was_stopped = v.stop;
            vm_pio(&v, port, size_b, write, &val);
            if (!write && size_b < 4)
                FUZZ_ASSERT((val >> (8 * size_b)) == 0); // reads are size-masked
            if (!was_stopped && v.stop)
                FUZZ_ASSERT(write && (port == MVM_PORT_EXIT || port == 0x64));
            break;
        }
        case 2: { // MMIO anywhere
            uint64_t val = r[4];
            const uint64_t gpa = (uint64_t)r[1] << 24 | (uint64_t)r[2] << 12 | r[5];
            vm_mmio(&v, gpa, size_b, write, &val);
            break;
        }
        default: { // MSR
            uint64_t val = (uint64_t)r[4] << 56 | r[5];
            const uint32_t idx = (uint32_t)r[1] << 24 | (uint32_t)r[2] << 8 | r[5];
            (void)vm_msr(&v, idx, write, &val);
            break;
        }
        }
        FUZZ_ASSERT(v.com1.outlen <= sizeof v.com1.out);
        FUZZ_ASSERT(v.cmos.index < sizeof v.cmos.regs);
        FUZZ_ASSERT(v.nmarks <= MVM_MAX_MARKS);
    }
    uart_flush(&v.com1);
    return 0;
}

const fuzz_seed *fuzz_seeds(size_t *n)
{
    // The kernel's 8250 probe/console sequence, a CMOS time read and a
    // control-port exit, roughly as Linux issues them.
    static const uint8_t boot[] = {
        1, 3, 0, 0, 0x80, 0, // LCR = DLAB
        1, 0, 0, 0, 0x01, 0, // DLL
        1, 3, 0, 0, 0x03, 0, // LCR = 8N1
        1, 2, 0, 0, 0xc7, 0, // FCR: FIFO on
        0, 2, 0, 0, 0, 0,    // IIR
        1, 4, 0, 0, 0x10, 0, // MCR loopback
        0, 6, 0, 0, 0, 0,    // MSR
        0, 5, 0, 0, 0, 0,    // LSR
        1, 0, 0, 0, 'h', 0,  // THR
        1, 0, 0, 0, '\n', 0, // THR newline -> flush
        1, 8, 0, 0, 0x0a, 0, // CMOS index 0x0a
        0, 9, 0, 0, 0, 0,    // CMOS data
        1, 8, 0, 0, 0x8e, 0, // CMOS index with NMI bit
        0, 9, 0, 0, 0, 0,
        1, 18, 0, 0, 7, 0,   // marker
        4, 0xfe, 0x0f, 0, 0, 0, // MMIO read
        6, 0xc0, 0x01, 0, 0x15, 0x15, // MSR read
        1, 19, 0, 0, 0, 0,   // exit 0
    };
    static fuzz_seed s[1] = {{boot, sizeof boot}};
    *n = 1;
    return s;
}
