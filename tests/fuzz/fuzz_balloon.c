// SPDX-License-Identifier: MIT
// Fuzz virtio-balloon's free page reporting: the guest controls the
// transport registers, the rings and every range it reports. Whatever it
// does, the device discards only whole pages inside guest RAM: guest RAM
// sits between two canary pages, which must keep their contents.
//
// Input as fuzz_virtq's: u16 n, then n bytes (at most 8 KiB) placed at
// guest address 0, then 5-byte records {op, u32 value}:
//   op < 0x40         write `value` to register REGS[op % NREG]
//   0x40 <= op < 0x80 read register REGS[op % NREG]
//   0x80 <= op < 0xc0 the guest writes guest memory: byte (value >> 16) at
//                     offset value & 0x7fff
//   op >= 0xc0        the guest kicks queue value % 4
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dev/balloon.h"
#include "fuzz.h"
#include "os.h"

static void count_msi(void *ctx, uint64_t addr, uint32_t data) { (void)ctx, (void)addr, (void)data; }

static const uint16_t REGS[] = {
    0x000, 0x004, 0x008, 0x010, 0x014, 0x020, 0x024, 0x030, 0x034, 0x038, 0x044, 0x050,
    0x060, 0x064, 0x070, 0x080, 0x084, 0x090, 0x094, 0x0a0, 0x0a4, 0x0fc, 0x100, 0x104,
};
constexpr unsigned NREG = sizeof REGS / sizeof REGS[0];
constexpr uint64_t PAGE = 4096;
constexpr uint64_t MEM_SIZE = 32 << 10;
constexpr uint8_t CANARY = 0x5a;

static uint8_t *area; // canary page, guest RAM, canary page
static guest_mem mem;

static bool canaries_intact(void)
{
    for (uint64_t i = 0; i < PAGE; i++)
        if (area[i] != CANARY || area[PAGE + MEM_SIZE + i] != CANARY)
            return false;
    return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!area) {
        area = os_mem_reserve(MEM_SIZE + 2 * PAGE);
        FUZZ_ASSERT(area);
        memset(area, CANARY, PAGE);
        memset(area + PAGE + MEM_SIZE, CANARY, PAGE);
        mem = (guest_mem){.base = area + PAGE, .size = MEM_SIZE};
    }
    memset(mem.base, 0, MEM_SIZE);
    if (size < 2)
        return 0;
    size_t n = (size_t)(data[0] | data[1] << 8) % 8193;
    if (n > size - 2)
        n = size - 2;
    memcpy(mem.base, data + 2, n);
    static ioapic a;
    ioapic_init(&a, 1, count_msi, nullptr);
    balloon *b = balloon_create(&mem, &a, 5);
    FUZZ_ASSERT(b);
    virtio_dev *d = balloon_dev(b);

    for (size_t i = 2 + n; i + 5 <= size; i += 5) {
        const uint8_t op = data[i];
        const uint32_t v = (uint32_t)data[i + 1] | (uint32_t)data[i + 2] << 8 |
                           (uint32_t)data[i + 3] << 16 | (uint32_t)data[i + 4] << 24;
        uint64_t val = v;
        if (op < 0x80)
            virtio_mmio_access(d, REGS[op % NREG], op & 0x20 ? 2 : 4, op < 0x40, &val);
        else if (op < 0xc0)
            mem.base[v & 0x7fff] = (uint8_t)(v >> 16);
        else {
            val = v % 4;
            virtio_mmio_access(d, 0x050, 4, true, &val);
        }
        FUZZ_ASSERT(balloon_discarded(b) % PAGE == 0);
        FUZZ_ASSERT(canaries_intact());
    }
    free(b); // one calloc
    return 0;
}

// The Linux driver bringing the device up with reporting, then one report
// of two ranges (a page-aligned one and a partial one) on queue 2.
static uint8_t seed_buf[2 + 0x200 + 64 * 5];

static size_t rec(size_t at, uint8_t op, uint32_t v)
{
    seed_buf[at] = op;
    put_le32(seed_buf + at + 1, v);
    return at + 5;
}

static uint8_t reg(uint16_t off)
{
    for (unsigned i = 0; i < NREG; i++)
        if (REGS[i] == off)
            return (uint8_t)i;
    return 0;
}

const fuzz_seed *fuzz_seeds(size_t *n)
{
    // Ring memory: desc at 0x000 (8 entries), avail at 0x080, used at 0x0c0.
    uint8_t *m = seed_buf + 2;
    put_le16(seed_buf, 0x200);
    put_le64(m + 0, 0x2000), put_le32(m + 8, 0x2000), put_le16(m + 12, 3), put_le16(m + 14, 1);
    put_le64(m + 16, 0x4800), put_le32(m + 24, 0x1800), put_le16(m + 28, 2);
    put_le16(m + 0x80 + 2, 1); // avail idx 1, ring[0] = 0
    size_t at = 2 + 0x200;
    at = rec(at, reg(0x070), 0);
    at = rec(at, reg(0x070), 3);
    at = rec(at, reg(0x024), 1);
    at = rec(at, reg(0x020), 1);
    at = rec(at, reg(0x024), 0);
    at = rec(at, reg(0x020), 1u << 5);
    at = rec(at, reg(0x070), 11);
    at = rec(at, reg(0x030), 2);
    at = rec(at, reg(0x038), 8);
    at = rec(at, reg(0x080), 0x000);
    at = rec(at, reg(0x090), 0x080);
    at = rec(at, reg(0x0a0), 0x0c0);
    at = rec(at, reg(0x044), 1);
    at = rec(at, reg(0x070), 15);
    at = rec(at, 0xc0, 2);
    at = rec(at, 0x80, 0x00020082); // avail idx = 2: the same report again
    at = rec(at, 0xc0, 2);
    static fuzz_seed s[1];
    s[0] = (fuzz_seed){seed_buf, at};
    *n = 1;
    return s;
}
