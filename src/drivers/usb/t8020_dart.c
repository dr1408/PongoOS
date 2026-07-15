/*
 * Minimal T8020 USB DART owner.
 *
 * DWC2 exposes 32-bit DMA registers on T8020. J305 routes that master through
 * dart-usb stream 0, so the register value is an IOVA, not a truncated PA.
 */
#include <pongo.h>

#define DART_PAGE_SIZE                 0x4000ULL

#define DART_STREAM_COMMAND            0x20
#define DART_STREAM_COMMAND_BUSY       (1U << 2)
#define DART_STREAM_COMMAND_INVALIDATE (1U << 20)
#define DART_STREAM_SELECT             0x34
#define DART_CONFIG                    0x60
#define DART_CONFIG_LOCK               (1U << 15)
#define DART_ENABLED_STREAMS           0xfc
#define DART_TCR0                      0x100
#define DART_TCR_TRANSLATE_ENABLE      (1U << 7)
#define DART_TTBR0                     0x200
#define DART_TTBR_VALID                (1U << 31)

#define DART_PTE_ADDR_MASK             0x000000ffffffc000ULL
#define DART_PTE_SP_END_ALL            0x000fff0000000000ULL
#define DART_PTE_DISABLE_SP            (1ULL << 1)
#define DART_PTE_VALID                 (1ULL << 0)

static volatile uint32_t *dart_regs;
static uint64_t *dart_l1[4];

static inline uint32_t dart_read(uint32_t off)
{
    return dart_regs[off / sizeof(uint32_t)];
}

static inline void dart_write(uint32_t off, uint32_t value)
{
    dart_regs[off / sizeof(uint32_t)] = value;
}

static bool dart_invalidate_stream0(void)
{
    dart_write(DART_STREAM_SELECT, 1);
    __asm__ volatile("dsb sy" ::: "memory");
    dart_write(DART_STREAM_COMMAND, DART_STREAM_COMMAND_INVALIDATE);

    for (uint32_t i = 0; i < 100000; i++) {
        if (!(dart_read(DART_STREAM_COMMAND) & DART_STREAM_COMMAND_BUSY)) {
            return true;
        }
    }
    return false;
}

static uint64_t *dart_alloc_table(uint64_t *paddr)
{
    uint64_t *table = alloc_contig(DART_PAGE_SIZE);
    if (!table) {
        return NULL;
    }
    bzero(table, DART_PAGE_SIZE);
    *paddr = vatophys_static(table);
    return table;
}

static bool dart_load_or_create_root(uint32_t root, bool locked)
{
    uint32_t ttbr = dart_read(DART_TTBR0 + 4 * root);
    if (locked && (ttbr & DART_TTBR_VALID)) {
        uint64_t paddr = ((uint64_t)(ttbr & ~DART_TTBR_VALID)) << 12;
        dart_l1[root] = phystokv(paddr);
        return true;
    }

    if (locked) {
        return false;
    }

    uint64_t paddr;
    dart_l1[root] = dart_alloc_table(&paddr);
    if (!dart_l1[root] || (paddr >> 43)) {
        return false;
    }
    cache_clean_and_invalidate(dart_l1[root], DART_PAGE_SIZE);
    dart_write(DART_TTBR0 + 4 * root,
               DART_TTBR_VALID | (uint32_t)(paddr >> 12));
    return true;
}

static bool dart_map_page(uint64_t iova, uint64_t paddr)
{
    uint32_t root = (iova >> 36) & 3;
    uint32_t l1_index = (iova >> 25) & 0x7ff;
    uint32_t l2_index = (iova >> 14) & 0x7ff;
    uint64_t *l1 = dart_l1[root];
    uint64_t *l2;
    uint64_t l2_paddr;

    if (l1[l1_index] & DART_PTE_VALID) {
        l2_paddr = l1[l1_index] & DART_PTE_ADDR_MASK;
        l2 = phystokv(l2_paddr);
    } else {
        l2 = dart_alloc_table(&l2_paddr);
        if (!l2) {
            return false;
        }
        l1[l1_index] = (l2_paddr & DART_PTE_ADDR_MASK) | DART_PTE_VALID;
        cache_clean_and_invalidate(l1, DART_PAGE_SIZE);
    }

    uint64_t descriptor = (paddr & DART_PTE_ADDR_MASK) |
                          DART_PTE_SP_END_ALL |
                          DART_PTE_DISABLE_SP |
                          DART_PTE_VALID;
    if (l2[l2_index] & DART_PTE_VALID) {
        return (l2[l2_index] & DART_PTE_ADDR_MASK) ==
               (descriptor & DART_PTE_ADDR_MASK) &&
               (l2[l2_index] & DART_PTE_DISABLE_SP);
    }
    l2[l2_index] = descriptor;
    cache_clean_and_invalidate(l2, DART_PAGE_SIZE);
    return true;
}

bool t8020_usb_dart_map(uint64_t paddr, uint32_t size)
{
    if (!size || paddr + size < paddr) {
        return false;
    }

    dt_node_t *node = dt_get("/arm-io/dart-usb");
    if (!node) {
        return false;
    }
    dart_regs = (volatile uint32_t *)(gIOBase + dt_node_u64(node, "reg", 0));

    bool locked = dart_read(DART_CONFIG) & DART_CONFIG_LOCK;
    dart_write(DART_ENABLED_STREAMS, dart_read(DART_ENABLED_STREAMS) | 1);
    uint64_t first = paddr & ~(DART_PAGE_SIZE - 1);
    uint64_t last = (paddr + size + DART_PAGE_SIZE - 1) &
                    ~(DART_PAGE_SIZE - 1);
    for (uint64_t page = first; page < last; page += DART_PAGE_SIZE) {
        uint64_t iova = (uint32_t)page;
        uint32_t root = (iova >> 36) & 3;
        if (!dart_l1[root] && !dart_load_or_create_root(root, locked)) {
            return false;
        }
        if (!dart_map_page(iova, page)) {
            return false;
        }
    }

    if (locked) {
        if (!(dart_read(DART_TCR0) & DART_TCR_TRANSLATE_ENABLE)) {
            return false;
        }
    } else {
        dart_write(DART_TCR0, DART_TCR_TRANSLATE_ENABLE);
    }

    return dart_invalidate_stream0();
}
