/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2023 checkra1n team
 *
 * This file is part of pongoOS.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "kpf.h"
#include <pongo.h>
#include <xnu/xnu.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool nvram_patch_found = false;

/*
 * iOS 18.7.10 / iPhone11,8 (22H374) uses a newer, inlined guard around the
 * NVRAM permission-table walk.  The older "aapl,pci" table signature is not
 * present in this layout.  In the XR kernel the bit-2 test is the
 * kernel-only permission gate; removing it is the equivalent of the older
 * patch's tbnz removal.
 */
static bool kpf_nvram_xr_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(nvram_patch_found)
    {
        panic("kpf_nvram_unlock: Found twice");
    }

    /*
     *   ldr  w8, [x21, #0x10]
     *   mov  w9, #5
     *   and  w8, w8, w9
     *   cmp  w8, #1
     *   b.ne ...
     *   ldr  x8, [x16, #0x20]
     *   cbz  x8, ...
     *   ldr  w8, [x21, #0x10]
     *   tbz  w8, #1, ...
     *   ldr  x9, [x16, #0x18]
     *   tbnz w8, #2, ...       <-- kernel-only gate
     */
    const uint32_t expected[] = {
        0xb94012a8, 0x528000a9, 0x0a090108, 0x7100051f,
        0x54000061, 0xf9401208, 0xb4000508, 0xb94012a8,
        0x36080368, 0xf9400e09, 0x37100308,
    };
    const uint32_t masks[] = {
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff,
    };

    for(size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); i++)
    {
        if((opcode_stream[i] & masks[i]) != (expected[i] & masks[i]))
        {
            return false;
        }
    }

    opcode_stream[10] = NOP;
    nvram_patch_found = true;
    puts("KPF: Found NVRAM unlock (XR 18.7.10)");
    return true;
}

static bool kpf_nvram_table_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(nvram_patch_found)
    {
        panic("kpf_nvram_unlock: Found twice");
    }

    uint32_t reg = opcode_stream[0] & 0x1f;
    if((opcode_stream[1] & 0x3ff) != (reg | (reg << 5)))
    {
        return false;
    }

    const char *str = (const char *)(((uint64_t)(opcode_stream + 2) & ~0xfffULL) +
        adrp_off(opcode_stream[2]) + ((opcode_stream[3] >> 10) & 0xfff));
    if(strcmp(str, "aapl,pci") != 0)
    {
        return false;
    }

    uint32_t *ldr = opcode_stream + 9;
    uint32_t *tbnz = find_next_insn(ldr + 1, 10,
        0x37100000 | (ldr[0] & 0x1f), 0xfff8001f);
    if(!tbnz)
    {
        panic_at(opcode_stream, "kpf_nvram_unlock: Failed to find tbnz");
    }

    *tbnz = NOP;
    nvram_patch_found = true;
    puts("KPF: Found NVRAM unlock");
    return true;
}

static void kpf_nvram_patches(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    /* XR 18.7.10 / 22H374 exact guard at com.apple.kernel+0x11c878. */
    uint64_t xr_matches[] =
    {
        0xb94012a8, 0x528000a9, 0x0a090108, 0x7100051f,
        0x54000061, 0xf9401208, 0xb4000508, 0xb94012a8,
        0x36080368, 0xf9400e09, 0x37100308,
    };
    uint64_t xr_masks[] =
    {
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "nvram_unlock_xr_18710",
        xr_matches, xr_masks, sizeof(xr_matches) / sizeof(xr_matches[0]),
        false, (void *)kpf_nvram_xr_callback);

    /*
     * T8020/J305 uses the iOS 16.4-style permission table. The match locates
     * the "aapl,pci" table walk and the callback removes only the later
     * kernel-only permission decision. No function entry, return, LR, or
     * callable pointer is changed.
     */
    uint64_t matches[] =
    {
        0x90000010, // adrp xN, 0x...
        0x91000210, // add xN, xN, 0x...
        0x90000000, // adrp x0, 0x...
        0x91000000, // add x0, x0, 0x...
        0xaa1003e1, // mov x1, x{16-31}
        0x94000000, // bl strcmp
        0x34000060, // cbz w0, .+12
        0xf8400c00, // ldr x0, [xN, ...]!
        0xb5ffff80, // cbnz x0, .-16
        0xf9400610, // ldr x{16-31}, [xN, 8]
    };
    uint64_t masks[] =
    {
        0x9f000010,
        0xffc00210,
        0x9f00001f,
        0xffc003ff,
        0xfff0ffff,
        0xfc000000,
        0xffffffff,
        0xffe00c1f,
        0xffffffff,
        0xfffffe10,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "nvram_unlock", matches, masks,
        sizeof(matches) / sizeof(matches[0]), false,
        (void *)kpf_nvram_table_callback);
}

static void kpf_nvram_finish(struct mach_header_64 *hdr)
{
#ifdef DEV_BUILD
    if(!nvram_patch_found)
    {
        panic("Missing patch: nvram_unlock");
    }
#endif
}

kpf_component_t kpf_nvram =
{
    .finish = kpf_nvram_finish,
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_nvram_patches },
        {},
    },
};
