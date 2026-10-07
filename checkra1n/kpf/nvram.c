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

static bool kpf_nvram_table_common_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream, uint32_t *ldr)
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

static bool kpf_nvram_table_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    return kpf_nvram_table_common_callback(patch, opcode_stream, opcode_stream + 9);
}

static bool kpf_nvram_table_xr_18710_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    return kpf_nvram_table_common_callback(patch, opcode_stream, opcode_stream + 13);
}

static void kpf_nvram_patches(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
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

    if(gKernelVersion.darwinMajor == 24 && gKernelVersion.darwinMinor == 6 &&
       gKernelVersion.xnuMajor == 11417 && gKernelVersion.xnuMinor == 140 &&
       gKernelVersion.xnuPatch == 69 && gKernelVersion.xnuFlags == 706 &&
       gKernelVersion.xnuRevision == 66 && gKernelVersion.xnuRun == 1 &&
       gKernelVersion.machineConfig == 0x8020 && xnu_platform() == PLATFORM_IOS)
    {
        // XR 18.7.10 uses the iOS 18.4-style table walker: the permission
        // load is instruction 13, followed by a tbnz of its kernel-only bit.
        uint64_t xr_matches[] = {
            0x90000010, 0x91000210, 0x90000000, 0x91000000,
            0xaa1003e1, 0x94000000, 0x340000c0, 0x91000200,
            0xf9400200, 0xaa0003f0, 0xb5ffff40, 0x14000002,
            0xaa1003e0, 0xf9400410,
        };
        uint64_t xr_masks[] = {
            0x9f000010, 0xffc00210, 0x9f00001f, 0xffc003ff,
            0xfff0ffff, 0xfc000000, 0xffffffff, 0xffc00210,
            0xffc0021f, 0xfff0fff0, 0xffffffff, 0xffffffff,
            0xfff0fff0, 0xfffffe10,
        };
        xnu_pf_maskmatch(xnu_text_exec_patchset, "nvram_unlock_xr_18710",
            xr_matches, xr_masks, sizeof(xr_matches) / sizeof(xr_matches[0]),
            false, (void *)kpf_nvram_table_xr_18710_callback);
    }
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
