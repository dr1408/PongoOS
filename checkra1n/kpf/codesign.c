/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2026 checkra1n team
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
#include <stdbool.h>
#include <stdint.h>

static bool found_ppl_allow_invalid = false;

static bool
kpf_ppl_allow_invalid_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(found_ppl_allow_invalid)
    {
        panic("kpf_ppl_allow_invalid: Found more than one pmap initializer");
    }

    /*
     * Exact T8020 pmap_create_options_internal final state producer:
     *
     *   mov   w8, #1
     *   sturh w8, [x19, #0xc1]
     *
     * The little-endian halfword store initializes pmap + 0xc1 to one and
     * pmap + 0xc2 (the PPL allow-invalid byte) to zero.  The same w8 is then
     * consumed by the 32-bit store which publishes pmap + 0xb0, the reference
     * count.  Changing only the immediate producer would therefore initialize
     * every pmap with ref_count == 0x101 and prevent final-reference teardown.
     *
     * The object allocator initializes +0xb0 to zero before an object enters
     * the free pool, and final-reference destruction leaves it at zero before
     * recycling.  Preserve the allow-invalid halfword while narrowing the
     * later reference-count store to its low byte.  At this point the object
     * has not yet been published, so the resulting state is exactly:
     *
     *   pmap + 0xc1 == 1
     *   pmap + 0xc2 == 1
     *   pmap + 0xb0 == 1
     */
    if(opcode_stream[0] != 0x6f00e400 || // movi.2d v0, #0
       opcode_stream[1] != 0x3c858260 || // stur q0, [x19, #0x58]
       opcode_stream[2] != 0xf9003e7f || // str xzr, [x19, #0x78]
       opcode_stream[3] != 0xb900827f || // str wzr, [x19, #0x80]
       opcode_stream[4] != 0x780c527f || // sturh wzr, [x19, #0xc5]
       opcode_stream[5] != 0x3c888260 || // stur q0, [x19, #0x88]
       opcode_stream[6] != 0x3d802a60 || // str q0, [x19, #0xa0]
       opcode_stream[7] != 0x3902627f || // strb wzr, [x19, #0x98]
       opcode_stream[8] != 0x52800028 || // mov w8, #1
       opcode_stream[9] != 0x780c1268 || // sturh w8, [x19, #0xc1]
       (opcode_stream[10] != 0x2916fe7f && // stp wzr, wzr, [x19, #0xb4]
        opcode_stream[10] != 0xf80b427f) || // stur xzr, [x19, #0xb4]
       opcode_stream[11] != 0xd5033bbf || // dmb ish
       opcode_stream[12] != 0xb900b268)   // str w8, [x19, #0xb0]
    {
        return false;
    }

    opcode_stream[8] = 0x52802028; // mov w8, #0x101
    opcode_stream[12] = 0x3902c268; // strb w8, [x19, #0xb0]

    found_ppl_allow_invalid = true;
    xnu_pf_disable_patch(patch);
    puts("KPF: Found PPL pmap allow-invalid producer");
    return true;
}

static bool
kpf_ppl_allow_invalid_byte_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(found_ppl_allow_invalid)
    {
        panic("kpf_ppl_allow_invalid: Found more than one pmap initializer");
    }

    /* iOS 18.7.10 stores the two adjacent flags as separate bytes. */
    if(opcode_stream[0] != 0x6f00e400 ||
       opcode_stream[1] != 0x3c858260 ||
       opcode_stream[2] != 0xf9003e7f ||
       opcode_stream[3] != 0xb900827f ||
       opcode_stream[4] != 0x3903167f || // strb wzr, [x19, #0xc5]
       opcode_stream[5] != 0x39031a7f || // strb wzr, [x19, #0xc6]
       opcode_stream[6] != 0x3c888260 ||
       opcode_stream[7] != 0x3d802a60 ||
       opcode_stream[8] != 0x3902627f ||
       opcode_stream[9] != 0x52800028 ||
       opcode_stream[10] != 0x39030668 || // strb w8, [x19, #0xc1]
       opcode_stream[11] != 0x39030a7f || // strb wzr, [x19, #0xc2]
       opcode_stream[12] != 0x2916fe7f ||
       opcode_stream[13] != 0xd5033bbf ||
       opcode_stream[14] != 0xb900b268)
    {
        return false;
    }

    /* Preserve +c1 == 1 and enable only the +c2 allow-invalid byte. */
    opcode_stream[11] = 0x39030a68; // strb w8, [x19, #0xc2]
    found_ppl_allow_invalid = true;
    xnu_pf_disable_patch(patch);
    puts("KPF: Found PPL pmap allow-invalid byte producer");
    return true;
}

static void
kpf_ppl_allow_invalid_patches(xnu_pf_patchset_t *ppl_text_patchset)
{
    uint64_t matches[] =
    {
        0x6f00e400, // movi.2d v0, #0
        0x3c858260, // stur q0, [x19, #0x58]
        0xf9003e7f, // str xzr, [x19, #0x78]
        0xb900827f, // str wzr, [x19, #0x80]
        0x780c527f, // sturh wzr, [x19, #0xc5]
        0x3c888260, // stur q0, [x19, #0x88]
        0x3d802a60, // str q0, [x19, #0xa0]
        0x3902627f, // strb wzr, [x19, #0x98]
        0x52800028, // mov w8, #1
        0x780c1268, // sturh w8, [x19, #0xc1]
        0x2916fe7f, // stp wzr, wzr, [x19, #0xb4]
        0xd5033bbf, // dmb ish
        0xb900b268, // str w8, [x19, #0xb0]
    };
    uint64_t masks[] =
    {
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
    };

    xnu_pf_maskmatch(ppl_text_patchset, "ppl_pmap_allow_invalid",
        matches, masks, sizeof(matches) / sizeof(uint64_t), false,
        (void *)kpf_ppl_allow_invalid_callback);

    /*
     * Darwin 25.3 emits an equivalent 64-bit zero store for pmap + 0xb4.
     * Keep both exact encodings: masking across STP and STUR would admit
     * unrelated stores and would weaken the producer identity.
     */
    matches[10] = 0xf80b427f; // stur xzr, [x19, #0xb4]
    xnu_pf_maskmatch(ppl_text_patchset, "ppl_pmap_allow_invalid_stur",
        matches, masks, sizeof(matches) / sizeof(uint64_t), false,
        (void *)kpf_ppl_allow_invalid_callback);

    /*
     * iOS 18.7.10 (Darwin 24.6) emits byte stores for +c5/+c6 and +c1/+c2
     * instead of the halfword stores used by the tvOS 26 profile.
     */
    uint64_t byte_matches[] =
    {
        0x6f00e400, 0x3c858260, 0xf9003e7f, 0xb900827f,
        0x3903167f, 0x39031a7f, 0x3c888260, 0x3d802a60,
        0x3902627f, 0x52800028, 0x39030668, 0x39030a7f,
        0x2916fe7f, 0xd5033bbf, 0xb900b268,
    };
    uint64_t byte_masks[] =
    {
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff,
    };
    xnu_pf_maskmatch(ppl_text_patchset, "ppl_pmap_allow_invalid_bytes",
        byte_matches, byte_masks, sizeof(byte_matches) / sizeof(uint64_t), false,
        (void *)kpf_ppl_allow_invalid_byte_callback);
}

static void
kpf_codesign_finish(struct mach_header_64 *hdr)
{
    (void)hdr;
    if(!found_ppl_allow_invalid)
    {
        panic("Missing patch: PPL pmap allow-invalid producer");
    }
}

kpf_component_t kpf_codesign =
{
    .finish = kpf_codesign_finish,
    .patches =
    {
        { NULL, "__PPLTEXT", "__text", XNU_PF_ACCESS_32BIT, kpf_ppl_allow_invalid_patches },
        {},
    },
};
