/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2023 checkra1n team
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
 *
 */

#include "kpf.h"
#include <pongo.h>
#include <xnu/xnu.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

static bool found_amfi_trustcache = false;
static bool found_ppl_trustcache = false;

static bool kpf_trustcache_new_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(found_amfi_trustcache)
    {
        panic("kpf_trustcache: Found more then one trustcache func");
    }
    found_amfi_trustcache = true;

    // Seek backwards to start of func. This func uses local stack space,
    // so we should always have a "sub sp, sp, 0x..." instruction.
    uint32_t *start = find_prev_insn(opcode_stream, 20, 0xd10003ff, 0xffc003ff);
    if(!start)
    {
        panic_at(opcode_stream, "kpf_trustcache: Failed to find start of function");
    }

    if(start[-1] != 0xd503237f) // pacibsp
    {
        panic_at(start, "kpf_trustcache: missing arm64e entry PAC");
    }

    // Replace the true entry, including pacibsp. LR remains unsigned, so the
    // replacement returns with an ordinary RET.
    start[-1] = 0xd2800020; // mov x0, 1
    start[0]  = 0xb4000042; // cbz x2, .+0x8
    start[1]  = 0xf9000040; // str x0, [x2]
    start[2]  = RET;        // ret

    puts("KPF: Found trustcache");
    return true;
}

static bool kpf_ppl_trustcache_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(found_ppl_trustcache)
    {
        panic("kpf_ppl_trustcache: Found more than one loaded trustcache decision");
    }

    // Exact T8020 PPL helper contract:
    //
    //   copy the 20-byte CodeDirectory hash to the local safe buffer
    //   query kTCQueryTypeLoadable (2)
    //   return query_result == KERN_SUCCESS
    //
    // Keep the query, frame, stack canary and RETAB intact. Only change the
    // boolean policy result so the caller remains the owner of trust state 9
    // (PMAP_CS_IN_LOADED_TRUST_CACHE).
    if(opcode_stream[-4] != 0x3dc00000 || // ldr q0, [x0]
       opcode_stream[-3] != 0x3d8003e0 || // str q0, [sp]
       opcode_stream[-2] != 0xb9401008 || // ldr w8, [x0, #0x10]
       opcode_stream[-1] != 0xb90013e8 || // str w8, [sp, #0x10]
       opcode_stream[5]  != 0x1a9f17e0)  // cset w0, eq
    {
        return false;
    }

    uint32_t *frame = find_prev_insn(opcode_stream, 16, 0xd10003ff, 0xffc003ff);
    if(!frame || frame[-1] != 0xd503237f) // pacibsp
    {
        panic_at(opcode_stream, "kpf_ppl_trustcache: missing arm64e entry PAC/frame");
    }

    uint32_t *epilogue = find_next_insn(opcode_stream + 6, 16, 0xd65f0fff, 0xffffffff);
    if(!epilogue)
    {
        panic_at(opcode_stream, "kpf_ppl_trustcache: missing RETAB");
    }

    opcode_stream[5] = 0x52800020; // mov w0, #1
    found_ppl_trustcache = true;
    xnu_pf_disable_patch(patch);
    puts("KPF: Found PPL loaded trustcache decision");
    return true;
}

static void kpf_ppl_trustcache_patches(xnu_pf_patchset_t *ppl_text_patchset)
{
    uint64_t matches[] =
    {
        0x910003e1, // mov x1, sp
        0x52800040, // mov w0, #2 (kTCQueryTypeLoadable)
        0xd2800002, // mov x2, #0
        0x94000000, // bl pmap_query_trust_cache_safe
        0x7100001f, // cmp w0, #0
        0x1a9f17e0, // cset w0, eq
    };
    uint64_t masks[] =
    {
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xfc000000,
        0xffffffff,
        0xffffffff,
    };
    xnu_pf_maskmatch(ppl_text_patchset, "ppl_loaded_trustcache",
        matches, masks, sizeof(matches) / sizeof(uint64_t), false,
        (void *)kpf_ppl_trustcache_callback);
}

static void kpf_trustcache_patches(xnu_pf_patchset_t *amfi_text_exec_patchset)
{
    // T8020 uses the query_trust_cache form below:
    //
    // 0xfffffff005684a34      ffc300d1       sub sp, sp, 0x30
    // 0xfffffff005684a38      f44f01a9       stp x20, x19, [sp, 0x10]
    // 0xfffffff005684a3c      fd7b02a9       stp x29, x30, [sp, 0x20]
    // 0xfffffff005684a40      fd830091       add x29, sp, 0x20
    // 0xfffffff005684a44      f30302aa       mov x19, x2
    // 0xfffffff005684a48      ff7f00a9       stp xzr, xzr, [sp]
    // 0xfffffff005684a4c      e2030091       mov x2, sp
    // 0xfffffff005684a50      e86a0094       bl query_trust_cache
    // 0xfffffff005684a54      f40300aa       mov x20, x0
    // 0xfffffff005684a58      c0000035       cbnz w0, 0xfffffff005684a70
    // 0xfffffff005684a5c      530000b4       cbz x19, 0xfffffff005684a64
    // 0xfffffff005684a60      7f0200f9       str xzr, [x19]
    // 0xfffffff005684a64      e0030091       mov x0, sp
    // 0xfffffff005684a68      e10313aa       mov x1, x19
    // 0xfffffff005684a6c      5e310094       bl trustCacheQueryGetFlags
    // 0xfffffff005684a70      9f020071       cmp w20, 0
    // 0xfffffff005684a74      e0179f1a       cset w0, eq
    // 0xfffffff005684a78      fd7b42a9       ldp x29, x30, [sp, 0x20]
    // 0xfffffff005684a7c      f44f41a9       ldp x20, x19, [sp, 0x10]
    // 0xfffffff005684a80      ffc30091       add sp, sp, 0x30
    // 0xfffffff005684a84      c0035fd6       ret
    //
    // Can be found trivially with this:
    // /x e0030091e10313aa000000949f020071e0179f1a:ffffffffffffffff000000fcffffffffffffffff
    uint64_t matches_new[] =
    {
        0x910003e0, // mov x0, sp
        0xaa1303e1, // mov x1, x19
        0x94000000, // bl trustCacheQueryGetFlags
        0x7100029f, // cmp w20, 0
        0x1a9f17e0, // cset w0, eq
    };
    uint64_t masks_new[] =
    {
        0xffffffff,
        0xffffffff,
        0xfc000000,
        0xffffffff,
        0xffffffff,
    };
    xnu_pf_maskmatch(amfi_text_exec_patchset, "trustcache", matches_new, masks_new, sizeof(matches_new)/sizeof(uint64_t), false, (void*)kpf_trustcache_new_callback);
}

static void kpf_trustcache_finish(struct mach_header_64 *hdr)
{
    if(!found_amfi_trustcache)
    {
        panic("Missing patch: AMFI trustcache");
    }
    if(!found_ppl_trustcache)
    {
        panic("Missing patch: PPL loaded trustcache");
    }
}

kpf_component_t kpf_trustcache =
{
    .finish = kpf_trustcache_finish,
    .patches =
    {
        { NULL, "__PPLTEXT", "__text", XNU_PF_ACCESS_32BIT, kpf_ppl_trustcache_patches },
        { "com.apple.driver.AppleMobileFileIntegrity", "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_trustcache_patches },
        {},
    },
};
