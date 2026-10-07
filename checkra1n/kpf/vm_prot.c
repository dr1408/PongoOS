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
#include <xnu/xnu.h>

static bool found_ppl_debugger_mapping = false;

static bool
kpf_ppl_debugger_mapping_ios18_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    // iOS 18 variant: the baseline cbz/mov/b triple is replaced by
    //   cmp w0, #0 ; cset wN, eq ; b .+imm
    // and the subsequent allow/deny decision reads wN downstream. Force
    // success by rewriting `cset wN, eq` into `mov wN, #1`. Keep the PAC
    // call and surrounding frame intact so authentication state is sound.
    if(found_ppl_debugger_mapping)
    {
        // Older matcher already succeeded; don't double-patch.
        return false;
    }

    uint64_t entitlement_va =
        (xnu_ptr_to_va(opcode_stream + 1) & ~0xfffULL) +
        adrp_off(opcode_stream[1]) +
        ((opcode_stream[2] >> 10) & 0xfff);
    const char *entitlement = xnu_va_to_ptr(entitlement_va);
    if(strcmp(entitlement, "com.apple.private.cs.debugger") != 0)
    {
        return false;
    }

    // cset wN, eq -> mov wN, #1 (MOVZ Wd, #1, lsl 0)
    uint32_t rd = opcode_stream[6] & 0x1fu;
    opcode_stream[6] = 0x52800020u | rd;

    found_ppl_debugger_mapping = true;
    xnu_pf_disable_patch(patch);
    puts("KPF: Found PPL debugger mapping entitlement gate (iOS 18)");
    return true;
}

static bool
kpf_ppl_debugger_mapping_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    /*
     * T8020 ppl_associate_debug_region() inlines
     * IOCurrentTaskHasEntitlement().  The authenticated call below is the
     * OSEntitlements.queryEntitlementBooleanWithProc() vtable call, whose ABI
     * returns kern_return_t: KERN_SUCCESS (zero) means that the boolean
     * entitlement exists and is true.
     *
     * Keep the task/proc lookup, authenticated entitlement query, COW
     * association, and PPL call intact.  Change only the branch which rejects
     * a nonzero query result.
     */
    if(found_ppl_debugger_mapping)
    {
        panic("kpf_ppl_debugger_mapping: Found more than one entitlement gate");
    }

    if(opcode_stream[0] != 0xf940e108 ||                 // ldr x8, [x8, #0x1c0]
       (opcode_stream[1] & 0x9f00001f) != 0x90000001 || // adrp x1, entitlement
       (opcode_stream[2] & 0xffc003ff) != 0x91000021 || // add x1, x1, #...
       (opcode_stream[3] & 0xffe0001f) != 0xd2800011 || // mov x17, discriminator
       opcode_stream[4] != 0xd73f0911 ||                // blraa x8, x17
       opcode_stream[5] != 0x34000260 ||                // cbz w0, associate_cow
       opcode_stream[6] != 0x528006a0 ||                // mov w0, #KERN_DENIED
       (opcode_stream[7] & 0xfc000000) != 0x14000000)   // b return
    {
        return false;
    }

    uint64_t entitlement_va =
        (xnu_ptr_to_va(opcode_stream + 1) & ~0xfffULL) +
        adrp_off(opcode_stream[1]) +
        ((opcode_stream[2] >> 10) & 0xfff);
    const char *entitlement = xnu_va_to_ptr(entitlement_va);
    if(strcmp(entitlement, "com.apple.private.cs.debugger") != 0)
    {
        return false;
    }

    uint32_t *associate_cow = opcode_stream + 5 +
        sxt32(opcode_stream[5] >> 5, 19);
    if(associate_cow[0] != 0xaa1403e0 || // mov x0, x20 (pmap)
       associate_cow[1] != 0x92800021 || // mov x1, #-2 (PMAP_CS_ASSOCIATE_COW)
       associate_cow[2] != 0xaa1503e2 || // mov x2, x21 (region address)
       associate_cow[3] != 0xaa1303e3 || // mov x3, x19 (region size)
       associate_cow[4] != 0xd2800004 || // mov x4, #0
       (associate_cow[5] & 0xfc000000) != 0x94000000 || // bl pmap_cs_associate
       associate_cow[6] != 0x7100181f)   // cmp w0, #KERN_ABORTED
    {
        return false;
    }

    opcode_stream[5] = 0x14000013; // b associate_cow

    found_ppl_debugger_mapping = true;
    xnu_pf_disable_patch(patch);
    puts("KPF: Found PPL debugger mapping entitlement gate");
    return true;
}

#if 0
// XXX doesn't work like this, needs new strat

static bool kpf_aprr_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    // We recognise two types of matches here.
    // 1. Loads from thread state of two forms:
    //
    // 0xfffffff007ce9c2c      e8f23cd5       mrs x8, s3_4_c15_c2_7
    // 0xfffffff007ce9c30      a86a02f9       str x8, [x21, 0x4d0]
    // 0xfffffff007ce9c34      686a42f9       ldr x8, [x19, 0x4d0]
    // 0xfffffff007ce9c38      e8f21cd5       msr s3_4_c15_c2_7, x8
    //
    // 0xfffffff007b7ed5c      e9f23cd5       mrs x9, s3_4_c15_c2_7
    // 0xfffffff007b7ed60      a97202f9       str x9, [x21, 0x4e0]
    // 0xfffffff007b7ed64      687242f9       ldr x8, [x19, 0x4e0]
    // 0xfffffff007b7ed68      3f0108eb       cmp x9, x8
    // 0xfffffff007b7ed6c      40000054       b.eq 0xfffffff007b7ed74
    // 0xfffffff007b7ed70      e8f21cd5       msr s3_4_c15_c2_7, x8
    //
    // 0xfffffff00733bc0c      e9f23cd5       mrs x9, s3_4_c15_c2_7
    // 0xfffffff00733bc10      689a40f9       ldr x8, [x19, 0x130]
    // 0xfffffff00733bc14      3f0108eb       cmp x9, x8
    // 0xfffffff00733bc18      40000054       b.eq 0xfffffff00733bc20
    // 0xfffffff00733bc1c      e8f21cd5       msr s3_4_c15_c2_7, x8
    //
    // We ignore these.
    if
    (
        (
            (opcode_stream[-3] & 0xffffffe0) == 0xd53cf2e0 && // mrs x*, s3_4_c15_c2_7
            (opcode_stream[-2] & 0xffc00000) == 0xf9000000 && // str x*, [x*, 0x...]
            (opcode_stream[-1] & 0xffc00000) == 0xf9400000    // ldr x*, [x*, 0x...]
        )
        ||
        (
            (opcode_stream[-5] & 0xffffffe0) == 0xd53cf2e0 && // mrs x*, s3_4_c15_c2_7
            (opcode_stream[-4] & 0xffc00000) == 0xf9000000 && // str x*, [x*, 0x...]
            (opcode_stream[-3] & 0xffc00000) == 0xf9400000 && // ldr x*, [x*, 0x...]
            (opcode_stream[-2] & 0xffe0fc1f) == 0xeb00001f && // cmp x*, x*
            (opcode_stream[-1] & 0xff00001f) == 0x54000000    // b.eq 0x...
        )
        ||
        (
            (opcode_stream[-4] & 0xffffffe0) == 0xd53cf2e0 && // mrs x*, s3_4_c15_c2_7
            (opcode_stream[-3] & 0xffc00000) == 0xf9400000 && // ldr x*, [x*, 0x...]
            (opcode_stream[-2] & 0xffe0fc1f) == 0xeb00001f && // cmp x*, x*
            (opcode_stream[-1] & 0xff00001f) == 0x54000000    // b.eq 0x...
        )
    )
    {
        DEVLOG("Ignoring APRR load from thread state at 0x%llx", xnu_ptr_to_va(opcode_stream));
        return false;
    }
    // 2. Immediates of two forms:
    //
    // 0xfffffff0071c046c      4046e6f2       movk x0, 0x3232, lsl 48
    // 0xfffffff0071c0470      c0cecef2       movk x0, 0x7676, lsl 32
    // 0xfffffff0071c0474      0042a2f2       movk x0, 0x1210, lsl 16
    // 0xfffffff0071c0478      c0ce8ef2       movk x0, 0x7676
    // 0xfffffff0071c047c      e0f21cd5       msr s3_4_c15_c2_7, x0
    //
    // 0xfffffff007320f48      cace8ed2       mov x10, 0x7676
    // 0xfffffff007320f4c      0a42a2f2       movk x10, 0x1210, lsl 16
    // 0xfffffff007320f50      cacecef2       movk x10, 0x7676, lsl 32
    // 0xfffffff007320f54      4a46e6f2       movk x10, 0x3232, lsl 48
    // 0xfffffff007320f58      eaf21cd5       msr s3_4_c15_c2_7, x10
    //
    // Here we patch 0x1210 -> 0x1010.
    // NOTE: The first block really starts with "movk", it's hand-rolled asm.
    uint32_t *op = NULL;
    if
    (
        (opcode_stream[-4] & 0xffffffe0) == 0xf2e64640 && // movk x*, 0x3232, lsl 48
        (opcode_stream[-3] & 0xffffffe0) == 0xf2cecec0 && // movk x*, 0x7676, lsl 32
        (opcode_stream[-2] & 0xffffffe0) == 0xf2a24200 && // movk x*, 0x1210, lsl 16
        (opcode_stream[-1] & 0xffffffe0) == 0xf28ecec0    // movk x*, 0x7676
    )
    {
        op = opcode_stream - 2;
    }
    else if
    (
        (opcode_stream[-4] & 0xffffffe0) == 0xd28ecec0 && // mov x*, 0x7676
        (opcode_stream[-3] & 0xffffffe0) == 0xf2a24200 && // movk x*, 0x1210, lsl 16
        (opcode_stream[-2] & 0xffffffe0) == 0xf2cecec0 && // movk x*, 0x7676, lsl 32
        (opcode_stream[-1] & 0xffffffe0) == 0xf2e64640    // movk x*, 0x3232, lsl 48
    )
    {
        op = opcode_stream - 3;
    }
    else
    {
        panic_at(opcode_stream, "kpf_aprr: Unknown instruction sequence");
    }

    puts("KPF: Found APRR load");
    *op = (*op & 0xffe0001f) | (0x1010 << 5);
    return true;
}

static void kpf_aprr_patch(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    // The vm_map_protect patch allows setting RWX permissions at the page table level,
    // but on A11 APRR interferes with this by stripping the write bit via its
    // default register values. So we patch the default to allow RWX.
    // Applications that write to this register should be unaffected.

    // Special register, trivial match.
    // /x e0f21cd5:e0ffffff
    uint64_t matches[] =
    {
        0xd51cf2e0, // msr s3_4_c15_c2_7, xN
    };
    uint64_t masks[] =
    {
        0xffffffe0,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "aprr", matches, masks, sizeof(matches)/sizeof(uint64_t), false, (void*)kpf_aprr_callback);
}
#endif

static void kpf_vm_prot_patches(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    //kpf_aprr_patch(xnu_text_exec_patchset);

    uint64_t matches[] =
    {
        0xf940e108, // ldr x8, [x8, #0x1c0]
        0x90000001, // adrp x1, entitlement
        0x91000021, // add x1, x1, #...
        0xd2800011, // mov x17, discriminator
        0xd73f0911, // blraa x8, x17
        0x34000260, // cbz w0, associate_cow
        0x528006a0, // mov w0, #KERN_DENIED
        0x14000000, // b return
    };
    uint64_t masks[] =
    {
        0xffffffff,
        0x9f00001f,
        0xffc003ff,
        0xffe0001f,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xfc000000,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "ppl_debugger_mapping",
        matches, masks, sizeof(matches) / sizeof(uint64_t), false,
        (void *)kpf_ppl_debugger_mapping_callback);

    // iOS 18.7.10 restructures the entitlement gate. The old code was
    //   cbz w0, .associate_cow ; mov w0, #KERN_DENIED ; b .return
    // Observed on iPhone11,8 22H374 at VA 0xfffffff0083288c4 it is
    //   cmp w0, #0 ; cset wN, eq ; b .+8
    // and the allow/deny decision is pushed downstream via wN. The LDR
    // vtable offset also moved from 0x1c0 to 0x1b0 and the BLRAA uses
    // register pairs beyond (x8,x16). Match that iOS 18 shape and in the
    // callback overwrite `cset wN, eq` with `mov wN, #1` so the downstream
    // consumer treats the entitlement query as always-successful.
    uint64_t ios18_matches[] =
    {
        0xf9400108, // ldr x8, [x8, #imm]
        0x90000001, // adrp x1, entitlement
        0x91000021, // add x1, x1, #...
        0xd2800011, // mov x17, discriminator
        0xd73f0800, // blraa xN, xM (any pointer reg, any modifier reg)
        0x7100001f, // cmp w0, #0
        0x1a9f17e0, // cset wN, eq
        0x14000000, // b .+imm
    };
    uint64_t ios18_masks[] =
    {
        0xffc003ff, // keep opcode + Rt=x8 + Rn=x8, wildcard imm12
        0x9f00001f,
        0xffc003ff,
        0xffe0001f,
        0xfffffc00, // keep opcode, wildcard Rn (9:5) + Rm (4:0)
        0xffffffff,
        0xffffffe0, // keep opcode + cond=EQ + Rn=Rm=WZR, wildcard Rd
        0xfc000000,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "ppl_debugger_mapping_ios18",
        ios18_matches, ios18_masks, sizeof(ios18_matches) / sizeof(uint64_t), false,
        (void *)kpf_ppl_debugger_mapping_ios18_callback);
}

static void kpf_vm_prot_finish(struct mach_header_64 *hdr)
{
    (void)hdr;
    if(!found_ppl_debugger_mapping)
    {
        panic("Missing patch: PPL debugger mapping entitlement gate");
    }
}

kpf_component_t kpf_vm_prot =
{
    .finish = kpf_vm_prot_finish,
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_vm_prot_patches },
        {},
    },
};
