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

/* iOS 18.7.10 inlines the entitlement query through a helper instead of
 * using the authenticated OSEntitlements vtable sequence below. */
static bool
kpf_ppl_debugger_mapping_xr_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(found_ppl_debugger_mapping)
    {
        panic("kpf_ppl_debugger_mapping: Found more than one entitlement gate");
    }

    uint64_t entitlement_va =
        (xnu_ptr_to_va(opcode_stream) & ~0xfffULL) +
        adrp_off(opcode_stream[0]) + ((opcode_stream[1] >> 10) & 0xfff);
    if(strcmp((const char *)xnu_va_to_ptr(entitlement_va),
              "com.apple.private.cs.debugger") != 0)
    {
        return false;
    }

    /* The XR sequence is:
     *   ... query entitlement into w22 ...
     *   tbnz w22, #0, allow
     *   mov  w0, #0x32
     *
     * Make the gate unconditional while retaining the pmap checks and the
     * subsequent PPL association logic. */
    uint32_t *gate = find_next_insn(opcode_stream, 32,
        0x37000016, 0xfff8001f);
    if(!gate)
    {
        return false;
    }

    int32_t delta = sxt32(gate[0] >> 5, 19);
    if(gate + delta != gate + 5)
    {
        return false;
    }

    *gate = 0x14000005; // b +0x14, the original tbnz target
    found_ppl_debugger_mapping = true;
    xnu_pf_disable_patch(patch);
    puts("KPF: Found PPL debugger mapping entitlement gate (XR 18.7.10)");
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

    if((opcode_stream[0] & 0xffc003ff) != 0xf9400108 || // ldr x8, [x8, #vtable offset]
       (opcode_stream[1] & 0x9f00001f) != 0x90000001 || // adrp x1, entitlement
       (opcode_stream[2] & 0xffc003ff) != 0x91000021 || // add x1, x1, #...
       (opcode_stream[3] & 0xffe00000) != 0xd2800000 || // mov xN, discriminator
       (opcode_stream[4] & 0xffffffe0) != 0xd73f0900 || // blraa x8, xN
       (opcode_stream[4] & 0x1f) != (opcode_stream[3] & 0x1f) ||
       (opcode_stream[5] & 0xff00001f) != 0x34000000 || // cbz w0, associate_cow
       opcode_stream[6] != 0x528006a0)                  // mov w0, #KERN_DENIED
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
    if((associate_cow[0] & 0xffe0ffff) != 0xaa0003e0 || // mov x0, xPmap
       associate_cow[1] != 0x92800021 || // mov x1, #-2 (PMAP_CS_ASSOCIATE_COW)
       (associate_cow[2] & 0xffe0ffff) != 0xaa0003e2 || // mov x2, xAddress
       (associate_cow[3] & 0xffe0ffff) != 0xaa0003e3 || // mov x3, xSize
       associate_cow[4] != 0xd2800004) // mov x4, #0
    {
        return false;
    }

    bool direct_call =
        (associate_cow[5] & 0xfc000000) == 0x94000000 && // bl pmap_cs_associate
        associate_cow[6] == 0x7100181f;                  // cmp w0, #KERN_ABORTED

    // Older Darwin 25 builds restore and authenticate the frame, then tail
    // call pmap_cs_associate instead of returning through this function.
    uint32_t *autibsp = find_next_insn(associate_cow + 5, 12, 0xd50323ff, 0xffffffff);
    bool tail_call = autibsp &&
        autibsp[1] == 0xca1e07d0 &&                       // eor x16, x30, x30, lsl #1
        (autibsp[2] & 0xfff8001f) == 0xb6f00010 &&       // tbz x16, #62, ...
        autibsp[3] == 0xd4388e20 &&                       // brk #0xc471
        (autibsp[4] & 0xfc000000) == 0x14000000;         // b pmap_cs_associate
    if(!direct_call && !tail_call)
    {
        return false;
    }

    uint32_t pmap_reg = (associate_cow[0] >> 16) & 0x1f;
    uint32_t address_reg = (associate_cow[2] >> 16) & 0x1f;
    uint32_t size_reg = (associate_cow[3] >> 16) & 0x1f;
    uint32_t *entry = find_prev_insn(opcode_stream, 0x40, 0xd503237f, 0xffffffff); // pacibsp
    uint32_t *pmap_producer = find_prev_insn(opcode_stream, 0x40, 0xaa0003e0 | pmap_reg, 0xffffffff);
    uint32_t *address_producer = find_prev_insn(opcode_stream, 0x40, 0xaa0103e0 | address_reg, 0xffffffff);
    uint32_t *size_producer = find_prev_insn(opcode_stream, 0x40, 0xaa0203e0 | size_reg, 0xffffffff);
    if(!entry ||
       pmap_reg < 19 || pmap_reg > 28 ||
       address_reg < 19 || address_reg > 28 ||
       size_reg < 19 || size_reg > 28 ||
       pmap_reg == address_reg || pmap_reg == size_reg || address_reg == size_reg ||
       !pmap_producer || pmap_producer < entry ||
       !address_producer || address_producer < entry ||
       !size_producer || size_producer < entry)
    {
        return false;
    }

    int32_t associate_cow_delta = sxt32(opcode_stream[5] >> 5, 19);
    opcode_stream[5] = 0x14000000 | (associate_cow_delta & 0x03ffffff); // b associate_cow

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
    uint64_t xr_matches[] = {
        0xd0ff87f7, // adrp x23, com.apple.private.cs.debugger
        0x910216f7, // add x23, x23, #0x85
    };
    uint64_t xr_masks[] = { 0xffffffff, 0xffffffff };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "ppl_debugger_mapping_xr_18710",
        xr_matches, xr_masks, sizeof(xr_matches) / sizeof(uint64_t), false,
        (void *)kpf_ppl_debugger_mapping_xr_callback);

    //kpf_aprr_patch(xnu_text_exec_patchset);

    uint64_t matches[] =
    {
        0xf9400108, // ldr x8, [x8, #vtable offset]
        0x90000001, // adrp x1, entitlement
        0x91000021, // add x1, x1, #...
        0xd2800000, // mov xN, discriminator
        0xd73f0900, // blraa x8, xN
        0x34000000, // cbz w0, associate_cow
        0x528006a0, // mov w0, #KERN_DENIED
    };
    uint64_t masks[] =
    {
        0xffc003ff,
        0x9f00001f,
        0xffc003ff,
        0xffe00000,
        0xffffffe0,
        0xff00001f,
        0xffffffff,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "ppl_debugger_mapping",
        matches, masks, sizeof(matches) / sizeof(uint64_t), false,
        (void *)kpf_ppl_debugger_mapping_callback);
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
