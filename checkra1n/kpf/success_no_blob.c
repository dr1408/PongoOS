/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2026 checkra1n team
 *
 * This file is part of pongoOS.
 */

#include "kpf.h"
#include <pongo.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * iOS 18.7.10 removed the retry loop that tvOS 26.6 still has at the
 * "success, but no blob!" diagnostic emitted by the LC_CODE_SIGNATURE handler
 * (sub_A980 → ubc_cs_blob_add).  When ubc_cs_blob_add returns 0 but leaves the
 * out-blob NULL, iOS 18 fatally sets w26 = LOAD_FAILURE (4) and bails, which
 * propagates to vfork_exec_internal and is emitted as OS_REASON_EXEC
 * namespace 9, code 4 against launchd on first exec.  The equivalent tvOS 26.6
 * code loops around via `tbz w27, #0x1f, retry`.
 *
 * The firing site on XR 18.7.10 looks like:
 *
 *   adrp x8, "mach_loader.c"
 *   add  x8, x8, #0x7cf
 *   mov  w9, #0xe2a           ; 3626
 *   stp  x8, x9, [sp]
 *   adrp x0, "success, but no blob! @%s:%d"
 *   add  x0, x0, #0x7b2
 *   bl   _printf
 *   mov  w26, #4              ; LOAD_FAILURE
 *   b    <cleanup>            ; → return 4
 *
 * The nine-element anchor above is unique to that call site (only one
 * line-3626/mach_loader.c printf exists in the kernel).  The adjacent "blob
 * non-NULL" success path at offset -0x1EC from the final branch loads blob
 * fields unconditionally, so we cannot simply flip the earlier `cbnz x8` to
 * `b` – doing so NULL-derefs.  Instead we rewrite the terminal two words to:
 *
 *   mov  w26, #0              ; LOAD_SUCCESS
 *   b    <loc_837aba0>        ; skip blob derefs, jump into "move on" tail
 *
 * The "move on" tail (loc_837aba0 in the uncollided layout) begins with
 * `ldr x1, [sp, #0x30]; cbnz x1, 0x837ad00; b 0x837ad34`, i.e. finishes the
 * current record and advances to the next LC.  It does not touch the blob.
 */

static bool found_success_no_blob = false;

static bool
kpf_success_no_blob_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(found_success_no_blob)
    {
        panic("kpf_success_no_blob: Found more than one site");
    }

    /*
     * opcode_stream[7] = mov w26, #4         -> mov w26, #0 (LOAD_SUCCESS)
     * opcode_stream[8] = b   cleanup (fail)  -> b   loc_aba0 (success tail)
     *
     * The relative branch offset is invariant across KASLR because the two
     * sites live in the same function body; the delta from the matched B at
     * the fatal site to the success tail is -0x1EC (= -0x7B instructions),
     * which encodes as 0x17FFFF85 for `b imm26`.
     */
    opcode_stream[7] = 0x5280001a; /* mov w26, #0 */
    opcode_stream[8] = 0x17FFFF85; /* b -0x1EC → skip blob derefs */

    puts("KPF: patched 'success, but no blob!' fatal into non-fatal fall-through");

    found_success_no_blob = true;
    xnu_pf_disable_patch(patch);
    return true;
}

static void
kpf_success_no_blob_patches(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    /*
     * Nine-instruction anchor; see comment at top of file.  Fixed words are
     * matched by equal-mask; register-only ADRP/ADD and the two BL/B
     * immediates are masked out so KASLR / minor-rev slide does not break the
     * match.
     */
    uint64_t matches[] =
    {
        0x90000008, /* adrp x8, ... */
        0x91000108, /* add  x8, x8, #imm */
        0x5281c549, /* mov  w9, #0xe2a */
        0xa90027e8, /* stp  x8, x9, [sp] */
        0x90000000, /* adrp x0, ... */
        0x91000000, /* add  x0, x0, #imm */
        0x94000000, /* bl   _printf */
        0x5280009a, /* mov  w26, #4 */
        0x14000000, /* b    cleanup */
    };
    uint64_t masks[] =
    {
        0x9F00001F,
        0xFFC003FF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0x9F00001F,
        0xFFC003FF,
        0xFC000000,
        0xFFFFFFFF,
        0xFC000000,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "success_no_blob",
        matches, masks, sizeof(matches) / sizeof(uint64_t), false,
        (void *)kpf_success_no_blob_callback);
}

static void
kpf_success_no_blob_finish(struct mach_header_64 *hdr)
{
    (void)hdr;
    if(!found_success_no_blob)
    {
        puts("KPF: success_no_blob matcher did not fire (OK on non-18.7.10 kernels)");
    }
}

kpf_component_t kpf_success_no_blob =
{
    .finish = kpf_success_no_blob_finish,
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_success_no_blob_patches },
        {},
    },
};
