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

/*
 * Expose the real load_machfile() return value as the OS_REASON_EXEC code in
 * "unexpected SIGKILL of init" panics, and (as a diagnostic layer on top)
 * tag each LOAD_FAILURE return site in load_machfile / parse_machfile with a
 * distinct sentinel so the panic code identifies the exact firing gate.
 *
 * XNU's vfork_exec_internal() emits
 *      os_reason_create(OS_REASON_EXEC = 9, 1)
 * at every "load_machfile returned non-zero" site, so every init-exec load
 * failure appears as "code 0x1" in panic.ips with no gate information.
 *
 * ============================================================================
 * MATCHER (1): panic_detail
 *
 *      opcode_stream[0] = mov w0, #9
 *      opcode_stream[1] = mov w1, #1
 *      opcode_stream[2] = bl _os_reason_create
 *
 *   Rewrite mov w1, #1 -> mov w1, w24.  Anchored on a nearby MOV W24, #0x55
 *   or the aV_6 LDR (UXTW variant) so other os_reason_create(9,1) call sites
 *   in unrelated kernel code are not mutated.
 *
 * ============================================================================
 * MATCHER (2): panic_detail_raw
 *
 *   At the aV_6 dispatch in vfork_exec_internal:
 *      cmp  w0, #0xb
 *      b.hi fallback                 ; v29 > 11 -> fallback mov w24, #0x55
 *      sub  w8, w0, #1
 *      adrp x9, aV_6
 *      add  x9, x9, #imm
 *      ldr  w24, [x9, w8, uxtw #2]   ; w24 = aV_6[v29 - 1]
 *   rewrite the first two insns to
 *      mov  w24, w0                  ; w24 = raw v29 (LOAD_* code)
 *      b    panic_emit               ; unconditional, skip aV_6 + fallback
 *
 *   Combined with (1), the crashlog "code" field carries the raw v29 value.
 *
 * ============================================================================
 * MATCHERS (3)-(6): return-4 sentinel tagging
 *
 *   Multiple sites in load_machfile and parse_machfile return LOAD_FAILURE (4),
 *   so a raw v29 = 4 panic alone does not identify which gate fired.  Tag
 *   each candidate with a unique sentinel so the panic code names it:
 *
 *     site 6  (parse_machfile @ 0x8379eb8, "LC_LOAD_DYLINKER + imgp flag"):
 *             mov w8, #4   ->  mov w8, #0x24
 *     site 7  (parse_machfile @ 0x8379d94, "segment-validation loop"):
 *             mov w9, #4   ->  mov w9, #0x34
 *     site 8  (parse_machfile @ 0x8379fc0, "LC_UUID / v111 && (a7||v104)"):
 *             mov w9, #4   ->  mov w9, #0x44
 *     site 9  (load_machfile wrapper @ 0x8379284, "identity-gate result = 4"):
 *             mov w0, #4   ->  mov w0, #0x14
 *
 *   The sentinel values are chosen so that:
 *     * they are all > 11, so they bypass aV_6 and show up directly (through
 *       matcher 2's rewired dispatch) in the panic code;
 *     * they are mutually distinct, so one panic names exactly one site;
 *     * 0x4 remains the "unknown / parse_machfile sub-call return" bucket.
 */

static bool panic_detail_found = false;
static bool panic_detail_raw_found = false;
static bool pdr_site6_found = false;
static bool pdr_site7_found = false;
static bool pdr_site8_found = false;
static bool pdr_site9_found = false;
static bool pdr_siteA_found = false;
static bool pdr_siteB_found = false;
static bool pdr_siteC_found = false;
static bool pdr_siteD_found = false;
static bool pdr_siteE_found = false;
static bool pdr_site1asm_found = false;
static bool pdr_br4_found = false;
static bool pdr_br7_found = false;
static bool pdr_a980_1_found = false;
static bool pdr_a980_2_found = false;
static bool pdr_a980_3_found = false;
static bool pdr_b12c_1_found = false;
static bool pdr_b12c_2_found = false;

static bool kpf_panic_detail_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    /* opcode_stream[0] = mov w0, #9
       opcode_stream[1] = mov w1, #1
       opcode_stream[2] = bl _os_reason_create */

    uint32_t *fallback_anchor =
        find_prev_insn(opcode_stream, 16, 0x52800ab8, 0xffffffff);
    uint32_t *ldr_anchor =
        find_prev_insn(opcode_stream, 16, 0xb8605818, 0xffe0fc1f);
    if(!fallback_anchor && !ldr_anchor)
    {
        return false;
    }

    /* mov w1, w24 */
    opcode_stream[1] = 0x2a1803e1;

    panic_detail_found = true;
    puts("KPF: Found init-exec panic detail producer");
    return true;
}

static bool kpf_panic_detail_raw_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    /* opcode_stream[0] = cmp w0, #0xb       (0x71002c1f)
       opcode_stream[1] = b.hi #fallback     (0x54xxxxx8)
       opcode_stream[2] = sub w8, w0, #1     (0x51000408)
       opcode_stream[3] = adrp x9, aV_6_page (0x90xxxx09)
       opcode_stream[4] = add  x9, x9, #imm  (0x9100xx29)
       opcode_stream[5] = ldr  w24, [x9, w8, uxtw #2] (0xb8685938) */

    uint32_t bhi    = opcode_stream[1];
    int32_t  imm19  = (int32_t)((bhi >> 5) & 0x7ffff);
    if(imm19 & (1 << 18))
    {
        imm19 |= ~((1 << 19) - 1);
    }
    int32_t  imm26  = imm19 + 1;
    uint32_t imm26u = (uint32_t)imm26 & 0x3ffffff;

    /* orr w24, wzr, w0  (= mov w24, w0) */
    opcode_stream[0] = 0x2a0003f8;
    /* b panic_emit */
    opcode_stream[1] = 0x14000000 | imm26u;

    panic_detail_raw_found = true;
    puts("KPF: Found aV_6 dispatch, rewired to pass raw LOAD_* code");
    return true;
}

/*
 * Site 6: parse_machfile @ 0xfffffff008379eb0..0x8379ebc
 *
 *   and  w8, w8, #2            121f0108
 *   ccmp w8, #0, #4, ne        7a401904
 *   mov  w8, #4                52800088   <- patch opcode_stream[2] to 0x52800488 (mov w8, #0x24)
 *   csel w9, w8, wzr, eq       1a9f0109
 */
static bool kpf_pdr_site6_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[2] = 0x52800488; /* mov w8, #0x24 */
    pdr_site6_found = true;
    puts("KPF: Tagged parse_machfile site 6 (LC_LOAD_DYLINKER + imgp flag) with sentinel 0x24");
    return true;
}

/*
 * Site 7: parse_machfile @ 0xfffffff008379d8c..0x8379d98
 *
 *   and  w8, w8, #0xfffffffe   121f7908
 *   str  w8, [x9, #0x48]       b9004928
 *   mov  w9, #4                52800089   <- patch opcode_stream[2] to 0x52800689 (mov w9, #0x34)
 *   b    <loop head>           14xxxxxx
 */
static bool kpf_pdr_site7_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[2] = 0x52800689; /* mov w9, #0x34 */
    pdr_site7_found = true;
    puts("KPF: Tagged parse_machfile site 7 (segment-validation loop) with sentinel 0x34");
    return true;
}

/*
 * Site 8: parse_machfile @ 0xfffffff008379fbc..0x8379fc4
 *
 *   ldur x1, [x29, #-0xb0]     f85503a1
 *   mov  w9, #4                52800089   <- patch opcode_stream[1] to 0x52800889 (mov w9, #0x44)
 *   b    LABEL_245             14xxxxxx
 */
static bool kpf_pdr_site8_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[1] = 0x52800889; /* mov w9, #0x44 */
    pdr_site8_found = true;
    puts("KPF: Tagged parse_machfile site 8 (LC_UUID / v111 && (a7||v104)) with sentinel 0x44");
    return true;
}

/*
 * Site 9: load_machfile wrapper @ 0xfffffff008379274..0x8379284
 *
 *   bl   _ea04b8               94xxxxxx   (identity lock-wrapper)
 *   cbz  w0, <success>         34xxxxxx
 *   add  x8, x21, #0x2f8       910be2a8
 *   str  x8, [sp, #0x68]       f90037e8
 *   mov  w0, #4                52800080   <- patch opcode_stream[4] to 0x52800280 (mov w0, #0x14)
 */
static bool kpf_pdr_site9_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[4] = 0x52800280; /* mov w0, #0x14 */
    pdr_site9_found = true;
    puts("KPF: Tagged load_machfile identity-gate result (site 9) with sentinel 0x14");
    return true;
}

/*
 * Site A: parse_machfile sub-callee (sub_FFFFFFF00837A010 tail)
 *   tbnz w8, #5, +0xc           37280068
 *   ldr  x9, [x2, #8]           f9400449
 *   cbz  x9, +0xc               b4000069
 *   mov  w0, #4                 52800080   <- patch opcode_stream[3] to 0x52800e80 (mov w0, #0x74)
 *   ret                          d65f03c0
 */
static bool kpf_pdr_siteA_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[3] = 0x52800e80; /* mov w0, #0x74 */
    pdr_siteA_found = true;
    puts("KPF: Tagged parse_machfile sub-callee site A (sub_A010 tail) with sentinel 0x74");
    return true;
}

/*
 * Site B: parse_machfile sub-callee (sub_FFFFFFF00837A0A0 / 00837A640 shared tail)
 *   ldr  w9, [x3, #0x40]        b9404069
 *   cbz  w9, +0xc               34000069
 *   mov  w0, #4                 52800080   <- patch opcode_stream[2] to 0x52801080 (mov w0, #0x84)
 *   ret                          d65f03c0
 */
static bool kpf_pdr_siteB_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[2] = 0x52801080; /* mov w0, #0x84 */
    pdr_siteB_found = true;
    puts("KPF: Tagged parse_machfile sub-callee site B (sub_A0A0/A640 ret-4) with sentinel 0x84");
    return true;
}

/*
 * Site C: parse_machfile sub-callee (sub_FFFFFFF00837A86C tail)
 *   ldr  w8, [x3, #0x40]        b9404068
 *   cbz  w8, +0xc               34000068
 *   mov  w0, #4                 52800080   <- patch opcode_stream[2] to 0x52801280 (mov w0, #0x94)
 *   ret                          d65f03c0
 */
static bool kpf_pdr_siteC_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[2] = 0x52801280; /* mov w0, #0x94 */
    pdr_siteC_found = true;
    puts("KPF: Tagged parse_machfile sub-callee site C (sub_A86C ret-4) with sentinel 0x94");
    return true;
}

/*
 * Site D: parse_machfile sub-callee (sub_FFFFFFF00837ADE0 tail-call return)
 *   bl   <inner>                94xxxxxx
 *   mov  w0, #4                 52800080   <- patch opcode_stream[1] to 0x52801480 (mov w0, #0xA4)
 *   ldp  x29, x30, [sp, #0xa0]  a94a7bfd  (anchor into epilogue)
 */
static bool kpf_pdr_siteD_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[1] = 0x52801480; /* mov w0, #0xA4 */
    pdr_siteD_found = true;
    puts("KPF: Tagged parse_machfile sub-callee site D (sub_ADE0 ret-4) with sentinel 0xA4");
    return true;
}

/*
 * Site E: parse_machfile @ 0xfffffff008379e14 — "stash local = 4; cleanup; reload"
 *
 *   mov  w8, #4                 52800088   <- patch opcode_stream[0] to 0x52801688 (mov w8, #0xB4)
 *   str  w8, [sp, #0xc0]        b900c3e8
 *   ldur x0, [x29, #-0x98]      f85683a0
 *   bl   <cleanup>              94xxxxxx
 *   ldur x1, [x29, #-0xb0]      f85503a1
 *   ldr  w9, [sp, #0xc0]        b940c3e9
 *   b    <common exit>          14xxxxxx
 *
 * This path stashes 4 to sp+0xc0, calls a cleanup helper, reloads 4 into w9
 * (which later lands in v64), and falls through to LABEL_245 where
 * parse_machfile's return v41 = v64 = 4.  Easy to miss by naive scans because
 * the literal mov isn't followed by `b <epilogue>` directly.
 */
static bool kpf_pdr_siteE_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[0] = 0x52801688; /* mov w8, #0xB4 */
    pdr_siteE_found = true;
    puts("KPF: Tagged parse_machfile stash-local-4 cleanup path (site E) with sentinel 0xB4");
    return true;
}

/*
 * Site 1-asm: parse_machfile @ 0xfffffff0083793ec — the a7 > 2 gate
 *
 *   cmp  w22, #2                71000adf
 *   b.le +0x8                   5400000d
 *   mov  w0, #4                 52800080   <- patch opcode_stream[2] to 0x52801880 (mov w0, #0xC4)
 *   b    <epilogue>             14xxxxxx
 *
 * Expected to be unreachable at top-level init exec (a7=0), tagged anyway so
 * a code 0xC4 crashlog would positively identify unexpected deep recursion.
 */
static bool kpf_pdr_site1asm_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[2] = 0x52801880; /* mov w0, #0xC4 */
    pdr_site1asm_found = true;
    puts("KPF: Tagged parse_machfile a7>2 gate (site 1-asm) with sentinel 0xC4");
    return true;
}

/*
 * BR4 landing pad: parse_machfile common-exit convergence @ 0xfffffff008379f6c
 *
 *   ldur x1, [x29, #-0xb0]      f85503a1
 *   mov  x9, x20                aa1403e9   <- patch opcode_stream[1] to 0x52801a89
 *                                             (mov w9, #0xD4 — overrides x20)
 *   b    <common exit>          14xxxxxx
 *
 * This landing pad is reached sequentially after an intermediate panic/cleanup
 * sequence (mov w4,#9; bl 0x82ff3e4; bl 0x83902b4).  It carries parse_machfile's
 * error through x20 into the common exit.  If x20 == 4, parse_machfile returns
 * 4 untagged.  Overriding mov x9,x20 with mov w9,#0xD4 forces panic code 0xD4
 * when this convergence fires, regardless of what x20 held.
 */
static bool kpf_pdr_br4_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[1] = 0x52801a89; /* mov w9, #0xD4 */
    pdr_br4_found = true;
    puts("KPF: Tagged parse_machfile BR4 landing (mov x9,x20) with sentinel 0xD4");
    return true;
}

/*
 * BR7 landing pad: parse_machfile common-exit convergence @ 0xfffffff008379fc8
 *
 *   mov  x9, x0                 aa0003e9   <- patch opcode_stream[0] to 0x52801c89
 *                                             (mov w9, #0xE4 — overrides x0)
 *   ldur x1, [x29, #-0xb0]      f85503a1
 *   b    <common exit>          14xxxxxx
 *
 * This landing pad is reached from `cbnz w0, <here>` after `bl sub_A0A0`
 * (parse_machfile @ 0x8379b5c and 0x8379c7c).  It inherits sub_A0A0's return
 * value as w9.  If sub_A0A0 returns 4 via a non-tagged path, parse_machfile
 * returns 4 untagged.  Overriding mov x9,x0 with mov w9,#0xE4 forces panic
 * code 0xE4 when this landing-pad fires.
 */
static bool kpf_pdr_br7_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[0] = 0x52801c89; /* mov w9, #0xE4 */
    pdr_br7_found = true;
    puts("KPF: Tagged parse_machfile BR7 landing (mov x9,x0 — sub_A0A0 ret) with sentinel 0xE4");
    return true;
}

/*
 * sub_A980 (parse_machfile line 564: v64 = sub_A980()) uses callee-saved w26 as
 * its return channel.  Three `mov w26, #4` sites inside the function later
 * become sub_A980's return value via `mov x0, x26; retab`.  Byte-scanning for
 * `mov w0, #4` missed these.  Three distinct sentinels so the next crashlog
 * names which sub_A980 path fired.
 *
 * Site A1 @ 0xfffffff00837ac94  (after `bl 0x8347c08`):
 *   ldr x1, [sp, #0x20]        f94013e1
 *   bl  _0x8347c08             94xxxxxx
 *   mov w26, #4                5280009a   <- patch opcode_stream[2] to 0x528002ba (mov w26, #0x15)
 *   b   <common tail>          14xxxxxx
 */
static bool kpf_pdr_a980_1_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[2] = 0x528002ba; /* mov w26, #0x15 */
    pdr_a980_1_found = true;
    puts("KPF: Tagged sub_A980 return-4 site 1 (after sub_8347c08) with sentinel 0x15");
    return true;
}

/*
 * Site A2 @ 0xfffffff00837aca4  ("mov w26,#4; ldr x1,[sp,#0x30]; cbnz x1; b"):
 *   mov w26, #4                5280009a   <- patch opcode_stream[0] to 0x528002da (mov w26, #0x16)
 *   ldr x1, [sp, #0x30]        f9401be1
 *   cbnz x1, +N                b5000001
 *   b   <common tail>          14xxxxxx
 */
static bool kpf_pdr_a980_2_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[0] = 0x528002da; /* mov w26, #0x16 */
    pdr_a980_2_found = true;
    puts("KPF: Tagged sub_A980 return-4 site 2 (cbnz x1 path) with sentinel 0x16");
    return true;
}

/*
 * Site A3 @ 0xfffffff00837ad80  (after `bl 0x85e4f8c`):
 *   add x0, x0, #imm           91000000
 *   bl  _0x85e4f8c             94xxxxxx
 *   mov w26, #4                5280009a   <- patch opcode_stream[2] to 0x528002fa (mov w26, #0x17)
 *   b   <common tail>          14xxxxxx
 */
static bool kpf_pdr_a980_3_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[2] = 0x528002fa; /* mov w26, #0x17 */
    pdr_a980_3_found = true;
    puts("KPF: Tagged sub_A980 return-4 site 3 (after sub_85e4f8c) with sentinel 0x17");
    return true;
}

/*
 * sub_B12C (parse_machfile line 363: v64 = sub_B12C(dyld-related)) returns 4
 * via two chains that converge on `result = v24; return result`:
 *
 *   • w28 chain:  mov w28, #4 (0x837b328) → via LABEL_24 → v24 = v26 → result
 *     fires when sub_8011E2C(task, …) MAC-check returned non-zero (dyld task
 *     context rejected).
 *   • w22 chain:  mov w22, #4 (0x837b330) → v24 → result
 *     fires on a different error branch earlier in the function.
 *
 * Site B1 @ 0xfffffff00837b320  (MAC-check-fail path):
 *   bl  _0x8011e2c             94xxxxxx
 *   cbz w0, <success>          34xxxxxx
 *   mov w28, #4                5280009c   <- patch opcode_stream[2] to 0x5280031c (mov w28, #0x18)
 *   b   <LABEL_24>             14xxxxxx
 */
static bool kpf_pdr_b12c_1_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[2] = 0x5280031c; /* mov w28, #0x18 */
    pdr_b12c_1_found = true;
    puts("KPF: Tagged sub_B12C MAC-check-fail path (w28=4) with sentinel 0x18");
    return true;
}

/*
 * Site B2 @ 0xfffffff00837b328  (pair w28/w22, patches the w22 slot):
 *   mov w28, #4                5280009c   (B1 target, already tagged)
 *   b   <LABEL_24>             14xxxxxx
 *   mov w22, #4                52800096   <- patch opcode_stream[2] to 0x52800336 (mov w22, #0x19)
 *   b   <LABEL_different>      14xxxxxx
 */
static bool kpf_pdr_b12c_2_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream)
{
    opcode_stream[2] = 0x52800336; /* mov w22, #0x19 */
    pdr_b12c_2_found = true;
    puts("KPF: Tagged sub_B12C alt-error path (w22=4) with sentinel 0x19");
    return true;
}

static void kpf_panic_detail_patches(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    /* ---- matcher (1): mov w0, #9; mov w1, #1; bl _os_reason ---- */
    uint64_t m_detail[] =
    {
        0x52800120,
        0x52800021,
        0x94000000,
    };
    uint64_t k_detail[] =
    {
        0xffffffff,
        0xffffffff,
        0xfc000000,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail",
        m_detail, k_detail, sizeof(m_detail) / sizeof(uint64_t), false,
        (void *)kpf_panic_detail_callback);

    /* ---- matcher (2): aV_6 dispatch in vfork_exec_internal ---- */
    uint64_t m_raw[] =
    {
        0x71002c1f,
        0x54000008,
        0x51000408,
        0x90000009,
        0x91000129,
        0xb8685938,
    };
    uint64_t k_raw[] =
    {
        0xffffffff,
        0xff00001f,
        0xffffffff,
        0x9f00001f,
        0xffc003ff,
        0xffffffff,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_raw",
        m_raw, k_raw, sizeof(m_raw) / sizeof(uint64_t), false,
        (void *)kpf_panic_detail_raw_callback);

    /* ---- matcher (3): parse_machfile site 6 ---- */
    uint64_t m_s6[] =
    {
        0x121f0108, /* and w8, w8, #2 */
        0x7a401904, /* ccmp w8, #0, #4, ne */
        0x52800088, /* mov w8, #4 */
        0x1a9f0109, /* csel w9, w8, wzr, eq */
    };
    uint64_t k_s6[] = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_site6",
        m_s6, k_s6, sizeof(m_s6) / sizeof(uint64_t), false,
        (void *)kpf_pdr_site6_callback);

    /* ---- matcher (4): parse_machfile site 7 ---- */
    uint64_t m_s7[] =
    {
        0x121f7908, /* and w8, w8, #0xfffffffe */
        0xb9004928, /* str w8, [x9, #0x48] */
        0x52800089, /* mov w9, #4 */
        0x14000000, /* b <loop head> */
    };
    uint64_t k_s7[] = { 0xffffffff, 0xffffffff, 0xffffffff, 0xfc000000 };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_site7",
        m_s7, k_s7, sizeof(m_s7) / sizeof(uint64_t), false,
        (void *)kpf_pdr_site7_callback);

    /* ---- matcher (5): parse_machfile site 8 ---- */
    uint64_t m_s8[] =
    {
        0xf85503a1, /* ldur x1, [x29, #-0xb0] */
        0x52800089, /* mov w9, #4 */
        0x14000000, /* b LABEL_245 */
    };
    uint64_t k_s8[] = { 0xffffffff, 0xffffffff, 0xfc000000 };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_site8",
        m_s8, k_s8, sizeof(m_s8) / sizeof(uint64_t), false,
        (void *)kpf_pdr_site8_callback);

    /* ---- matcher (6): load_machfile wrapper identity-gate result site 9 ---- */
    uint64_t m_s9[] =
    {
        0x94000000, /* bl _ea04b8 */
        0x34000000, /* cbz w0, <success> */
        0x910be2a8, /* add x8, x21, #0x2f8 */
        0xf90037e8, /* str x8, [sp, #0x68] */
        0x52800080, /* mov w0, #4 */
    };
    uint64_t k_s9[] =
    {
        0xfc000000, 0xff00001f, 0xffffffff, 0xffffffff, 0xffffffff,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_site9",
        m_s9, k_s9, sizeof(m_s9) / sizeof(uint64_t), false,
        (void *)kpf_pdr_site9_callback);

    /* ---- matcher (7): parse_machfile sub-callee site A ---- */
    uint64_t m_sA[] =
    {
        0x37280008, /* tbnz w8, #5, +N */
        0xf9400449, /* ldr x9, [x2, #8] */
        0xb4000009, /* cbz x9, +N */
        0x52800080, /* mov w0, #4 */
        0xd65f03c0, /* ret */
    };
    uint64_t k_sA[] =
    {
        0xfff8001f, 0xffffffff, 0xff00001f, 0xffffffff, 0xffffffff,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_siteA",
        m_sA, k_sA, sizeof(m_sA) / sizeof(uint64_t), false,
        (void *)kpf_pdr_siteA_callback);

    /* ---- matcher (8): parse_machfile sub-callee site B ---- */
    uint64_t m_sB[] =
    {
        0xb9404069, /* ldr w9, [x3, #0x40] */
        0x34000009, /* cbz w9, +N */
        0x52800080, /* mov w0, #4 */
        0xd65f03c0, /* ret */
    };
    uint64_t k_sB[] =
    {
        0xffffffff, 0xff00001f, 0xffffffff, 0xffffffff,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_siteB",
        m_sB, k_sB, sizeof(m_sB) / sizeof(uint64_t), false,
        (void *)kpf_pdr_siteB_callback);

    /* ---- matcher (9): parse_machfile sub-callee site C ---- */
    uint64_t m_sC[] =
    {
        0xb9404068, /* ldr w8, [x3, #0x40] */
        0x34000008, /* cbz w8, +N */
        0x52800080, /* mov w0, #4 */
        0xd65f03c0, /* ret */
    };
    uint64_t k_sC[] =
    {
        0xffffffff, 0xff00001f, 0xffffffff, 0xffffffff,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_siteC",
        m_sC, k_sC, sizeof(m_sC) / sizeof(uint64_t), false,
        (void *)kpf_pdr_siteC_callback);

    /* ---- matcher (10): parse_machfile sub-callee site D ---- */
    uint64_t m_sD[] =
    {
        0x94000000, /* bl <inner> */
        0x52800080, /* mov w0, #4 */
        0xa94a7bfd, /* ldp x29, x30, [sp, #0xa0] (epilogue anchor) */
    };
    uint64_t k_sD[] =
    {
        0xfc000000, 0xffffffff, 0xffffffff,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_siteD",
        m_sD, k_sD, sizeof(m_sD) / sizeof(uint64_t), false,
        (void *)kpf_pdr_siteD_callback);

    /* ---- matcher (11): parse_machfile stash-local-4 cleanup path (site E) ---- */
    uint64_t m_sE[] =
    {
        0x52800088, /* mov w8, #4 */
        0xb900c3e8, /* str w8, [sp, #0xc0] */
        0xf85683a0, /* ldur x0, [x29, #-0x98] */
        0x94000000, /* bl <cleanup> */
        0xf85503a1, /* ldur x1, [x29, #-0xb0] */
        0xb940c3e9, /* ldr w9, [sp, #0xc0] */
        0x14000000, /* b <common exit> */
    };
    uint64_t k_sE[] =
    {
        0xffffffff, 0xffffffff, 0xffffffff, 0xfc000000,
        0xffffffff, 0xffffffff, 0xfc000000,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_siteE",
        m_sE, k_sE, sizeof(m_sE) / sizeof(uint64_t), false,
        (void *)kpf_pdr_siteE_callback);

    /* ---- matcher (12): parse_machfile a7>2 gate (site 1-asm) ---- */
    uint64_t m_s1a[] =
    {
        0x71000adf, /* cmp w22, #2 */
        0x5400000d, /* b.le +N */
        0x52800080, /* mov w0, #4 */
        0x14000000, /* b <epilogue> */
    };
    uint64_t k_s1a[] =
    {
        0xffffffff, 0xff00001f, 0xffffffff, 0xfc000000,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_site1asm",
        m_s1a, k_s1a, sizeof(m_s1a) / sizeof(uint64_t), false,
        (void *)kpf_pdr_site1asm_callback);

    /* ---- matcher (13): parse_machfile BR4 landing pad ---- */
    uint64_t m_br4[] =
    {
        0xf85503a1, /* ldur x1, [x29, #-0xb0] */
        0xaa1403e9, /* mov x9, x20 */
        0x14000000, /* b <common exit> */
    };
    uint64_t k_br4[] =
    {
        0xffffffff, 0xffffffff, 0xfc000000,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_br4",
        m_br4, k_br4, sizeof(m_br4) / sizeof(uint64_t), false,
        (void *)kpf_pdr_br4_callback);

    /* ---- matcher (14): parse_machfile BR7 landing pad ---- */
    uint64_t m_br7[] =
    {
        0xaa0003e9, /* mov x9, x0 */
        0xf85503a1, /* ldur x1, [x29, #-0xb0] */
        0x14000000, /* b <common exit> */
    };
    uint64_t k_br7[] =
    {
        0xffffffff, 0xffffffff, 0xfc000000,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_br7",
        m_br7, k_br7, sizeof(m_br7) / sizeof(uint64_t), false,
        (void *)kpf_pdr_br7_callback);

    /* ---- matcher (15): sub_A980 return-4 site 1 (after bl 0x8347c08) ---- */
    uint64_t m_a980_1[] =
    {
        0xf94013e1, /* ldr x1, [sp, #0x20] */
        0x94000000, /* bl  _0x8347c08 */
        0x5280009a, /* mov w26, #4 */
        0x14000000, /* b   <common tail> */
    };
    uint64_t k_a980_1[] =
    {
        0xffffffff, 0xfc000000, 0xffffffff, 0xfc000000,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_a980_1",
        m_a980_1, k_a980_1, sizeof(m_a980_1) / sizeof(uint64_t), false,
        (void *)kpf_pdr_a980_1_callback);

    /* ---- matcher (16): sub_A980 return-4 site 2 (cbnz x1 path) ---- */
    uint64_t m_a980_2[] =
    {
        0x5280009a, /* mov w26, #4 */
        0xf9401be1, /* ldr x1, [sp, #0x30] */
        0xb5000001, /* cbnz x1, +N */
        0x14000000, /* b   <common tail> */
    };
    uint64_t k_a980_2[] =
    {
        0xffffffff, 0xffffffff, 0xff00001f, 0xfc000000,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_a980_2",
        m_a980_2, k_a980_2, sizeof(m_a980_2) / sizeof(uint64_t), false,
        (void *)kpf_pdr_a980_2_callback);

    /* ---- matcher (17): sub_A980 return-4 site 3 (after bl 0x85e4f8c) ---- */
    uint64_t m_a980_3[] =
    {
        0x91000000, /* add x0, x0, #imm (any) */
        0x94000000, /* bl  _0x85e4f8c */
        0x5280009a, /* mov w26, #4 */
        0x14000000, /* b   <common tail> */
    };
    uint64_t k_a980_3[] =
    {
        0xff800000, 0xfc000000, 0xffffffff, 0xfc000000,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_a980_3",
        m_a980_3, k_a980_3, sizeof(m_a980_3) / sizeof(uint64_t), false,
        (void *)kpf_pdr_a980_3_callback);

    /* ---- matcher (18): sub_B12C MAC-check-fail path (w28=4) ---- */
    uint64_t m_b12c_1[] =
    {
        0x94000000, /* bl _0x8011e2c */
        0x34000000, /* cbz w0, <success> */
        0x5280009c, /* mov w28, #4 */
        0x14000000, /* b <LABEL_24> */
    };
    uint64_t k_b12c_1[] =
    {
        0xfc000000, 0xff00001f, 0xffffffff, 0xfc000000,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_b12c_1",
        m_b12c_1, k_b12c_1, sizeof(m_b12c_1) / sizeof(uint64_t), false,
        (void *)kpf_pdr_b12c_1_callback);

    /* ---- matcher (19): sub_B12C alt-error path (w22=4) ---- */
    uint64_t m_b12c_2[] =
    {
        0x5280009c, /* mov w28, #4 (B1 target, co-located) */
        0x14000000, /* b <LABEL_24> */
        0x52800096, /* mov w22, #4 */
        0x14000000, /* b <LABEL_different> */
    };
    uint64_t k_b12c_2[] =
    {
        0xffffffff, 0xfc000000, 0xffffffff, 0xfc000000,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "panic_detail_b12c_2",
        m_b12c_2, k_b12c_2, sizeof(m_b12c_2) / sizeof(uint64_t), false,
        (void *)kpf_pdr_b12c_2_callback);
}

static void kpf_panic_detail_finish(struct mach_header_64 *hdr)
{
#ifdef DEV_BUILD
    if(!panic_detail_found)
        puts("KPF: panic_detail producer not located; crashlog code stays 0x1");
    if(!panic_detail_raw_found)
        puts("KPF: panic_detail_raw dispatch not located; raw v29 unavailable");
    if(!pdr_site6_found)
        puts("KPF: panic_detail site 6 not located; parse_machfile DYLINKER-imgp return=4 untagged");
    if(!pdr_site7_found)
        puts("KPF: panic_detail site 7 not located; parse_machfile segment-loop return=4 untagged");
    if(!pdr_site8_found)
        puts("KPF: panic_detail site 8 not located; parse_machfile LC_UUID return=4 untagged");
    if(!pdr_site9_found)
        puts("KPF: panic_detail site 9 not located; load_machfile identity-gate return=4 untagged");
    if(!pdr_siteA_found)
        puts("KPF: panic_detail site A not located; sub_A010 ret-4 untagged");
    if(!pdr_siteB_found)
        puts("KPF: panic_detail site B not located; sub_A0A0/A640 ret-4 untagged");
    if(!pdr_siteC_found)
        puts("KPF: panic_detail site C not located; sub_A86C ret-4 untagged");
    if(!pdr_siteD_found)
        puts("KPF: panic_detail site D not located; sub_ADE0 ret-4 untagged");
    if(!pdr_siteE_found)
        puts("KPF: panic_detail site E not located; parse_machfile stash-local-4 cleanup path untagged");
    if(!pdr_site1asm_found)
        puts("KPF: panic_detail site 1-asm not located; parse_machfile a7>2 gate untagged");
    if(!pdr_br4_found)
        puts("KPF: panic_detail BR4 landing not located; mov x9,x20 convergence untagged");
    if(!pdr_br7_found)
        puts("KPF: panic_detail BR7 landing not located; mov x9,x0 (sub_A0A0 ret) untagged");
    if(!pdr_a980_1_found)
        puts("KPF: panic_detail sub_A980 site 1 not located");
    if(!pdr_a980_2_found)
        puts("KPF: panic_detail sub_A980 site 2 not located");
    if(!pdr_a980_3_found)
        puts("KPF: panic_detail sub_A980 site 3 not located");
    if(!pdr_b12c_1_found)
        puts("KPF: panic_detail sub_B12C MAC-fail path not located");
    if(!pdr_b12c_2_found)
        puts("KPF: panic_detail sub_B12C w22 alt path not located");
#endif
}

kpf_component_t kpf_panic_detail =
{
    .finish = kpf_panic_detail_finish,
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_panic_detail_patches },
        {},
    },
};
