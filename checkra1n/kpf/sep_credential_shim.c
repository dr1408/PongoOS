/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2026 checkra1n team
 */

#include "kpf.h"
#include <pongo.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/*
 * SEP credential shim: on T8020 iPhone with iOS 18 the KPF cannot drive
 * `sep auto` from PongoOS (the T8020 SEP IRQ bindings in Pongo's SEP driver
 * are intentionally skipped: see src/drivers/sep/sep.c:1297, "Every single
 * irq fires constantly on t8020").  Any `sep auto`/`sep ping`/`sep tz0`
 * command hangs on `event_wait_asserted(&sep_msg_event)` because the IRQ
 * handler that would fire the event is never registered.
 *
 * Consequently SEP is left in ROM-wait state (sepfw loaded by iBoot into
 * SRAM, but no `opcode-5 boot_tz0` ever sent).  On iOS the DT has
 * `/chosen/memory-map/SEP sepfw-booted = 1`, so XNU boots assuming SEP is
 * up and sends mailbox messages.  The very first mailbox send (from
 * AppleSMC::start -> AppleCredentialManager/AppleSEPCredentialManager ->
 * sendSEPCommand/sendSEPMessage/writeToSEPBuffer) hits SEP ROM in the
 * wrong state and SEP ROM panics (SEPROMPanicBuffer.cpp:71).
 *
 * This matches the pattern Liter8 handles for A12 iPadOS 26.7.1 (j171aap
 * / 23H30) with its `kernel-credential-manager` resolver: patch every
 * credential-manager method that talks to SEP (or whose cascade failure
 * would propagate once SEP is "dead") to `mov w0,#0 ; ret`.  Liter8's
 * compiled signatures are build-specific (Darwin 25.6 / 24A435) and don't
 * transfer, but the strategy and anchor set do.
 *
 * Approach: each AppleCredentialManager method logs its own name on entry
 * via `printf("%s::%s called\n", classname, "<methodname>")`.  The
 * `<methodname>` string in __cstring is referenced by an ADRP+ADD pair
 * inside the method's own body.  Our matcher:
 *   1. Scans for any ADRP+ADD pair in __TEXT_EXEC.
 *   2. Decodes its target.
 *   3. If the target string is one of our SEP-touching method names,
 *      walks back to the enclosing function's PACIBSP (same technique as
 *      kpf_launch_constraints_callback).
 *   4. Replaces PACIBSP with `mov w0, #0` and the next word with RET.
 *      Removing PACIBSP disarms the PAC return-address signing, so plain
 *      RET is safe (no AUT required).
 */

static const char *const kSepMethodNames[] = {
    "sendSEPCommand",
    "sendSEPMessage",
    "writeToSEPBuffer",
    "readFromSEPBuffer",
    "handleSEPMessage",
    "getSEPEndpoint",
    /* Liter8 lists this as `performKernelControl` but on XR 18.7.10 the
     * actual Apple-side method names are `performKernelControlGated` and
     * `_performKernelControl`. */
    "performKernelControlGated",
    "_performKernelControl",
};

#define kSepMethodCount ((int)(sizeof(kSepMethodNames)/sizeof(kSepMethodNames[0])))

static int sep_shim_hits_per_name[kSepMethodCount];
static int sep_shim_total_hits;

static bool
kpf_sep_credential_shim_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    (void)patch;
    uint32_t adrp = opcode_stream[0];
    uint32_t add  = opcode_stream[1];
    const char *str = (const char *)(((uint64_t)opcode_stream & ~0xfffULL)
                                     + adrp_off(adrp)
                                     + ((add >> 10) & 0xfff));

    int which = -1;
    for (int i = 0; i < kSepMethodCount; i++)
    {
        if (strcmp(str, kSepMethodNames[i]) == 0)
        {
            which = i;
            break;
        }
    }
    if (which < 0) return false;

    uint32_t *entry = NULL;

    uint32_t *stp = find_prev_insn(opcode_stream, 0x400, 0xa9007bfd, 0xffc07fff); /* stp x29, x30, [sp, #imm] */
    if (stp)
    {
        uint32_t *start = find_prev_insn(stp, 32, 0xa98003e0, 0xffc003e0); /* stp xN, xM, [sp, #imm]! */
        if (!start)
        {
            start = find_prev_insn(stp, 32, 0xd10003ff, 0xffc003ff); /* sub sp, sp, #imm */
        }
        if (start && start[-1] == 0xd503237f) /* pacibsp */
        {
            entry = start - 1;
        }
    }

    if (!entry)
    {
        /* Fallback for thunk prologues like
         *   pacibsp ; mov x5, x30 ; bl helper ; mov x30, x1 ; ...
         * which skip the conventional stack frame.  Scan for pacibsp
         * directly within a short window.
         */
        uint32_t *pacibsp = find_prev_insn(opcode_stream, 0x100, 0xd503237f, 0xffffffff);
        if (!pacibsp) return false;
        entry = pacibsp;
    }

    if (entry[0] != 0xd503237f) return false; /* already patched */

    entry[0] = 0x52800000; /* mov w0, #0 */
    entry[1] = 0xd65f03c0; /* ret */

    sep_shim_hits_per_name[which]++;
    sep_shim_total_hits++;
    return true;
}

static void
kpf_sep_credential_shim_patch(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    uint64_t matches[] =
    {
        0x90000000, /* adrp xN, ... */
        0x91000000, /* add  xN, xN, #imm12 (same reg) */
    };
    uint64_t masks[] =
    {
        0x9f00001f,
        0xffc003ff,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "sep_credential_shim",
        matches, masks, sizeof(matches)/sizeof(uint64_t), false,
        (void *)kpf_sep_credential_shim_callback);
}

static void
kpf_sep_credential_shim_finish(struct mach_header_64 *hdr)
{
    (void)hdr;
    printf("KPF: sep_credential_shim patched %d function entries\n", sep_shim_total_hits);
    for (int i = 0; i < kSepMethodCount; i++)
    {
        if (sep_shim_hits_per_name[i] == 0)
        {
            printf("KPF: WARN: sep_credential_shim: no hits for %s\n", kSepMethodNames[i]);
        }
        else
        {
            printf("KPF: sep_credential_shim: %s x%d\n",
                   kSepMethodNames[i], sep_shim_hits_per_name[i]);
        }
    }
}

kpf_component_t kpf_sep_credential_shim =
{
    .finish = kpf_sep_credential_shim_finish,
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_sep_credential_shim_patch },
        {},
    },
};
