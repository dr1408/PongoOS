/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2026
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
#include <string.h>

static const char *kpf_adrp_add_string(uint32_t *opcode_stream)
{
    return (const char *)(((uint64_t)opcode_stream & ~0xfffULL) +
        adrp_off(opcode_stream[0]) + ((opcode_stream[1] >> 10) & 0xfff));
}

static bool kpf_usb_restore_mode_xr_18710_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    // AppleUSBHost/IOAccessoryManager asks whether this is a restore/ramdisk
    // boot by parsing both "rd" and "rootdev" into the same 32-byte buffer.
    // Pongo renames rootdev to spartan, so the native predicate incorrectly
    // returns false and IOAccessoryTRM publishes
    // SupervisedTransportsRestricted=true.  Match both parse sites and their
    // shared helper before forcing only this predicate to return true.
    if(strcmp(kpf_adrp_add_string(opcode_stream), "rd") != 0 ||
       strcmp(kpf_adrp_add_string(opcode_stream + 7), "rootdev") != 0 ||
       opcode_stream[9] != 0x910003e1 || // mov x1, sp
       opcode_stream[10] != 0x52800402 || // mov w2, #0x20
       (opcode_stream[11] & 0xfc000000) != 0x94000000 ||
       follow_call(opcode_stream + 4) != follow_call(opcode_stream + 11))
    {
        return false;
    }

    uint32_t *predicate = opcode_stream - 11;
    if(predicate[0] != 0xd503237f || // pacibsp
       predicate[1] != 0xd10143ff)   // sub sp, sp, #0x50
    {
        return false;
    }

    predicate[0] = 0xd2800020; // mov x0, #1
    predicate[1] = 0xd65f03c0; // ret

    puts("KPF: Found USB restore-mode predicate (XR 18.7.10)");
    return true;
}

static bool kpf_sep_panic_check_xr_18710_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    // AppleSEPManager::sepPanicCheck consumes the panic record at this+0x108.
    // Returning zero prevents the subsequent dump-and-panic path while leaving
    // SEP boot, power management, and command handling unchanged.
    opcode_stream[0] = 0xd2800000; // mov x0, #0
    opcode_stream[1] = 0xd65f03c0; // ret

    puts("KPF: Found SEP panic check (XR 18.7.10)");
    return true;
}

static bool kpf_sep_boot_timeout_xr_18710_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    // Distinct from AppleSEPManager::_didTimeout: this callback reports the
    // fatal boot stage when SEP never reaches the OS-active state.
    opcode_stream[0] = 0xd2800000; // mov x0, #0
    opcode_stream[1] = 0xd65f03c0; // ret

    puts("KPF: Found SEP boot timeout (XR 18.7.10)");
    return true;
}

static bool kpf_aks_selector7_xr_18710_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    // This is the selector-7 jump-table case inside the gated
    // AppleKeyStoreUserClient externalMethod handler, not the externalMethod
    // entry. Keep its BTI landing pad and all other selector cases intact.
    // The original two argument-count failures branch to the shared epilogue.
    int32_t epilogue_delta = sxt32((opcode_stream[10] >> 5) & 0x7ffff, 19);
    uint32_t *epilogue = opcode_stream + 10 + epilogue_delta;
    if(opcode_stream[0] != 0xd503249f || // bti j
       opcode_stream[10] != (0x54000001 | (((uint32_t)epilogue_delta & 0x7ffff) << 5)) ||
       (opcode_stream[13] & 0xff00001f) != 0x54000001 ||
       opcode_stream + 13 + sxt32((opcode_stream[13] >> 5) & 0x7ffff, 19) != epilogue ||
       opcode_stream[20] != 0x528000e1 || // mov w1, #7
       (opcode_stream[21] & 0xfc000000) != 0x94000000 ||
       epilogue[0] != 0xd503249f || // bti j
       epilogue[1] != 0xf85983a8 || // ldur x8, [x29, #-0x68]
       epilogue[15] != 0xd65f0fff)  // retab
    {
        return false;
    }

    // IOExternalMethodArguments on this XR kernel: scalarInput at +0x20,
    // scalarInputCount at +0x28, scalarOutput at +0x48, scalarOutputCount
    // at +0x50. The native selector-7 path requires one input and output.
    // Synthesize the Liter8 noPin | beenUnlocked state (6), but only for
    // selector 7. Unlike the iPhone 11 patch, other selectors still execute.
    uint32_t *bad_argument = opcode_stream + 16;
    opcode_stream[1]  = 0xb4000014 | (((uint32_t)(bad_argument - (opcode_stream + 1)) & 0x7ffff) << 5); // cbz x20
    opcode_stream[2]  = 0xf9401288; // ldr x8, [x20, #0x20]
    opcode_stream[3]  = 0xb4000008 | (((uint32_t)(bad_argument - (opcode_stream + 3)) & 0x7ffff) << 5); // cbz x8
    opcode_stream[4]  = 0xb9402a88; // ldr w8, [x20, #0x28]
    opcode_stream[5]  = 0x7100051f; // cmp w8, #1
    opcode_stream[6]  = 0x54000001 | (((uint32_t)(bad_argument - (opcode_stream + 6)) & 0x7ffff) << 5); // b.ne
    opcode_stream[7]  = 0xf9402689; // ldr x9, [x20, #0x48]
    opcode_stream[8]  = 0xb4000009 | (((uint32_t)(bad_argument - (opcode_stream + 8)) & 0x7ffff) << 5); // cbz x9
    opcode_stream[9]  = 0xb9405288; // ldr w8, [x20, #0x50]
    opcode_stream[10] = 0x7100051f; // cmp w8, #1
    opcode_stream[11] = 0x54000001 | (((uint32_t)(bad_argument - (opcode_stream + 11)) & 0x7ffff) << 5); // b.ne
    opcode_stream[12] = 0xd28000c8; // mov x8, #6
    opcode_stream[13] = 0xf9000128; // str x8, [x9]
    opcode_stream[14] = 0x52800013; // mov w19, #0 (success)
    opcode_stream[15] = 0x14000000 | ((uint32_t)(epilogue - (opcode_stream + 15)) & 0x03ffffff);
    opcode_stream[16] = 0x52805853; // mov w19, #0x2c2
    opcode_stream[17] = 0x72bc0013; // movk w19, #0xe000, lsl #16 (kIOReturnBadArgument)
    opcode_stream[18] = 0x14000000 | ((uint32_t)(epilogue - (opcode_stream + 18)) & 0x03ffffff);

    xnu_pf_disable_patch(patch);
    puts("KPF: Found AKS selector-7 gated handler (XR 18.7.10)");
    return true;
}

static bool kpf_aks_selector14_xr_18710_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    // Selector 14 (KeyBagGetSystem / aks_get_system) at AKSUserClient::externalMethod.
    // Case body is:
    //   [0] BTI j
    //   [1] LDR W8, [X20, #0x28]  ; scalarInputCount
    //   [2] CMP W8, #1
    //   [3] B.EQ <shared-with-input>
    //   [4] CBNZ W8, <default>
    //   [5] LDR W8, [X20, #0x50]  ; scalarOutputCount
    //   [6] CMP W8, #1
    //   [7] B.NE <default>
    //   [8] MOV W22, #0           ; keybag type arg = 0
    //   [9] B   loc_...9245A14    ; -> shared SEP command handler (HANGS)
    //
    // The shared SEP handler ends on CBZ W0 to a success epilogue that does:
    //   MOV W19,#0; SXTW X8,W22; LDR X9,[X20,#0x48]; STR X8,[X9]; B default_ret
    //
    // The skipped SEP block normally replaces W22 with the returned system
    // keybag handle.  Retargeting [9] while leaving W22=0 therefore returns a
    // bogus handle.  A keybag-less system uses the distinguished system
    // handle -3 (also observed in keybagd's KBChangeSystemSecret logging), so
    // synthesize that value before entering the native success epilogue.
    // The fixed delta between the SEP block and its success epilogue is 0x11f
    // instructions on this build.

    uint32_t old_b = opcode_stream[9];
    if((old_b & 0xfc000000) != 0x14000000)
    {
        return false;
    }

    int32_t old_imm = sxt32(old_b & 0x03ffffff, 26);
    if(old_imm <= 0 || old_imm > 0x4000)
    {
        return false;
    }

    int32_t new_imm = old_imm + 0x11f;
    opcode_stream[8] = 0x12800056; // mov w22, #-3 (movn w22, #2)
    opcode_stream[9] = 0x14000000 | ((uint32_t)new_imm & 0x03ffffff);

    xnu_pf_disable_patch(patch);
    puts("KPF: Found AKS selector-14 gated handler (XR 18.7.10)");
    return true;
}

static bool kpf_aks_start_sep_call_xr_18710_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    // AppleKeyStoreUserClient::start: skip only the SEP-dependent call after
    // the this+0xd8 load. Preserve the surrounding start/registration path.
    if((opcode_stream[5] & 0xfc000000) != 0x94000000 ||
       opcode_stream[6] != 0x7941e268 ||
       opcode_stream[7] != 0x321d0109)
    {
        return false;
    }

    opcode_stream[5] = 0xd503201f; // nop (XR 22H374: 0xfffffff00923fc20)
    xnu_pf_disable_patch(patch);
    puts("KPF: Found AKS start SEP call (XR 18.7.10)");
    return true;
}

static void kpf_aks_patches(xnu_pf_patchset_t *aks_text_exec_patchset)
{
    if(gKernelVersion.darwinMajor != 24 || gKernelVersion.darwinMinor != 6 ||
       gKernelVersion.xnuMajor != 11417 || gKernelVersion.xnuMinor != 140 ||
       gKernelVersion.xnuPatch != 69 || gKernelVersion.xnuFlags != 706 ||
       gKernelVersion.xnuRevision != 66 || gKernelVersion.xnuRun != 1 ||
       gKernelVersion.machineConfig != 0x8020 || xnu_platform() != PLATFORM_IOS)
    {
        return;
    }

    // XR 22H374, AppleKeyStoreUserClient::start SEP call: the BL is word 5.
    uint64_t start_matches[] = {
        0xd73f0931, 0x7941e268, 0x37180008, 0xf9406e60,
        0xb4000000, 0x94000000, 0x7941e268, 0x321d0109,
    };
    uint64_t start_masks[] = {
        0xffffffff, 0xffffffff, 0xfff8001f, 0xffffffff,
        0xff00001f, 0xfc000000, 0xffffffff, 0xffffffff,
    };
    xnu_pf_maskmatch(aks_text_exec_patchset, "aks_start_sep_call_xr_18710",
        start_matches, start_masks, sizeof(start_matches) / sizeof(uint64_t), true,
        (void *)kpf_aks_start_sep_call_xr_18710_callback);

    // XR 22H374, AppleKeyStoreUserClient gated externalMethod selector 7:
    // jump-table BTI; one scalar input/output check; SEP command 7.
    uint64_t sel7_matches[] = {
        0xd503249f, 0xf90063ff, 0xb900b3ff, 0xb90133ff,
        0x6f00e400, 0xad0883e0, 0xad0783e0, 0x3d803be0,
        0xb9402a88, 0x7100051f, 0x54000001, 0xb9405288,
        0x7100051f, 0x54000001, 0x12800008, 0xb900bfe8,
        0xf9401288, 0xb9400102, 0x9102f3e3, 0xaa1603e0,
        0x528000e1, 0x94000000,
    };
    uint64_t sel7_masks[] = {
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xff00001f, 0xffffffff,
        0xffffffff, 0xff00001f, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xfc000000,
    };
    xnu_pf_maskmatch(aks_text_exec_patchset, "aks_selector7_xr_18710",
        sel7_matches, sel7_masks, sizeof(sel7_matches) / sizeof(uint64_t), true,
        (void *)kpf_aks_selector7_xr_18710_callback);

    // XR 22H374, AppleKeyStoreUserClient gated externalMethod selector 14
    // (KeyBagGetSystem / aks_get_system). Anchored on the exact 10-word
    // prologue ending in "MOV W22, #0; B shared_sep_handler". The callback
    // changes W22 from the request type (0) to the keybag-less system handle
    // (-3), then retargets the final B to the shared success epilogue.
    uint64_t sel14_matches[] = {
        0xd503249f, // BTI j
        0xb9402a88, // LDR W8, [X20, #0x28]  (scalarInputCount)
        0x7100051f, // CMP W8, #1
        0x54000000, // B.EQ <has-input shared path>
        0x35000008, // CBNZ W8, <default>  (Rt=8 baked into base; mask wildcards only imm19)
        0xb9405288, // LDR W8, [X20, #0x50]  (scalarOutputCount)
        0x7100051f, // CMP W8, #1
        0x54000001, // B.NE <default>
        0x52800016, // MOV W22, #0           (keybag type = 0)
        0x14000000, // B <SEP shared handler>  -> retargeted by callback
    };
    uint64_t sel14_masks[] = {
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xff00001f, // any 19-bit imm, cond=EQ
        0xff00001f, // CBNZ with any imm, exact Rt=W8
        0xffffffff,
        0xffffffff,
        0xff00001f, // B.NE with any imm
        0xffffffff, // exact MOV W22, #0
        0xfc000000, // any 26-bit imm, exact B opcode
    };
    xnu_pf_maskmatch(aks_text_exec_patchset, "aks_selector14_xr_18710",
        sel14_matches, sel14_masks, sizeof(sel14_matches) / sizeof(uint64_t), true,
        (void *)kpf_aks_selector14_xr_18710_callback);
}

static void kpf_sep_patches(xnu_pf_patchset_t *sep_text_exec_patchset)
{
    if(gKernelVersion.darwinMajor != 24 || xnu_platform() != PLATFORM_IOS)
    {
        return;
    }

    // XR 18.7.10 AppleSEPManager::sepPanicCheck:
    //   pacibsp
    //   stp x20, x19, [sp, #-0x20]!
    //   stp x29, x30, [sp, #0x10]
    //   add x29, sp, #0x10
    //   mov x19, x0
    //   ldr x0, [x0, #0x108]
    //   cbz x0, return
    //   bl  parse_panic_record
    //   cbnz w0, dump_and_panic
    uint64_t matches[] =
    {
        0xd503237f,
        0xa9be4ff4,
        0xa9017bfd,
        0x910043fd,
        0xaa0003f3,
        0xf9408400,
        0xb4000000,
        0x94000000,
        0x35000000,
    };
    uint64_t masks[] =
    {
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xff00001f,
        0xfc000000,
        0xff00001f,
    };
    xnu_pf_maskmatch(sep_text_exec_patchset, "sep_panic_check_xr_18710",
        matches, masks, sizeof(matches) / sizeof(uint64_t), true,
        (void *)kpf_sep_panic_check_xr_18710_callback);

    // XR 18.7.10 AppleSEPManager boot-timeout callback (0xfffffff00928f4e8):
    //   pacibsp; sub sp, sp, #0x20; stp x29, x30, [sp, #0x10]
    //   add x29, sp, #0x10; ldr w8, [x0, #0xdc]; cmp w8, #7
    //   b.eq return; add x1, x0, #0xdc; sub w9, w8, #5
    uint64_t boot_timeout_matches[] =
    {
        0xd503237f,
        0xd10083ff,
        0xa9017bfd,
        0x910043fd,
        0xb940dc08,
        0x71001d1f,
        0x54000000,
        0x91037001,
        0x51001509,
    };
    uint64_t boot_timeout_masks[] =
    {
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xff00001f,
        0xffffffff,
        0xffffffff,
    };
    xnu_pf_maskmatch(sep_text_exec_patchset, "sep_boot_timeout_xr_18710",
        boot_timeout_matches, boot_timeout_masks,
        sizeof(boot_timeout_matches) / sizeof(uint64_t), true,
        (void *)kpf_sep_boot_timeout_xr_18710_callback);
}

static void kpf_usb_restore_mode_patches(xnu_pf_patchset_t *accessory_text_exec_patchset)
{
    if(gKernelVersion.darwinMajor != 24 || xnu_platform() != PLATFORM_IOS)
    {
        return;
    }

    // First boot-argument parse in the restore-mode predicate:
    //   adrp/add x0, "rd"; mov x1, sp; mov w2, #0x20; bl parse_boot_arg
    // The callback validates the nearby "rootdev" parse, common call target,
    // and exact function prologue before writing anything.
    uint64_t matches[] =
    {
        0x90000000,
        0x91000000,
        0x910003e1,
        0x52800402,
        0x94000000,
    };
    uint64_t masks[] =
    {
        0x9f00001f,
        0xffc003ff,
        0xffffffff,
        0xffffffff,
        0xfc000000,
    };
    xnu_pf_maskmatch(accessory_text_exec_patchset, "usb_restore_mode_xr_18710",
        matches, masks, sizeof(matches) / sizeof(uint64_t), true,
        (void *)kpf_usb_restore_mode_xr_18710_callback);
}

kpf_component_t kpf_sep =
{
    .patches =
    {
        { "com.apple.driver.AppleSEPKeyStore", "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_aks_patches },
        { "com.apple.driver.AppleSEPManager", "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_sep_patches },
        { "com.apple.iokit.IOAccessoryManager", "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_usb_restore_mode_patches },
        {},
    },
};
