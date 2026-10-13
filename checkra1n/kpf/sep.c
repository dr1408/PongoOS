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
        { "com.apple.driver.AppleSEPManager", "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_sep_patches },
        { "com.apple.iokit.IOAccessoryManager", "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_usb_restore_mode_patches },
        {},
    },
};
