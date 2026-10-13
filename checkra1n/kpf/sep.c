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

kpf_component_t kpf_sep =
{
    .patches =
    {
        { "com.apple.driver.AppleSEPManager", "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_sep_patches },
        {},
    },
};
