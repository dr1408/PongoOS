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
 *
 */

#include "kpf.h"
#include <paleinfo.h>
#include <pongo.h>
#include <xnu/xnu.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern uint32_t kdi_shc[], kdi_shc_orig[], kdi_shc_get[], kdi_shc_get_vtable_auth[],
    kdi_shc_get_call_auth[], kdi_shc_addr[], kdi_shc_size[], kdi_shc_new[],
    kdi_shc_set[], kdi_shc_set_vtable_auth[], kdi_shc_set_call_auth[],
    kdi_shc_release_vtable_auth[], kdi_shc_release_call_auth[], kdi_shc_end[];

static bool did_run = false;
static bool do_patchfind = false;
static bool do_shellcode = false;

static void *overlay_buf = NULL;
static uint32_t overlay_size = 0;

static uint32_t *kdi_patchpoint = NULL;
static uint16_t OSDictionary_getObject_idx = 0, OSDictionary_setObject_idx = 0;
static uint16_t OSDictionary_vtable_discriminator = 0;
static uint16_t OSDictionary_getObject_discriminator = 0;
static uint16_t OSDictionary_setObject_discriminator = 0;
static uint16_t OSObject_vtable_discriminator = 0;
static uint16_t OSObject_release_discriminator = 0;
static uint64_t IOMemoryDescriptor_withPhysicalAddress = 0;

static uint16_t movk_imm16(uint32_t insn)
{
    return (insn >> 5) & 0xffff;
}

static uint32_t *find_prev_movk48(uint32_t *from, size_t count, uint32_t reg)
{
    return find_prev_insn(from, count, 0xf2e00000 | reg, 0xffe0001f);
}

static void patch_add_imm12(uint32_t *insn, uint32_t reg, uint32_t value)
{
    uint32_t expected = 0x91000000 | (reg << 5) | reg;
    if(*insn != expected || value > 0xfff)
    {
        panic("KDI invalid ADD placeholder/value: 0x%08x/0x%x", *insn, value);
    }
    *insn = expected | (value << 10);
}

static void patch_movk48_imm16(uint32_t *insn, uint32_t reg, uint16_t value)
{
    uint32_t expected = 0xf2e00000 | reg;
    if(*insn != expected)
    {
        panic("KDI invalid MOVK placeholder: 0x%08x", *insn);
    }
    *insn = expected | ((uint32_t)value << 5);
}

static bool kpf_overlay_iomemdesc_physical_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(IOMemoryDescriptor_withPhysicalAddress)
    {
        panic("kpf_overlay: Ambiguous IOMemoryDescriptor::withPhysicalAddress implementations");
    }

    uint32_t *entry = find_prev_insn(opcode_stream, 32, 0xd503237f, 0xffffffff); // pacibsp
    if(!entry)
    {
        return false;
    }

    IOMemoryDescriptor_withPhysicalAddress = xnu_ptr_to_va(entry);
    puts("KPF: Found IOMemoryDescriptor::withPhysicalAddress");
    return true;
}

static void kpf_overlay_iomemdesc(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    uint64_t matches[] =
    {
        0x321b0265, // orr w5, w19, 0x20 (kIOMemoryTypePhysical64)
        0xaa0003f3, // mov x19, x0
        0x52800022, // mov w2, 1
        0x52800003, // mov w3, 0
        0xd2800004, // mov x4, 0 (TASK_NULL)
        0xd2800006, // mov x6, 0
    };
    uint64_t masks[] =
    {
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "iomemdesc_physical", matches, masks,
        sizeof(matches)/sizeof(uint64_t), false,
        (void*)kpf_overlay_iomemdesc_physical_callback);
}

static bool kpf_overlay_kdi_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    uint64_t page = ((uint64_t)(opcode_stream + 1) & ~0xfffULL) + adrp_off(opcode_stream[1]);
    uint32_t off = (opcode_stream[2] >> 10) & 0xfff;
    const char *str = (const char*)(page + off);

    if(strcmp(str, "image-secrets") == 0)
    {
        if(!OSDictionary_getObject_idx) // first match
        {
            OSDictionary_getObject_idx = (opcode_stream[0] >> 10) & 0xfff;
        }
        else // second match
        {
            uint32_t *blr = find_next_insn(opcode_stream + 3, 5, 0xd63f0100, 0xffffffff); // blr x8
            if(!blr)
            {
                return false;
            }
            uint32_t *bl = find_next_insn(blr + 1, 8, 0x94000000, 0xfc000000); // bl
            if(!bl || (bl[1] & 0xff00001f) != 0xb5000000) // cbnz x0
            {
                return false;
            }
            kdi_patchpoint = bl;
        }
    }
    else if(strcmp(str, "netboot-image") == 0)
    {
        OSDictionary_setObject_idx = (opcode_stream[0] >> 10) & 0xfff;
    }
    else
    {
        return false;
    }

    // Return true once all found
    if(kdi_patchpoint != NULL && OSDictionary_getObject_idx != 0 && OSDictionary_setObject_idx != 0)
    {
        puts("KPF: Found KDI");
        return true;
    }
    return false;
}

static bool kpf_overlay_kdi_fileset_get_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    uint64_t page = ((uint64_t)(opcode_stream + 3) & ~0xfffULL) + adrp_off(opcode_stream[3]);
    uint32_t off = (opcode_stream[4] >> 10) & 0xfff;
    const char *str = (const char*)(page + off);
    if(strcmp(str, "image-secrets")) return false;

    uint16_t index = ((opcode_stream[0] >> 5) & 0xffff) / sizeof(uint64_t);
    uint32_t *autda = find_prev_insn(opcode_stream, 8, 0xdac11810, 0xfffffc1f); // autda x16, xN
    uint32_t modifier_reg = autda ? ((*autda >> 5) & 0x1f) : 0;
    uint32_t *vtable_movk = autda ? find_prev_movk48(autda, 4, modifier_reg) : NULL;
    uint32_t *blraa = find_next_insn(opcode_stream + 4, 5, 0xd73f0910, 0xffffffff); // blraa x8, x16
    uint32_t *call_movk = blraa ? find_prev_movk48(blraa, 4, 16) : NULL;
    if(!call_movk)
    {
        return false;
    }

    if(!OSDictionary_getObject_idx)
    {
        if(!vtable_movk)
        {
            return false;
        }
        OSDictionary_getObject_idx = index;
        OSDictionary_vtable_discriminator = movk_imm16(*vtable_movk);
        OSDictionary_getObject_discriminator = movk_imm16(*call_movk);
        return false;
    }

    uint32_t *bl = blraa ? find_next_insn(blraa + 1, 16, 0x94000000, 0xfc000000) : NULL;
    if(!bl || (bl[1] & 0xff00001f) != 0xb5000000) // cbnz x0
    {
        return false;
    }

    kdi_patchpoint = bl;
    if(OSDictionary_setObject_idx)
    {
        puts("KPF: Found KDI (fileset)");
        return true;
    }
    return false;
}

// iOS 18.7.10 arm64e variant of kpf_overlay_kdi_fileset_get_callback.
// Compared to the baseline callback this shifts ADRP/ADD indices by +1
// (because the matcher window includes an extra `mov Xd, x16` after the
// `ldr x8, [x16]`), and broadens the forward BLRAA search to accept any
// (pointer, modifier) register pair - iOS 18 observed `blraa x8, x17` here.
static bool kpf_overlay_kdi_fileset_get_ios18_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    uint64_t page = ((uint64_t)(opcode_stream + 4) & ~0xfffULL) + adrp_off(opcode_stream[4]);
    uint32_t off = (opcode_stream[5] >> 10) & 0xfff;
    const char *str = (const char*)(page + off);
    if(strcmp(str, "image-secrets")) return false;

    uint16_t index = ((opcode_stream[0] >> 5) & 0xffff) / sizeof(uint64_t);
    uint32_t *autda = find_prev_insn(opcode_stream, 8, 0xdac11810, 0xfffffc1f); // autda x16, xN
    uint32_t modifier_reg = autda ? ((*autda >> 5) & 0x1f) : 0;
    uint32_t *vtable_movk = autda ? find_prev_movk48(autda, 4, modifier_reg) : NULL;
    uint32_t *blraa = find_next_insn(opcode_stream + 5, 5, 0xd73f0800, 0xfffffc00); // blraa xN, xM
    uint32_t blraa_rm = blraa ? (*blraa & 0x1f) : 0;
    uint32_t *call_movk = blraa ? find_prev_movk48(blraa, 4, blraa_rm) : NULL;
    if(!call_movk)
    {
        return false;
    }

    if(!OSDictionary_getObject_idx)
    {
        if(!vtable_movk)
        {
            return false;
        }
        OSDictionary_getObject_idx = index;
        OSDictionary_vtable_discriminator = movk_imm16(*vtable_movk);
        OSDictionary_getObject_discriminator = movk_imm16(*call_movk);
        return false;
    }

    uint32_t *bl = blraa ? find_next_insn(blraa + 1, 16, 0x94000000, 0xfc000000) : NULL;
    if(!bl || (bl[1] & 0xff00001f) != 0xb5000000) // cbnz x0
    {
        return false;
    }

    kdi_patchpoint = bl;
    if(OSDictionary_setObject_idx)
    {
        puts("KPF: Found KDI (fileset iOS 18)");
        return true;
    }
    return false;
}

static bool kpf_overlay_kdi_fileset_set_common_callback(struct xnu_pf_patch *patch,
    uint32_t *opcode_stream, bool xr_18710)
{
    uint64_t page = ((uint64_t)(opcode_stream + 2) & ~0xfffULL) + adrp_off(opcode_stream[2]);
    uint32_t off = (opcode_stream[3] >> 10) & 0xfff;
    const char *str = (const char*)(page + off);
    if(strcmp(str, "netboot-image")) return false;

    uint32_t *set_blraa = find_next_insn(opcode_stream + 4, 12, 0xd73f0920, 0xffffffe0); // blraa x9, xN
    uint32_t set_modifier = set_blraa ? (*set_blraa & 0x1f) : 0;
    uint32_t *set_call_movk = set_blraa ? find_prev_movk48(set_blraa, 4, set_modifier) : NULL;

    uint32_t *release_autda = set_blraa ? find_next_insn(set_blraa + 1, 12, 0xdac11a30, 0xffffffff) : NULL;
    uint32_t *release_vtable_movk = release_autda ? find_prev_movk48(release_autda, 4, 17) : NULL;
    // XR 18.7.10 uses blraa x9, x17 here; the tvOS fileset uses x8, x16.
    uint32_t *release_blraa = release_autda ? find_next_insn(release_autda + 1, 12,
        xr_18710 ? 0xd73f0931 : 0xd73f0910, 0xffffffff) : NULL;
    uint32_t *release_call_movk = release_blraa ? find_prev_movk48(release_blraa, 4,
        xr_18710 ? 17 : 16) : NULL;
    if(!set_call_movk || !release_vtable_movk || !release_call_movk)
    {
        return false;
    }

    OSDictionary_setObject_idx = (opcode_stream[1] >> 10) & 0xfff;
    OSDictionary_setObject_discriminator = movk_imm16(*set_call_movk);
    OSObject_vtable_discriminator = movk_imm16(*release_vtable_movk);
    OSObject_release_discriminator = movk_imm16(*release_call_movk);
    if(kdi_patchpoint && OSDictionary_getObject_idx)
    {
        puts("KPF: Found KDI (fileset)");
        return true;
    }
    return false;
}

static bool kpf_overlay_kdi_fileset_set_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    return kpf_overlay_kdi_fileset_set_common_callback(patch, opcode_stream, false);
}

static bool kpf_overlay_kdi_fileset_set_xr_18710_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    return kpf_overlay_kdi_fileset_set_common_callback(patch, opcode_stream, true);
}

static void kpf_overlay_kdi_patch(xnu_pf_patchset_t *kdi_text_exec_patchset)
{
    uint64_t matches[] =
    {
        0xf9400108, // ldr x8, [x8, 0x...]
        0x90000001, // adrp x1, 0x...
        0x91000021, // add x1, x1, 0x...
    };
    uint64_t masks[] =
    {
        0xffc003ff,
        0x9f00001f,
        0xffc003ff,
    };
    xnu_pf_maskmatch(kdi_text_exec_patchset, "KDI_legacy", matches, masks, sizeof(matches)/sizeof(uint64_t), false, (void*)kpf_overlay_kdi_callback);

    uint64_t fileset_get_matches[] =
    {
        0xd2800011, // mov x17, vtable byte offset
        0x8b110210, // add x16, x16, x17
        0xf9400208, // ldr x8, [x16]
        0x90000001, // adrp x1, string
        0x91000021, // add x1, x1, string offset
    };
    uint64_t fileset_get_masks[] =
    {
        0xff80001f,
        0xffffffff,
        0xffffffff,
        0x9f00001f,
        0xffc003ff,
    };
    xnu_pf_maskmatch(kdi_text_exec_patchset, "KDI_fileset_get", fileset_get_matches, fileset_get_masks, sizeof(fileset_get_matches)/sizeof(uint64_t), false, (void*)kpf_overlay_kdi_fileset_get_callback);

    // iOS 18.7.10 arm64e inserts a `MOV Xd, x16` between `ldr x8, [x16]` and
    // `adrp x1, string`. Match the 6-insn variant separately so the KDI get
    // path resolves on iOS 18 kernels. The dedicated ios18 callback shifts the
    // adrp/add indices by +1 and broadens the forward BLRAA search.
    uint64_t fileset_get_ios18_matches[] =
    {
        0xd2800011, // mov x17, vtable byte offset
        0x8b110210, // add x16, x16, x17
        0xf9400208, // ldr x8, [x16]
        0xaa1003e0, // mov Xd, x16 (ORR Xd, XZR, X16)
        0x90000001, // adrp x1, string
        0x91000021, // add x1, x1, string offset
    };
    uint64_t fileset_get_ios18_masks[] =
    {
        0xff80001f,
        0xffffffff,
        0xffffffff,
        0xffffffe0, // keep opcode + Rm=16 + Rn=XZR, wildcard Rd
        0x9f00001f,
        0xffc003ff,
    };
    xnu_pf_maskmatch(kdi_text_exec_patchset, "KDI_fileset_get_ios18", fileset_get_ios18_matches, fileset_get_ios18_masks, sizeof(fileset_get_ios18_matches)/sizeof(uint64_t), false, (void*)kpf_overlay_kdi_fileset_get_ios18_callback);

    uint64_t fileset_set_matches[] =
    {
        0x91000208, // add x8, x16, vtable byte offset
        0xf9400209, // ldr x9, [x16, same offset]
        0x90000001, // adrp x1, string
        0x91000021, // add x1, x1, string offset
    };
    uint64_t fileset_set_masks[] =
    {
        0xffc003ff,
        0xffc003ff,
        0x9f00001f,
        0xffc003ff,
    };
    if(gKernelVersion.darwinMajor == 24 && gKernelVersion.darwinMinor == 6 &&
       gKernelVersion.xnuMajor == 11417 && gKernelVersion.xnuMinor == 140 &&
       gKernelVersion.xnuPatch == 69 && gKernelVersion.xnuFlags == 706 &&
       gKernelVersion.xnuRevision == 66 && gKernelVersion.xnuRun == 1 &&
       gKernelVersion.machineConfig == 0x8020 && xnu_platform() == PLATFORM_IOS)
    {
        xnu_pf_maskmatch(kdi_text_exec_patchset, "KDI_fileset_set_xr_18710",
            fileset_set_matches, fileset_set_masks,
            sizeof(fileset_set_matches)/sizeof(uint64_t), false,
            (void*)kpf_overlay_kdi_fileset_set_xr_18710_callback);
    }
    else
    {
        xnu_pf_maskmatch(kdi_text_exec_patchset, "KDI_fileset_set",
            fileset_set_matches, fileset_set_masks,
            sizeof(fileset_set_matches)/sizeof(uint64_t), false,
            (void*)kpf_overlay_kdi_fileset_set_callback);
    }
}

static void kpf_overlay_xnu_patches(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    if(do_patchfind)
    {
        kpf_overlay_iomemdesc(xnu_text_exec_patchset);
    }
}

static void kpf_overlay_kdi_patches(xnu_pf_patchset_t *kdi_text_exec_patchset)
{
    if(do_patchfind)
    {
        kpf_overlay_kdi_patch(kdi_text_exec_patchset);
    }
}

static void kpf_overlay_init(struct mach_header_64 *hdr, xnu_pf_range_t *cstring)
{
    did_run = true;

    // Do this unconditionally on DEV_BUILD
    // TODO: Turn this into flags somehow.
#ifdef DEV_BUILD
    do_patchfind = true;
#else
    do_patchfind = overlay_size > 0;
#endif
    do_shellcode = overlay_size > 0;
}

static void kpf_overlay_finish(struct mach_header_64 *hdr)
{
    if(do_patchfind && (!kdi_patchpoint || !OSDictionary_getObject_idx ||
        !OSDictionary_setObject_idx || !OSDictionary_vtable_discriminator ||
        !OSDictionary_getObject_discriminator || !OSDictionary_setObject_discriminator ||
        !OSObject_vtable_discriminator || !OSObject_release_discriminator))
    {
        panic("Missing patch: KDI");
    }

    if (do_shellcode)
        palera1n_flags |= palerain_option_overlay;
}


static uint32_t kpf_overlay_size(void)
{
    if(!do_shellcode)
    {
        return 0;
    }
    return kdi_shc_end - kdi_shc;
}

static uint32_t kpf_overlay_emit(uint32_t *shellcode_area)
{
    // Check this here, before we decide whether to actually emit shellcode.
    if(do_patchfind && !IOMemoryDescriptor_withPhysicalAddress)
    {
        panic("Missing patch: IOMemoryDescriptor");
    }

    if(!do_shellcode)
    {
        return 0;
    }

    void *ov_static_buf = alloc_static(overlay_size);
    printf("Allocated static region for overlay: %p, sz: 0x%x\n", ov_static_buf, overlay_size);
    memcpy(ov_static_buf, overlay_buf, overlay_size);

    uint64_t overlay_paddr = vatophys_static(ov_static_buf);
    uint64_t shellcode_addr = xnu_ptr_to_va(shellcode_area);
    uint64_t patchpoint_addr = xnu_ptr_to_va(kdi_patchpoint);
    uint64_t orig_func = patchpoint_addr + (sxt32(*kdi_patchpoint, 26) << 2);

    size_t orig_idx = kdi_shc_orig - kdi_shc;
    size_t get_idx  = kdi_shc_get  - kdi_shc;
    size_t set_idx  = kdi_shc_set  - kdi_shc;
    size_t get_vtable_auth_idx = kdi_shc_get_vtable_auth - kdi_shc;
    size_t get_call_auth_idx = kdi_shc_get_call_auth - kdi_shc;
    size_t set_vtable_auth_idx = kdi_shc_set_vtable_auth - kdi_shc;
    size_t set_call_auth_idx = kdi_shc_set_call_auth - kdi_shc;
    size_t release_vtable_auth_idx = kdi_shc_release_vtable_auth - kdi_shc;
    size_t release_call_auth_idx = kdi_shc_release_call_auth - kdi_shc;
    size_t new_idx  = kdi_shc_new  - kdi_shc;
    size_t addr_idx = kdi_shc_addr - kdi_shc;
    size_t size_idx = kdi_shc_size - kdi_shc;

    int64_t orig_off  = orig_func - (shellcode_addr + (orig_idx << 2));
    int64_t new_off   = IOMemoryDescriptor_withPhysicalAddress - (shellcode_addr + (new_idx << 2));
    int64_t patch_off = shellcode_addr - patchpoint_addr;
    if(orig_off > 0x7fffffcLL || orig_off < -0x8000000LL || new_off > 0x7fffffcLL || new_off < -0x8000000LL || patch_off > 0x7fffffcLL || patch_off < -0x8000000LL)
    {
        panic("kdi_patch jump too far: 0x%llx/0x%llx/0x%llx", orig_off, new_off, patch_off);
    }

    memcpy(shellcode_area, kdi_shc, (uintptr_t)kdi_shc_end - (uintptr_t)kdi_shc);

    shellcode_area[orig_idx] |= (orig_off >> 2) & 0x03ffffff;
    patch_add_imm12(&shellcode_area[get_idx], 16,
        OSDictionary_getObject_idx * sizeof(uint64_t));
    patch_add_imm12(&shellcode_area[set_idx], 16,
        OSDictionary_setObject_idx * sizeof(uint64_t));
    patch_movk48_imm16(&shellcode_area[get_vtable_auth_idx], 17,
        OSDictionary_vtable_discriminator);
    patch_movk48_imm16(&shellcode_area[get_call_auth_idx], 16,
        OSDictionary_getObject_discriminator);
    patch_movk48_imm16(&shellcode_area[set_vtable_auth_idx], 17,
        OSDictionary_vtable_discriminator);
    patch_movk48_imm16(&shellcode_area[set_call_auth_idx], 17,
        OSDictionary_setObject_discriminator);
    patch_movk48_imm16(&shellcode_area[release_vtable_auth_idx], 17,
        OSObject_vtable_discriminator);
    patch_movk48_imm16(&shellcode_area[release_call_auth_idx], 16,
        OSObject_release_discriminator);
    shellcode_area[new_idx]  |= (new_off >> 2) & 0x03ffffff;
    shellcode_area[addr_idx + 0] |= ((overlay_paddr >> 48) & 0xffff) << 5;
    shellcode_area[addr_idx + 1] |= ((overlay_paddr >> 32) & 0xffff) << 5;
    shellcode_area[addr_idx + 2] |= ((overlay_paddr >> 16) & 0xffff) << 5;
    shellcode_area[addr_idx + 3] |= ((overlay_paddr >>  0) & 0xffff) << 5;
    shellcode_area[size_idx + 0] |= ((overlay_size >> 16) & 0xffff) << 5;
    shellcode_area[size_idx + 1] |= ((overlay_size >>  0) & 0xffff) << 5;

    *kdi_patchpoint = 0x94000000 | ((patch_off >> 2) & 0x03ffffff);

    free(overlay_buf);
    overlay_buf = NULL;
    overlay_size = 0;

    return kdi_shc_end - kdi_shc;
}

void kpf_overlay_cmd(const char *cmd, char *args)
{
    if(did_run)
    {
        // TODO: Should this panic?
        //       Probably refactor if and when we ever get retval to pongoterm?
        puts("KPF ran already, overlay cannot be set anymore.");
        return;
    }
    if(!loader_xfer_recv_count)
    {
        puts("Please upload an overlay before issuing this command.");
        return;
    }
    if(overlay_buf)
    {
        free(overlay_buf);
    }
    overlay_buf = malloc(loader_xfer_recv_count);
    if(!overlay_buf)
    {
        panic("Failed to allocate heap for overlay");
    }
    overlay_size = loader_xfer_recv_count;
    memcpy(overlay_buf, loader_xfer_recv_data, overlay_size);
    loader_xfer_recv_count = 0;
}

kpf_component_t kpf_overlay =
{
    .init = kpf_overlay_init,
    .finish = kpf_overlay_finish,
    .shc_size = kpf_overlay_size,
    .shc_emit = kpf_overlay_emit,
    .patches =
    {
        { NULL,                          "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_overlay_xnu_patches },
        { "com.apple.driver.DiskImages", "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_overlay_kdi_patches },
        {},
    },
};
