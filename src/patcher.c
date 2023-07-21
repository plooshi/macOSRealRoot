#ifdef __gnu_linux__
#define _GNU_SOURCE 
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "formats/macho.h"
#include "plooshfinder.h"
#include "plooshfinder32.h"

void *kernel_buf;
size_t kernel_len;
int platform = 0;

bool has_rootvp;
bool found_trustcache_new;
bool found_trustcache_old;
void *_apfs_kext;
void *_amfi_kext;

bool patch_snapshot(struct pf_patch_t *patch, uint32_t *stream) {
    printf("%s: Found apfs_root_snapshot_select\n", __FUNCTION__);

    stream[5] = nop;
    stream[6] = nop;
    return true;
}

bool patch_vnop_rootvp_auth(struct pf_patch_t *patch, uint32_t *stream) {
    if (!has_rootvp) return false;

    // cmp xN, xM - wrong match
    if(pf_maskmatch32(stream[2], 0xeb000300, 0xffe0ffe0)) {
        return false;
    }

    // Old sequence like:
    // 0xfffffff00759d9f8      61068d52       mov w1, 0x6833
    // 0xfffffff00759d9fc      8100b072       movk w1, 0x8004, lsl 16
    // 0xfffffff00759da00      020080d2       mov x2, 0
    // 0xfffffff00759da04      03008052       mov w3, 0
    // 0xfffffff00759da08      4ca3f797       bl sym._VNOP_IOCTL
    if (
        stream[0] == 0x528d0661 && // mov w1, 0x6833
        stream[1] == 0x72b00081 && // movk w1, 0x8004, lsl 16
        stream[2] == 0xd2800002 && // mov x2, 0
        stream[3] == 0x52800003 && // mov w3, 0
        pf_maskmatch32(stream[4], 0x94000000, 0xfc000000) // bl sym._VNOP_IOCTL
    ) {
        printf("%s: Found vnop_rootvp_auth\n", __FUNCTION__);
        // Replace the call with mov x0, 0
        stream[4] = 0xd2800000;
        return true;
    } else if (
        (
            pf_maskmatch32(stream[2], 0xa90003e0, 0xffc003e0) && // stp xN, xM, [sp, ...]
            ((stream[2] & 0x1f) == (stream[1] & 0x1f) || ((stream[2] >> 10) & 0x1f) == (stream[1] & 0x1f)) // match reg
        ) ||
        (
            pf_maskmatch32(stream[2], 0xf90003e0, 0xffc003e0) && // str xN, [sp, ...]
            (stream[2] & 0x1f) == (stream[1] & 0x1f) // match reg
        )
    ) {
        // add x0, sp, 0x...
        uint32_t *sp = pf_find_next(stream + 3, 0x10, 0x910003e0, 0xffc003ff);
        if(sp && (sp[1] & 0xfffffc1f) == 0xd63f0000) // blr
        {
            printf("%s: Found vnop_rootvp_auth\n", __FUNCTION__);
            // Replace the call with mov x0, 0
            sp[1] = 0xd2800000;
            return true;
        }
    }
    return false;
}

bool patch_livefs(struct pf_patch_t *patch, uint32_t *stream) {
    char *str = fileset_follow_xref(kernel_buf, _apfs_kext, stream);
    if (strcmp(str, "\"Failed to find the root snapshot: %s (%d). Rooting from the live fs of a sealed volume is not allowed on a RELEASE build\\n\" @%s:%d") == 0) {
        uint32_t *call = pf_find_prev(stream, 0x250, 0x37280000, 0xfff80000);

        if (!call) {
            call = pf_find_prev(stream, 0x100, 0x14000000, 0xfc000000);
            
            if (!call) {
                printf("%s: Failed to find call!\n", __FUNCTION__);
                return false;
            }
        }

        call[0] = nop;
        printf("%s: Found livefs\n", __FUNCTION__);
    }
    return true;
}

bool patch_trustcache_old(struct pf_patch_t *patch, uint32_t *stream) {
    if (found_trustcache_new) return false;
    if(found_trustcache_old) {
        printf("%s: Found more then one trustcache call\n", __FUNCTION__);
        return false;
    }
    found_trustcache_old = true;

    uint32_t *bl = stream - 1;
    if(pf_maskmatch32(*bl, 0xaa0003f0, 0xffff03f0)) { // mov x{16-31}, x0 
        --bl;
    }
    if(!pf_maskmatch32(*bl, 0x94000000, 0xfc000000)) { // bl
        printf("%s: Missing bl\n", __FUNCTION__);
        return false;
    }

    // Follow the call
    uint32_t *lookup_in_static_trust_cache = fileset_follow_branch(kernel_buf, _amfi_kext, bl);
    // Skip any redirects
    while((*lookup_in_static_trust_cache & 0xfc000000) == 0x14000000) {
        lookup_in_static_trust_cache = fileset_follow_branch(kernel_buf, _amfi_kext, lookup_in_static_trust_cache);
    }
    // We legit, trust me bro.
    lookup_in_static_trust_cache[0] = 0xd2802020; // mov x0, 0x101
    lookup_in_static_trust_cache[1] = ret;

    printf("%s: Found trustcache\n", __FUNCTION__);
    return true;
}

bool patch_trustcache_new(struct pf_patch_t *patch, uint32_t *stream) {
    if (found_trustcache_old) return false;
    if(found_trustcache_new) {
        printf("%s: Found more then one trustcache function\n", __FUNCTION__);
        return false;
    }
    found_trustcache_new = true;

    // Seek backwards to start of func. This func uses local stack space,
    // so we should always have a "sub sp, sp, 0x..." instruction.
    uint32_t *start = pf_find_prev(stream, 20, 0xd10003ff, 0xffc003ff);
    if(!start) {
        printf("%s: Failed to find start of function\n", __FUNCTION__);
        return false;
    }

    // Just replace the entire func, no prisoners today.
    start[0] = 0xd2800020; // mov x0, 1
    start[1] = 0xb4000042; // cbz x2, .+0x8
    start[2] = 0xf9000040; // str x0, [x2]
    start[3] = ret;

    printf("%s: Found trustcache\n", __FUNCTION__);
    return true;
}


#define addr_to_ptr(macho, addr) fileset_va_to_ptr(macho, macho_xnu_untag_va(addr))
#define patch(macho, function, addr, size, ...) function(macho, kernel_buf + addr, size, ##__VA_ARGS__);
#define find_str_in_region(str, addr, size) memmem(addr, size, str, sizeof(str));
#define find_partial_str_in_region(str, addr, size) memmem(addr, size, str, sizeof(str) - 1);
#define patch_sbop(ops, op, val)       \
    if (ops->op) {                     \
        ops->op &= 0xFFFFFFFF00000000; \
        ops->op |= val;                \
    }

void patch_kernel() {
    printf("Starting KPlooshFinder\n");

    struct fileset_entry_command *kernel_entry = macho_get_fileset(kernel_buf, "com.apple.kernel");
    struct mach_header_64 *kernel = kernel_buf + kernel_entry->fileoff;

    struct section_64 *data_const = macho_find_section(kernel, "__DATA_CONST", "__const");
    if (!data_const) {
        printf("Unable to find data const!\n");
        return;
    }

    struct section_64 *cstring = macho_find_section(kernel, "__TEXT", "__cstring");
    if (!cstring) {
        printf("Unable to find cstring!\n");
        return;
    }

    struct section_64 *text = macho_find_section(kernel, "__TEXT_EXEC", "__text");
    if (!text) {
        printf("Unable to find text!\n");
        return;
    }


    const char rootvp_string[] = "rootvp not authenticated after mounting";
    const char *rootvp_string_match = find_partial_str_in_region(rootvp_string, kernel_buf + cstring->offset, cstring->size);
    const char constraints_string[] = "mac_proc_check_launch_constraints";
    const char *constraints_string_match = find_str_in_region(constraints_string, kernel_buf + cstring->offset, cstring->size);
    const char cryptex_string[] = "/private/preboot/Cryptexes";
    const char *cryptex_string_match = find_str_in_region(cryptex_string, kernel_buf + cstring->offset, cstring->size);
    const char kmap_port_string[] = "userspace has control access to a"; // iOS 14 had broken panic strings
    const char *kmap_port_string_match = find_partial_str_in_region(kmap_port_string, kernel_buf + cstring->offset, cstring->size);

    has_rootvp = rootvp_string_match != NULL;

    struct fileset_entry_command *apfs_entry = macho_get_fileset(kernel_buf, "com.apple.filesystems.apfs");
    struct mach_header_64 *apfs_kext = kernel_buf + apfs_entry->fileoff;
    _apfs_kext = apfs_kext;

    struct section_64 *apfs_text = macho_find_section(apfs_kext, "__TEXT_EXEC", "__text");
    if (!apfs_text) {
        printf("Unable to find APFS text!\n");
        return;
    }

    uint32_t snapshot_matches[] = {
        0x52800200, // mov w0, 0x10
        0x94000000, // bl csr_check
        0xaa0003e0, // mov x*, x0
        0x52810000, // mov w0, 0x800
        0x94000000, // bl csr_check
        0x34000000, // cbnz
        0x34000000  // cbnz
    };
    uint32_t snapshot_masks[] = {
        0xffffffff, 
        0xfc000000, 
        0xffffffe0, 
        0xffffffff, 
        0xfc000000, 
        0xff000000, 
        0xff000000
    };

    struct pf_patch_t snapshot = pf_construct_patch(snapshot_matches, snapshot_masks, sizeof(snapshot_matches) / sizeof(uint32_t), (void *) patch_snapshot);

    struct pf_patch_t snapshot_patches[] = {
        snapshot
    };

    struct pf_patchset_t snapshot_patchset = pf_construct_patchset(snapshot_patches, sizeof(snapshot_patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(kernel_buf + apfs_text->offset, apfs_text->size, snapshot_patchset);

    // r2: /x 60068d528000b072:f0fffffff0ffffff
    uint32_t rootvp_matches[] = {
        0x528d0660, // movz w{0-15}, 0x6833
        0x72b00080  // movk w{0-15}, 0x8004, lsl 16
    };
    uint32_t rootvp_masks[] = {
        0xfffffff0,
        0xfffffff0
    };

    struct pf_patch_t rootvp = pf_construct_patch(rootvp_matches, rootvp_masks, sizeof(rootvp_matches) / sizeof(uint32_t), (void *) patch_vnop_rootvp_auth);

    struct pf_patch_t patches[] = {
        rootvp
    };

    struct pf_patchset_t patchset = pf_construct_patchset(patches, sizeof(patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(kernel_buf + text->offset, text->size, patchset);

    uint32_t livefs_matches[] = {
        0x90000000, // adrp
        0x91000000  // add
    };
    uint32_t livefs_masks[] = {
        0x9f000000,
        0xff800000
    };

    struct pf_patch_t livefs = pf_construct_patch(livefs_matches, livefs_masks, sizeof(livefs_matches) / sizeof(uint32_t), (void *) patch_livefs);

    struct pf_patch_t livefs_patches[] = {
        livefs
    };

    struct pf_patchset_t livefs_patchset = pf_construct_patchset(livefs_patches, sizeof(livefs_patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(kernel_buf + apfs_text->offset, apfs_text->size, livefs_patchset);

    struct fileset_entry_command *amfi_entry = macho_get_fileset(kernel_buf, "com.apple.driver.AppleMobileFileIntegrity");
    struct mach_header_64 *amfi_kext = kernel_buf + amfi_entry->fileoff;
    _amfi_kext = amfi_kext;

    struct section_64 *amfi_text = macho_find_section(amfi_kext, "__TEXT_EXEC", "__text");
    if (!amfi_text) {
        printf("Unable to find AMFI text!\n");
        return;
    }


    // r2: /x 28208052
    uint32_t trustcache_matches_old[] = {
        0x52802028 // mov w8, 0x101
    };
    uint32_t trustcache_masks_old[] = {
        0xffffffff
    };

    struct pf_patch_t trustcache_old = pf_construct_patch(trustcache_matches_old, trustcache_masks_old, sizeof(trustcache_matches_old) / sizeof(uint32_t), (void *) patch_trustcache_old);

    // r2: /x e0030091e10313aa000000949f020071e0179f1a:ffffffffffffffff000000fcffffffffffffffff
    uint32_t trustcache_matches_new[] = {
        0x910003e0, // mov x0, sp
        0xaa1303e1, // mov x1, x19
        0x94000000, // bl trustCacheQueryGetFlags
        0x7100029f, // cmp w20, 0
        0x1a9f17e0  // cset w0, eq
    };
    uint32_t trustcache_masks_new[] = {
        0xffffffff,
        0xffffffff,
        0xfc000000,
        0xffffffff,
        0xffffffff
    };

    struct pf_patch_t trustcache_new = pf_construct_patch(trustcache_matches_new, trustcache_masks_new, sizeof(trustcache_matches_new) / sizeof(uint32_t), (void *) patch_trustcache_new);

    struct pf_patch_t amfi_patches[] = {
        trustcache_old,
        trustcache_new
    };

    struct pf_patchset_t amfi_patchset = pf_construct_patchset(amfi_patches, sizeof(amfi_patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(kernel_buf + amfi_text->offset, amfi_text->size, amfi_patchset);

    printf("Patching completed successfully.\n");
}

int main(int argc, char **argv) {
    FILE *fp = NULL;

    if (argc < 3) {
        printf("Usage: %s <input kernel> <patched kernel>\n", argv[0]);
        return 0;
    }

    fp = fopen(argv[1], "rb");
    if (!fp) {
        printf("Failed to open kernel!\n");
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    kernel_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    kernel_buf = (void *) malloc(kernel_len);
    if (!kernel_buf) {
        printf("Out of memory while allocating region for kernel!\n");
        fclose(fp);
        return -1;
    }

    fread(kernel_buf, 1, kernel_len, fp);
    fclose(fp);

    uint32_t magic = macho_get_magic(kernel_buf);

    if (!magic) {
        free(kernel_buf);
        return 1;
    }

    void *orig_kernel = kernel_buf;
    if (magic == 0xbebafeca) {
        kernel_buf = macho_find_arch(kernel_buf, CPU_TYPE_ARM64);
        if (!kernel_buf) {
            free(orig_kernel);
            return 1;
        }
    }

    /*platform = macho_get_platform(kernel);
    if (platform == 0) {
        free(orig_kernel);
        return 1;
    }*/

    patch_kernel();

    fp = fopen(argv[2], "wb");
    if(!fp) {
        printf("Failed to open output file!\n");
        free(orig_kernel);
        return -1;
    }
    
    fwrite(orig_kernel, 1, kernel_len, fp);
    fflush(fp);
    fclose(fp);

    free(orig_kernel);

    return 0;
}