#include <stdio.h>
#include <signal.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <mach/mach_error.h>
#include <pthread.h>

#define XOR_KEY 0x55

static const struct mach_header_64 *target_header = NULL;
static uint32_t target_image_index = 0;
static mach_vm_address_t image_slide = 0;
static mach_vm_address_t text_runtime_start = 0;
static mach_vm_size_t text_runtime_size = 0;

#define MAX_PROTECTED_PAGES 128

struct ProtectedPage {
    mach_vm_address_t start;
    mach_vm_size_t size;
    bool decrypted;
};

static struct ProtectedPage protected_pages[MAX_PROTECTED_PAGES];
static size_t protected_page_count = 0;
static mach_vm_address_t text_page_start = 0;
static mach_vm_size_t text_protect_size = 0;
static vm_prot_t text_max_prot = 0;
static vm_prot_t text_init_prot = 0;
static bool atexit_registered = false;
static mach_vm_size_t page_size = 0;

#ifndef MAP_JIT
#define MAP_JIT 0
#endif

static void log_line(const char *msg) {
    printf("[watcher] %s\n", msg);
}

static void log_value(const char *label, uint64_t value) {
    printf("[watcher] %s: 0x%llx (%llu)\n", label, (unsigned long long)value, (unsigned long long)value);
}

static void log_kern_error(const char *label, kern_return_t kr) {
    printf("[watcher] %s (kr=0x%x: %s)\n", label, kr, mach_error_string(kr));
}

static bool apply_protection(size_t page_index, vm_prot_t prot) {
    if (page_index >= protected_page_count) {
        return false;
    }

    mach_vm_address_t page_start = protected_pages[page_index].start;
    mach_vm_size_t page_size = protected_pages[page_index].size;
    vm_prot_t request = prot;
    if (prot != VM_PROT_NONE) {
        vm_prot_t allowed = text_max_prot;
        if ((prot & ~allowed) != 0) {
            log_line("Requested protection exceeds segment maxprot.");
            return false;
        }
    }

    kern_return_t kr = mach_vm_protect(mach_task_self(), page_start, page_size, false, request);
    if (kr != KERN_SUCCESS) {
        log_kern_error("mach_vm_protect failed to update protections", kr);
        return false;
    }
    return true;
}

static void xor_page_contents(size_t page_index) {
    mach_vm_address_t page_start = protected_pages[page_index].start;
    mach_vm_address_t page_end = page_start + protected_pages[page_index].size;
    mach_vm_address_t content_start = page_start < text_runtime_start ? text_runtime_start : page_start;
    mach_vm_address_t content_end = page_end;
    mach_vm_address_t text_end = text_runtime_start + text_runtime_size;
    if (content_end > text_end) {
        content_end = text_end;
    }
    if (content_end <= content_start) {
        return;
    }
    size_t span = (size_t)(content_end - content_start);
    uint8_t *ptr = (uint8_t *)content_start;
    for (size_t i = 0; i < span; ++i) {
        ptr[i] ^= XOR_KEY;
    }
    __builtin___clear_cache((char *)content_start, (char *)(content_start + span));
}

static inline mach_vm_address_t page_align_down(mach_vm_address_t addr) {
    return addr & ~(page_size - 1);
}

static inline mach_vm_size_t aligned_range_size(mach_vm_address_t addr, mach_vm_size_t size) {
    mach_vm_address_t start = page_align_down(addr);
    mach_vm_address_t end = (addr + size + page_size - 1) & ~(page_size - 1);
    return end - start;
}

static void xor_crypt(void *addr, size_t size, uint8_t key) {
    uint8_t *data = (uint8_t *)addr;
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

static int locate_text_section(void) {
    if (target_header == NULL) {
        log_line("Target Mach header not selected.");
        return -1;
    }

    const struct load_command *command = (const struct load_command *)((const uint8_t *)target_header + sizeof(*target_header));
    for (uint32_t i = 0; i < target_header->ncmds; i++) {
        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment = (const struct segment_command_64 *)command;
            const struct section_64 *section = (const struct section_64 *)((const uint8_t *)segment + sizeof(*segment));
            for (uint32_t j = 0; j < segment->nsects; j++, section++) {
                if (strcmp(section->segname, "__TEXT") == 0 && strcmp(section->sectname, "__text") == 0) {
                    text_runtime_start = section->addr + image_slide;
                    text_runtime_size = section->size;
                    text_page_start = page_align_down(text_runtime_start);
                    text_protect_size = aligned_range_size(text_runtime_start, text_runtime_size);
                    text_max_prot = segment->maxprot;
                    text_init_prot = segment->initprot;
                    log_value("Text runtime start", text_runtime_start);
                    log_value("Text size bytes", text_runtime_size);
                    log_value("Text page start", text_page_start);
                    log_value("Protected span bytes", text_protect_size);
                    log_value("Segment maxprot", text_max_prot);
                    log_value("Segment initprot", text_init_prot);
                    if ((text_max_prot & VM_PROT_WRITE) == 0) {
                        log_line("Warning: __TEXT segment maxprot lacks write permission; decryption will fail.");
                    }

                    mach_vm_address_t region_start = text_page_start;
                    mach_vm_address_t region_end = text_page_start + text_protect_size;
                    protected_page_count = 0;
                    while (region_start < region_end) {
                        if (protected_page_count >= MAX_PROTECTED_PAGES) {
                            log_line("Too many pages to protect; truncating.");
                            break;
                        }
                        mach_vm_address_t next = region_start + page_size;
                        if (next > region_end) {
                            next = region_end;
                        }
                        protected_pages[protected_page_count].start = region_start;
                        protected_pages[protected_page_count].size = next - region_start;
                        protected_pages[protected_page_count].decrypted = false;
                        protected_page_count++;
                        region_start = next;
                    }

                    return 0;
                }
            }
        }
        command = (const struct load_command *)((const uint8_t *)command + command->cmdsize);
    }

    log_line("Failed to locate __TEXT,__text section.");
    return -1;
}

static void reencrypt_at_exit(void);

static void segv_handler(int sig, siginfo_t *info, void *context) {
    mach_vm_address_t fault_addr = (mach_vm_address_t)info->si_addr;
    printf("SIGSEGV at address: %p\n", info->si_addr);
    log_value("Fault address", fault_addr);

    if (protected_page_count == 0) {
        log_line("Protected region not initialized; aborting.");
        exit(1);
    }

    size_t page_index = SIZE_MAX;
    for (size_t i = 0; i < protected_page_count; ++i) {
        mach_vm_address_t start = protected_pages[i].start;
        mach_vm_address_t end = start + protected_pages[i].size;
        if (fault_addr >= start && fault_addr < end) {
            page_index = i;
            break;
        }
    }

    if (page_index != SIZE_MAX) {
        if (protected_pages[page_index].decrypted) {
            log_line("Page already decrypted; restoring RX and continuing.");
            if (!apply_protection(page_index, text_init_prot)) {
                log_line("Failed to restore RX protections.");
                exit(1);
            }
            return;
        }

        if (!apply_protection(page_index, VM_PROT_READ | VM_PROT_WRITE)) {
            log_line("Failed to grant write access.");
            exit(1);
        }

#if defined(__APPLE__) && defined(__arm64__)
        pthread_jit_write_protect_np(0);
#endif
        printf("Decrypting page at %p\n", (void *)protected_pages[page_index].start);
        log_line("Decrypting protected region.");
        xor_page_contents(page_index);

#if defined(__APPLE__) && defined(__arm64__)
        pthread_jit_write_protect_np(1);
#endif
        if (!apply_protection(page_index, text_init_prot)) {
            log_line("Failed to restore RX protections.");
            exit(1);
        }

        printf("Page decrypted and executable.\n");
        log_line("Region set to RX.");

        protected_pages[page_index].decrypted = true;
        if (!atexit_registered) {
            atexit(reencrypt_at_exit);
            atexit_registered = true;
        }
        return;
    }

    fprintf(stderr, "Unhandled SIGSEGV at %p\n", info->si_addr);
    log_line("Unhandled SIGSEGV outside protected region.");
    exit(1);
}

static void reencrypt_at_exit(void) {
    log_line("Process exiting; re-encrypting protected pages.");
    for (size_t i = 0; i < protected_page_count; ++i) {
        if (!protected_pages[i].decrypted) {
            continue;
        }

        if (!apply_protection(i, VM_PROT_READ | VM_PROT_WRITE)) {
            log_line("Failed to grant write access for exit re-encryption.");
            continue;
        }

#if defined(__APPLE__) && defined(__arm64__)
        pthread_jit_write_protect_np(0);
#endif
        xor_page_contents(i);
#if defined(__APPLE__) && defined(__arm64__)
        pthread_jit_write_protect_np(1);
#endif

        if (!apply_protection(i, VM_PROT_NONE)) {
            log_line("Failed to reset PROT_NONE during exit re-encryption.");
        } else {
            log_value("Page re-encrypted", protected_pages[i].start);
        }
    }
}

__attribute__((constructor))
static void init_watcher(void) {
    uint32_t image_count = _dyld_image_count();
    if (page_size == 0) {
        vm_size_t host_page = 0;
        kern_return_t kr = host_page_size(mach_host_self(), &host_page);
        if (kr != KERN_SUCCESS || host_page == 0) {
            log_kern_error("host_page_size failed", kr);
            page_size = 0x4000;
        } else {
            page_size = (mach_vm_size_t)host_page;
        }
        log_value("Detected page size", page_size);
    }
    for (uint32_t i = 0; i < image_count; i++) {
        const struct mach_header *header = _dyld_get_image_header(i);
        if (!header) {
            continue;
        }
        if (header->magic != MH_MAGIC_64) {
            continue;
        }
        const struct mach_header_64 *header64 = (const struct mach_header_64 *)header;
        if (header64->filetype == MH_EXECUTE) {
            target_header = header64;
            target_image_index = i;
            image_slide = (mach_vm_address_t)_dyld_get_image_vmaddr_slide(i);
            const char *image_name = _dyld_get_image_name(i);
            if (image_name) {
                printf("[watcher] Target image: %s (index %u)\n", image_name, i);
            } else {
                printf("[watcher] Target image index %u selected.\n", i);
            }
            break;
        }
    }

    if (target_header == NULL) {
        log_line("Failed to locate MH_EXECUTE image; watcher disabled.");
        return;
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    log_line("Watcher dylib loaded.");

    log_value("Image slide", image_slide);

    if (locate_text_section() != 0) {
        log_line("Initialization aborted; could not determine target section.");
        return;
    }

    struct sigaction sa;
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0 || sigaction(SIGBUS, &sa, NULL) != 0) {
        perror("sigaction failed");
        return;
    }

    for (size_t i = 0; i < protected_page_count; ++i) {
        if (!apply_protection(i, VM_PROT_NONE)) {
            log_line("Failed to arm protected region.");
            return;
        }
    }

    log_value("Protected pages armed", protected_page_count);
}
