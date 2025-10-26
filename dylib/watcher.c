#include <stdio.h>
#include <signal.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/mach_time.h>
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

#define MAX_PROTECTED_REGIONS 8
#define MAX_PROTECTED_PAGES 256

enum RegionKind {
    REGION_KIND_TEXT = 0,
    REGION_KIND_IMPORT = 1,
};

struct ProtectedRegion {
    mach_vm_address_t runtime_start;
    mach_vm_size_t runtime_size;
    mach_vm_address_t page_start;
    mach_vm_size_t protect_size;
    vm_prot_t max_prot;
    vm_prot_t init_prot;
    char label[32];
    enum RegionKind kind;
    bool encrypted_ready;
};

struct ProtectedPage {
    mach_vm_address_t start;
    mach_vm_size_t size;
    bool decrypted;
    uint64_t last_touch_ns;
    const struct ProtectedRegion *region;
};

static struct ProtectedRegion protected_regions[MAX_PROTECTED_REGIONS];
static size_t protected_region_count = 0;
static struct ProtectedPage protected_pages[MAX_PROTECTED_PAGES];
static size_t protected_page_count = 0;
static bool atexit_registered = false;
static mach_vm_size_t page_size = 0;
static mach_timebase_info_data_t timebase_info = {0};
static pthread_mutex_t page_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile bool monitor_running = false;
static pthread_t monitor_thread;
static bool monitor_thread_started = false;
static const uint64_t inactivity_ns = 500000000ULL;

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

    const struct ProtectedPage *page = &protected_pages[page_index];
    const struct ProtectedRegion *region = page->region;
    if (region == NULL) {
        return false;
    }

    mach_vm_address_t page_start = protected_pages[page_index].start;
    mach_vm_size_t page_size = protected_pages[page_index].size;
    vm_prot_t request = prot;
    if (prot != VM_PROT_NONE) {
        vm_prot_t allowed = region->max_prot;
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
    const struct ProtectedPage *page = &protected_pages[page_index];
    const struct ProtectedRegion *region = page->region;
    if (region == NULL) {
        return;
    }

    mach_vm_address_t page_start = page->start;
    mach_vm_address_t page_end = page_start + page->size;
    mach_vm_address_t region_start = region->runtime_start;
    mach_vm_address_t region_end = region_start + region->runtime_size;
    mach_vm_address_t content_start = page_start < region_start ? region_start : page_start;
    mach_vm_address_t content_end = page_end;
    if (content_end > region_end) {
        content_end = region_end;
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

static inline uint64_t monotonic_ns(void) {
    uint64_t now = mach_absolute_time();
    if (timebase_info.denom == 0) {
        return now;
    }
    return (now * timebase_info.numer) / timebase_info.denom;
}

static bool reencrypt_page_locked(size_t page_index) {
    if (page_index >= protected_page_count) {
        return false;
    }
    if (!protected_pages[page_index].decrypted) {
        return true;
    }

    if (!apply_protection(page_index, VM_PROT_READ | VM_PROT_WRITE)) {
        log_line("Failed to grant write access during re-encryption.");
        return false;
    }

#if defined(__APPLE__) && defined(__arm64__)
    pthread_jit_write_protect_np(0);
#endif
    xor_page_contents(page_index);
#if defined(__APPLE__) && defined(__arm64__)
    pthread_jit_write_protect_np(1);
#endif

    if (!apply_protection(page_index, VM_PROT_NONE)) {
        log_line("Failed to reset PROT_NONE during re-encryption.");
        return false;
    }

    protected_pages[page_index].decrypted = false;
    protected_pages[page_index].last_touch_ns = 0;
    log_value("Page re-encrypted", protected_pages[page_index].start);
    return true;
}

static void *page_monitor(void *arg) {
    (void)arg;
    while (monitor_running) {
        usleep(100000);

        uint64_t now_ns = monotonic_ns();
        pthread_mutex_lock(&page_lock);
        for (size_t i = 0; i < protected_page_count; ++i) {
            struct ProtectedPage *page = &protected_pages[i];
            if (!page->decrypted || page->last_touch_ns == 0) {
                continue;
            }
            if (now_ns > page->last_touch_ns && (now_ns - page->last_touch_ns) > inactivity_ns) {
                log_value("Idle page re-encrypt", page->start);
                if (!reencrypt_page_locked(i)) {
                    log_line("Background re-encryption failed.");
                }
            }
        }
        pthread_mutex_unlock(&page_lock);
    }
    return NULL;
}

static void reset_protection_state(void) {
    protected_region_count = 0;
    protected_page_count = 0;
    memset(protected_regions, 0, sizeof(protected_regions));
    memset(protected_pages, 0, sizeof(protected_pages));
}

static bool register_region(const char *segname, const char *sectname, const char *reason,
                            enum RegionKind kind,
                            mach_vm_address_t runtime_start, mach_vm_size_t runtime_size,
                            vm_prot_t init_prot, vm_prot_t max_prot) {
    if (runtime_size == 0) {
        return true;
    }

    if (protected_region_count >= MAX_PROTECTED_REGIONS) {
        log_line("Too many protected regions; skipping additional ones.");
        return false;
    }

    struct ProtectedRegion *region = &protected_regions[protected_region_count++];
    region->runtime_start = runtime_start;
    region->runtime_size = runtime_size;
    region->page_start = page_align_down(runtime_start);
    region->protect_size = aligned_range_size(runtime_start, runtime_size);
    region->init_prot = init_prot;
    region->max_prot = max_prot;
    snprintf(region->label, sizeof(region->label), "%s,%s", segname, sectname);
    region->kind = kind;
    region->encrypted_ready = (kind == REGION_KIND_TEXT);

    printf("[watcher] Protecting %s (%s)\n", region->label, reason);
    log_value("Region start", region->runtime_start);
    log_value("Region span bytes", region->protect_size);
    log_value("Region initprot", region->init_prot);
    log_value("Region maxprot", region->max_prot);
    if ((max_prot & VM_PROT_WRITE) == 0) {
        log_line("Warning: segment maxprot lacks write permission; decryption will fail.");
    }

    mach_vm_address_t region_start = region->page_start;
    mach_vm_address_t region_end = region->page_start + region->protect_size;
    while (region_start < region_end) {
        if (protected_page_count >= MAX_PROTECTED_PAGES) {
            log_line("Too many pages to protect; truncating.");
            return false;
        }
        mach_vm_address_t next = region_start + page_size;
        if (next > region_end) {
            next = region_end;
        }
        struct ProtectedPage *page = &protected_pages[protected_page_count++];
        page->start = region_start;
        page->size = next - region_start;
        page->decrypted = false;
        page->last_touch_ns = 0;
        page->region = region;
        region_start = next;
    }

    return true;
}

static bool prime_region_encryption(struct ProtectedRegion *region) {
    if (region == NULL) {
        return true;
    }

    if (region->kind == REGION_KIND_TEXT) {
        region->encrypted_ready = true;
        return true;
    }

    if (region->encrypted_ready) {
        return true;
    }

    bool ok = true;
    for (size_t i = 0; i < protected_page_count; ++i) {
        if (protected_pages[i].region != region) {
            continue;
        }
        if (!apply_protection(i, VM_PROT_READ | VM_PROT_WRITE)) {
            log_line("Failed to grant write access during region priming.");
            ok = false;
            break;
        }
#if defined(__APPLE__) && defined(__arm64__)
        pthread_jit_write_protect_np(0);
#endif
        xor_page_contents(i);
#if defined(__APPLE__) && defined(__arm64__)
        pthread_jit_write_protect_np(1);
#endif
        if (!apply_protection(i, region->init_prot)) {
            log_line("Failed to restore protections after region priming.");
            ok = false;
            break;
        }
    }

    if (ok) {
        region->encrypted_ready = true;
        printf("[watcher] Region primed encrypted: %s\n", region->label);
    }
    return ok;
}

static bool should_protect_code_section(const char *segname, const char *sectname) {
    if (strcmp(segname, "__TEXT") != 0) {
        return false;
    }
    return strcmp(sectname, "__text") == 0 ||
           strcmp(sectname, "__stubs") == 0 ||
           strcmp(sectname, "__stub_helper") == 0 ||
           strcmp(sectname, "__picsymbolstub4") == 0;
}

static int locate_protected_sections(void) {
    if (target_header == NULL) {
        log_line("Target Mach header not selected.");
        return -1;
    }

    reset_protection_state();

    struct {
        mach_vm_address_t start;
        mach_vm_address_t end;
        vm_prot_t init_prot;
        vm_prot_t max_prot;
        bool valid;
    } code_span = {0};

#define MAX_IMPORT_SPANS 8
    struct {
        mach_vm_address_t start;
        mach_vm_size_t size;
        vm_prot_t init_prot;
        vm_prot_t max_prot;
        char segname[17];
        char sectname[17];
    } import_spans[MAX_IMPORT_SPANS];
    size_t import_span_count = 0;

    const struct load_command *command = (const struct load_command *)((const uint8_t *)target_header + sizeof(*target_header));
    for (uint32_t i = 0; i < target_header->ncmds; i++) {
        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment = (const struct segment_command_64 *)command;
            const struct section_64 *section = (const struct section_64 *)((const uint8_t *)segment + sizeof(*segment));
            for (uint32_t j = 0; j < segment->nsects; j++, section++) {
                uint32_t section_type = section->flags & SECTION_TYPE;
                bool is_text = should_protect_code_section(section->segname, section->sectname);
                bool is_import = (section_type == S_NON_LAZY_SYMBOL_POINTERS) || (section_type == S_LAZY_SYMBOL_POINTERS);
                if (!is_text && !is_import) {
                    continue;
                }
                if (section->size == 0) {
                    continue;
                }

                char segname_buf[17];
                char sectname_buf[17];
                memcpy(segname_buf, section->segname, sizeof(section->segname));
                segname_buf[16] = '\0';
                memcpy(sectname_buf, section->sectname, sizeof(section->sectname));
                sectname_buf[16] = '\0';

                mach_vm_address_t runtime_start = section->addr + image_slide;
                if (is_text) {
                    mach_vm_address_t runtime_end = runtime_start + section->size;
                    if (!code_span.valid) {
                        code_span.start = runtime_start;
                        code_span.end = runtime_end;
                        code_span.init_prot = segment->initprot;
                        code_span.max_prot = segment->maxprot;
                        code_span.valid = true;
                    } else {
                        if (runtime_start < code_span.start) {
                            code_span.start = runtime_start;
                        }
                        if (runtime_end > code_span.end) {
                            code_span.end = runtime_end;
                        }
                        code_span.init_prot = segment->initprot;
                        code_span.max_prot = segment->maxprot;
                    }
                } else if (is_import) {
                    if (import_span_count >= MAX_IMPORT_SPANS) {
                        log_line("Too many import spans; truncating.");
                    } else {
                        import_spans[import_span_count].start = runtime_start;
                        import_spans[import_span_count].size = section->size;
                        import_spans[import_span_count].init_prot = segment->initprot;
                        import_spans[import_span_count].max_prot = segment->maxprot;
                        memcpy(import_spans[import_span_count].segname, segname_buf, sizeof(segname_buf));
                        memcpy(import_spans[import_span_count].sectname, sectname_buf, sizeof(sectname_buf));
                        import_span_count++;
                    }
                }
            }
        }
        command = (const struct load_command *)((const uint8_t *)command + command->cmdsize);
    }

    if (code_span.valid) {
        mach_vm_size_t span_size = (mach_vm_size_t)(code_span.end - code_span.start);
        if (!register_region("__TEXT", "__protected_code", "text", REGION_KIND_TEXT,
                             code_span.start, span_size, code_span.init_prot, code_span.max_prot)) {
            return -1;
        }
    }

    for (size_t idx = 0; idx < import_span_count; ++idx) {
        if (!register_region(import_spans[idx].segname, import_spans[idx].sectname, "import pointers", REGION_KIND_IMPORT,
                             import_spans[idx].start, import_spans[idx].size,
                             import_spans[idx].init_prot, import_spans[idx].max_prot)) {
            return -1;
        }
    }

    if (protected_region_count == 0) {
        log_line("Failed to locate sections to protect.");
        return -1;
    }

    return 0;
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
        bool register_exit = false;

        pthread_mutex_lock(&page_lock);
        struct ProtectedPage *page = &protected_pages[page_index];
        const struct ProtectedRegion *region = page->region;
        if (region == NULL) {
            pthread_mutex_unlock(&page_lock);
            log_line("Faulted page missing region metadata.");
            exit(1);
        }

        if (page->decrypted) {
            page->last_touch_ns = monotonic_ns();
            pthread_mutex_unlock(&page_lock);
            if (!apply_protection(page_index, region->init_prot)) {
                log_line("Failed to restore initial protections.");
                exit(1);
            }
            return;
        }

        if (!apply_protection(page_index, VM_PROT_READ | VM_PROT_WRITE)) {
            pthread_mutex_unlock(&page_lock);
            log_line("Failed to grant write access.");
            exit(1);
        }

#if defined(__APPLE__) && defined(__arm64__)
        pthread_jit_write_protect_np(0);
#endif
        printf("Decrypting page at %p (%s)\n", (void *)page->start, region->label);
        log_line("Decrypting protected region.");
        xor_page_contents(page_index);
#if defined(__APPLE__) && defined(__arm64__)
        pthread_jit_write_protect_np(1);
#endif
        if (!apply_protection(page_index, region->init_prot)) {
            pthread_mutex_unlock(&page_lock);
            log_line("Failed to restore initial protections.");
            exit(1);
        }

        printf("Page decrypted and accessible.\n");
        log_line("Region reset to initial protections.");

        page->decrypted = true;
        page->last_touch_ns = monotonic_ns();
        if (!atexit_registered) {
            atexit_registered = true;
            register_exit = true;
        }
        pthread_mutex_unlock(&page_lock);
        if (register_exit) {
            if (atexit(reencrypt_at_exit) != 0) {
                log_line("Failed to register atexit handler.");
            }
        }
        return;
    }

    fprintf(stderr, "Unhandled SIGSEGV at %p\n", info->si_addr);
    log_line("Unhandled SIGSEGV outside protected region.");
    exit(1);
}

static void reencrypt_at_exit(void) {
    log_line("Process exiting; re-encrypting protected pages.");
    if (monitor_thread_started) {
        monitor_running = false;
        pthread_join(monitor_thread, NULL);
        monitor_thread_started = false;
    }

    pthread_mutex_lock(&page_lock);
    for (size_t i = 0; i < protected_page_count; ++i) {
        if (!reencrypt_page_locked(i)) {
            log_line("Re-encryption during exit encountered an error.");
        }
    }
    pthread_mutex_unlock(&page_lock);
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
    if (timebase_info.denom == 0) {
        mach_timebase_info(&timebase_info);
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

    if (locate_protected_sections() != 0) {
        log_line("Initialization aborted; could not determine target sections.");
        return;
    }

    log_value("Protected region count", (uint64_t)protected_region_count);
    log_value("Protected page count", (uint64_t)protected_page_count);

    for (size_t r = 0; r < protected_region_count; ++r) {
        if (!prime_region_encryption(&protected_regions[r])) {
            log_line("Initialization aborted; failed to prime region encryption.");
            return;
        }
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

    log_value("Protected pages armed", (uint64_t)protected_page_count);

    monitor_running = true;
    if (pthread_create(&monitor_thread, NULL, page_monitor, NULL) != 0) {
        log_line("Failed to start page monitor thread.");
        monitor_running = false;
    } else {
        monitor_thread_started = true;
    }
}
