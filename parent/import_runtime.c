#include "import_runtime.h"

#if __has_include("import_manifest.h")

#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef IMPORT_NAME_KEY
#define IMPORT_NAME_KEY 0x5A
#endif

static void *import_runtime_table[IMPORT_MANIFEST_COUNT];

static void decode_name(size_t offset, size_t length, char *buffer)
{
    for (size_t i = 0; i < length; ++i) {
        buffer[i] = (char)(import_name_blob[offset + i] ^ IMPORT_NAME_KEY);
    }
    buffer[length] = '\0';
}

static void secure_zero(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

static void *attempt_with_prefix_stripping(const char *name)
{
    const char *candidate = name;
    while (candidate[0] == '_' && candidate[1] != '\0') {
        candidate++;
        void *symbol = dlsym(RTLD_DEFAULT, candidate);
        if (symbol) {
            return symbol;
        }
    }
    return NULL;
}

static void *resolve_symbol_with_fallback(char *name)
{
    void *symbol = dlsym(RTLD_DEFAULT, name);
    if (symbol) {
        return symbol;
    }

    symbol = attempt_with_prefix_stripping(name);
    if (symbol) {
        return symbol;
    }

    const size_t len = strlen(name);
    if (len > 4 && strcmp(name + len - 4, "_chk") == 0) {
        char *fallback = (char *)malloc(len - 3);
        if (!fallback) {
            return NULL;
        }
        memcpy(fallback, name, len - 4);
        fallback[len - 4] = '\0';
        symbol = dlsym(RTLD_DEFAULT, fallback);
        if (!symbol) {
            symbol = attempt_with_prefix_stripping(fallback);
        }
        free(fallback);
        if (symbol) {
            return symbol;
        }
    }

    return NULL;
}

static void import_runtime_init(void)
{
    for (size_t i = 0; i < IMPORT_MANIFEST_COUNT; ++i) {
        const struct import_manifest_entry *entry = &import_manifest[i];
        size_t length = entry->name_length;
        char *buffer = (char *)malloc(length + 1);
        if (!buffer) {
            abort();
        }

        decode_name(entry->name_offset, length, buffer);
        void *symbol = resolve_symbol_with_fallback(buffer);

        if (!symbol) {
            const char prefix[] = "[import] unresolved: ";
            write(STDERR_FILENO, prefix, sizeof(prefix) - 1);
            write(STDERR_FILENO, buffer, length);
            write(STDERR_FILENO, "\n", 1);
            abort();
        }

        secure_zero(buffer, length + 1);
        free(buffer);

        import_runtime_table[i] = symbol;
    }
}

void *import_runtime_get(size_t index)
{
    if (index >= IMPORT_MANIFEST_COUNT) {
        abort();
    }
    return import_runtime_table[index];
}

__attribute__((constructor))
static void import_runtime_constructor(void)
{
    import_runtime_init();
}

#endif
