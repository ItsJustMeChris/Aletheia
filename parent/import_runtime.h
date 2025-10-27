#pragma once

#include <stddef.h>

#if __has_include("import_manifest.h")
#include "import_manifest.h"

void *import_runtime_get(size_t index);

#else

static inline void *import_runtime_get(size_t index) {
    (void)index;
    return NULL;
}

#endif
