#include "sentinel/sentinel.h"

static bool g_initialized = false;

int sentinel_init(void) {
    if (g_initialized) return SENTINEL_ERROR_ALREADY_INITIALIZED;
    g_initialized = true;
    return SENTINEL_OK;
}

void sentinel_shutdown(void) {
    if (!g_initialized) return;
    g_initialized = false;
}

const char* sentinel_version(void) {
    return SENTINEL_VERSION_STRING;
}
