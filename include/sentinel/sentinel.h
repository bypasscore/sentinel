#ifndef SENTINEL_H
#define SENTINEL_H

#define SENTINEL_VERSION_MAJOR 3
#define SENTINEL_VERSION_MINOR 2
#define SENTINEL_VERSION_PATCH 0
#define SENTINEL_VERSION_STRING "3.2.0"

#include "core/types.h"
#include "core/error.h"
#include "core/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

int sentinel_init(void);
void sentinel_shutdown(void);
const char* sentinel_version(void);

#ifdef __cplusplus
}
#endif

#endif
