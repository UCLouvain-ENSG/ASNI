#pragma once

#ifdef KLEE_VERIFICATION
#define NF_INFO(text, ...)
#else // KLEE_VERIFICATION
#include <inttypes.h>
#include <stdio.h>
#define NF_INFO(text, ...)                                                     \
    printf(text "\n", ##__VA_ARGS__);                                          \
    fflush(stdout);
#endif // KLEE_VERIFICATION

#ifdef ENABLE_LOG
#include <inttypes.h>
#include <stdio.h>
#define NF_DEBUG(text, ...)                                                    \
    fprintf(stderr, "DEBUG: " text "\n", ##__VA_ARGS__);                       \
    fflush(stderr);
#else // ENABLE_LOG
#define NF_DEBUG(...)
#endif // ENABLE_LOG
