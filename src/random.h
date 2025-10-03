// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#ifndef MINICRYPT_RANDOM_H
#define MINICRYPT_RANDOM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#ifdef _MSC_VER
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
#include <unistd.h>
#endif

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

typedef struct {
#ifdef _WIN32
    HCRYPTPROV handle;
#else
    int fd;
#endif
} mc_random_ctx;

int mc_random_init(mc_random_ctx *ctx);
void mc_random_free(mc_random_ctx *ctx);
ssize_t mc_random_fill(mc_random_ctx *ctx, uint8_t *buf, size_t size);
uint64_t mc_uniform_random(mc_random_ctx *ctx, uint64_t min, uint64_t max);
ssize_t mc_make_random(void *data, size_t size);

#ifdef __cplusplus
}
#endif
#endif
