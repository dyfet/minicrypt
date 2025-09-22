// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#include "random.h"
#include <string.h>

#include <stddef.h>
#include <fcntl.h>

int mc_random_init(mc_random_ctx *ctx) {
    if (!ctx) return -1;
#ifdef _WIN32
    ctx->handle = 0;
    if (!CryptAcquireContext(&ctx->handle, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    return 0;
#else
    ctx->fd = open("/dev/urandom", O_RDONLY); // FlawFinder: ignore
    return ctx->fd;
#endif
}

void mc_random_free(mc_random_ctx *ctx) {
#ifdef _WIN32
    if (!ctx || ctx->handle == 0) return;
    CryptReleaseContext(ctx->handle, 0);
    ctx->handle = 0;
#else
    if (!ctx || ctx->fd < 0) return;
    close(ctx->fd);
    ctx->fd = -1;
#endif
}

ssize_t mc_random_fill(mc_random_ctx *ctx, uint8_t *out, size_t size) {
    if (!size || !out) return 0;
#ifdef _WIN32
    if (!ctx || ctx->handle == 0) return 0;
    return CryptGenRandom(ctx->handle, size, out) ? size : 0;
#else
    if (!ctx || ctx->fd < 0) return 0;
    return read(ctx->fd, out, size); // FlawFinder: safe exit
#endif
}

#define MAX_UINT54 ((1ULL << 54) - 1)

static uint64_t get_random_uint54(mc_random_ctx *ctx) {
    uint64_t value;
    uint8_t *out = (uint8_t *)&value;
    mc_random_fill(ctx, out, sizeof(value));
    return value & MAX_UINT54;
}

uint64_t mc_uniform_random(mc_random_ctx *ctx, uint64_t min, uint64_t max) {
    uint64_t range = max - min + 1;
    uint64_t limit = MAX_UINT54 - (MAX_UINT54 % range);
    uint64_t value;
    do {
        value = get_random_uint54(ctx);
    } while (value >= limit);
    return min + (value % range);
}

ssize_t mc_make_random(void *data, size_t size) {
    if (!data || size == 0) return -1;
    mc_random_ctx ctx;
    ssize_t rc = mc_random_init(&ctx);
    if (rc < 0) return rc;
    rc = mc_random_fill(&ctx, data, size);
    mc_random_free(&ctx);
    return rc;
}
