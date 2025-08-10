// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#include "random.h"
#include <string.h>

#include <stddef.h>
#include <fcntl.h>

int mc_random_init(mc_random_ctx *ctx) {
    if (!ctx) return -1;
    ctx->fd = open("/dev/urandom", O_RDONLY);
    return ctx->fd;
}

void mc_random_free(mc_random_ctx *ctx) {
    if (!ctx || ctx->fd < 0) return;
    close(ctx->fd);
    ctx->fd = -1;
}

ssize_t mc_random_fill(mc_random_ctx *ctx, uint8_t *out, size_t size) {
    if (!ctx || ctx->fd < 0) return 0;
    return read(ctx->fd, out, size);
}
