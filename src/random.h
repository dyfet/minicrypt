// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#ifndef MINICRYPT_RANDOM_H
#define MINICRYPT_RANDOM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <unistd.h>

typedef struct {
    int fd;
} mc_random_ctx;

int mc_random_init(mc_random_ctx *ctx);
void mc_random_free(mc_random_ctx *ctx);
ssize_t mc_random_fill(mc_random_ctx *ctx, uint8_t *buf, size_t size);

#ifdef __cplusplus
}
#endif
#endif
