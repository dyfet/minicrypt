// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#ifndef MINICRYPT_2in5256_H
#define MINICRYPT_RING256_H

#include "sha256.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _mc_ring256_item {
    struct _mc_ring256_item *next;
    uint64_t key; // entry hash key
    char host[1]; // space for null byte
} mc_ring256_item;

typedef struct {
    size_t count, active;
    unsigned vnodes;
    mc_ring256_item *index[256];
    mc_ring256_item *lowest;
    mc_ring256_item *highest;
} mc_ring256_ctx;

void mc_ring256_init(mc_ring256_ctx *ctx, unsigned vnodes);
void mc_ring256_free(mc_ring256_ctx *ctx);
bool mc_ring256_insert(mc_ring256_ctx *ctx, const char *host);
bool mc_ring256_remove(mc_ring256_ctx *ctx, const char *host);
const char *mc_ring256_find(mc_ring256_ctx *ctx, const char *id);

#ifdef __cplusplus
}
#endif
#endif
