// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#ifndef MINICRYPT_SHA256_H
#define MINICRYPT_SHA256_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define MC_SHA256_BLOCK_SIZE 64
#define MC_SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t total_len;
    uint8_t buffer[MC_SHA256_BLOCK_SIZE];
    size_t buffer_len;
} mc_sha256_ctx;

void mc_sha256_init(mc_sha256_ctx *md);
int mc_sha256_update(mc_sha256_ctx *md, const uint8_t *in, size_t inlen);
int mc_sha256_final(mc_sha256_ctx *md, uint8_t *out);
int mc_sha256_digest(const void *data, size_t size, uint8_t *out, const uint8_t *salt);

#ifdef __cplusplus
}
#endif
#endif
