// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#ifndef MINICRYPT_SHA1_H
#define MINICRYPT_SHA1_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define MC_SHA1_BLOCK_SIZE 64
#define MC_SHA1_DIGEST_SIZE 20

typedef struct {
    uint32_t state[5];
    uint64_t total_len;
    uint8_t buffer[MC_SHA1_BLOCK_SIZE];
    size_t buffer_len;
} mc_sha1_ctx;

void mc_sha1_init(mc_sha1_ctx *md);
int mc_sha1_update(mc_sha1_ctx *md, const uint8_t *in, size_t inlen);
int mc_sha1_final(mc_sha1_ctx *md, uint8_t *out);
int mc_sha1_digest(const void *data, size_t size, uint8_t *out, const uint8_t *salt);

#ifdef __cplusplus
}
#endif
#endif
