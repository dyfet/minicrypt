// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#ifndef MINICRYPT_MD5_H
#define MINICRYPT_MD5_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define MC_MD5_BLOCK_SIZE 64
#define MC_MD5_DIGEST_SIZE 16

typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[MC_MD5_BLOCK_SIZE];
} mc_md5_ctx;

void mc_md5_init(mc_md5_ctx *md);
int mc_md5_update(mc_md5_ctx *md, const uint8_t *input, uint32_t size);
int mc_md5_final(mc_md5_ctx *md, uint8_t *out);
int mc_md5_digest(const void *data, size_t size, uint8_t *out, uint8_t *salt);

#ifdef __cplusplus
}
#endif
#endif
