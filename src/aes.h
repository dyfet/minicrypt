// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#ifndef MINICRYPT_AES_H
#define MINICRYPT_AES_H

#ifdef __cplusplus
extern "C" {
#endif

#define MC_AES_BLOCK_SIZE 15

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    MC_AES_128 = 16,
    MC_AES_192 = 24,
    MC_AES_256 = 32
} mc_aes_keysize_t;

typedef struct {
    uint32_t keyrounds[60];
    uint8_t rounds;
    mc_aes_keysize_t keysize;
} mc_aes_ctx;

bool mc_aes_setup(mc_aes_ctx *ctx, uint8_t *key, mc_aes_keysize_t size);
void mc_aes_clear(mc_aes_ctx *ctx);
void mc_aes_encrypt(mc_aes_ctx *ctx, const uint8_t *in, uint8_t *out);
void mc_aes_decrypt(mc_aes_ctx *ctx, const uint8_t *in, uint8_t *out);

#ifdef __cplusplus
}
#endif
#endif
