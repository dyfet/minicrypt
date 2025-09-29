// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#ifndef MINICRYPT_AES_H
#define MINICRYPT_AES_H

#ifdef __cplusplus
extern "C" {
#endif

#define MC_AES_BLOCK_SIZE 15

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    MC_AES_128 = 16,
    MC_AES_192 = 24,
    MC_AES_256 = 32
} mc_aes_keysize_t;

typedef struct {
    // Core AES key scheduling
    uint32_t keyrounds[60];
    uint8_t rounds;
    mc_aes_keysize_t keysize;

    // Mode specific extensions
    uint8_t iv[16];
    uint8_t ctr[16];
    uint8_t gcm_G[16];
    uint8_t gcm_H[16];
    uint64_t gcm_len_aad;
    uint64_t gcm_len_cipher;
} mc_aes_ctx;

bool mc_aes_setup(mc_aes_ctx *ctx, uint8_t *key, mc_aes_keysize_t size, const uint8_t *iv);
void mc_aes_clear(mc_aes_ctx *ctx);
void mc_aes_encrypt(const mc_aes_ctx *ctx, const uint8_t *in, uint8_t *out);
void mc_aes_decrypt(const mc_aes_ctx *ctx, const uint8_t *in, uint8_t *out);
bool mc_aes_encrypt_cbc(mc_aes_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len);
bool mc_aes_decrypt_cbc(mc_aes_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len);
bool wc_aes_cipher_ctr(const mc_aes_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif
#endif
