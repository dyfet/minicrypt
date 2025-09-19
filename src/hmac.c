// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#include "hmac.h"
#include "minicrypt.h"
#include <string.h>

#define SALT_SIZE 16

static void sha1_normalize_key(const uint8_t *key, size_t keysize, uint8_t *out) {
    if (keysize > MC_SHA1_BLOCK_SIZE) {
        uint8_t digest[MC_SHA1_DIGEST_SIZE];
        mc_sha1_ctx key_ctx;
        mc_sha1_init(&key_ctx);
        mc_sha1_update(&key_ctx, key, keysize);
        mc_sha1_final(&key_ctx, digest); // 20 bytes
        minicrypt_memcpy(out, digest, MC_SHA1_DIGEST_SIZE);
        memset(out + MC_SHA1_DIGEST_SIZE, 0, MC_SHA1_BLOCK_SIZE - MC_SHA1_DIGEST_SIZE);
    } else {
        minicrypt_memcpy(out, key, keysize);
        memset(out + keysize, 0, MC_SHA1_BLOCK_SIZE - keysize);
    }
}

void mc_hmac_sha1(const uint8_t *key, size_t keysize, const uint8_t *data, size_t size, uint8_t *out) {
    uint8_t keyblock[MC_SHA1_BLOCK_SIZE];
    uint8_t ipad[MC_SHA1_BLOCK_SIZE];
    uint8_t opad[MC_SHA1_BLOCK_SIZE];
    sha1_normalize_key(key, keysize, keyblock);
    for (size_t i = 0; i < MC_SHA1_BLOCK_SIZE; ++i) {
        ipad[i] = keyblock[i] ^ 0x36;
        opad[i] = keyblock[i] ^ 0x5c;
    }

    mc_sha1_ctx inner;
    mc_sha1_init(&inner);
    mc_sha1_update(&inner, ipad, MC_SHA1_BLOCK_SIZE);
    mc_sha1_update(&inner, data, size);
    uint8_t inner_digest[MC_SHA1_DIGEST_SIZE];
    mc_sha1_final(&inner, inner_digest);

    mc_sha1_ctx outer;
    mc_sha1_init(&outer);
    mc_sha1_update(&outer, opad, MC_SHA1_BLOCK_SIZE);
    mc_sha1_update(&outer, inner_digest, MC_SHA1_DIGEST_SIZE);
    mc_sha1_final(&outer, out);
}

static void sha256_normalize_key(const uint8_t *key, size_t keysize, uint8_t *out) {
    if (keysize > MC_SHA256_BLOCK_SIZE) {
        mc_sha256_ctx key_ctx;
        mc_sha256_init(&key_ctx);
        mc_sha256_update(&key_ctx, key, keysize);
        mc_sha256_final(&key_ctx, out); // 32 bytes
        memset(out + 32, 0, MC_SHA256_BLOCK_SIZE - 32);
    } else {
        minicrypt_memcpy(out, key, keysize);
        memset(out + keysize, 0, MC_SHA256_BLOCK_SIZE - keysize);
    }
}

void mc_hmac_sha256(const uint8_t *key, size_t keysize, const uint8_t *data, size_t size, uint8_t *out) {
    uint8_t keyblock[MC_SHA256_BLOCK_SIZE];
    uint8_t ipad[MC_SHA256_BLOCK_SIZE];
    uint8_t opad[MC_SHA256_BLOCK_SIZE];
    sha256_normalize_key(key, keysize, keyblock);
    for (size_t i = 0; i < MC_SHA256_BLOCK_SIZE; ++i) {
        ipad[i] = keyblock[i] ^ 0x36;
        opad[i] = keyblock[i] ^ 0x5c;
    }

    mc_sha256_ctx inner;
    mc_sha256_init(&inner);
    mc_sha256_update(&inner, ipad, MC_SHA256_BLOCK_SIZE);
    mc_sha256_update(&inner, data, size);
    uint8_t inner_digest[32];
    mc_sha256_final(&inner, inner_digest);

    // Outer hash
    mc_sha256_ctx outer;
    mc_sha256_init(&outer);
    mc_sha256_update(&outer, opad, MC_SHA256_BLOCK_SIZE);
    mc_sha256_update(&outer, inner_digest, 32);
    mc_sha256_final(&outer, out);
}

void mc_hmac256_pbkdf2(const uint8_t *pass, size_t len, const uint8_t *salt, uint32_t rounds, uint8_t *out, size_t size) {
    uint32_t block_count = (size + 31) / 32;
    uint8_t U[32], T[32];
    uint8_t salt_block[SALT_SIZE + 4];
    for (uint32_t i = 1; i <= block_count; ++i) {
        minicrypt_memcpy(salt_block, salt, SALT_SIZE);
        salt_block[SALT_SIZE + 0] = (i >> 24) & 0xff;
        salt_block[SALT_SIZE + 1] = (i >> 16) & 0xff;
        salt_block[SALT_SIZE + 2] = (i >> 8) & 0xff;
        salt_block[SALT_SIZE + 3] = i & 0xff;
        mc_hmac_sha256(pass, len, salt_block, SALT_SIZE + 4, U);
        minicrypt_memcpy(T, U, 32);
        for (uint32_t j = 1; j < rounds; ++j) {
            mc_hmac_sha256(pass, len, U, 32, U);
            for (int k = 0; k < 32; ++k)
                T[k] ^= U[k];
        }

        size_t offset = (i - 1) * 32;
        size_t copy = (offset + 32 > size) ? size - offset : 32;
        minicrypt_memcpy(out + offset, T, copy);
    }
}
