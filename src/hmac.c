// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#include "hmac.h"
#include "minicrypt.h"
#include <string.h>

static void sha1_normalize_key(const uint8_t *key, size_t keysize, uint8_t *out) {
    if (keysize > MC_SHA1_BLOCK_SIZE) {
        uint8_t digest[MC_SHA1_DIGEST_SIZE];
        mc_sha1_ctx key_ctx;
        mc_sha1_init(&key_ctx);
        mc_sha1_update(&key_ctx, key, keysize);
        mc_sha1_final(&key_ctx, digest); // 20 bytes
        memcpy(out, digest, MC_SHA1_DIGEST_SIZE);
        memset(out + MC_SHA1_DIGEST_SIZE, 0, MC_SHA1_BLOCK_SIZE - MC_SHA1_DIGEST_SIZE);
    } else {
        memcpy(out, key, keysize);
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
        memcpy(out, key, keysize);
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
