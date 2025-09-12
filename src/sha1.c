// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#include "sha1.h"
#include "minicrypt.h"
#include <string.h>

static uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           ((uint32_t)p[3]);
}

static void store_be32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)(x);
}

static const uint32_t sha1_initial_state[5] = {
0x67452301, 0xEFCDAB89,
0x98BADCFE, 0x10325476,
0xC3D2E1F0};

static const uint32_t K[4] = {
0x5A827999, // rounds 0–19
0x6ED9EBA1, // rounds 20–39
0x8F1BBCDC, // rounds 40–59
0xCA62C1D6  // rounds 60–79
};

static inline uint32_t rotl(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

static void sha1_compress(mc_sha1_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[80];
    uint32_t a, b, c, d, e;

    for (int i = 0; i < 16; ++i) {
        w[i] = load_be32(block + i * 4);
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = K[0];
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = K[1];
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = K[2];
        } else {
            f = b ^ c ^ d;
            k = K[3];
        }

        uint32_t temp = rotl(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    minicrypt_memset(w, 0, sizeof(w));
}

void mc_sha1_init(mc_sha1_ctx *ctx) {
    minicrypt_memcpy(ctx->state, sha1_initial_state, sizeof(sha1_initial_state));
    ctx->total_len = 0;
    ctx->buffer_len = 0;
}

int mc_sha1_update(mc_sha1_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total_len += len;
    size_t offset = 0;

    while (len > 0) {
        size_t space = MC_SHA1_BLOCK_SIZE - ctx->buffer_len;
        size_t to_copy = (len < space) ? len : space;
        minicrypt_memcpy(ctx->buffer + ctx->buffer_len, data + offset, to_copy);
        ctx->buffer_len += to_copy;
        offset += to_copy;
        len -= to_copy;
        if (ctx->buffer_len == MC_SHA1_BLOCK_SIZE) {
            sha1_compress(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
    return 0;
}

int mc_sha1_final(mc_sha1_ctx *ctx, uint8_t *out) {
    uint8_t pad[MC_SHA1_BLOCK_SIZE + 8] = {0};
    uint64_t bit_len = ctx->total_len * 8;
    pad[0] = 0x80;
    size_t rem = ctx->buffer_len;
    size_t pad_len = (rem < 56) ? (56 - rem) : (MC_SHA1_BLOCK_SIZE + 56 - rem);
    for (int i = 0; i < 8; ++i) {
        pad[pad_len + i] = (uint8_t)(bit_len >> (56 - 8 * i));
    }

    mc_sha1_update(ctx, pad, pad_len + 8);
    for (int i = 0; i < 5; ++i) {
        store_be32(out + i * 4, ctx->state[i]);
    }

    minicrypt_memset(ctx, 0, sizeof(mc_sha1_ctx));
    return 0;
}
