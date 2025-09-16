// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#include "sha256.h"
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

static const uint32_t sha256_initial_state[8] = {
0x6A09E667, 0xBB67AE85,
0x3C6EF372, 0xA54FF53A,
0x510E527F, 0x9B05688C,
0x1F83D9AB, 0x5BE0CD19};

static const uint32_t K[64] = {
0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2};

static inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t big_sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static inline uint32_t big_sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static inline uint32_t small_sigma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

static inline uint32_t small_sigma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

static void sha256_compress(mc_sha256_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (int i = 0; i < 16; ++i) {
        w[i] = load_be32(block + i * 4);
    }

    for (int i = 16; i < 64; ++i) {
        w[i] = small_sigma1(w[i - 2]) + w[i - 7] +
               small_sigma0(w[i - 15]) + w[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t T1 = h + big_sigma1(e) + ch(e, f, g) + K[i] + w[i];
        uint32_t T2 = big_sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
    minicrypt_memset(w, 0, sizeof(w));
}

void mc_sha256_init(mc_sha256_ctx *ctx) {
    minicrypt_memcpy(ctx->state, sha256_initial_state, sizeof(sha256_initial_state));
    ctx->total_len = 0;
    ctx->buffer_len = 0;
}

int mc_sha256_update(mc_sha256_ctx *ctx, const uint8_t *in, size_t inlen) {
    if (!ctx || (!in && inlen > 0)) return -1;
    ctx->total_len += inlen;
    while (inlen > 0) {
        size_t space = MC_SHA256_BLOCK_SIZE - ctx->buffer_len;
        size_t to_copy = (inlen < space) ? inlen : space;
        minicrypt_memcpy(ctx->buffer + ctx->buffer_len, in, to_copy);
        ctx->buffer_len += to_copy;
        in += to_copy;
        inlen -= to_copy;
        if (ctx->buffer_len == MC_SHA256_BLOCK_SIZE) {
            sha256_compress(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
    return 0;
}

int mc_sha256_final(mc_sha256_ctx *ctx, uint8_t *out) {
    uint8_t pad[MC_SHA256_BLOCK_SIZE + 8] = {0};
    uint64_t bit_len = ctx->total_len * 8;

    pad[0] = 0x80;
    size_t rem = ctx->buffer_len;
    size_t pad_len = (rem < 56) ? (56 - rem) : (MC_SHA256_BLOCK_SIZE + 56 - rem);

    for (int i = 0; i < 8; ++i) {
        pad[pad_len + i] = (uint8_t)(bit_len >> (56 - 8 * i));
    }

    mc_sha256_update(ctx, pad, pad_len + 8);
    for (int i = 0; i < 8; ++i)
        store_be32(out + i * 4, ctx->state[i]);
    minicrypt_memset(ctx, 0, sizeof(mc_sha256_ctx));
    return 0;
}

int mc_sha256_digest(const void *data, size_t size, uint8_t *out, uint8_t *salt) {
    mc_sha256_ctx ctx;
    mc_sha256_init(&ctx);
    if (salt)
        mc_sha256_update(&ctx, salt, 16);
    mc_sha256_update(&ctx, data, size);
    return mc_sha256_final(&ctx, out);
}
