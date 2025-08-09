// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#undef  NDEBUG
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "../src/sha256.h"

void print_digest(const uint8_t *digest) {
    for (int i = 0; i < 32; ++i)
        printf("%02x", digest[i]);
    printf("\n");
}

int main() {
    const uint8_t input[] = {'a', 'b', 'c'};
    const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    mc_sha256_ctx ctx;
    uint8_t digest[32];

    mc_sha256_init(&ctx);
    mc_sha256_update(&ctx, input, sizeof(input));
    mc_sha256_final(&ctx, digest);

    print_digest(digest);
    assert(memcmp(digest, expected, 32) == 0);
}
