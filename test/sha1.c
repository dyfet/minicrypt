// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#undef  NDEBUG
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "../src/sha1.h"

void print_digest(const uint8_t *digest) {
    for (int i = 0; i < 32; ++i)
        printf("%02x", digest[i]);
    printf("\n");
}


int main() {
    const uint8_t input[] = {'a', 'b', 'c'};
    const uint8_t expected[20] = {
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d
    };

    mc_sha1_ctx ctx;
    uint8_t digest[MC_SHA1_DIGEST_SIZE];

    mc_sha1_init(&ctx);
    mc_sha1_update(&ctx, input, sizeof(input));
    mc_sha1_final(&ctx, digest);

    print_digest(digest);  // Optional: for visual confirmation
    assert(memcmp(digest, expected, MC_SHA1_DIGEST_SIZE) == 0);
}

