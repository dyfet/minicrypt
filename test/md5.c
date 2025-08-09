// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#undef  NDEBUG
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "../src/md5.h"

void print_digest(const uint8_t *digest) {
    for (int i = 0; i < 16; ++i)
        printf("%02x", digest[i]);
    printf("\n");
}

int main() {
    const uint8_t input[] = {'a', 'b', 'c'};
    const uint8_t expected[16] = {
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
        0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
    };

    mc_md5_ctx ctx;
    uint8_t digest[16];

    mc_md5_init(&ctx);
    mc_md5_update(&ctx, input, sizeof(input));
    mc_md5_final(&ctx, digest);

    print_digest(digest);
    assert(memcmp(digest, expected, 16) == 0);
}
