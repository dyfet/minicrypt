// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#undef  NDEBUG
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "../src/hmac.h"

void print_digest(const uint8_t *digest) {
    for (int i = 0; i < 32; ++i)
        printf("%02x", digest[i]);
    printf("\n");
}

int main() {
    const uint8_t key[] = {'k', 'e', 'y'};
    const uint8_t input[] = {'a', 'b', 'c'};
    const uint8_t expected[32] = {
        0x9c, 0x19, 0x6e, 0x32, 0xdc, 0x01, 0x75, 0xf8,
        0x6f, 0x4b, 0x1c, 0xb8, 0x92, 0x89, 0xd6, 0x61,
        0x9d, 0xe6, 0xbe, 0xe6, 0x99, 0xe4, 0xc3, 0x78,
        0xe6, 0x83, 0x09, 0xed, 0x97, 0xa1, 0xa6, 0xab
    };

    uint8_t hmac[32];
    mc_hmac_sha256(key, sizeof(key), input, sizeof(input), hmac);

    print_digest(hmac);
    assert(memcmp(hmac, expected, 32) == 0);
}
