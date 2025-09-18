// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#undef  NDEBUG
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "../src/aes.h"

void print_value(const uint8_t *digest) {
    for (int i = 0; i < 16; ++i)
        printf("%02x", digest[i]);
    printf("\n");
}

static const uint8_t key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const uint8_t plaintext[16] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};

static const uint8_t expected_ciphertext[16] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
    0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
};

int main() {
    uint8_t ciphertext[16] = {0};
    uint8_t decrypted[16] = {0};
    mc_aes_ctx ctx = {0};
    assert(mc_aes_setup(&ctx, (uint8_t *)key, MC_AES_128));

    mc_aes_encrypt(&ctx, plaintext, ciphertext);
    assert(!memcmp(ciphertext, expected_ciphertext, 16));

    mc_aes_decrypt(&ctx, ciphertext, decrypted);
    assert(!memcmp(plaintext, decrypted, 16));
}
