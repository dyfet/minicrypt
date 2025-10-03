// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#include "minicrypt.h"

void *minicrypt_memset(void *ptr, int value, size_t size) {
    volatile uint8_t *volatile p = (volatile uint8_t *volatile)ptr;
    if (!p) return NULL;
    while (size--) {
        *p++ = (uint8_t)value;
    }
    return ptr;
}

void minicrypt_memcpy(void *outp, const void *inp, size_t len) {
    if (!outp || !inp || outp == inp || len == 0) return;
    uint8_t *out = (uint8_t *)outp;
    const uint8_t *in = (uint8_t *)inp;
    if ((out > in && out < in + len) || (in > out && in < out + len)) return;
    size_t i;
    for (i = 0; i < len; i++)
        out[i] = in[i];
}

size_t minicrypt_strlen(const char *cp, size_t max) {
    size_t count = 0;
    if (!cp) return 0;
    while (*cp && (++count < max))
        ++cp;
    if (*cp) return 0; // invalid or overflow
    return count;
}

uint64_t minicrypt_keyvalue(uint8_t *digest, size_t size) {
    uint64_t result = 0;
    for (unsigned i = 0; i < sizeof(result); ++i) {
        result = (result << 8) | digest[i];
    }
    minicrypt_memset(digest, 0, size);
    return result;
}
