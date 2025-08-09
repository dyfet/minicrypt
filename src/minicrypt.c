// SPDX-License-Identifier: GPL-3.0-or-later
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
    uint8_t *out = (uint8_t *)outp;
    const uint8_t *in = (uint8_t *)inp;
    if (out == in || !out || !in) return;
    size_t i;
    for (i = 0; i < len; i++)
        out[i] = in[i];
}
