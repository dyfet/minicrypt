// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#ifndef MINICRYPT_UTILS_H
#define MINICRYPT_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>
#include <stddef.h>

void *minicrypt_memset(void *ptr, int value, size_t size);
void minicrypt_memcpy(void *outp, const void *inp, size_t len);
size_t minicrypt_strlen(const char *cp, size_t max);
uint64_t minicrypt_keyvalue(uint8_t *digest);

#ifdef __cplusplus
}
#endif
#endif
