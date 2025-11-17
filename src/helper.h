// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#ifndef MINICRYPT_HELPER_H
#define MINICRYPT_YELPER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>
#include <stddef.h>

void *mc_memset(void *ptr, int value, size_t size);
void mc_memcpy(void *outp, const void *inp, size_t len);
size_t mc_strlen(const char *cp, size_t max);
uint64_t mc_keyvalue(uint8_t *digest, size_t size);

#ifdef __cplusplus
}
#endif
#endif
