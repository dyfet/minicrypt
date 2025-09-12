// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#ifndef MINICRYPT_HMAC256_H
#define MINICRYPT_HMAC256_H

#include "sha256.h"
#include "sha1.h"

#ifdef __cplusplus
extern "C" {
#endif

void mc_hmac_sha256(const uint8_t *key, size_t keysize, const uint8_t *data, size_t size, uint8_t *out);
void mc_hmac_sha1(const uint8_t *key, size_t keysize, const uint8_t *data, size_t size, uint8_t *out);

#ifdef __cplusplus
}
#endif
#endif
