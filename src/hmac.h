// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#ifndef MINICRYPT_HMAC_H
#define MINICRYPT_HMAC_H

#include "sha256.h"
#include "sha1.h"

#ifdef __cplusplus
extern "C" {
#endif

void mc_hmac_sha256(const uint8_t *key, size_t keysize, const uint8_t *data, size_t size, uint8_t *out);
void mc_hmac_sha1(const uint8_t *key, size_t keysize, const uint8_t *data, size_t size, uint8_t *out);
void mc_hmac256_pbkdf2(const uint8_t *pass, size_t len, const uint8_t *salt, uint32_t rounds, uint8_t *out, size_t size);

#ifdef __cplusplus
}
#endif
#endif
