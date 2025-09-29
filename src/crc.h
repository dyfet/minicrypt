// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#ifndef MINICRYPT_CRC_H
#define MINICRYPT_CRC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// While technically not really cryptographic hashing, this seemed an
// interesting  place to stick some old and existing crc implementations.

uint16_t mc_crc16(const uint8_t *data, size_t size);
uint32_t mc_crc32(const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif
#endif
