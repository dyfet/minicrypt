// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#include "crc.h"
#include "minicrypt.h"

uint16_t mc_crc16(const uint8_t *data, size_t size) {
    uint16_t crc = 0x0000;
    while (size--) {
        crc ^= *data++ << 8;
        for (uint8_t i = 0; i < 8; i++) {
            if (crc & 0x8000)
                crc = (crc << 1) ^ 0x8005;
            else
                crc <<= 1;
        }
    }
    return crc;
}

uint32_t mc_crc32(const uint8_t *data, size_t size) {
    uint32_t table[256];
    uint32_t crc = 0xffffffff;
    minicrypt_memset(table, 0, sizeof(table));
    for (size_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (size_t j = 0; j < 8; j++)
            c = (c & 1) ? 0xedb88320 ^ (c >> 1) : c >> 1;
        table[i] = c;
    }

    for (size_t i = 0; i < size; i++)
        crc = table[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
    return crc ^ 0xffffffff;
}
