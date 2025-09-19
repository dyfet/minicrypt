// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#include "ring256.h"
#include "minicrypt.h"

#include <stdlib.h>
#include <stdio.h>

static void ring256_update(mc_ring256_ctx *ctx) {
    ctx->lowest = ctx->highest = NULL;
    if (!ctx->count) return;
    for (int path = 0; path < 256; ++path) {
        mc_ring256_item *item = ctx->index[path];
        while (item != NULL) {
            if (!ctx->lowest) {
                ctx->lowest = ctx->highest = item;
            }
            if (ctx->lowest->key > item->key)
                ctx->lowest = item;
            if (ctx->highest->key < item->key)
                ctx->highest = item;
            item = item->next;
        }
    }
}

void mc_ring256_init(mc_ring256_ctx *ctx, unsigned vnodes) {
    minicrypt_memset(ctx, 0, sizeof(mc_ring256_ctx));
    ctx->vnodes = vnodes;
}

void mc_ring256_free(mc_ring256_ctx *ctx) {
    for (int i = 0; i < 256; ++i) {
        mc_ring256_item *item = ctx->index[i];
        while (item) {
            mc_ring256_item *next = item->next;
            minicrypt_memset(item, 0, sizeof(mc_ring256_item));
            free(item);
            item = next;
        }
    }
    mc_ring256_init(ctx, 0);
}

bool mc_ring256_insert(mc_ring256_ctx *ctx, const char *host) {
    size_t len = minicrypt_strlen(host, 256);
    if (!len) return false;
    uint8_t digest[MC_SHA256_DIGEST_SIZE];
    char buf[len + 8];
    for (unsigned i = 0; i < ctx->vnodes; ++i) {
        snprintf(buf, sizeof(buf), "%s#%u", host, i);
        size_t vsize = minicrypt_strlen(buf, sizeof(buf));
        if (!vsize) return false;
        mc_sha256_digest(buf, vsize, digest, NULL);
        uint8_t path = digest[0];
        uint64_t key = minicrypt_keyvalue(digest, MC_SHA256_DIGEST_SIZE);
        mc_ring256_item *item = malloc(sizeof(mc_ring256_item) + len);
        if (!item) return false;
        item->next = NULL;
        item->key = key;
        minicrypt_memcpy(item->host, host, len + 1);

        // make sure we are not overwriting a collision
        mc_ring256_item *dup = ctx->index[path];
        while (dup != NULL) {
            if (dup->key == key) break;
            dup = dup->next;
        }
        if (dup) continue;

        // lets inseert a new node
        ++ctx->active;
        item->next = ctx->index[path];
        ctx->index[path] = item;
    }
    ++ctx->count;
    ring256_update(ctx);
    return true;
}

const char *mc_ring256_find(mc_ring256_ctx *ctx, const char *id) {
    if (!ctx || !ctx->count) return NULL;
    uint8_t digest[MC_SHA256_DIGEST_SIZE];
    size_t len = minicrypt_strlen(id, 256);
    if (!len) return NULL;
    mc_sha256_digest(id, len, digest, NULL);
    int path = digest[0];
    uint64_t key = minicrypt_keyvalue(digest, MC_SHA256_DIGEST_SIZE);
    if (key <= ctx->lowest->key || key > ctx->highest->key)
        return ctx->lowest->host;

    // find on current path if possible
    mc_ring256_item *low = NULL, *item = ctx->index[path];
    while (item) {
        if (item->key >= key) {
            if (!low || item->key < low->key)
                low = item;
        }
        item = item->next;
    }
    if (low != NULL)
        return low->host;

    // find next lowest slot...
    while (++path < 256 && ctx->index[path] == NULL)
        ;
    if (path > 255) return NULL;
    low = item = ctx->index[path];
    while (item) {
        if (item->key < low->key)
            low = item;
        item = item->next;
    }
    return low->host;
}

bool mc_ring256_remove(mc_ring256_ctx *ctx, const char *host) {
    size_t len = minicrypt_strlen(host, 256);
    if (!len) return false;
    uint8_t digest[MC_SHA256_DIGEST_SIZE];
    char buf[len + 8];
    bool found = false;
    for (unsigned i = 0; i < ctx->vnodes; ++i) {
        snprintf(buf, sizeof(buf), "%s#%u", host, i);
        size_t vsize = minicrypt_strlen(buf, sizeof(buf));
        if (!vsize) return false;
        mc_sha256_digest(buf, vsize, digest, NULL);
        uint8_t path = digest[0];
        uint64_t key = minicrypt_keyvalue(digest, MC_SHA256_DIGEST_SIZE);
        mc_ring256_item *item = ctx->index[path], *prior = NULL;
        while (item != NULL) {
            if (item->key == key) {
                if (!strcmp(item->host, host)) {
                    if (prior != NULL) {
                        prior->next = item->next;
                    } else {
                        ctx->index[path] = item->next;
                    }
                    --ctx->active;
                    found = true;
                }
                item = NULL;
            } else {
                prior = item;
                item = item->next;
            }
        }
    }
    --ctx->count;
    ring256_update(ctx);
    return found;
}
