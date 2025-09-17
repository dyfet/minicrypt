// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#undef  NDEBUG
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "../src/ring256.h"

int main() {
    mc_ring256_ctx ctx;
    mc_ring256_init(&ctx, 100);

    assert(mc_ring256_insert(&ctx, "nodeA"));
    assert(mc_ring256_insert(&ctx, "nodeB"));
    assert(mc_ring256_insert(&ctx, "nodeC"));
    assert(ctx.count == 3);
    assert(ctx.active > 200);

    const char *result = mc_ring256_find(&ctx, "user:67");
    assert(!strcmp(result, "nodeC"));

    assert(mc_ring256_remove(&ctx, "nodeB"));
    assert(!mc_ring256_remove(&ctx, "nodeD"));
    assert(ctx.active <= 200);
    mc_ring256_free(&ctx);
}
