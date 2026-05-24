#include "context.h"
#include <string.h>

struct context g_ctx;

void context_init() {
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.rsp.client = INVALID_SOCKET;
}
