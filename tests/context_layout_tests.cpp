// The 2.x ESR is adjacent to an instruction word; reading 64 bits corrupts it.
#include "openhyp/ohv_context.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <initializer_list>
const ohv_hv_layout_t *ohv_layout;
static void put(unsigned char *p, unsigned off, uint64_t v, unsigned size) {
    memcpy(p + off, &v, size);
}
int main() {
    alignas(16) unsigned char ctx[0x8000] = {};
    for (const auto &layout : ohv_hv_layouts) {
        ohv_layout = &layout;
        memset(ctx, 0, sizeof(ctx));
        if (layout.ver == OHV_STATE_VER(2, 0, 1)) {
            put(ctx, 0x4008, 1, 4);
            put(ctx, 0x400c, 0x93c08046, 4);
            put(ctx, 0x4010, 0xdeadbeef, 4);
            put(ctx, 0x4018, 0x123456789abcdef0, 8);
            put(ctx, 0x4020, 0xfedcba9876543210, 8);
            put(ctx, 0x4118, 0x12345678, 4);
            put(ctx, 0x411c, 0x87654321, 4);
            assert(ohv_ro_field(ctx, layout.ro_ich_vtr) == 0x12345678);
        } else {
            put(ctx, 0x4008, 1, 4);
            put(ctx, 0x4010, 0x1000000093c08046, 8);
            put(ctx, 0x4020, 0x123456789abcdef0, 8);
            put(ctx, 0x4028, 0xfedcba9876543210, 8);
        }
        auto e = ohv_read_exit_info(ctx);
        assert(e.vmexit_reason == 1);
        assert(e.vmexit_esr == (layout.ver == OHV_STATE_VER(2,0,1) ?
                               0x93c08046 : 0x1000000093c08046));
        assert(e.vmexit_far == 0x123456789abcdef0);
        assert(e.vmexit_hpfar == 0xfedcba9876543210);
        e.vmexit_reason = OHV_VMEXIT_SYNC;
        e.vmexit_esr = 0xfc000022;
        assert(ohv_is_legacy_gexit(&e) == (layout.ver == OHV_STATE_VER(2,0,1)));
        // Async exits can retain the previous synchronous syndrome.
        for (auto reason : {OHV_VMEXIT_IRQ, OHV_VMEXIT_HOST_AST, OHV_VMEXIT_NONE}) {
            e.vmexit_reason = reason;
            assert(!ohv_is_legacy_gexit(&e));
        }
    }
    puts("context layouts PASS (2.0.1 and every retained 3.x row)");
}
