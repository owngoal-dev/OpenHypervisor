#include "openhyp/ohv_core.h"
#include <cassert>
#include <cstdio>
#include <cstring>
hv_return_t ohv_read_capabilities(ohv_capabilities_t *caps);
static ohv_capabilities_t payload;
static hv_return_t result;
extern "C" hv_return_t ohv_raw_trap(unsigned trap, void *out) {
    assert(trap == OHV_TRAP_CAPABILITIES);
    if (!result) memcpy(out, &payload, sizeof(payload));
    return result;
}
int main() {
    ohv_capabilities_t expected{};
    expected.__header[0] = 64;
    expected.control_hcr = 0xf8202f0077ffd1c0;
    expected.ctr_el0 = 0x9444c004;
    expected.id_aa64pfr0_el1 = 0x1101000010110111;
    expected.id_aa64isar0_el1 = 0x221100110212120;
    expected.ipa_bits_4k = 40;
    expected.ipa_bits_16k = 42;
    payload = expected;
    ohv_capabilities_t got{};
    assert(ohv_read_capabilities(&got) == HV_SUCCESS);
    assert(memcmp(&got, &expected, sizeof(got)) == 0);
    memset(&payload, 0, sizeof(payload));
    memcpy(&payload, reinterpret_cast<char *>(&expected) + 64, sizeof(payload)-64);
    assert(ohv_read_capabilities(&got) == HV_SUCCESS);
    assert(got.control_hcr == expected.control_hcr);
    assert(got.ctr_el0 == expected.ctr_el0);
    assert(got.id_aa64pfr0_el1 == expected.id_aa64pfr0_el1);
    assert(got.id_aa64isar0_el1 == expected.id_aa64isar0_el1);
    assert(got.ipa_bits_4k == 40 && got.ipa_bits_16k == 42);
    result = HV_DENIED;
    assert(ohv_read_capabilities(&got) == HV_DENIED);
    result = HV_SUCCESS; memset(&payload, 0, sizeof(payload));
    assert(ohv_read_capabilities(&got) == HV_UNSUPPORTED);
    puts("capabilities PASS (3.x, 2.0.1, denied, unknown)");
}
