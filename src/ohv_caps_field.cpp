// ohv_caps_field.cpp - capabilities snapshot bridge used by sysreg table.
#include "ohv_internal.h"
#include <cstddef>
#include <cstring>

/*
 * Offsets measured against a live trap 0 on this machine: CTR_EL0 reads
 * 0x9444c004 at +0xb0, CLIDR_EL1 0x80000023 at +0xc0, and the ID register
 * block runs from +0x148 in the same order the framework's feature_reg enum
 * uses.  If a field moves, this stops the library building rather than
 * letting it answer with the neighbouring register.
 */
static_assert(offsetof(ohv_capabilities_t, control_hcr) == OHV_CAPS_CONTROL_HCR_OFF, "control_hcr@0x40");
static_assert(offsetof(ohv_capabilities_t, ctr_el0) == 0xb0, "ctr_el0@0xb0");
static_assert(offsetof(ohv_capabilities_t, dczid_el0) == 0xb8, "dczid_el0@0xb8");
static_assert(offsetof(ohv_capabilities_t, clidr_el1) == 0xc0, "clidr_el1@0xc0");
static_assert(offsetof(ohv_capabilities_t, id_aa64dfr0_el1) == 0x148, "dfr0@0x148");
static_assert(offsetof(ohv_capabilities_t, id_aa64zfr0_el1) == 0x198, "zfr0@0x198");

static ohv_capabilities_t g_caps{};
static bool g_have = false;

/* 2.0.1's trap-0 payload starts at control_hcr.  3.x prefixes that payload
 * with 0x40 bytes.  Validate two architectural ID fields before selecting
 * either layout: Apple CPUs implement AArch64 EL0/EL1 (PFR0[7:0] == 0x11)
 * and CTR_EL0 has its architectural RES1 bit 31 set.
 * The public raw trap keeps returning the kernel's original representation.
 */
hv_return_t ohv_read_capabilities(ohv_capabilities_t *caps) {
    ohv_capabilities_t raw{};
    hv_return_t r = ohv_raw_trap(OHV_TRAP_CAPABILITIES, &raw);
    if (r != HV_SUCCESS) return r;
    auto valid = [](const ohv_capabilities_t &c) {
        return (c.id_aa64pfr0_el1 & 0xff) == 0x11 &&
               (c.ctr_el0 & (1ull << 31));
    };
    if (valid(raw)) {
        *caps = raw;
        return HV_SUCCESS;
    }
    constexpr size_t prefix = sizeof(raw.__header);
    memset(caps, 0, sizeof(*caps));
    memcpy(reinterpret_cast<char *>(caps) + prefix, &raw, sizeof(raw) - prefix);
    if (!valid(*caps)) return HV_UNSUPPORTED;
    return HV_SUCCESS;
}

const ohv_capabilities_t *ohv_caps_cached() {
    if (!g_have) {
        if (ohv_read_capabilities(&g_caps) == HV_SUCCESS) g_have = true;
    }
    return &g_caps;
}
