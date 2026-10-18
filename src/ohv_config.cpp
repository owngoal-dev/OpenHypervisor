// ohv_config.cpp - the library's switches, set by the VMM through ohv_config.h.
//
// These used to be environment variables, read once at load and again at the
// first hv_vcpu_run() -- twice because the machine itself set one of them
// (which vCPU is the SEP) and could not know the answer until it had built
// the core.  A call has no such problem: the machine says it when it knows
// it, and the run's command line, not its environment, is what records the
// rest.
#include <ctype.h>
#include <string.h>
#include "ohv_internal.h"

namespace ohv {

Config g_cfg;
std::atomic<uint64_t> g_trace{0};

} // namespace ohv

using namespace ohv;

#define OHV_SET_BOOL(fn, field)                                             \
    extern "C" hv_return_t fn(bool on) {                                    \
        g_cfg.field.store(on, std::memory_order_relaxed);                   \
        return HV_SUCCESS;                                                  \
    }
#define OHV_SET_U64(fn, field)                                              \
    extern "C" hv_return_t fn(uint64_t v) {                                 \
        g_cfg.field.store(v, std::memory_order_relaxed);                    \
        return HV_SUCCESS;                                                  \
    }
/* A setting that means "leave the library's own choice alone" until set. */
#define OHV_SET_GIVEN(fn, type, field)                                      \
    extern "C" hv_return_t fn(type v) {                                     \
        g_cfg.field.store(v, std::memory_order_relaxed);                    \
        g_cfg.field##_given.store(true, std::memory_order_release);         \
        return HV_SUCCESS;                                                  \
    }

OHV_SET_BOOL(ohv_set_bank_inline, bank_inline)
OHV_SET_BOOL(ohv_set_impdef_shadow, impdef_shadow)
OHV_SET_BOOL(ohv_set_ipi_inline, ipi_inline)
OHV_SET_BOOL(ohv_set_wfe_inline, wfe_inline)
OHV_SET_BOOL(ohv_set_one_space, one_space)
OHV_SET_GIVEN(ohv_set_tlbi_replay, bool, tlbi_replay)
OHV_SET_BOOL(ohv_set_nested_space, nested_space)
OHV_SET_BOOL(ohv_set_nested_inherit, nested_inherit)
OHV_SET_BOOL(ohv_set_monitor_level_gate, monitor_level_gate)
OHV_SET_BOOL(ohv_set_monitor_nv, monitor_nv)
OHV_SET_BOOL(ohv_set_hw_geret, hw_geret)
OHV_SET_BOOL(ohv_set_eret_emulation, eret_emulation)
OHV_SET_BOOL(ohv_set_el2_injection, el2_injection)
OHV_SET_BOOL(ohv_set_mirror_gl1, mirror_gl1)
OHV_SET_BOOL(ohv_set_vmkey_mirror, vmkey_mirror)
OHV_SET_BOOL(ohv_set_allow_apsts_write, allow_apsts_write)
OHV_SET_BOOL(ohv_set_trap_wfe, trap_wfe)
OHV_SET_GIVEN(ohv_set_hcr_tidcp, bool, hcr_tidcp)
OHV_SET_GIVEN(ohv_set_tidcp_vcpus, uint64_t, tidcp_vcpus)
OHV_SET_BOOL(ohv_set_trap_pac_keys, trap_pac_keys)
OHV_SET_BOOL(ohv_set_trap_gxf, trap_gxf)
OHV_SET_BOOL(ohv_set_hacr_tactl0, hacr_tactl0)
OHV_SET_U64(ohv_set_hcr_nested_mask, hcr_nested_mask)
OHV_SET_U64(ohv_set_hcr_xmo, hcr_xmo)
OHV_SET_GIVEN(ohv_set_cnthctl, uint64_t, cnthctl)
OHV_SET_GIVEN(ohv_set_try_14c8, uint64_t, try_14c8)
OHV_SET_U64(ohv_set_timer_irq_vcpus, timer_irq_vcpus)
OHV_SET_BOOL(ohv_set_sw_vtimer, sw_vtimer)
OHV_SET_BOOL(ohv_set_sw_vtimer_istatus, sw_vtimer_istatus)
OHV_SET_U64(ohv_set_nv_keep_vcpus, nv_keep_vcpus)
OHV_SET_U64(ohv_set_amxidr, amxidr)
OHV_SET_BOOL(ohv_set_sync_once, sync_once)
OHV_SET_BOOL(ohv_set_spin_wfi, spin_wfi)
OHV_SET_BOOL(ohv_set_survey_sysreg, survey_sysreg)
OHV_SET_U64(ohv_set_trace_after, trace_after)
OHV_SET_U64(ohv_set_trace_from, trace_from)
OHV_SET_U64(ohv_set_trace_max, trace_max)
OHV_SET_U64(ohv_set_trace_vcpu, trace_vcpu)
OHV_SET_U64(ohv_set_trace_sysreg, trace_sysreg)

/*
 * A mask of OHV_STATE_* bits.  1 -- bit 0, which is not a class anyone could
 * mean to claim -- is taken as "the default set", which is what
 * OHV_CLAIM_STATE=1 meant.
 */
extern "C" hv_return_t ohv_set_claim_state(uint64_t mask) {
    g_cfg.claim_state.store(mask == 1 ? OHV_CLAIM_STATE_DEFAULT : mask,
                            std::memory_order_relaxed);
    return HV_SUCCESS;
}
static_assert(OHV_CLAIM_STATE_DEFAULT ==
              (OHV_STATE_GXF | OHV_STATE_SPRR | OHV_STATE_AMX |
               OHV_STATE_JITBOX | OHV_STATE_PTRAUTH_APPLE),
              "ohv_config.h spells the default claim out in numbers");

/* Five rules, of which only 4 is right; 0..3 are kept to compare against. */
extern "C" hv_return_t ohv_set_timer_gate(uint64_t mode) {
    if (mode > 4) {
        return HV_BAD_ARGUMENT;
    }
    g_cfg.timer_gate.store(mode, std::memory_order_relaxed);
    return HV_SUCCESS;
}

// ---------------------------------------------------------------- traces --
static const char *const kTraceNames[OHV_TRACE_COUNT] = {
    "all", "at", "band", "ctrr", "eret", "exit", "ext", "fault", "firstrun",
    "gate", "gic", "gl1", "glvl", "gxfstate", "hacr", "hcr", "impdef", "ipi",
    "irq", "kfault", "kick", "kirq", "ktimer", "nested", "pac", "reasons",
    "sysreg", "tid2", "timer", "timerreg", "tlbi", "tmrena", "tpidr-el2",
    "unmatched", "used", "vf", "vf-k", "vm",
};
static_assert(OHV_TRACE_COUNT <= 64, "the trace set is one word");

extern "C" hv_return_t ohv_set_trace(ohv_trace_t which, bool on) {
    if ((unsigned)which >= OHV_TRACE_COUNT) {
        return HV_BAD_ARGUMENT;
    }
    uint64_t bit = 1ull << (unsigned)which;

    if (on) {
        g_trace.fetch_or(bit, std::memory_order_relaxed);
    } else {
        g_trace.fetch_and(~bit, std::memory_order_relaxed);
    }
    return HV_SUCCESS;
}

extern "C" const char *ohv_trace_name(ohv_trace_t which) {
    return (unsigned)which < OHV_TRACE_COUNT ? kTraceNames[which] : nullptr;
}

extern "C" int ohv_trace_lookup(const char *name) {
    if (name == nullptr) {
        return -1;
    }
    for (unsigned i = 0; i < OHV_TRACE_COUNT; i++) {
        const char *a = kTraceNames[i];
        const char *b = name;

        while (*a != '\0' && *b != '\0') {
            char c = (char)tolower((unsigned char)*b);

            if (c == '_') {
                c = '-';
            }
            if (c != *a) {
                break;
            }
            a++;
            b++;
        }
        if (*a == '\0' && *b == '\0') {
            return (int)i;
        }
    }
    return -1;
}
