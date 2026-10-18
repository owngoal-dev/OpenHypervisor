// ohv_vcpu_control.cpp - private control-field, context and ext-register API.
#include "ohv_internal.h"

using namespace ohv;

// -------------------------------------------------- private control/ext API --
/*
 * A control field is not the n-th word of the controls block.  The framework
 * numbers them through a table, and the order is nothing like the layout:
 * field 1 is CPTR_EL2 where the second word is HACR_EL2, field 6 is HACR_EL2,
 * field 9 is APSTS_EL1 where the tenth word is HFGRTR_EL2.  Treating the
 * number as an index puts every write on a different register than the caller
 * named -- a VMM asking for the guarded-operation trap sets a bit in HACR
 * instead of CPTR, and one raising the guarded level sets a fine-grained trap
 * instead, which is enough to take a core somewhere it never returns from.
 *
 * Offsets are from the start of the controls block, read out of the
 * framework's own table.  Two of the eighteen are not fields at all.
 */
#define OHV_CONTROL_FIELD_NONE 0xffff
static const uint16_t kControlFieldOffset[] = {
    0x00,                   /*  0  HCR_EL2      */
    0x10,                   /*  1  CPTR_EL2     */
    0x18,                   /*  2  MDCR_EL2     */
    0x20,                   /*  3  VMPIDR_EL2   */
    OHV_CONTROL_FIELD_NONE, /*  4               */
    0x28,                   /*  5  VPIDR_EL2    */
    0x08,                   /*  6  HACR_EL2     */
    0x70,                   /*  7  VMKEYHI_EL2  */
    0x78,                   /*  8  VMKEYLO_EL2  */
    0x80,                   /*  9  APSTS_EL1    */
    OHV_CONTROL_FIELD_NONE, /* 10               */
    0x38,                   /* 11  HFGRTR_EL2   */
    0x40,                   /* 12  HFGWTR_EL2   */
    0x48,                   /* 13  HFGITR_EL2   */
    0x50,                   /* 14  HDFGRTR_EL2  */
    0x58,                   /* 15  HDFGWTR_EL2  */
    0x60,                   /* 16  CNTHCTL_EL2  */
    0xD0,                   /* 17  HCRX_EL2     */
};

static hv_return_t control_field_access(hv_vcpu_t id, _hv_control_field_t f, uint64_t *v, bool w) {
    VcpuSlot *s = owned_vcpu(id); if (!s || !v) return HV_BAD_ARGUMENT;
    if ((unsigned)f >= sizeof(kControlFieldOffset) / sizeof(kControlFieldOffset[0]))
        return HV_BAD_ARGUMENT;
    uint16_t off = kControlFieldOffset[(unsigned)f];
    if (off == OHV_CONTROL_FIELD_NONE) return HV_BAD_ARGUMENT;

    volatile uint64_t *c =
        (volatile uint64_t *)((uint8_t *)ohv_rw_controls(s->ctx) + off);
    if (w) {
        /*
         * Field 9 is APSTS_EL1, the guarded level.  A caller that raises it
         * from out here is describing a state the guest is not in, and the
         * framework does not let the write stand: ask it to set field 9 and
         * it still reads back zero.  Doing what it was told instead leaves
         * every later reader -- including the code that decides whether a
         * trapped ERET is a guarded return -- believing the guest is guarded
         * before it has ever executed a GENTER.
         */
        if ((unsigned)f == 9 && !ohv_cfg(allow_apsts_write)) {
            return HV_SUCCESS;
        }
        *c = *v;
        mark_dirty(s->ctx, OHV_STATE_CONTROLS);
    }
    else *v = *c;
    return HV_SUCCESS;
}
extern "C" hv_return_t __hv_vcpu_get_control_field(hv_vcpu_t id, _hv_control_field_t f, uint64_t *v) {
    return control_field_access(id, f, v, false);
}
extern "C" hv_return_t __hv_vcpu_set_control_field(hv_vcpu_t id, _hv_control_field_t f, uint64_t v) {
    return control_field_access(id, f, &v, true);
}
extern "C" hv_return_t __hv_vcpu_get_context(hv_vcpu_t id, void **context) {
    VcpuSlot *s = owned_vcpu(id); if (!s || !context) return HV_BAD_ARGUMENT;
    *context = s->ctx; return HV_SUCCESS;
}
/*
 * The same private surface under the names Apple actually exports.
 *
 * Every consumer of this surface reaches it with dlsym("_hv_..."), because
 * the symbols are not in any SDK header -- QEMU's HVF backend does exactly
 * that.  Exporting only the two-underscore spelling means those lookups
 * return null and the caller carries on with the feature quietly disabled:
 * control fields are never written, so the traps they enable never arrive,
 * and the context is never read.  Nothing reports an error, which is the
 * worst shape a missing symbol can take.
 *
 * _hv_vcpu_get_context also has a different shape there: it answers with the
 * pointer rather than writing it through an out-parameter.
 */
extern "C" void *_hv_vcpu_get_context(hv_vcpu_t id) {
    VcpuSlot *s = owned_vcpu(id);
    return s ? s->ctx : nullptr;
}

extern "C" hv_return_t _hv_vcpu_get_control_field(hv_vcpu_t id,
                                                 _hv_control_field_t f,
                                                 uint64_t *v) {
    return control_field_access(id, f, v, false);
}

extern "C" hv_return_t _hv_vcpu_set_control_field(hv_vcpu_t id,
                                                 _hv_control_field_t f,
                                                 uint64_t v) {
    return control_field_access(id, f, &v, true);
}

extern "C" hv_return_t __hv_vcpu_get_ext_reg(hv_vcpu_t id, _hv_ext_reg_t reg, uint64_t *value) {
    VcpuSlot *s = owned_vcpu(id); if (!s || !value) return HV_BAD_ARGUMENT;
    if ((unsigned)reg >= sizeof(ohv_extregs_t) / 8) return HV_BAD_ARGUMENT;
    *value = ((volatile uint64_t *)(s ? (uint8_t *)s->ctx + OHV_RW_EXTREGS : nullptr))[(unsigned)reg];
    return HV_SUCCESS;
}
