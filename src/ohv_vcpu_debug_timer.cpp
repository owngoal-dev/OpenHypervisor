// ohv_vcpu_debug_timer.cpp - vCPU debug-trap, timer and TLB accessors.
#include "ohv_internal.h"

using namespace ohv;

extern "C" hv_return_t hv_vcpu_get_trap_debug_exceptions(hv_vcpu_t id, bool *v) {
    VcpuSlot *s = owned_vcpu(id); if (!s || !v) return HV_BAD_ARGUMENT;
    *v = (ohv_rw_controls(s->ctx)->mdcr_el2 >> 8) & 1; // MDCR_EL2.TDE
    return HV_SUCCESS;
}
extern "C" hv_return_t hv_vcpu_set_trap_debug_exceptions(hv_vcpu_t id, bool on) {
    VcpuSlot *s = owned_vcpu(id); if (!s) return HV_BAD_ARGUMENT;
    volatile uint64_t *mdcr = &ohv_rw_controls(s->ctx)->mdcr_el2;
    *mdcr = on ? (*mdcr | (1ull << 8)) : (*mdcr & ~(1ull << 8));
    mark_dirty(s->ctx, OHV_STATE_CONTROLS);
    return HV_SUCCESS;
}
extern "C" hv_return_t hv_vcpu_get_trap_debug_reg_accesses(hv_vcpu_t id, bool *v) {
    VcpuSlot *s = owned_vcpu(id); if (!s || !v) return HV_BAD_ARGUMENT;
    *v = (ohv_rw_controls(s->ctx)->mdcr_el2 >> 9) & 1; // TDA|TDOSA|TDRA collapsed
    return HV_SUCCESS;
}
extern "C" hv_return_t hv_vcpu_set_trap_debug_reg_accesses(hv_vcpu_t id, bool on) {
    VcpuSlot *s = owned_vcpu(id); if (!s) return HV_BAD_ARGUMENT;
    volatile uint64_t *mdcr = &ohv_rw_controls(s->ctx)->mdcr_el2;
    const uint64_t mask = (1ull << 9) | (1ull << 10) | (1ull << 11);
    *mdcr = on ? (*mdcr | mask) : (*mdcr & ~mask);
    mark_dirty(s->ctx, OHV_STATE_CONTROLS);
    return HV_SUCCESS;
}

extern "C" hv_return_t hv_vcpu_get_exec_time(hv_vcpu_t id, uint64_t *t) {
    VcpuSlot *s = owned_vcpu(id); if (!s || !t) return HV_BAD_ARGUMENT;
    *t = *ohv_rw_u64(s->ctx, OHV_RW_GUEST_TICKS);
    return HV_SUCCESS;
}
extern "C" hv_return_t hv_vcpu_get_wait_for_interrupt_time(hv_vcpu_t id, uint64_t *t) {
    VcpuSlot *s = owned_vcpu(id); if (!s || !t) return HV_BAD_ARGUMENT;
    *t = s->wfi_ticks;
    return HV_SUCCESS;
}

extern "C" hv_return_t hv_vcpu_get_vtimer_mask(hv_vcpu_t id, bool *masked) {
    VcpuSlot *s = owned_vcpu(id); if (!s || !masked) return HV_BAD_ARGUMENT;
    *masked = (ohv_rw_controls(s->ctx)->timer & OHV_TIMER_MASK) != 0;
    return HV_SUCCESS;
}
extern "C" hv_return_t hv_vcpu_set_vtimer_mask(hv_vcpu_t id, bool masked) {
    VcpuSlot *s = owned_vcpu(id); if (!s) return HV_BAD_ARGUMENT;
    volatile uint64_t *t = &ohv_rw_controls(s->ctx)->timer;
    *t = masked ? (*t | OHV_TIMER_MASK) : (*t & ~OHV_TIMER_MASK);
    mark_dirty(s->ctx, OHV_STATE_CONTROLS);
    return HV_SUCCESS;
}
extern "C" hv_return_t hv_vcpu_get_vtimer_offset(hv_vcpu_t id, uint64_t *off) {
    VcpuSlot *s = owned_vcpu(id); if (!s || !off) return HV_BAD_ARGUMENT;
    *off = ohv_rw_controls(s->ctx)->virtual_timer_offset;
    return HV_SUCCESS;
}
extern "C" hv_return_t hv_vcpu_set_vtimer_offset(hv_vcpu_t id, uint64_t off) {
    VcpuSlot *s = owned_vcpu(id); if (!s) return HV_BAD_ARGUMENT;
    ohv_rw_controls(s->ctx)->virtual_timer_offset = off;
    mark_dirty(s->ctx, OHV_STATE_CONTROLS);
    return HV_SUCCESS;
}

extern "C" hv_return_t hv_vcpu_invalidate_tlb(hv_vcpu_t id, hv_tlbi_op_t op, uint64_t param) {
    VcpuSlot *s = owned_vcpu(id); if (!s) return HV_BAD_ARGUMENT;
    ohv_vm_stage1_tlb_op_t a{ 0, (uint64_t)op, param };
    return ohv_raw_trap(OHV_TRAP_VM_STAGE1_TLB_OP, &a);
}
