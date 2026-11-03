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
    uint64_t kernel_op;

    /*
     * Hypervisor.framework exposes architectural TLBI encodings here, while
     * the kernel trap consumes PMAP_S1_TLB_OP_ ordinals.  Passing 0x18 for
     * VMALLE1IS was therefore rejected as an out-of-range operation.
     */
    switch (op) {
    case HV_TLBI_OP_ASIDE1IS:  kernel_op = kS1TlbAside1is; break;
    case HV_TLBI_OP_VAE1IS:    kernel_op = kS1TlbVae1is; break;
    case HV_TLBI_OP_VAAE1IS:   kernel_op = kS1TlbVaae1is; break;
    case HV_TLBI_OP_VAALE1IS:  kernel_op = kS1TlbVaale1is; break;
    case HV_TLBI_OP_VALE1IS:   kernel_op = kS1TlbVale1is; break;
    case HV_TLBI_OP_VMALLE1IS: kernel_op = kS1TlbVmalle1is; break;
    case HV_TLBI_OP_RVAE1IS:   kernel_op = kS1TlbRvae1is; break;
    case HV_TLBI_OP_RVAAE1IS:  kernel_op = kS1TlbRvaae1is; break;
    case HV_TLBI_OP_RVAALE1IS: kernel_op = kS1TlbRvaale1is; break;
    case HV_TLBI_OP_RVALE1IS:  kernel_op = kS1TlbRvale1is; break;
    default: return HV_BAD_ARGUMENT;
    }
    ohv_vm_stage1_tlb_op_t a{ 0, kernel_op, param };
    return ohv_raw_trap(OHV_TRAP_VM_STAGE1_TLB_OP, &a);
}
