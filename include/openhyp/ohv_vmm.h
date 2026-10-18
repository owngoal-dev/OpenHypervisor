/*
 * ohv_vmm.h - what a VMM can ask of this library beyond the Hypervisor API.
 *
 * These used to be reached by dlsym() from QEMU with no declaration anywhere,
 * which is how a renamed or missing one turns into a feature that is silently
 * off.  They are declared here, and ohv_api_version() says which set exists:
 *
 *   1  ohv_vcpu_timer_state, ohv_vcpu_timer_deadline, ohv_vcpu_set_parked
 *   2  the switches in ohv_config.h, and everything below marked (2)
 *   3  ohv_hv_layout
 *
 * Each per-vCPU call must be made on the thread that owns the vCPU, like the
 * rest of the vCPU API, unless it says otherwise.
 */
#ifndef OHV_VMM_H
#define OHV_VMM_H

#include <stdbool.h>
#include <stdint.h>
#include "openhyp/ohv_core.h"
#include "openhyp/hv_compat_enums.h"
#include "openhyp/ohv_hv_layouts.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OHV_API_VERSION 3
uint32_t ohv_api_version(void);

/*
 * (3) The layout of this kernel's vCPU context pages, as the first
 * hv_vcpu_create() picked it out of ohv_hv_layouts.h by the version word the
 * kernel wrote; NULL before any vCPU exists.  A VMM that reads the context
 * page itself (`_hv_vcpu_get_context`) takes every offset past the banked
 * registers from here: they move with the kernel build -- the state dirty
 * word is at 0x788 under 3.0.0, 0xa00 under 3.0.2/3.0.3 and 0xa08 under
 * 3.0.4 -- and a number written into the VMM is right on one host only.
 */
const ohv_hv_layout_t *ohv_hv_layout(void);

/*
 * The guest's own timers, worked out at the moment of asking.  Bit 0: the
 * physical timer is enabled, unmasked and due; bit 1: the virtual one is.
 * Bits 3:2: S3_5_C15_C1_3, the guest's per-timer FIQ enable.
 */
uint32_t ohv_vcpu_timer_state(hv_vcpu_t vcpu);

/* The earliest enabled compare value, in the host's counter; 0 for none. */
uint64_t ohv_vcpu_timer_deadline(hv_vcpu_t vcpu);

/* The VMM saw the guest stop on a WFI or WFE (true), or leave one (false). */
void ohv_vcpu_set_parked(hv_vcpu_t vcpu, bool parked);

/*
 * (2) The affinity -- Aff1 << 8 | Aff0 of MPIDR_EL1 -- this vCPU answers fast
 * IPIs at, once ohv_set_ipi_inline() is on.  A vCPU never given one is never
 * a target, which is what keeps a second guest on the same VM (the SEP) out
 * of the application cores' IPI domain.  OHV_IPI_AFFINITY_NONE takes it away.
 * May be called from any thread.
 */
#define OHV_IPI_AFFINITY_NONE (~0ull)
hv_return_t ohv_vcpu_set_ipi_affinity(hv_vcpu_t vcpu, uint64_t affinity);

/*
 * (2) How this library asks the VMM to wake a vCPU it has just raised an
 * interrupt for, when that vCPU is not inside hv_vcpu_run() -- most often
 * because the VMM has halted it on a WFI and is waiting for work of its own.
 * Called on the sending vCPU's thread, with nothing of this library's held;
 * it must not block on anything that vCPU thread may be holding, and it may
 * be called for a vCPU that turns out to be awake already.  Afterwards the
 * VMM only has to let the vCPU run: the interrupt itself is raised here, on
 * the vCPU's way into the guest.
 */
typedef void (*ohv_vcpu_wake_fn)(hv_vcpu_t vcpu, void *opaque);
void ohv_set_vcpu_wake_handler(ohv_vcpu_wake_fn fn, void *opaque);

/*
 * (2) Whether this library has an interrupt of its own pending for the vCPU
 * -- today, a fast IPI it took in.  A VMM that halts a vCPU on WFI asks this
 * beside its own interrupt lines, after hv_vcpu_run() has returned and before
 * it sleeps: together with the wake handler above that closes the window in
 * which an IPI sent while the vCPU was leaving would otherwise wait for the
 * next timer.  May be called from any thread.
 */
bool ohv_vcpu_interrupt_pending(hv_vcpu_t vcpu);

#ifdef __cplusplus
}
#endif
#endif /* OHV_VMM_H */
