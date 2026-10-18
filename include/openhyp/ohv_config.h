/*
 * ohv_config.h - the library's own switches, set by calls.
 *
 * Every behaviour this library lets a VMM turn on or off, and every trace it
 * can print, is set here -- none of it is read out of the environment any
 * more.  A switch held in the environment is invisible in a run's own
 * record: a VMM that logs its argv does not log environ, so two runs that
 * differed in one OHV_* variable were indistinguishable afterwards, and
 * `env | grep OHV_` had to be saved beside each run to make up for it.
 * A switch the VMM sets from its own command line is in that record.
 *
 * Each setting is one word, written by its setter and read relaxed by the
 * vCPU threads (a plain load), so a setter racing a running vCPU decides only
 * which of the two values that vCPU sees next.  The ones that shape a vCPU
 * when it is made -- marked "read at hv_vcpu_create()" -- have to be set
 * before then to have any effect; everything else can be changed at any time.
 *
 * The defaults are the ones the library ran with when nothing was set, so a
 * VMM that calls none of these gets exactly the behaviour it always had.
 * Every setter answers HV_SUCCESS, or HV_BAD_ARGUMENT for a value outside its
 * range, which leaves the setting as it was.
 */
#ifndef OHV_CONFIG_H
#define OHV_CONFIG_H

#include <stdbool.h>
#include <stdint.h>
#include "openhyp/ohv_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------- answered in here -- */

/*
 * Answer the op0=3 CRn 11/15 space -- the guarded banks and every Apple
 * IMPDEF register the VMM would only have forwarded -- without leaving the
 * library.  Default on.  Only meaningful with ohv_set_claim_state() leaving
 * ARM_GUEST_STATE_GXF claimed: alone it answers from a bank nobody carries.
 * (Was OHV_BANK_INLINE=0.)
 */
hv_return_t ohv_set_bank_inline(bool on);

/*
 * Keep the Apple registers this library has no descriptor for in a per-vCPU
 * shadow here, so they are answered without the VMM.  Default on.  Off hands
 * them back to the VMM, which then has to keep them itself -- the shadow must
 * have exactly one owner.  (Was OHV_IMPDEF_SHADOW=0.)
 */
hv_return_t ohv_set_impdef_shadow(bool on);

/*
 * The fast IPI -- IPI_RR_LOCAL/GLOBAL, IPI_SR and IPI_CR -- carried out here,
 * between the vCPUs of this VM, instead of by the VMM under its own lock.
 * Default off.  With it on the pending bit of each core's IPI_SR lives in
 * this library and is folded into that core's virtual FIQ, the sender kicks a
 * target that is running and asks the VMM to wake one that is not (see
 * ohv_set_vcpu_wake_handler() in ohv_vmm.h), and the VMM must stop modelling
 * the registers itself.  A target is any vCPU given an affinity with
 * ohv_vcpu_set_ipi_affinity(); one never given one is never a target.
 */
hv_return_t ohv_set_ipi_inline(bool on);

/*
 * Step over a trapped WFE here rather than handing it to the VMM, whose whole
 * answer to one is to move the program counter on.  Default off.  It is only
 * done while the VMM has no FIQ asserted on the core and the guest's timers
 * still say what the VMM last read from ohv_vcpu_timer_state(), so an edge
 * the VMM has to see is never skipped.
 */
hv_return_t ohv_set_wfe_inline(bool on);

/* ----------------------------------------------- state the host carries -- */

/*
 * Which Apple guest-state classes the host kernel is told to carry, as
 * OHV_STATE_* bits put in rw.state_dirty at vCPU creation.  Default
 * OHV_CLAIM_STATE_DEFAULT; zero claims nothing.  Never include CTRR.
 * Read at hv_vcpu_create().  (Was OHV_CLAIM_STATE.)
 */
/* OHV_STATE_GXF | _SPRR | _AMX | _JITBOX | _PTRAUTH_APPLE (ohv_context.h) */
#define OHV_CLAIM_STATE_DEFAULT \
    ((1ull << 58) | (1ull << 59) | (1ull << 57) | (1ull << 56) | (1ull << 60))
hv_return_t ohv_set_claim_state(uint64_t mask);

/*
 * Every vCPU in nested address space 0, so the VM has one VMID and a guest
 * TLBI broadcast reaches every core.  Default on; off is one space per vCPU,
 * which is what produced the stale-TLB corruption and is kept for A/B only.
 * Read at hv_vcpu_create().  (Was OHV_ONE_SPACE=0.)
 */
hv_return_t ohv_set_one_space(bool on);

/*
 * Trap the guest's stage-1 TLBIs (HCR_EL2.TTLB) and replay each into every
 * address space.  Follows ohv_set_one_space() unless set: off with one space,
 * on without.  (Was OHV_TLBI_REPLAY.)
 */
hv_return_t ohv_set_tlbi_replay(bool on);

/*
 * Join the VM's nested address spaces at all.  Default on.  (Was
 * OHV_NO_NESTED_SPACE.)
 */
hv_return_t ohv_set_nested_space(bool on);

/*
 * Seed a vCPU's guest HCR_EL2 with the part's reset value RW|APK|API, and
 * re-seed it when it reads back as the bare RW a fresh VNCR page has.
 * Default on.  (Was OHV_NO_NESTED_INHERIT.)
 */
hv_return_t ohv_set_nested_inherit(bool on);

/* ---------------------------------------------------- guest EL2 / GXF -- */

/*
 * Hold the VMM's IRQ and FIQ levels while the guest is in its monitor, on a
 * chain whose ROM announced one.  Default on.  (Was OHV_MONITOR_LEVEL_GATE=0.)
 */
hv_return_t ohv_set_monitor_level_gate(bool on);

/*
 * Re-arm HCR_EL2.NV once the announced monitor runs.  Default on.  (Was
 * OHV_NO_MONITOR_NV.)
 */
hv_return_t ohv_set_monitor_nv(bool on);

/*
 * Hand a trapped guarded ERET to the silicon.  Default on.  (Was
 * OHV_NO_HW_GERET.)
 */
hv_return_t ohv_set_hw_geret(bool on);

/*
 * Complete a guest hypervisor's trapped ERET here.  Default on.  (Was
 * OHV_NO_ERET_EMULATION.)
 */
hv_return_t ohv_set_eret_emulation(bool on);

/*
 * Deliver a nested guest's HVC to the guest hypervisor's vector.  Default
 * on.  (Was OHV_NO_EL2_INJECTION.)
 */
hv_return_t ohv_set_el2_injection(bool on);

/*
 * Mirror the GL1 return pair onto the EL1 pair on every MSR trap.  Default
 * off.  (Was OHV_MIRROR_GL1.)
 */
hv_return_t ohv_set_mirror_gl1(bool on);

/*
 * Mirror KERNKEYLO/HI into the VM key.  Default off.  (Was
 * OHV_VMKEY_MIRROR.)
 */
hv_return_t ohv_set_vmkey_mirror(bool on);

/*
 * Let the VMM write control field 9, APSTS_EL1.  Default off.  (Was
 * OHV_ALLOW_APSTS_WRITE.)
 */
hv_return_t ohv_set_allow_apsts_write(bool on);

/* --------------------------------------------- trap controls at creation -- */
/* All of these are read at hv_vcpu_create(). */

/*
 * HCR_EL2.TWE, so a parked core is one this side can hear from.  Default on.
 * (Was OHV_NO_TWE.)
 */
hv_return_t ohv_set_trap_wfe(bool on);

/*
 * HCR_EL2.TIDCP for every vCPU, overriding the kernel's default for a new
 * one.  Not applied unless set.  ohv_set_tidcp_vcpus() wins over it.
 * (Was OHV_HCR_TIDCP.)
 */
hv_return_t ohv_set_hcr_tidcp(bool on);

/*
 * Which vCPUs keep HCR_EL2.TIDCP -- a bitmap by vCPU id; every other vCPU has
 * it cleared.  Not applied unless set.  (Was OHV_TIDCP_VCPUS.)
 */
hv_return_t ohv_set_tidcp_vcpus(uint64_t mask);

/*
 * Clear HCR_EL2.APK so the guest's key registers trap.  Default off.  (Was
 * OHV_TRAP_PAC_KEYS.)
 */
hv_return_t ohv_set_trap_pac_keys(bool on);

/* Set HACR_EL2.TGXF.  Default off.  (Was OHV_TRAP_GXF.) */
hv_return_t ohv_set_trap_gxf(bool on);

/*
 * Set HACR_EL2 bit 0, the APCTL_EL1 trap.  Default off.  (Was
 * OHV_HACR_TACTL0.)
 */
hv_return_t ohv_set_hacr_tactl0(bool on);

/*
 * The nested bits given to vCPU 0's HCR_EL2.  Default NV|NV2.  (Was
 * OHV_HCR_NESTED_MASK.)
 */
hv_return_t ohv_set_hcr_nested_mask(uint64_t mask);

/*
 * HCR_EL2.{AMO,IMO,FMO}, taken from these bits.  Default all three.  (Was
 * OHV_HCR_XMO.)
 */
hv_return_t ohv_set_hcr_xmo(uint64_t bits);

/*
 * The whole of CNTHCTL_EL2.  Not applied unless set; the library works one
 * out.  (Was OHV_CNTHCTL.)
 */
hv_return_t ohv_set_cnthctl(uint64_t value);

/*
 * A word written at context offset 0x14c8 at creation.  Not applied unless
 * set.  (Was OHV_TRY_14C8.)
 */
hv_return_t ohv_set_try_14c8(uint64_t value);

/* ------------------------------------------------------------- timers -- */

/*
 * Which vCPUs take a due timer as an IRQ instead of an FIQ, by vCPU id --
 * the SEP's core, whose FIQ vectors halt.  Default none.  The machine sets
 * this; it is the one that knows which core that is.  (Was
 * OHV_TIMER_IRQ_VCPUS.)
 */
hv_return_t ohv_set_timer_irq_vcpus(uint64_t mask);

/* The timer delivery rule, 0..4.  Default 4.  (Was OHV_TIMER_GATE.) */
hv_return_t ohv_set_timer_gate(uint64_t mode);

/*
 * Deliver the virtual timer from software.  Default on.  (Was
 * OHV_NO_SW_VTIMER.)
 */
hv_return_t ohv_set_sw_vtimer(bool on);

/*
 * Maintain the virtual timer's ISTATUS in software.  Default on.  (Was
 * OHV_NO_SW_ISTATUS.)
 */
hv_return_t ohv_set_sw_vtimer_istatus(bool on);

/* ------------------------------------------------------- the SEP and NV -- */

/*
 * Which vCPUs keep HCR_EL2.NV after the kernel leaves EL2, by vCPU id -- a
 * second guest on the same VM, such as the SEP.  Default none.
 * (Was OHV_NV_KEEP_VCPUS.)
 */
hv_return_t ohv_set_nv_keep_vcpus(uint64_t mask);

/* What AMXIDR_EL1 reads.  Default 1.  (Was OHV_AMXIDR.) */
hv_return_t ohv_set_amxidr(uint64_t value);

/* --------------------------------------------------------- diagnostics -- */

/*
 * Batch the sync_before trap to once per exit.  Default off.  (Was
 * OHV_SYNC_ONCE.)
 */
hv_return_t ohv_set_sync_once(bool on);

/*
 * Step over a WFI instead of handing it to the VMM.  Default off.  (Was
 * OHV_SPIN_WFI.)
 */
hv_return_t ohv_set_spin_wfi(bool on);

/*
 * Drop a refused system register write instead of failing it.  Default off.
 * (Was OHV_SURVEY_SYSREG.)
 */
hv_return_t ohv_set_survey_sysreg(bool on);

/* -------------------------------------------------------------- traces -- */

/*
 * One bit each, printed to stderr.  Each was the environment variable
 * OHV_TRACE_<NAME>; OHV_TRACE_VM was OHV_DEBUG.
 */
typedef enum ohv_trace {
    OHV_TRACE_ALL,          /* every exit; see the trace window below */
    OHV_TRACE_AT,
    OHV_TRACE_BAND,
    OHV_TRACE_CTRR,
    OHV_TRACE_ERET,
    OHV_TRACE_EXIT,
    OHV_TRACE_EXT,
    OHV_TRACE_FAULT,
    OHV_TRACE_FIRSTRUN,
    OHV_TRACE_GATE,
    OHV_TRACE_GIC,
    OHV_TRACE_GL1,
    OHV_TRACE_GLVL,
    OHV_TRACE_GXFSTATE,
    OHV_TRACE_HACR,
    OHV_TRACE_HCR,
    OHV_TRACE_IMPDEF,
    OHV_TRACE_IPI,
    OHV_TRACE_IRQ,
    OHV_TRACE_KFAULT,
    OHV_TRACE_KICK,
    OHV_TRACE_KIRQ,
    OHV_TRACE_KTIMER,
    OHV_TRACE_NESTED,
    OHV_TRACE_PAC,
    OHV_TRACE_REASONS,
    OHV_TRACE_SYSREG,
    OHV_TRACE_TID2,
    OHV_TRACE_TIMER,
    OHV_TRACE_TIMERREG,
    OHV_TRACE_TLBI,
    OHV_TRACE_TMRENA,
    OHV_TRACE_TPIDR_EL2,
    OHV_TRACE_UNMATCHED,
    OHV_TRACE_USED,
    OHV_TRACE_VF,
    OHV_TRACE_VF_K,         /* narrows OHV_TRACE_VF to the kernel era */
    OHV_TRACE_VM,
    OHV_TRACE_COUNT
} ohv_trace_t;

hv_return_t ohv_set_trace(ohv_trace_t which, bool on);

/*
 * A trace by name -- the enumerator without its prefix, in either case, with
 * '-' or '_' between words: "band", "tpidr-el2", "VF_K".  -1 for none.
 */
int ohv_trace_lookup(const char *name);
/* The lower-case, dash-separated name of a trace, or NULL. */
const char *ohv_trace_name(ohv_trace_t which);

/*
 * The window OHV_TRACE_ALL prints in: not before `seconds` into the run
 * (default 0), only at a pc at or above `pc` (default 0x1fc000000), at most
 * `count` lines (default unlimited), only for vCPU `id` (default every one;
 * any id of 64 or more means every one).  (Were OHV_TRACE_AFTER, _FROM, _MAX
 * and _VCPU.)
 */
hv_return_t ohv_set_trace_after(uint64_t seconds);
hv_return_t ohv_set_trace_from(uint64_t pc);
hv_return_t ohv_set_trace_max(uint64_t count);
hv_return_t ohv_set_trace_vcpu(uint64_t id);

/*
 * Print every access to one system register, by its hv_sys_reg_t encoding.
 * Default none; any value above 0xffff means none.  (Was OHV_TRACE_ONE.)
 */
hv_return_t ohv_set_trace_sysreg(uint64_t encoding);

#ifdef __cplusplus
}
#endif
#endif /* OHV_CONFIG_H */
