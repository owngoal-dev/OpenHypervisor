// ohv_internal.h - library-internal state and helpers.
#ifndef OHV_INTERNAL_H
#define OHV_INTERNAL_H

#include <atomic>
#include <pthread.h>
#include <stdint.h>
#include "openhyp/ohv_context.h"
#include "openhyp/hv_compat_protos.h"
#include "openhyp/ohv_config.h"
#include "openhyp/ohv_vmm.h"

// Process-global VM singleton: the kernel binds exactly one VM per task.
namespace ohv {

extern pthread_mutex_t g_vm_mutex;
extern pthread_mutex_t g_vcpus_mutex;
extern bool g_vm_alive;
extern uint32_t g_vm_isa;
extern bool g_vm_el2;
extern bool g_vm_vhe;
extern void *g_gic;         // userspace GIC model (opaque)
extern uint32_t g_max_vcpus;

constexpr uint64_t kMaxVcpuIds = 64; // vcpus_exit bitmask width

/*
 * The switches ohv_config.h sets, with the defaults the library has always
 * run with.  One word each: read relaxed on the vCPU threads -- a plain load
 * on arm64, which is what a setting consulted on every trapped register has
 * to cost -- and written by the setters in ohv_config.cpp.  A `_given` word
 * marks a setting whose absence means "leave the library's own choice".
 */
struct Config {
    std::atomic<bool> bank_inline{true};
    std::atomic<bool> impdef_shadow{true};
    std::atomic<bool> ipi_inline{false};
    std::atomic<bool> wfe_inline{false};
    std::atomic<uint64_t> claim_state{OHV_CLAIM_STATE_DEFAULT};
    std::atomic<bool> one_space{true};
    std::atomic<bool> tlbi_replay{false};
    std::atomic<bool> tlbi_replay_given{false};
    std::atomic<bool> nested_space{true};
    std::atomic<bool> nested_inherit{true};
    std::atomic<bool> monitor_level_gate{true};
    std::atomic<bool> monitor_nv{true};
    std::atomic<bool> hw_geret{true};
    std::atomic<bool> eret_emulation{true};
    std::atomic<bool> el2_injection{true};
    std::atomic<bool> mirror_gl1{false};
    std::atomic<bool> vmkey_mirror{false};
    std::atomic<bool> allow_apsts_write{false};
    std::atomic<bool> trap_wfe{true};
    std::atomic<bool> hcr_tidcp{false};
    std::atomic<bool> hcr_tidcp_given{false};
    std::atomic<uint64_t> tidcp_vcpus{0};
    std::atomic<bool> tidcp_vcpus_given{false};
    std::atomic<bool> trap_pac_keys{false};
    std::atomic<bool> trap_gxf{false};
    std::atomic<bool> hacr_tactl0{false};
    std::atomic<uint64_t> hcr_nested_mask{OHV_HCR_NESTED};
    std::atomic<uint64_t> hcr_xmo{OHV_HCR_AMO | OHV_HCR_IMO | OHV_HCR_FMO};
    std::atomic<uint64_t> cnthctl{0};
    std::atomic<bool> cnthctl_given{false};
    std::atomic<uint64_t> try_14c8{0};
    std::atomic<bool> try_14c8_given{false};
    std::atomic<uint64_t> timer_irq_vcpus{0};
    std::atomic<uint64_t> timer_gate{4};
    std::atomic<bool> sw_vtimer{true};
    std::atomic<bool> sw_vtimer_istatus{true};
    std::atomic<uint64_t> nv_keep_vcpus{0};
    std::atomic<uint64_t> amxidr{1};
    std::atomic<bool> sync_once{false};
    std::atomic<bool> spin_wfi{false};
    std::atomic<bool> survey_sysreg{false};
    std::atomic<uint64_t> trace_after{0};
    std::atomic<uint64_t> trace_from{0x1fc000000ull};
    std::atomic<uint64_t> trace_max{~0ull};
    std::atomic<uint64_t> trace_vcpu{~0ull};
    std::atomic<uint64_t> trace_sysreg{~0ull};
};

extern Config g_cfg;
/* One bit per ohv_trace_t. */
extern std::atomic<uint64_t> g_trace;

struct VcpuSlot {
    bool used;
    pthread_t owner;       // thread that created / currently runs it
    void *ctx;             // mapped interface (2 pages)
    uint64_t id;
    uint64_t run_count;
    /*
     * The run this vCPU's shared copy was last synced for, for the entries
     * that carry `sync_before`.  ~0 means never.  See the use in
     * `sysreg_access`: the guarded bank is filled by hardware, and hardware
     * only runs while the guest does, so one sync per exit is enough.
     */
    uint64_t synced_run = ~0ull;
    uint64_t wfi_ticks;
    hv_vcpu_exit_t pub_exit;
    /*
     * A cancel the VMM asked for, latched here.
     *
     * hv_vcpus_exit() is how the VMM says "come out, I have an interrupt for
     * you": QEMU's cpu_interrupt -> qemu_cpu_kick lands on it.  Forwarding it
     * straight to the run trap only works while the vCPU is actually inside
     * that trap.  One call to hv_vcpu_run() is many entries into the guest --
     * everything the framework can answer itself is answered and the guest is
     * re-entered without the VMM being told -- so a cancel that arrives during
     * one of those internal turnarounds lands on nobody, and the guest is
     * re-entered with the interrupt still uninjected.
     *
     * Latching it means the next turnaround sees it and returns instead.
     */
    std::atomic<bool> exit_requested{false};
    /*
     * The fast IPI, when ohv_set_ipi_inline() has it carried here.
     *
     * `ipi_sr` is this core's IPI_SR: bit 0 is raised by whichever vCPU sends
     * and cleared by this one writing it back, and while it stands it is part
     * of this core's virtual FIQ.  `ipi_aff` is the affinity this core is
     * addressed at -- Aff1 << 8 | Aff0 -- or OHV_IPI_AFFINITY_NONE for a
     * vCPU no IPI may name.  Both are reached from the sender's thread, which
     * is why they are atomic and why nothing else about a fast IPI is kept.
     */
    std::atomic<uint64_t> ipi_sr{0};
    std::atomic<uint64_t> ipi_aff{OHV_IPI_AFFINITY_NONE};
    /*
     * Whether this vCPU's thread is inside hv_vcpu_run().  A sender raising
     * an IPI for a vCPU that is not asks the VMM to wake it; one that is gets
     * a run cancel, which the kernel latches even between two entries.
     */
    std::atomic<bool> in_run{false};
    /*
     * The two timer bits ohv_vcpu_timer_state() last handed the VMM, which is
     * the timer level the VMM's own FIQ line is carrying.  An exit finished
     * here while these still match leaves nothing behind that the VMM would
     * have had to move.
     */
    uint32_t timer_seen = 0;
    /*
     * The EL2 registers the context has no slot for.  Under NV2 the guest's
     * own accesses to these are redirected into the VNCR page in its own
     * memory, so what a VMM writes here is only ever read back by the VMM --
     * at reset and across migration.  The framework accepts them and shows
     * nothing in the context either; storing them keeps the pair honest
     * instead of refusing a write the caller treats as fatal.
     */
    uint64_t el2_shadow[32];
    /*
     * Where an Apple private register with no descriptor of its own is kept.
     *
     * Keyed by selector, allocated on first touch, zero until written -- the
     * same shape and the same answers as QEMU's `hvf_impdef_slot`, which is
     * what used to hold them.  Having it here is what lets `service_nv2_access`
     * answer the whole op0=3 CRn 11/15 space without a round trip out to the
     * VMM; see the block there.  Only one side may keep the shadow, and it is
     * this one.
     */
    uint16_t impdef_key[64];
    uint64_t impdef_val[64];
    /*
     * Set while HCR_EL2.NV is off because a guarded ERET was handed to the
     * hardware.  The guest is inside the guarded state it returned into and
     * is not acting as a hypervisor there; the bit goes back on when it
     * leaves, which is the guarded exit.
     */
    bool nv_off_for_geret;
    /*
     * VM_TMR_FIQ_ENA_EL2 (S3_5_C15_C1_3): bit 0 the guest's physical timer,
     * bit 1 its virtual one.  Both on until the guest says otherwise, which is
     * the state iBoot runs in.
     */
    uint64_t vm_tmr_fiq_ena = 3;
    /*
     * The two halves of the guest's virtual FIQ, kept apart so neither can
     * erase the other: the VMM asserts its own level once per entry, the
     * timers emulated here assert theirs on every internal one.
     */
    bool vmm_fiq = false;
    bool timer_fiq = false;
    /*
     * Which of the two timers has come due and is not masked at the timer
     * itself.  Kept apart from timer_fiq because the decision whether a due
     * timer may be delivered is not the timer's -- it depends on where the
     * guest is -- and that decision belongs with the level, not here.
     */
    bool timer_fired_v = false;
    bool timer_fired_p = false;
    /*
     * Where the monitor images live, learned rather than assumed.  SPTM, TXM
     * and the kernelcache are linked 0x10000000 apart -- 0xfffffff007004000,
     * 0xfffffff017004000, 0xfffffff027004000 -- and carry one slide between
     * them, so the first kernel-VA the guest is ever seen at, which is SPTM's
     * entry, fixes all three.  Below sptm_base + 0x20000000 is the monitor;
     * at or above it is XNU.
     */
    uint64_t sptm_base = 0;
    /*
     * TPIDR_EL2 when the monitor is the one using it.
     *
     * The name covers two storages on this chain.  The monitor runs at real
     * EL2 on the silicon and puts its per-CPU block into the physical
     * register; the kernel is the monitor's guest, with HCR_EL2.{NV,NV2} set,
     * so its own use of the register -- the arm_host_context_t it stores at
     * guest entry and recovers in PREP_HOST_REGS -- is redirected into its
     * VNCR page and never reaches the register at all.
     *
     * Flattened onto hardware EL1 both layers trap, and while both were sent
     * to the VNCR slot the monitor's per-CPU install overwrote the kernel's
     * host context.  Measured on 24A437: the kernel's next guest exception
     * read the monitor's block instead, took its guest_context pointer from
     * +0x90 (zero) and died storing to 0x370 --
     *
     *     panic(cpu 2): Synchronous exception taken while SP1 selected
     *       at pc 0xfffffff04f719cc0, far=0x370   (_fleh_guest_synchronous)
     *
     * so the monitor's copy lives here and the kernel keeps the VNCR slot.
     * One slot: the monitor installs this once per core and nothing else
     * uses it.
     */
    uint64_t monitor_tpidr_el2 = 0;
    uint64_t nested_hcr_seen = 0;   /* last guest HCR_EL2 this side printed */
    /*
     * The GL2 bank, s3_6_c15_c11_0..7, in the same order as GL1: SP, TPIDR,
     * VBAR, SPSR, ASPSR, ESR, ELR, FAR.  Kept here because the host's guest
     * state has nowhere to put it -- guest_thread_state.h carries *_gl1 and
     * nothing for GL2 -- so unlike the GL1 bank there is no silicon behind
     * these to disagree with.
     */
    uint64_t gl2_bank[8];
    /* The CTRR bank, whose two views share one shadow. */
    struct { uint8_t sel; uint64_t value; } ctrr[6];
    unsigned ctrr_used = 0;
    /* KTRACE_MESSAGE, HIST_TRIG and JCTL_EL0, per thread switch. */
    uint64_t ctx_trace[3] = {0, 0, 0};
    unsigned kernel_exits = 0;
    /* The VMM's virtual IRQ, held here so its level can be gated like the FIQ. */
    bool vmm_irq = false;
    /*
     * The guest stopped on a WFI or a WFE.
     *
     * Which is a moment the interrupt gates can always say yes to: a WFx is
     * never in the middle of a GENTER, and waking is the whole reason the
     * level exists.  Cores sitting in XNU's idle wait were the last ones the
     * gate would not answer, and they are the ones that most need it.
     */
    bool in_wfx = false;
    /* What the last exit was, so the gate trace can say why in_wfx is not set. */
    unsigned last_reason = 0;
    uint64_t last_esr = 0;
    /*
     * The Apple implementation-defined registers the guest touches that
     * nothing else answers.  They always trap -- HACR_EL2's THIDDVF, THIDCPU,
     * THIDLLC, THIDAMX and THIDDPC are in the kernel's fixed set -- and left
     * unanswered each one stops a boot stage dead, so they are kept here by
     * encoding: read gives back what was written, starting at zero.
     */
    struct { uint32_t enc; uint64_t value; } apple_shadow[96];
    unsigned apple_shadow_used;
/* The emulated physical timer control, kept out of the kernel's slot. */
#define OHV_SHADOW_CNTP_CTL 30
    /*
     * The ID registers.  They describe the machine, but they are the VMM's to
     * set: it builds a CPU model out of what the host reports, adjusts it,
     * writes the result back and then checks that reading it returns what it
     * wrote.  Serving them straight out of the capabilities and dropping
     * writes fails that check on the first exit.
     */
    uint64_t id_regs[20];
    bool id_regs_loaded;
    /*
     * The interrupt controller's CPU interface, as the guest sees it.  These
     * are system registers, and while the virtual interface is not serving
     * them every access leaves the guest; the framework answers them out of
     * its own model rather than passing them up, and so does this.
     */
    struct { uint16_t enc; uint64_t value; } gic_if[48];
    unsigned gic_if_count;
    bool gic_if_ready;
    /*
     * Which level the guest believes it is at.  HCR_EL2.NV is what makes an
     * EL1 guest look like a hypervisor to itself -- CurrentEL answers EL2 and
     * the EL2 registers redirect -- so it belongs on only while the guest
     * hypervisor is running its own code, and has to come off when the guest
     * drops into the guest it is hosting.
     */
    bool guest_at_el2;
};



extern VcpuSlot g_vcpus[kMaxVcpuIds];

// thread-local binding like the framework's thread_local vcpu guard
extern thread_local VcpuSlot *tl_current_vcpu;

inline VcpuSlot *find_vcpu(hv_vcpu_t id) {
    if (id >= kMaxVcpuIds) return nullptr;
    VcpuSlot &s = g_vcpus[id];
    return s.used ? &s : nullptr;
}

VcpuSlot *owned_vcpu(hv_vcpu_t id);
hv_return_t require_vm();
void mark_dirty(void *ctx, uint64_t bit);

// sysreg dispatch (ohv_sysreg.cpp)
struct SysRegDesc {
    uint16_t encoding;
    uint8_t kind;       // 0=shared 1=banked 2=extreg 3=debug 5=ro-id 6=raw offset 7=shadow 8=_EL12 view 9=run-controls word
    uint16_t index;     // element index within its class
    uint64_t dirty_bit; // state_dirty bit to set on write (0 = none)
    bool sync_before;   // issue TRAP_HV_VCPU_SYSREGS_SYNC before access
};
const SysRegDesc *sysreg_lookup(uint16_t encoding);
/* The Apple private encodings, which the generator has no source for. */
const SysRegDesc *sysreg_lookup_apple(uint16_t encoding);

} // namespace ohv

/* A switch from ohv_config.h, as the vCPU threads read it. */
#define ohv_cfg(field) (::ohv::g_cfg.field.load(std::memory_order_relaxed))
/* Whether a setting with no default of its own has been given at all. */
#define ohv_cfg_given(field) \
    (::ohv::g_cfg.field##_given.load(std::memory_order_acquire))
/* Whether one of ohv_config.h's traces is on. */
#define ohv_trace_on(which) \
    ((::ohv::g_trace.load(std::memory_order_relaxed) >> (unsigned)(which)) & 1u)

/*
 * Global scope, not ohv::, because these are the symbols the library already
 * exports under these names.
 */
/* The capabilities snapshot, fetched once (ohv_caps_field.cpp). */
const ohv_capabilities_t *ohv_caps_cached();
/* Set once the guest's PC first lands in the kernel (ohv_vcpu.cpp). */
extern bool g_kernel_running;

/* The narrowed ID registers (ohv_misc.cpp). */
extern "C" uint64_t ohv_caps_field(const ohv_capabilities_t *, uint16_t enc);
extern "C" uint64_t ohv_id_reg_for(const ohv_capabilities_t *, unsigned which, bool for_config);
/* Which slot in VcpuSlot::id_regs an encoding names, or -1 for none. */
extern "C" int ohv_id_slot(uint16_t encoding);
/*
 * MIDR and MPIDR are not in hv_feature_reg_t and get slots past its last
 * index; everything else keeps the index it is named by there, so the two
 * stay in step.
 */
#define OHV_ID_SLOT_MIDR  18
#define OHV_ID_SLOT_MPIDR 19

void *ohv_guest_ptr(uint64_t ipa, uint64_t len);
/* The nested address spaces a guest hypervisor runs in, if any. */
uint64_t ohv_nested_asid(unsigned index);

#endif
