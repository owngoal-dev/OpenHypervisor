// ohv_vcpu.cpp - vCPU lifecycle, register access, run loop glue.
#include <new>
#include <mach/mach_time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <sys/sysctl.h>
#include "openhyp/ohv_object.h"
#include "ohv_internal.h"
#include <cstdlib>
#include <cstdio>
#include "openhyp/ohv_trap.h"

/*
 * Every switch this file consults is set by the VMM through ohv_config.h and
 * read here with ohv_cfg() / ohv_trace_on() (ohv_internal.h) -- a relaxed
 * load of one word, which is what a setting asked on every trapped register
 * may cost.  They used to be environment variables, cached in a table read at
 * load and again at the first hv_vcpu_run(); see ohv_config.cpp for why that
 * is gone.
 */

using namespace ohv;

// ------------------------------------------------------------- ownership --
namespace ohv {
VcpuSlot *owned_vcpu(hv_vcpu_t id) {
    VcpuSlot *s = find_vcpu(id);
    if (!s) return nullptr;
    // The framework binds a vcpu to its creating thread for state safety.
    if (tl_current_vcpu && tl_current_vcpu != s) return nullptr;
    return s;
}

} // namespace ohv

using namespace ohv;

/*
 * What the kernel's classification means, taken from the framework's own
 * handler rather than from the names.  Three outcomes, not one: hand the exit
 * to the VMM, tell the VMM nothing happened, or do not return to the VMM at
 * all and enter the guest again.
 *
 * That last one is the part that was missing.  Several classifications are
 * the kernel asking to be re-entered -- they carry no exception and mean
 * nothing to a VMM -- and answering them with an exit record leaves the
 * caller looking at a reason it has no case for.  qemu's is a switch that
 * ends in g_assert_not_reached().
 */
enum ExitAction {
    EXIT_TO_VMM,
    EXIT_KEEP_RUNNING,
};

static void synth_msr_trap_syndrome(VcpuSlot *s, hv_vcpu_exit_t *out) {
    /*
     * The kernel says a system register access trapped and stops there: no
     * syndrome, no opcode, and nothing about it anywhere in the shared pages.
     * A VMM cannot answer an access it cannot name, so read the instruction
     * the guest is sitting on and build the syndrome the exception class is
     * defined to carry.
     *
     * PC is a virtual address in general; this reaches it as a guest physical
     * one, which is right while the guest MMU is off and is where a monitor
     * being brought up spends its first instructions.  With translation on
     * there is a stage-1 walk to do first, and until that exists the syndrome
     * stays zero rather than wrong.
     */
    uint64_t pc = ohv_rw(s->ctx)->regs.pc;
    const uint32_t *insn = (const uint32_t *)ohv_guest_ptr(pc, 4);

    if (insn && (*insn & 0xffd00000u) == 0xd5100000u) {
        uint32_t i = *insn;
        uint32_t read = (i >> 21) & 1;
        uint32_t op0 = 2 + ((i >> 19) & 1);
        uint32_t op1 = (i >> 16) & 7;
        uint32_t crn = (i >> 12) & 0xf;
        uint32_t crm = (i >> 8) & 0xf;
        uint32_t op2 = (i >> 5) & 7;
        uint32_t rt = i & 0x1f;

        out->exception.syndrome =
            (0x18ull << 26) | (1ull << 25) |
            (op0 << 20) | (op2 << 17) | (op1 << 14) |
            (crn << 10) | (rt << 5) | (crm << 1) | read;
    }
}

static void synth_guarded_exit_syndrome(VcpuSlot *s, hv_vcpu_exit_t *out) {
    /*
     * A guarded exit arrives as a plain synchronous exit with no syndrome:
     * the kernel does not perform GEXIT for a guest at EL2 and does not
     * describe it either.  The framework answers its caller with EC 0x3f, and
     * a VMM that has to complete the guarded return needs to be told which
     * exit this is -- so read the instruction the guest stopped on and say so.
     *
     * Only a guest actually in guarded state can execute it; outside guarded
     * state the same encoding is undefined, which is how the exception class
     * earns its meaning.
     */
    uint64_t pc = ohv_rw(s->ctx)->regs.pc;
    const uint32_t *insn = (const uint32_t *)ohv_guest_ptr(pc, 4);

    if (insn && *insn == 0x00201400u) {   /* GEXIT */
        out->exception.syndrome = (0x3full << 26) | (1ull << 25) | 0x22;
    }
}

/*
 * Which EL2 register an access names, as an offset into the VNCR page.  These
 * are the registers FEAT_NV2 redirects: at EL1 with HCR_EL2.{NV,NV2} set the
 * hardware turns the access into a memory access at VNCR_EL2 plus the offset,
 * and the guest never knows.  When it arrives here as a trapped register
 * access instead, doing the memory access is doing what was meant to happen.
 */
struct Nv2Reg { uint16_t enc; uint16_t ctx_off; bool banked; };

/*
 * Where a guest hypervisor's EL2 register actually lives.
 *
 * Two kinds.  The ones that describe the translation the guest runs under --
 * and the exception state it takes an exception with -- are the EL1 registers
 * themselves: with the host extensions on and the guest at hardware EL1, its
 * "EL2" MMU is the EL1 MMU, and a copy kept anywhere else is a value the
 * hardware never sees.  That is measurable: a guest at its EL2 writing
 * ELR_EL2, ESR_EL2 or FAR_EL2 lands on the banked EL1 slots without anything
 * here doing it.
 *
 * The rest have no EL1 counterpart -- the stage-2 registers, the traps, the
 * identification registers -- and go to the VNCR page, where the guest reads
 * them back and this library reads them when it has to enter or leave the
 * guest's EL2 on its behalf.
 */
#define VNCR(x)  (uint16_t)(0x1000 + (x)), false
#define BANKED(i) (uint16_t)(OHV_RW_BANKED_SYSREGS + (i) * 8), true

static const Nv2Reg kNv2Regs[] = {
    /* The EL1&0 translation regime, which is the guest's EL2&0 regime. */
    {0xe080, BANKED(12)},  /* SCTLR_EL2      -> SCTLR_EL1      */
    {0xe08a, BANKED(13)},  /* CPTR_EL2       -> CPACR_EL1      */
    {0xe100, BANKED(0)},   /* TTBR0_EL2      -> TTBR0_EL1      */
    {0xe101, BANKED(1)},   /* TTBR1_EL2      -> TTBR1_EL1      */
    {0xe102, BANKED(2)},   /* TCR_EL2        -> TCR_EL1        */
    {0xe510, BANKED(6)},   /* MAIR_EL2       -> MAIR_EL1       */
    {0xe518, BANKED(7)},   /* AMAIR_EL2      -> AMAIR_EL1      */
    {0xe681, BANKED(17)},  /* CONTEXTIDR_EL2 -> CONTEXTIDR_EL1 */
    {0xe200, BANKED(14)},  /* SPSR_EL2       -> SPSR_EL1       */
    {0xe201, BANKED(3)},   /* ELR_EL2        -> ELR_EL1        */
    {0xe300, BANKED(4)},   /* FAR_EL2        -> FAR_EL1        */
    {0xe290, BANKED(5)},   /* ESR_EL2        -> ESR_EL1        */


    /* The ones that are the guest hypervisor's alone. */
    {0xe000, VNCR(0x088)}, /* VPIDR_EL2   */
    {0xe005, VNCR(0x050)}, /* VMPIDR_EL2  */
    {0xe088, VNCR(0x078)}, /* HCR_EL2     */
    {0xe089, VNCR(0x130)}, /* MDCR_EL2    */
    {0xe08b, VNCR(0x080)}, /* HSTR_EL2    */
    {0xe108, VNCR(0x020)}, /* VTTBR_EL2   */
    {0xe10a, VNCR(0x040)}, /* VTCR_EL2    */
    {0xe304, VNCR(0x1f8)}, /* HPFAR_EL2   */
    {0xe682, VNCR(0x090)}, /* TPIDR_EL2   */
    {0xe703, VNCR(0x060)}, /* CNTVOFF_EL2 */
    {0xe708, VNCR(0x0e0)}, /* CNTHCTL_EL2 */
    /*
     * VBAR_EL2 stays here rather than aliasing onto VBAR_EL1, because a guest
     * hypervisor has both and uses them for different things: the boot ROM
     * installs an EL2 table, drops to EL1, and installs a second one there.
     * Folding the two together loses whichever it wrote first, and the entry
     * this library builds when it takes an exception into the guest's EL2
     * then lands in the wrong table.
     */
    {0xe600, VNCR(0x250)}, /* VBAR_EL2    */
};


static const Nv2Reg *nv2_lookup(unsigned enc) {
    for (const Nv2Reg &r : kNv2Regs) {
        if (r.enc == enc) return &r;
    }
    return nullptr;
}

/*
 * Carry out a trapped EL2 register access against the VNCR page.  Answers
 * false when the register is not one of them, and the exit goes to the VMM.
 */
/*
 * The CPU interface registers, kept per vCPU.  A guest that is only resetting
 * the controller -- which is what this machine's firmware does, having its
 * own interrupt controller elsewhere -- needs them to read back what it
 * wrote and nothing more.
 */
static uint64_t *gic_if_slot(VcpuSlot *s, unsigned enc) {
    if (!s->gic_if_ready) {
        s->gic_if_ready = true;
        s->gic_if_count = 0;
        /*
         * ICC_SRE_EL1 says the interface is reachable as system registers,
         * which is how the guest got here in the first place; reading back
         * zero would tell it to go looking for a memory-mapped one instead.
         */
        s->gic_if[s->gic_if_count].enc = 0xc665;
        s->gic_if[s->gic_if_count].value = 0x7;
        s->gic_if_count++;
    }
    for (unsigned i = 0; i < s->gic_if_count; i++) {
        if (s->gic_if[i].enc == enc) return &s->gic_if[i].value;
    }
    if (s->gic_if_count >= sizeof(s->gic_if) / sizeof(s->gic_if[0])) {
        return nullptr;
    }
    s->gic_if[s->gic_if_count].enc = (uint16_t)enc;
    s->gic_if[s->gic_if_count].value = 0;
    return &s->gic_if[s->gic_if_count++].value;
}

static bool is_gic_interface_reg(unsigned op0, unsigned op1, unsigned crn, unsigned crm, unsigned op2) {
    if (op0 != 3) {
        return false;
    }
    /* ICC_* and ICV_* at EL1, and ICH_* at EL2, all of which sit in c12. */
    if (crn == 12 && (op1 == 0 || op1 == 4) && crm >= 8 && crm <= 12) {
        return true;
    }
    /* ICC_PMR_EL1 and ICV_PMR_EL1 are the exception: they live in c4. */
    if (crn == 4 && op1 == 0 && crm == 6 && op2 == 0) {
        return true;
    }
    return false;
}

/*
 * A stage-1 walk of the guest's own tables, as AT would do it.  Returns what
 * PAR_EL1 should read: bit 0 clear and the physical address in place on a
 * hit, bit 0 set on a fault, which is the shape the caller checks first.
 *
 * Only what the guest actually uses is modelled -- a single TTBR0 regime with
 * one of the three granules, blocks and pages, no second stage.  A second
 * stage is the kernel's and does not appear in this answer: at EL1 an AT
 * reports the address its own tables produce.
 */
#define OHV_PAR_FAULT 1ull

static uint64_t ohv_translate_stage1(VcpuSlot *s, uint64_t va) {
    uint64_t tcr = *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 2 * 8);
    uint64_t ttbr0 = *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 0 * 8);
    uint64_t sctlr = *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 12 * 8);
    unsigned page_bits, level_bits;

    if ((sctlr & 1) == 0) {
        /* Translation off: the address is its own answer. */
        return va & 0x0000fffffffff000ull;
    }
    /*
     * Which half of the address space, and so which base register and size.
     * The payload runs in the EL2&0 regime with the host extensions on, and
     * that regime has both halves -- its stack is in the upper one, so a walk
     * that only knows TTBR0 answers "fault" for the address it is standing
     * on.
     */
    bool upper = (va >> 63) != 0;
    unsigned tsz = upper ? (unsigned)((tcr >> 16) & 0x3f)
                         : (unsigned)(tcr & 0x3f);
    unsigned tg = upper ? (unsigned)((tcr >> 30) & 3)
                        : (unsigned)((tcr >> 14) & 3);

    if (upper) {
        ttbr0 = *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 1 * 8);
        /* TG1 spells the granules in a different order than TG0 does. */
        switch (tg) {
            case 1: page_bits = 14; break;   /* 16 KiB */
            case 2: page_bits = 12; break;   /* 4 KiB  */
            case 3: page_bits = 16; break;   /* 64 KiB */
            default: return OHV_PAR_FAULT;
        }
    } else {
        switch (tg) {
            case 0: page_bits = 12; break;   /* 4 KiB  */
            case 1: page_bits = 16; break;   /* 64 KiB */
            case 2: page_bits = 14; break;   /* 16 KiB */
            default: return OHV_PAR_FAULT;
        }
    }
    unsigned t0sz = tsz;
    level_bits = page_bits - 3;

    unsigned va_bits = 64 - t0sz;
    if (va_bits < page_bits || va_bits > 52) {
        return OHV_PAR_FAULT;
    }
    /* The level the walk starts at, given how many bits are left to resolve. */
    unsigned level = 3;
    unsigned resolved = page_bits;
    while (level > 0 && resolved + level_bits < va_bits) {
        resolved += level_bits;
        level--;
    }

    uint64_t table = ttbr0 & 0x0000fffffffffffeull & ~((1ull << page_bits) - 1);
    for (;;) {
        unsigned shift = page_bits + (3 - level) * level_bits;
        unsigned bits = (shift + level_bits > va_bits) ? (va_bits - shift)
                                                       : level_bits;
        uint64_t index = (va >> shift) & ((1ull << bits) - 1);
        const uint64_t *entry =
            (const uint64_t *)ohv_guest_ptr(table + index * 8, 8);

        if (!entry) {
            return OHV_PAR_FAULT;
        }
        uint64_t desc = *entry;

        if ((desc & 1) == 0) {
            return OHV_PAR_FAULT;              /* invalid */
        }
        uint64_t next = desc & 0x0000fffffffff000ull;

        if ((desc & 3) == 1 || level == 3) {
            /* A block, or the last level, which is the page itself. */
            uint64_t mask = (1ull << shift) - 1;

            return (next & ~mask) | (va & mask & 0x0000fffffffff000ull);
        }
        table = next & ~((1ull << page_bits) - 1);
        level++;
        if (level > 3) {
            return OHV_PAR_FAULT;
        }
    }
}

/*
 * Where the guarded code is, when something knows rather than guesses.
 *
 * The band below is inferred from the lowest kernel address the guest has ever
 * executed at, which is right for a boot that starts SPTM before XNU and wrong
 * for one that has no separate monitor at all: on iOS 15 and 16 the privileged
 * layer is PPL, which is segments of the kernelcache itself, so the lowest band
 * is XNU's and every kernel pc then answers "in the monitor" -- measured on
 * 19A348, a self-IPI held 126553 times at PE_cpu_machine_init with PSTATE.F
 * clear and `mon` the only reason.
 *
 * The boot ROM knows the answer in both cases and says so at the handoff:
 * s3_6_c15_c15_6 carries the first address, s3_6_c15_c15_5 the length after
 * it.  Told, nothing is inferred.  It is a property of the machine rather than
 * of a core, like the band.
 */
#define OHV_GUARD_RANGES 4

static std::atomic<uint64_t> g_guard_lo[OHV_GUARD_RANGES];
static std::atomic<uint64_t> g_guard_hi[OHV_GUARD_RANGES];

/*
 * The boot ROM saying the stage it is handing to is a monitor.
 *
 * This is NOT the guarded range above.  The ROM announces a range on every
 * chain -- PPL's on 15 and 16, SPTM's on 17 -- because the interrupt gate
 * needs it in all of them, so `ohv_monitor_told()` is true everywhere and
 * cannot tell them apart.  Measured: a 19A348 boot announces
 * 0xfffffff02cb60000..0xfffffff02cb88000.
 *
 * The ROM's `s3_6_c15_c15_7` write is the one that separates them: its
 * handoff writes it under `cbz w22, 2f`, so only a chain with a monitor sends
 * it, and the same `w22` is what makes it return to EL1 rather than EL2 when
 * there is none.
 */
std::atomic<bool> g_monitor_next{false};

/*
 * The guest has stopped being a hypervisor, for the whole machine.
 *
 * Only the core that executes the ROM's handoff ERET goes through the
 * emulation that clears HCR_EL2.NV; every other vCPU is created with it set
 * -- `g_vm_el2` -- and nothing lowers it.  Measured on 19A348 with the kernel
 * entered at EL1: `vcpu 0 nv=0 guest_at_el2=0` against `vcpu 1..5 nv=1
 * guest_at_el2=1`.  So cpu0 ran as an EL1 kernel while every secondary core
 * believed it was at EL2, and the first ERET one of them made to what it
 * thought was its own level set PSTATE.IL -- `panic(cpu 1): Illegal
 * instruction set exception, class=14 @sleh.c:867`.
 *
 * Which level the kernel runs at is a property of the boot, not of a core, so
 * it is recorded here and applied to each vCPU on its way in.
 */
std::atomic<bool> g_guest_left_el2{false};

/* Entries at which the guest's virtual timer was already due. */
static std::atomic<unsigned> g_vfire{0};

/*
 * More than one range, because the guarded code is in more than one place.
 *
 * Slot 0 is what the boot ROM says at the handoff.  Slot 1 is the page the
 * guest itself points GXF_ENTRY_EL1 at, learned from the write, because that
 * is guarded code the ROM cannot name: on 19A348 the entry handler is
 * _gxf_ppl_entry_handler at 0xfffffff0085d6d98, which is in __TEXT_EXEC rather
 * than __PPLTEXT, and so are ppl_exit and the four fleh_*_from_ppl handlers
 * around it.  All of them live in one 4 KiB page, so the page containing the
 * entry is the whole block.
 *
 * Being a little over-inclusive costs an interrupt a few instructions of
 * delay.  Being under-inclusive costs the boot: the level is delivered while
 * the guest is guarded, the hardware here sends it to VBAR_EL1 instead of
 * VBAR_GL, and the layer never recovers.
 */
static void ohv_guard_set(unsigned slot, uint64_t lo, uint64_t hi) {
    if (slot >= OHV_GUARD_RANGES) {
        return;
    }
    g_guard_hi[slot].store(0, std::memory_order_relaxed);
    g_guard_lo[slot].store(lo, std::memory_order_relaxed);
    g_guard_hi[slot].store(hi, std::memory_order_relaxed);
}

/*
 * Remember a guarded page without forgetting the last one.
 *
 * The guest points GXF_ENTRY_EL1 at more than one place and moves it back and
 * forth.  Measured on 19A348, fifteen writes in one boot alternating between
 * two pages:
 *
 *     0xfffffff02cb85a1c -> page 0xfffffff02cb85000   (inside the ROM's range)
 *     0xfffffff02b0aed98 -> page 0xfffffff02b0ae000   (_gxf_ppl_entry_handler,
 *                                                      and NOT in that range)
 *
 * Writing them both into slot 1 means only whichever was written last is
 * guarded, so for most of the boot the page holding `ppl_exit`,
 * `preempt_underflow` and the four `fleh_*_from_ppl` handlers is not marked at
 * all -- which is exactly the under-inclusive case the comment above warns
 * about: a level delivered while the guest is guarded goes to VBAR_EL1
 * instead of VBAR_GL and the layer never recovers.  What that looked like:
 * `ppl_exit` running on the user's register file (x16 still the syscall
 * number, SP still the user stack) and panicking in its own underflow check,
 * "Preemption count negative on thread", three runs at the same
 * instruction.
 *
 * There are four slots and only two were ever used.  Slot 0 stays the ROM's.
 */
static bool ohv_pc_guarded(uint64_t pc);

static void ohv_guard_add(uint64_t lo, uint64_t hi) {
    if (lo == 0 || hi <= lo || ohv_pc_guarded(lo)) {
        return;
    }
    for (unsigned i = 1; i < OHV_GUARD_RANGES; i++) {
        if (g_guard_lo[i].load(std::memory_order_relaxed) == 0) {
            ohv_guard_set(i, lo, hi);
            return;
        }
    }
    /*
     * Out of slots.  Replacing the last is what this used to do to slot 1 on
     * every write, so it is no worse -- and it has not happened: two pages
     * against three free slots.
     */
    ohv_guard_set(OHV_GUARD_RANGES - 1, lo, hi);
}

static bool ohv_monitor_told(void) {
    for (unsigned i = 0; i < OHV_GUARD_RANGES; i++) {
        uint64_t a = g_guard_lo[i].load(std::memory_order_relaxed);
        uint64_t b = g_guard_hi[i].load(std::memory_order_relaxed);

        if (a != 0 && b > a) {
            return true;
        }
    }
    return false;
}

static bool ohv_pc_guarded(uint64_t pc) {
    for (unsigned i = 0; i < OHV_GUARD_RANGES; i++) {
        uint64_t a = g_guard_lo[i].load(std::memory_order_relaxed);
        uint64_t b = g_guard_hi[i].load(std::memory_order_relaxed);

        if (a != 0 && b > a && pc >= a && pc < b) {
            return true;
        }
    }
    return false;
}

/*
 * The same question, asked of slot 0 alone: is this pc the *monitor's* text?
 *
 * The two kinds of slot are not interchangeable.  Slot 0 is what the ROM
 * announced at the handoff -- the monitor's own text, PPL's on 15 and 16,
 * SPTM's on 17 and 27.  Slots 1 and up are pages learned from the guest's
 * GXF_ENTRY_EL1 writes, and a page is 4 KiB of whatever the linker put there:
 * on 19A348 the entry handler `_gxf_ppl_entry_handler` shares its page with
 * `ppl_exit`, the four `fleh_*_from_ppl` handlers **and the unguarded wrapper
 * `_gxf_ppl_enter` that calls into all of them**.
 *
 * Over-inclusiveness is free for the interrupt gate -- a level held a few
 * instructions longer -- which is why that keeps using every slot.  It is not
 * free for GXF_STATUS_EL1, because XNU polls that register to confirm it has
 * *left* the guarded layer:
 *
 *     mrs x14, GXF_STATUS_EL1
 *     cmp x14, #0
 *     b.ne .
 *
 * and on 19A348 that poll is at `_gxf_ppl_enter+0x88`, inside the learned
 * page.  Answered from every slot it reads one forever and the boot core spins
 * there: measured 2026-09-28, and again with nested inherit off
 * (ohv_set_nested_inherit(false)), the whole kernel era stopping four lines after
 * "CTRR (MMU) ... setting lockdown" with cpu0 on that instruction and cpu1..5
 * still in their reset poll.  Slot 0 is `0xfffffff02cb60000..0xfffffff02cb88000`
 * on that boot and the wrapper is nowhere near it, so asking slot 0 answers
 * zero there and one inside PPL, which is what the register means.
 */
static bool ohv_pc_in_monitor(uint64_t pc) {
    uint64_t a = g_guard_lo[0].load(std::memory_order_relaxed);
    uint64_t b = g_guard_hi[0].load(std::memory_order_relaxed);

    return a != 0 && b > a && pc >= a && pc < b;
}

static hv_return_t sysreg_access(hv_vcpu_t id, uint16_t enc, uint64_t *value, bool write);


/*
 * Stage-1 TLB maintenance, replayed into every address space the VM runs in.
 *
 * Each vCPU of a guest hypervisor is put in its own nested address space
 * (see hv_vcpu_create below), and each space is its own stage-2 pmap with its
 * own VMID (osfmk/arm64/hv/hv_space.c: _hv_space_create -> pmap_create_options
 * with PMAP_CREATE_STAGE2).  A `tlbi vae1is` the guest executes natively is
 * broadcast to every core -- for the *issuing vCPU's VMID only*.  The same
 * guest VA cached on another vCPU, under another VMID, stays as it was.  The
 * guest kernel's TLB shootdown, which assumes one VMID for the machine, then
 * silently does nothing for five of its six cores.
 *
 * Measured on a frozen guest: a
 * kmem_alloc'd buffer at a kernel VA that had just been a UPL mapping was
 * written through the old translation, 4 KiB at a time (the nested spaces are
 * 4 KiB-granule, so the combined TLB entries are 4 KiB), and the bytes landed
 * in the previous pages -- page-cache pages of other files.  That is the
 * "memory corruption" panic family: zone, decmpfs, code-signature, ledger.
 *
 * The kernel documents the contract (hv_interface.h, hv_vm_stage1_tlb_op_t):
 * a VMM whose guest hypervisor "is expected to be running in a different
 * space than the stage 1 context targeted by these instructions" sets
 * HCR_EL2.TTLB, takes the trap, and asks the kernel to perform the operation
 * in each space with TRAP_HV_VM_STAGE1_TLB_OP; pmap_stage1_tlb_op_internal
 * switches VTTBR to that space and executes the instruction.  Apple's
 * framework does this and calls it the "tlbi workaround".  This is ours.
 *
 * The op numbers are the kernel's PMAP_S1_TLB_OP_ order (pmap.h), which
 * hv_interface.h static-asserts against HV_VM_TLB_OP_.  They are the
 * inner-shareable forms; the outer-shareable and non-shareable encodings the
 * guest may use are mapped onto them, which invalidates at least as much.
 * EL2-encoded operations (op1 == 4) name the guest hypervisor's own regime,
 * which under NV is the EL1 regime the hardware is walking, so they are
 * mapped the same way; anything without a stage-1 counterpart (IPAS2*, ALLE1,
 * VMALLS12E1) becomes VMALLE1IS, which is more than was asked and never less.
 *
 * TTLB follows HCR_EL2.NV: it is set only on a vCPU that is *not* a guest
 * hypervisor.  A monitor at guest EL2 -- SPTM on 21A329 -- issues its TLBIs
 * from GL2, and this machine has no third guarded level to carry: a
 * synchronous exit taken there returns to plain EL2, the SPRR permissions
 * change under the monitor's feet, its next write to a page table faults into
 * XNU's vector, XNU hands back with genter #1 and SPTM's depth guard
 * (`[TPIDR_GL2+0x30]` must be 0) spins for good.  Measured 2026-09-19 on
 * 21A329: the first kernel-PC exit was the TLBI VAALE1IS at 0xfffffff04bbca42c
 * and the core never came back.  PPL on 19A348 is at GL1, which the hardware
 * banks, so a kernel with NV clear can be trapped and resumed.  Until the
 * guarded level can be banked from here ([[vmm-can-bank-the-guarded-level]]),
 * a guest hypervisor's TLBIs stay native -- and the cross-VMID staleness with
 * them; that chain is not fixed by this, only left as it was.
 *
 * ohv_set_tlbi_replay(false) turns this off -- the vCPUs then run with TTLB clear and
 * every TLBI is native, which is the behaviour that produced the corruption.
 * OHV_TRACE_TLBI prints the first replay and every 100,000th.
 */
enum : uint64_t {
    kS1TlbAside1is = 0, kS1TlbVae1is, kS1TlbVaae1is, kS1TlbVaale1is,
    kS1TlbVale1is, kS1TlbVmalle1is, kS1TlbRvae1is, kS1TlbRvaae1is,
    kS1TlbRvaale1is, kS1TlbRvale1is,
};

static const unsigned kTlbiSpacesMax = 16;
static std::atomic<uint64_t> g_tlbi_spaces[kTlbiSpacesMax];
static std::atomic<unsigned> g_tlbi_space_count{0};

/* Record an address space a vCPU runs in (0 is the VM's default space). */
static void ohv_tlbi_note_space(uint64_t asid) {
    unsigned n = g_tlbi_space_count.load();

    for (unsigned i = 0; i < n; i++) {
        if (g_tlbi_spaces[i].load() == asid) return;
    }
    if (n < kTlbiSpacesMax) {
        g_tlbi_spaces[n].store(asid);
        g_tlbi_space_count.store(n + 1);
    }
}

/*
 * One nested address space for the whole VM -- the default since 2026-09-23.
 *
 * Every vCPU joins nested space 0, so the VM has one VMID, the guest's own
 * `tlbi ...is` is broadcast by hardware to every core, and the replay below
 * is not needed at all.  One space per vCPU is what produced the long-chased
 * "memory corruption" family: a stage-1 TLBI reached only the issuing vCPU's
 * VMID, every other core kept a combined entry the page tables no longer
 * held, and a write went to the physical page the VA used to name.
 *
 * The reason recorded for one space per vCPU does not survive a read of the
 * kernel: the page the guest's EL2 registers are redirected to is
 * `vcpu->kif->rw.vncr`, per vCPU and named by a host address (hv_vcpu.c
 * programs VNCR_EL2.BADDR at every entry), and this library's own EL2
 * register emulation writes that same per-vCPU page.  Nothing EL2 lives in
 * the space.  The symptom that shelved it -- the second core's VBAR_EL2 write
 * lost, its exception landing at zero -- was measured while the control block
 * was still being written at the wrong offset, and did not return when this
 * was re-measured on 21A329.
 *
 * Measured, 2026-09-23 on 21A329: four guest restores out of
 * four reached `CHECKPOINT END [0x06A6] install_splat` with zero
 * `digest mismatch`, against a 3-in-4 failure rate before -- and at the same
 * speed, ASR 10%->90% in 287-308 s against 294.9 s, so a timing race is not
 * merely being hidden.  21A329 is the chain that could not be fixed by the
 * replay at all, because its monitor is at GL2 and TTLB must stay clear
 * there; one space fixes it without trapping anything.
 *
 * ChefKissInc/Inferno, which runs the same class of guest, never creates a
 * nested address space at all -- one VMID by construction.  One space is the
 * configuration, not the workaround.
 *
 * ohv_set_one_space(false) goes back to one space per vCPU, which is the behaviour
 * that produced the corruption; it is kept for A/B only.
 */
static bool ohv_tlbi_replay_on(void) {
    /*
     * With every vCPU in one space there is one VMID, the guest's own
     * broadcast reaches every core, and there is nothing to replay; trapping
     * would only add the exits (and, on a monitor chain, the guarded-level
     * problem above).  ohv_set_tlbi_replay(true) forces it on regardless, for A/B.
     */
    if (ohv_cfg_given(tlbi_replay)) {
        return ohv_cfg(tlbi_replay);
    }
    return !ohv_cfg(one_space);
}

static uint64_t ohv_tlbi_kernel_op(unsigned op1, unsigned crm, unsigned op2) {
    /* CRm 2/5/6 are the R*IS / R*OS / R* (range) forms. */
    bool ranged = (crm == 2 || crm == 5 || crm == 6);

    if (op1 == 0) {
        if (ranged) {
            switch (op2) {
            case 1: return kS1TlbRvae1is;
            case 3: return kS1TlbRvaae1is;
            case 5: return kS1TlbRvale1is;
            case 7: return kS1TlbRvaale1is;
            }
        } else {
            switch (op2) {
            case 0: return kS1TlbVmalle1is;
            case 1: return kS1TlbVae1is;
            case 2: return kS1TlbAside1is;
            case 3: return kS1TlbVaae1is;
            case 5: return kS1TlbVale1is;
            case 7: return kS1TlbVaale1is;
            }
        }
    } else if (op1 == 4 && crm != 0 && crm != 4) {   /* not IPAS2* */
        if (ranged) {
            switch (op2) {
            case 1: return kS1TlbRvae1is;               /* RVAE2*  */
            case 5: return kS1TlbRvale1is;              /* RVALE2* */
            }
        } else {
            switch (op2) {
            case 1: return kS1TlbVae1is;                /* VAE2*   */
            case 5: return kS1TlbVale1is;               /* VALE2*  */
            }
        }
    }
    return kS1TlbVmalle1is;
}

static void ohv_tlbi_replay(uint64_t vcpu_id, unsigned op1, unsigned crm, unsigned op2, uint64_t param) {
    static std::atomic<uint64_t> replays{0};
    static std::atomic<unsigned> failures{0};
    uint64_t op = ohv_tlbi_kernel_op(op1, crm, op2);
    unsigned n = g_tlbi_space_count.load();
    uint64_t done = replays.fetch_add(1) + 1;

    for (unsigned i = 0; i < (n ? n : 1u); i++) {
        ohv_vm_stage1_tlb_op_t a{ n ? g_tlbi_spaces[i].load() : 0, op, param };
        hv_return_t r = ohv_raw_trap(OHV_TRAP_VM_STAGE1_TLB_OP, &a);

        if (r != HV_SUCCESS && failures.fetch_add(1) < 8) {
            fprintf(stderr, "[ohv] tlbi replay op %llu asid %#llx param %#llx"
                            " refused (%#x)\n",
                    (unsigned long long)op, (unsigned long long)a.asid,
                    (unsigned long long)param, r);
        }
    }
    if (ohv_trace_on(OHV_TRACE_TLBI) && (done == 1 || done % 100000 == 0)) {
        fprintf(stderr, "[ohv] tlbi replay #%llu: vcpu %llu op1=%u crm=%u"
                        " op2=%u -> op %llu in %u space%s\n",
                (unsigned long long)done, (unsigned long long)vcpu_id,
                op1, crm, op2, (unsigned long long)op, n ? n : 1u,
                n == 1 ? "" : "s");
    }
}

/*
 * The fast IPI, carried between the vCPUs here instead of by the VMM.
 *
 * Each one used to be four exits into QEMU, every one of them queued on its
 * big lock: the IPI_RR write on the sender, the kick that brings the target
 * out of the guest, and the target's IPI_SR read and acknowledging write.
 * None of that touches a device -- it is one bit of one core's state, set by
 * another core and cleared by the first -- so with ohv_set_ipi_inline() on
 * the bit lives in the target's VcpuSlot and is part of its virtual FIQ,
 * which ohv_set_fiq_level() works out on every entry.
 *
 * Delivery is the part that has to be right.  A target inside hv_vcpu_run()
 * is sent OHV_TRAP_VCPU_RUN_CANCEL, which the kernel latches in its
 * `notified` word whether or not the vCPU is in the guest at that instant
 * (`_hv_vcpu_run_return`), so its next entry comes straight back out with
 * reason 0 and the level goes up on the way in again: no window.  A target
 * outside it is the VMM's -- most often halted on a WFI -- and only the VMM
 * can wake it, so the wake handler asks it to.  The two sides of that
 * hand-over are a store and a load each: the sender stores the bit and loads
 * `in_run`, the target stores `in_run` and (in the VMM, before it sleeps)
 * loads the bit through ohv_vcpu_interrupt_pending().  All four are
 * sequentially consistent, so at least one side sees the other.
 *
 * The rules are QEMU's own (hvf_apple_ipi_send): a core is addressed by its
 * affinity and the local form takes the sender's cluster; a retract clears a
 * pending bit and leaves the line for the target to settle on its way back
 * in; the deferred kinds are delivered at once, which only ever wakes a core
 * that was willing to be woken.
 */
#define OHV_SEL_IPI_RR_LOCAL   0xef80u   /* s3_5_c15_c0_0 */
#define OHV_SEL_IPI_RR_GLOBAL  0xef81u   /* s3_5_c15_c0_1 */
#define OHV_SEL_IPI_SR         0xef89u   /* s3_5_c15_c1_1 */
#define OHV_IPI_RR_CORE        0x0000000full
#define OHV_IPI_RR_CLUSTER     0x00ff0000ull
#define OHV_IPI_RR_RETRACT     1u
#define OHV_IPI_SR_PENDING     1ull

static std::atomic<ohv_vcpu_wake_fn> g_wake_fn{nullptr};
static std::atomic<void *> g_wake_opaque{nullptr};

static void ohv_set_fiq_level(VcpuSlot *s);
static uint32_t ohv_timer_due_bits(VcpuSlot *s, uint64_t now);

static bool ohv_ipi_pending(VcpuSlot *s) {
    return (s->ipi_sr.load(std::memory_order_seq_cst) &
            OHV_IPI_SR_PENDING) != 0;
}

static void ohv_ipi_notify(VcpuSlot *t) {
    ohv_raw_trap(OHV_TRAP_VCPU_RUN_CANCEL, (void *)(uintptr_t)(1ull << t->id));
    if (!t->in_run.load(std::memory_order_seq_cst)) {
        ohv_vcpu_wake_fn fn = g_wake_fn.load(std::memory_order_acquire);

        if (fn != nullptr) {
            fn(t->id, g_wake_opaque.load(std::memory_order_relaxed));
        }
    }
}

static void ohv_ipi_send(VcpuSlot *s, uint64_t val, bool global) {
    unsigned type = (unsigned)((val >> 28) & 3u);
    uint64_t want = val & OHV_IPI_RR_CORE;
    VcpuSlot *t = nullptr;

    if (global) {
        want |= ((val & OHV_IPI_RR_CLUSTER) >> 16) << 8;
    } else {
        want |= s->ipi_aff.load(std::memory_order_relaxed) & 0xff00;
    }
    for (uint64_t i = 0; i < kMaxVcpuIds; i++) {
        if (g_vcpus[i].ipi_aff.load(std::memory_order_acquire) == want) {
            t = &g_vcpus[i];
            break;
        }
    }
    if (t == nullptr) {
        if (ohv_trace_on(OHV_TRACE_IPI)) {
            fprintf(stderr, "[ohv] ipi from vcpu %llu: %s %#llx names no"
                    " core\n", (unsigned long long)s->id,
                    global ? "global" : "local", (unsigned long long)val);
        }
        return;
    }
    if (type == OHV_IPI_RR_RETRACT) {
        t->ipi_sr.fetch_and(~OHV_IPI_SR_PENDING, std::memory_order_seq_cst);
        return;
    }
    t->ipi_sr.fetch_or(OHV_IPI_SR_PENDING, std::memory_order_seq_cst);
    if (ohv_trace_on(OHV_TRACE_IPI)) {
        fprintf(stderr, "[ohv] ipi vcpu %llu -> vcpu %llu type %u%s\n",
                (unsigned long long)s->id, (unsigned long long)t->id, type,
                t == s ? " (self)" :
                t->in_run.load(std::memory_order_relaxed) ? "" : " (wake)");
    }
    if (t == s) {
        ohv_set_fiq_level(s);
        return;
    }
    ohv_ipi_notify(t);
}

/* One of the fast IPI's registers, on `s`'s own thread. */
static bool ohv_ipi_access(VcpuSlot *s, unsigned enc, uint64_t *v, bool write) {
    switch (enc) {
    case OHV_SEL_IPI_RR_LOCAL:
    case OHV_SEL_IPI_RR_GLOBAL:
        if (write) {
            ohv_ipi_send(s, *v, enc == OHV_SEL_IPI_RR_GLOBAL);
        } else {
            *v = 0;                 /* write-only in hardware */
        }
        return true;
    case OHV_SEL_IPI_SR:
        if (write) {
            /* Acknowledged by writing the bits back. */
            s->ipi_sr.fetch_and(~*v, std::memory_order_seq_cst);
            ohv_set_fiq_level(s);
        } else {
            *v = s->ipi_sr.load(std::memory_order_seq_cst);
        }
        return true;
    default:
        return false;
    }
}

/*
 * Whether an exit can be finished here without stranding the VMM's FIQ line.
 *
 * QEMU composes that line itself -- the guest's timers, which it reads from
 * ohv_vcpu_timer_state() on every exit it sees, and a wake latch it holds
 * until the core has run again -- and it can only move the line when an exit
 * reaches it.  An exit finished here while the line is up, or while the
 * timers no longer say what QEMU last read, is one QEMU needed: the edge then
 * waits for whatever exit happens to reach it next.  So the classes taken
 * over from QEMU here -- the fast IPI's registers and WFE -- are taken only
 * while there is nothing on the line and nothing new to put on it, and
 * otherwise go out exactly as they always did.
 */
static bool ohv_vmm_line_settled(VcpuSlot *s) {
    return !s->vmm_fiq &&
           ohv_timer_due_bits(s, mach_absolute_time()) == s->timer_seen;
}

static bool service_nv2_access(VcpuSlot *s, uint64_t esr) {
    unsigned op0 = (unsigned)((esr >> 20) & 3);
    unsigned op2 = (unsigned)((esr >> 17) & 7);
    unsigned op1 = (unsigned)((esr >> 14) & 7);
    unsigned crn = (unsigned)((esr >> 10) & 0xf);
    unsigned rt  = (unsigned)((esr >> 5) & 0x1f);
    unsigned crm = (unsigned)((esr >> 1) & 0xf);
    bool read = (esr & 1) != 0;
    unsigned enc = (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2;

    /*
     * ACNTVCT_EL0 and ACNTPCT_EL0 -- s3_4_c15_c10_6 and _5 -- decoded before
     * anything else, because they are the busiest register on the machine.
     *
     * This is XNU's clock: `ml_get_hwclock` reads ACNTVCT_EL0 and every
     * `mach_absolute_time`, scheduler decision, lock timeout and trace point
     * goes through it.  Measured with OHV_TRACE_REASONS on the installed
     * chain, **267,000 a second** -- level with the guarded bank and ahead of
     * the guest's own timer registers.  It was decoded *last*, in the general
     * Apple-IMPDEF block at the end of this function, behind fourteen other
     * tests.
     *
     * It cannot be made native: `HACR_EL2.TACNT` is in XNU's *fixed*
     * capability set and is in no overridable list at any ISA tier, and its
     * MSR handler has no case for these encodings, so every read is a full
     * kernel round trip into here whatever the VMM asks for.  Answering it
     * first is the whole of what this side can do about it.
     *
     * The general block still carries the same case for any other CRn, so
     * nothing that used to be answered stops being answered.
     */
    if (op0 == 3 && op1 == 4 && crn == 15 && crm == 10 &&
        (op2 == 5 || op2 == 6)) {
        ohv_rw_page_head_t *rw = ohv_rw(s->ctx);

        if (read) {
            uint64_t v = mach_absolute_time() -
                ohv_rw_controls(s->ctx)->virtual_timer_offset;

            if (rt != 31) rw->regs.x[rt] = v;
        }
        rw->regs.pc += 4;
        return true;
    }

    /*
     * The guarded bank, answered here instead of out in the VMM.
     *
     * `s3_6_c15_c10_*` is the busiest thing on this machine by a factor of
     * three: 20,824 guarded transitions a second at eight register accesses
     * each, `_3` and `_4` at 62,000 apiece, 167,000 of the 430,000 exits a
     * second.  Every one of them is a full round trip out to QEMU --
     * `hvf_sysreg_forward_read`/`_write` -- taken with the Big QEMU Lock held,
     * and measurement says the cost is the round trip itself: batching the
     * `sync_before` Mach trap to once per exit (`ohv_set_sync_once`) moved the
     * guest's share of vCPU time by nothing at all.  So the only thing left is
     * not to leave the library.
     *
     * This was tried before and the kernel rebooted inside four hundred
     * console lines, for a reason that is now fixed rather than worked
     * around: the shared copy read **zero**, because nothing was carrying the
     * bank.  `_hv_load_guest_gxf_regs` only runs once the host kernel has
     * `ARM_GUEST_STATE_GXF` in `state_used`, and it never claimed it here --
     * `ohv_set_claim_state()` now puts the bit in `rw.state_dirty`, which
     * `hv_vcpu_run` folds into `state_used` on the way in.  **This switch is
     * only meaningful with that one on**; alone it answers from the same zeros
     * that broke it the first time.
     *
     * SP_GL1 (`crm == 10 && op2 == 0`) is left to the VMM deliberately: QEMU
     * mirrors it onto SP_EL0, standing in for a bank the hardware is not
     * maintaining, and that mirror is not reproduced here.
     */
    /*
     * On by default; `ohv_set_bank_inline(false)` sends it all back out to the VMM.
     *
     * The same argument covers every class `ohv_set_claim_state()` has the kernel
     * carrying, not just the GL banks:
     *
     *   op1=6 crm 10/11   the GL1 and GL2 banks          (ARM_GUEST_STATE_GXF)
     *   op1=6 crm 1       SPRR_CONFIG/PPERM/UPERM/SH     (…_SPRR)
     *   op1=4 c1_3 c1_4   AMX_STATE_T / AMX_CONFIG       (…_AMX)
     *   op1=4 c15_6       JCTL_EL0                       (…_JITBOX)
     *
     * Measured after the banks went inline, per second reaching QEMU:
     * `s3_6_c15_c1_6` 62,957 · `s3_6_c15_c1_5` 8,375 · `s3_4_c15_c15_6` 8,372
     * · `s3_4_c15_c1_3`/`_4` 4,187 each -- SPRR alone is the busiest thing
     * left on the machine.
     *
     * Two exclusions, both because something else already owns the encoding:
     * `SP_GL1` (crm 10, op2 0), which QEMU mirrors onto SP_EL0, and
     * `GXF_CONFIG_EL1` (crm 1, op2 2), which the block above answers and uses
     * to learn the guarded band from GXF_ENTRY.
     */
    /*
     * The fast IPI's registers, when this library carries the IPI -- see
     * ohv_ipi_send().  IPI_CR is not among them: it is only ever written and
     * read back, which the block below does out of the impdef shadow.  Not
     * settled, they go to the VMM, which hands them back through
     * hv_vcpu_get/set_sys_reg() and so to the same place.
     */
    if (op0 == 3 && op1 == 5 && crn == 15 &&
        ((crm == 0 && op2 <= 1) || (crm == 1 && op2 == 1)) &&
        ohv_cfg(ipi_inline) && ohv_vmm_line_settled(s)) {
        ohv_rw_page_head_t *rw = ohv_rw(s->ctx);
        uint64_t v = (rt == 31) ? 0 : rw->regs.x[rt];

        ohv_ipi_access(s, enc, &v, !read);
        if (read && rt != 31) rw->regs.x[rt] = v;
        rw->regs.pc += 4;
        return true;
    }

    /*
     * APSTS_EL1, read: 1, which is all QEMU ever answered (hvf_sysreg_read,
     * "report the wait as over") -- and QEMU answered it under its big lock,
     * for the register that with GXF_STATUS_EL1 was the busiest single one
     * left reaching it.  A write is not this: it goes through the block below
     * to sysreg_access(), the same place QEMU's forward took it.
     */
    if (op0 == 3 && op1 == 6 && crn == 15 && crm == 12 && op2 == 4 && read &&
        ohv_cfg(bank_inline)) {
        if (rt != 31) ohv_rw(s->ctx)->regs.x[rt] = 1;
        ohv_rw(s->ctx)->regs.pc += 4;
        return true;
    }

    if (ohv_cfg(bank_inline) && op0 == 3 &&
        (crn == 15 || crn == 11) &&
        /*
         * Everything the VMM would only have forwarded.
         *
         * `hvf_sysreg_is_impdef` is exactly "op0 3, CRn 11 or 15", and for all
         * but a handful of those `hvf_sysreg_read`/`_write` fall straight
         * through to `hvf_sysreg_forward_read`/`_write`, which calls
         * `hv_vcpu_get/set_sys_reg` -- back into this library, by way of a
         * userspace round trip taken with the Big QEMU Lock held.  Answering
         * here skips the round trip and the lock; the answer is the same slot
         * either way.
         *
         * The exclusions are the ones QEMU does something of its own with, or
         * that a block further down in this function already owns:
         *
         *   op1 5, IPI_RR_LOCAL/GLOBAL, IPI_SR, IPI_CR  `hvf_apple_ipi_sysreg`,
         *                              unless ohv_set_ipi_inline() (above)
         *   op1 6 c10_0  SP_GL1        QEMU mirrors it onto SP_EL0
         *   op1 6 c8_0   GXF_STATUS    QEMU answers from apple_gxf_enabled
         *   op1 6 c12_4  APSTS_EL1     reads answered 1 above, as QEMU did
         *   op1 6 c1_2 / c8_1 / c8_2   the TGXF trio, below -- c8_1 is where
         *                              the guarded band is learned
         *   op1 6 c2_7   AMXIDR_EL1, below
         *   op1 6 c15_*  the ROM's handoff words, below; no hardware has them
         *   op1 4 c10_5/_6  ACNTPCT/ACNTVCT, below
         *
         * Anything `sysreg_lookup` has no descriptor for falls through to the
         * VMM as before, which is what keeps this safe: a register this
         * library does not model is still the VMM's.
         */
        !(op1 == 5 && ((crm == 0 && op2 <= 1) || (crm == 1 && op2 == 1) ||
                       (crm == 3 && op2 == 1 && !ohv_cfg(ipi_inline)))) &&
        !(op1 == 6 && crm == 10 && op2 == 0) &&
        !(op1 == 6 && crm == 8) &&
        !(op1 == 6 && crm == 12 && op2 == 4 && read) &&
        !(op1 == 6 && crm == 1 && op2 == 2) &&
        !(op1 == 6 && crm == 2 && op2 == 7) &&
        !(op1 == 6 && crm == 15) &&
        !(op1 == 4 && crm == 10 && (op2 == 5 || op2 == 6)) &&
        /*
         * CTRR, whose block is further down and must have it.
         *
         * The kernel's read-only region is one piece of silicon with two
         * encodings: SPTM programs it as CTRR_A_LWR/UPR_EL1, s3_4_c15_c2_3
         * and _4, and XNU reads it back as CTRR_A_LWR/UPR_EL2, s3_4_c15_c6_4
         * and _5.  Answered here they are two unrelated slots, so what SPTM
         * wrote is never what XNU reads and machine_init stashes a range of
         * nothing:
         *
         *     zalloc_ro_mut failed: source (...) not from RO zone map (...),
         *     current stack (...) or const memory (phys 0 - 0)
         *
         * with pid 1 as the thread, because every zalloc_ro_mut out of the
         * kernel's own const data is refused while that range is empty.
         *
         * This is the second time that fold has been shadowed by a block
         * above it, so: the fold is the owner of these six encodings, and
         * anything that claims op0 3 CRn 15 wholesale has to say so here.
         */
        !(op1 == 4 && ((crm == 2 && op2 >= 2 && op2 <= 5) ||
                       (crm == 6 && (op2 == 4 || op2 == 5))))) {
        ohv_rw_page_head_t *rw = ohv_rw(s->ctx);
        uint64_t v = 0;

        if (read) {
            if (sysreg_access(s->id, (uint16_t)enc, &v, false) != HV_SUCCESS) {
                return false;       /* let the VMM have it */
            }
            if (rt != 31) rw->regs.x[rt] = v;
        } else {
            v = (rt == 31) ? 0 : rw->regs.x[rt];
            if (sysreg_access(s->id, (uint16_t)enc, &v, true) != HV_SUCCESS) {
                return false;
            }
        }
        rw->regs.pc += 4;
        return true;
    }

    /*
     * AMXIDR_EL1, which the kernel insists on being told about.
     *
     * The Apple hidden-ID registers always trap -- HACR_EL2's THIDDVF,
     * THIDCPU, THIDLLC, THIDAMX and THIDDPC are in the kernel's fixed set --
     * so this one is the VMM's to answer, and XNU does not treat it as
     * optional.  configure_misc_apple_regs reads it and panics two ways: with
     * any of bits 5..15 set it is "Unknown AMX feature ID bit has been set",
     * and with bits 0..3 all clear it is "AMXIDR_EL1 doesn't advertise any
     * known ...".  Exactly one of the low four says which version, counting
     * downward from bit 3, so the lowest that satisfies it is one.
     *
     * Unanswered, the read takes an exception the kernel has no handler for
     * and the machine parks on its own synchronous vector at EL1 -- measured,
     * three thousand entries at the same instruction without retiring it.
     */
    if (op0 == 3 && op1 == 6 && crn == 15 && crm == 2 && op2 == 7 && read) {
        uint64_t v = ohv_cfg(amxidr);
        ohv_rw_page_head_t *rw = ohv_rw(s->ctx);

        if (rt != 31) rw->regs.x[rt] = v;
        rw->regs.pc += 4;
        return true;
    }

    /*
     * The boot ROM's handoff saying the monitor runs next.
     *
     * s3_6_c15_c15_7 is not a register anything implements; it is a word our
     * own handoff writes at the one instant that knows SPTM is about to
     * start.  Arming NV here is what makes SPTM's guarded ERET trap, which is
     * the only chance to mirror ELR_GL1/SPSR_GL1 onto the pair a hardware
     * return actually consumes.  Left to chance it works only when the
     * guest's last transition happened to leave NV set.
     */
    /*
     * The boot ROM naming the guarded range, in two writes: the first address
     * and then the length after it.  Neither register is anything the hardware
     * implements; they are words our own handoff writes at the one instant
     * that knows what runs next and where it lives.
     *
     * The length arrives second and is what completes the pair, so a range is
     * either whole or absent -- a half-written one would read as a monitor
     * that starts somewhere and never ends.
     */
    if (op0 == 3 && op1 == 6 && crn == 15 && crm == 15 &&
        (op2 == 6 || op2 == 5) && !read) {
        uint64_t v = (rt == 31) ? 0 : ohv_rw(s->ctx)->regs.x[rt];

        if (op2 == 6) {
            g_guard_hi[0].store(0, std::memory_order_relaxed);
            g_guard_lo[0].store(v, std::memory_order_relaxed);
        } else {
            uint64_t lo = g_guard_lo[0].load(std::memory_order_relaxed);

            g_guard_hi[0].store(lo != 0 && v != 0 ? lo + v : 0, std::memory_order_relaxed);
        }
        if (ohv_trace_on(OHV_TRACE_BAND)) {
            fprintf(stderr, "[ohv] handoff: guarded range %#llx .. %#llx\n",
                    (unsigned long long)g_guard_lo[0].load(
                        std::memory_order_relaxed),
                    (unsigned long long)g_guard_hi[0].load(
                        std::memory_order_relaxed));
        }
        ohv_rw(s->ctx)->regs.pc += 4;
        return true;
    }
    if (op0 == 3 && op1 == 6 && crn == 15 && crm == 15 && op2 == 7 && !read) {
        g_monitor_next.store(true, std::memory_order_relaxed);
        /*
         * Every core, not only this one: on a chain with a monitor the
         * secondaries are released into it and need the same arrangement.
         * They are all still parked here, which is what makes writing their
         * pages from this thread safe.
         */
        for (uint64_t i = 0; i < kMaxVcpuIds; i++) {
            VcpuSlot *o = &g_vcpus[i];

            if (o->used && o != s && o->ctx != nullptr) {
                ohv_rw_controls(o->ctx)->hcr_el2 |= OHV_HCR_NV | OHV_HCR_NV2;
                mark_dirty(o->ctx, OHV_STATE_CONTROLS);
                o->guest_at_el2 = true;
            }
        }
        ohv_rw_controls(s->ctx)->hcr_el2 |= OHV_HCR_NV;
        mark_dirty(s->ctx, OHV_STATE_CONTROLS);
        s->guest_at_el2 = true;
        if (ohv_trace_on(OHV_TRACE_ERET)) {
            fprintf(stderr, "[ohv] handoff: monitor next, NV armed, hcr %#llx\n",
                    (unsigned long long)ohv_rw_controls(s->ctx)->hcr_el2);
        }
        ohv_rw(s->ctx)->regs.pc += 4;
        return true;
    }

    /*
     * The three registers HACR_EL2.TGXF actually covers.
     *
     * It is not the guarded bank -- ELR_GL1 and SPSR_GL1 are never trapped by
     * anything, so there is nowhere to see SPTM set them.  What TGXF traps is
     * GXF_CONFIG_EL1, GXF_ENTRY_EL1 and GXF_PABENTRY_EL1, once: the kernel
     * clears the bit after servicing the first one.  That once is what
     * matters.  Servicing it marks ARM_GUEST_STATE_GXF used, and from then on
     * the kernel saves and restores the whole guarded bank around every entry
     * -- SP_GL1, ASPSR_GL12, VBAR_GL12, ELR_GL12, SPSR_GL12 and the rest.
     * Without it that bank is never carried at all, which is why the copy in
     * the shared page reads zero however often it is asked.
     */
    if (op0 == 3 && op1 == 6 && crn == 15 &&
        ((crm == 1 && op2 == 2) || (crm == 8 && (op2 == 1 || op2 == 2)))) {
        unsigned ext = (crm == 1) ? 42 : (op2 == 1 ? 43 : 44);
        volatile uint64_t *slot =
            ohv_rw_u64(s->ctx, OHV_RW_EXTREGS + ext * 8);
        ohv_rw_page_head_t *rw = ohv_rw(s->ctx);

        if (read) {
            if (rt != 31) rw->regs.x[rt] = *slot;
        } else {
            *slot = (rt == 31) ? 0 : rw->regs.x[rt];
            mark_dirty(s->ctx, OHV_STATE_GXF);
            /*
             * GXF_ENTRY_EL1 names where a genter lands, which is guarded code
             * by definition.  The kernel points it at itself once during
             * bootstrap and again from inside the layer, and the second target
             * is the one that matters.
             */
            if (crm == 8 && op2 == 1 && *slot >= 0xfffffff000000000ull) {
                ohv_guard_add(*slot & ~0xfffull, (*slot & ~0xfffull) + 0x1000ull);
                if (ohv_trace_on(OHV_TRACE_BAND)) {
                    fprintf(stderr, "[ohv] gxf entry %#llx -> guarded page"
                            " %#llx\n", (unsigned long long)*slot,
                            (unsigned long long)(*slot & ~0xfffull));
                }
            }
        }
        if (ohv_trace_on(OHV_TRACE_ERET)) {
            fprintf(stderr, "[ohv] gxf %s ext[%u] = %#llx pc %#llx\n",
                    read ? "read" : "write", ext,
                    (unsigned long long)*slot,
                    (unsigned long long)rw->regs.pc);
        }
        rw->regs.pc += 4;
        return true;
    }

    /*
     * GXF_STATUS_EL1, which says which layer the core is running in, not
     * whether guarded execution was ever enabled.
     *
     * It reads one while the core is inside the guarded layer and zero once
     * it is back out, and both directions of that difference are load
     * bearing:
     *
     *   - the monitor's own guard reads it to choose the bank its per-CPU
     *     block lives in (GXF_STATUS ? TPIDR_GL2 : TPIDR_EL2).  The
     *     monitor's code lives in the guarded range, so it has to read one
     *     there.  Answered from the enable bit it read zero instead, and
     *     the secondaries took the TPIDR_EL2 arm before anything had
     *     installed that register, then died on a null TLS -- `cpu 1
     *     failed to boot for the first time` in the boot core's log.
     *
     *   - XNU polls it to confirm it has left the guarded layer:
     *
     *         mrs x14, GXF_STATUS_EL1
     *         cmp x14, #0
     *         b.ne .                     ; XNU, 0xfffffff04f717a24
     *
     *     so an answer derived from GXF_CONFIG_EL1 -- which stays set for
     *     good once the guest enables guarded execution -- spins the boot
     *     core in XNU's own exit path on the first tick; measured
     *     2026-09-27, the boot core parked on that `b.ne` for ten minutes
     *     with every secondary still in its reset poll.
     *
     * The layer a core is in is the range its pc is in: the ROM hands the
     * guarded range over at handoff (0xfffffff020000000 + 0x20000000 on
     * this chain) and the monitor never leaves it except through a guarded
     * exit, which is exactly the moment this register has to fall back to
     * zero.  So it is answered from the same range test the guarded-entry
     * bookkeeping already uses, not from the enable bit.
     */
    if (op0 == 3 && op1 == 6 && crn == 15 && crm == 8 && op2 == 0) {
        if (read) {
            uint64_t pc = ohv_rw(s->ctx)->regs.pc;

            if (rt != 31) {
                ohv_rw(s->ctx)->regs.x[rt] =
                    ohv_pc_in_monitor(pc) ? 1 : 0;
            }
        }
        ohv_rw(s->ctx)->regs.pc += 4;
        return true;
    }

    /*
     * The GL1 bank is not answered here, and the attempt is worth keeping.
     *
     * It is the whole of the exit cost -- PPL saves and restores it around
     * every guarded transition, 206,000 of the 300,000 exits a second this
     * machine takes idle at the lock screen -- and answering it in this
     * function would keep every one of them out of the VMM entirely.  It was
     * tried, reading and writing the same extreg slots the register table
     * names and marking OHV_STATE_GXF dirty, and the guest reboots before the
     * kernel has printed four hundred lines.  These registers are not just
     * storage on the way through: ELR_GL1 and SPSR_GL1 have to be mirrored
     * onto the EL2 pair a hardware guarded return consumes, which is what the
     * handling further on does and what returning early here skipped.
     * Anything that takes these exits away has to carry that with it.
     */
    /*
     * The cache identification registers.  HCR_EL2.TID2 is in the kernel's
     * fixed set, so every CLIDR_EL1, CCSIDR_EL1 and CSSELR_EL1 access traps
     * here whatever this library asks for -- and a stage's entry code cleans
     * the data caches by set and way, which means reading both of the first
     * two before it has done anything else.  Left unanswered, the very first
     * instruction of the next stage takes an exception it has no handler for:
     * measured, iBEC reaches its fourth instruction and the machine resets.
     *
     * The answers are the host's, which is what the capabilities carry, and
     * which level and which of the two caches is being asked about comes from
     * CSSELR_EL1 -- a banked-per-guest value, so it is read back from the
     * shared page rather than from the host register.
     */
    if (op0 == 3 && crn == 0 && crm == 0 &&
        ((op1 == 1 && (op2 == 0 || op2 == 1)) || (op1 == 2 && op2 == 0))) {
        static ohv_capabilities_t caps{};
        static bool have = false;
        volatile uint64_t *csselr =
            ohv_rw_u64(s->ctx, OHV_RW_SHARED_SYSREGS + 7 * 8);
        ohv_rw_page_head_t *rw = ohv_rw(s->ctx);
        uint64_t v = 0;

        if (!have) {
            ohv_raw_trap(OHV_TRAP_CAPABILITIES, &caps);
            have = true;
        }
        if (op1 == 2) {                       /* CSSELR_EL1 */
            if (read) {
                v = *csselr;
            } else {
                *csselr = (rt == 31) ? 0 : rw->regs.x[rt];
                mark_dirty(s->ctx, OHV_STATE_SYSREGS);
            }
        } else if (op2 == 1) {                /* CLIDR_EL1 */
            if (!read) return false;
            v = caps.clidr_el1;
        } else {                              /* CCSIDR_EL1 */
            unsigned level = (unsigned)((*csselr >> 1) & 7);

            if (!read) return false;
            v = (*csselr & 1) ? caps.ccsidr_el1_inst[level]
                              : caps.ccsidr_el1_data_or_unified[level];
        }
        if (read && rt != 31) rw->regs.x[rt] = v;
        if (ohv_trace_on(OHV_TRACE_TID2)) {
            fprintf(stderr, "[ohv] tid2 %s op1=%u op2=%u csselr %#llx"
                    " -> %#llx pc %#llx\n", read ? "read" : "write", op1, op2,
                    (unsigned long long)*csselr, (unsigned long long)v,
                    (unsigned long long)rw->regs.pc);
        }
        rw->regs.pc += 4;
        return true;
    }

    /*
     * The counters.  A guest that believes it is at EL2 expects to read these
     * without asking anyone, and letting it -- by opening CNTHCTL_EL2 -- hands
     * it the host's raw count.  That is a different clock from the one the
     * VMM's devices run on, and firmware that waits by comparing a device's
     * tick against the counter then waits on two clocks that never agree.
     * Answering here keeps it on the VMM's, which is the offset the VMM
     * already told us about.
     */
    if (op0 == 3 && op1 == 3 && crn == 14 && crm == 0 && read) {
        uint64_t v = 0;

        if (op2 == 1 || op2 == 2) {          /* CNTPCT_EL0, CNTVCT_EL0 */
            v = mach_absolute_time() -
                ohv_rw_controls(s->ctx)->virtual_timer_offset;
        } else if (op2 == 0) {               /* CNTFRQ_EL0 */
            uint64_t freq;

            __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
            v = freq;
        } else {
            return false;
        }
        if (rt != 31) ohv_rw(s->ctx)->regs.x[rt] = v;
        ohv_rw(s->ctx)->regs.pc += 4;
        return true;
    }

    /*
     * The timers themselves.  Their state lives in the banked system
     * registers, which is where the kernel loads them from on the way into
     * the guest; TVAL is not stored at all, it is the distance from now to
     * the compare value and is read and written as such.
     */
    if (op0 == 3 && op1 == 3 && crn == 14 && (crm == 2 || crm == 3)) {
        bool physical = (crm == 2);

        /*
         * Gated on where the guest is rather than on a count.  The firmware
         * reads these registers in loops, so any budget is spent long before
         * the kernel runs -- and the question worth answering is whether the
         * kernel's own accesses arrive here at all, or are redirected to the
         * EL2 timers behind this side's back.
         */
        /*
         * Every write the guest makes to the physical timer, whatever era it
         * is in.  A trace of the interrupt's edges says when the timer fires
         * and when it is masked, but not whether the firmware ever arms it
         * again -- and arming with a deadline still in the future moves no
         * edge at all, so it is invisible from there.
         */
        if (ohv_trace_on(OHV_TRACE_TIMERREG) && !read && physical) {
            fprintf(stderr, "[ohv] cntp %s = %#llx pc %#llx\n",
                    op2 == 0 ? "tval" : (op2 == 1 ? "ctl " : "cval"),
                    (unsigned long long)(rt == 31 ? 0
                                         : ohv_rw(s->ctx)->regs.x[rt]),
                    (unsigned long long)ohv_rw(s->ctx)->regs.pc);
        }
        unsigned ctl_index = physical ? 19 : 18;
        unsigned cval_index = physical ? 10 : 9;
        /*
         * The physical timer is emulated, so the guest's control word is kept
         * here and the banked slot -- which the kernel loads straight into the
         * hardware timer -- is left disabled.  Armed for real, the hardware
         * timer keeps asserting into the host from the moment the compare
         * value passes until the guest re-arms it, and a guest that is waiting
         * for this very interrupt never gets a cycle in which to do so: every
         * entry leaves again before it retires an instruction.  The waking is
         * the VMM's job now, off its own clock.
         */
        volatile uint64_t *ctl = physical
            ? (volatile uint64_t *)&s->el2_shadow[OHV_SHADOW_CNTP_CTL]
            : ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + ctl_index * 8);

        if (physical) {
            *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + ctl_index * 8) = 0;
        }
        volatile uint64_t *cval =
            ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + cval_index * 8);
        /*
         * The compare value is kept in the host's counter, not the guest's.
         * The kernel restores this slot straight into the hardware timer,
         * which compares it against CNTPCT -- so a guest-relative value, tiny
         * beside the host's count, reads as already expired the moment the
         * guest enables the timer, and the interrupt that fires on every
         * entry from then on leaves no cycle for the guest to retire even the
         * instruction after the one that armed it.  Translate on the way in
         * and out instead: the guest keeps its own clock, the hardware keeps
         * the one it can act on.
         */
        uint64_t off = ohv_rw_controls(s->ctx)->virtual_timer_offset;
        uint64_t hnow = mach_absolute_time();
        ohv_rw_page_head_t *rw = ohv_rw(s->ctx);
        uint64_t v = (rt == 31) ? 0 : rw->regs.x[rt];

        switch (op2) {
            case 0:                                   /* TVAL */
                /*
                 * A 32-bit register, and the read has to look like one.
                 *
                 * `MRS x, CNTV_TVAL_EL0` zero-extends TimerValue, so on
                 * hardware an expired timer reads 0x00000000_FFFFFFxx.
                 * Handing back the full signed difference puts 0xFFFFFFFF in
                 * the top half instead, which is exactly what XNU's
                 * `ml_get_decrementer` asserts against -- `wide_val ==
                 * (uint64_t)dec`, machine_routines.c:2264.  Compiled out of a
                 * release kernel and fatal on a development one, so it has
                 * been latent rather than absent.
                 */
                if (read) v = (uint64_t)(uint32_t)((int64_t)*cval -
                                                   (int64_t)hnow);
                else *cval = hnow + (uint64_t)(int32_t)(uint32_t)v;
                break;
            case 1:                                   /* CTL  */
                if (read) v = *ctl;
                else *ctl = v;
                break;
            case 2:                                   /* CVAL */
                if (read) v = *cval - off;
                else *cval = v + off;
                break;
            default:
                return false;
        }
        if (read) {
            if (rt != 31) rw->regs.x[rt] = v;
        } else {
            mark_dirty(s->ctx, OHV_STATE_SYSREGS);
        }
        rw->regs.pc += 4;
        return true;
    }

    if (is_gic_interface_reg(op0, op1, crn, crm, op2)) {
        uint64_t *slot = gic_if_slot(s, enc);
        ohv_rw_page_head_t *rw = ohv_rw(s->ctx);

        if (!slot) return false;
        if (read) {
            if (rt != 31) rw->regs.x[rt] = *slot;
        } else {
            *slot = (rt == 31) ? 0 : rw->regs.x[rt];
        }
        rw->regs.pc += 4;
        return true;
    }
    /*
     * The EL2 cache and TLB maintenance instructions -- TLBI, DC, IC, AT with
     * Op0 of 1 and Op1 of 4.  A guest hypervisor issues them against its own
     * translation regime, which here is the EL1 one the hardware is already
     * keeping coherent: the kernel invalidates on every change it makes to
     * the stage-2 tables and to the registers that name them, so there is
     * nothing left for these to do.  What matters is that they complete --
     * left to fall through, the boot ROM's `tlbi alle2` on the way to
     * handing over the machine becomes an exception the guest takes with no
     * vector table to take it with.
     */
    if (ohv_trace_on(OHV_TRACE_AT) && op0 == 1 && crn == 7) {
        fprintf(stderr, "[ohv] vcpu %llu system insn op1=%u crn=%u crm=%u"
                " op2=%u rt=%u pc=%#llx\n", (unsigned long long)s->id,
                op1, crn, crm, op2, rt,
                (unsigned long long)ohv_rw(s->ctx)->regs.pc);
    }
    /*
     * AT is not maintenance: it answers.  The address translation
     * instructions sit at CRn 7 with CRm 8 or 9, and each one is a question
     * whose reply is PAR_EL1 -- iBoot asks its own EL2 regime to translate an
     * address and compares the answer with the walk it did itself, so an AT
     * that is quietly stepped over leaves a stale PAR, the two disagree, and
     * it panics on the mismatch.  Leave it for the VMM.
     */
    /*
     * AT is a question, not maintenance: it translates an address and leaves
     * the answer in PAR_EL1.  iBoot asks its own EL2 regime to translate an
     * address and compares the answer against the walk it did itself; an AT
     * that is stepped over leaves PAR holding whatever it held before, the
     * two disagree, and it panics on the mismatch.
     *
     * The guest's EL2 translation regime is the EL1 one -- its TTBR0_EL2 and
     * TCR_EL2 are kept in the real EL1 registers, which is what makes its
     * page tables the ones the hardware is walking -- so answering means
     * walking those same tables here.  Being the same tables, the answer is
     * the same by construction.
     */
    /*
     * The kernel's own AT S1E1R comes here too, for a reason of our making:
     * with HCR_EL2.NV set the address-translation instructions trap out of
     * EL1, and NV is set because SPTM's guarded return had to be trapped to be
     * completed.  So once XNU is running, every translation it asks for is
     * ours to answer -- measured, one AT S1E1R at arm_init time arrives as an
     * undefined instruction and handle_uncategorized turns it into a panic.
     * The tables are the same ones the hardware walks, so the same walk
     * answers both.
     */
    if (op0 == 1 && (op1 == 4 || op1 == 0) && crn == 7 &&
        (crm == 8 || crm == 9)) {
        uint64_t va = (rt == 31) ? 0 : ohv_rw(s->ctx)->regs.x[rt];

        *ohv_rw_u64(s->ctx, OHV_RW_SHARED_SYSREGS + 6 * 8) =
            ohv_translate_stage1(s, va);
        mark_dirty(s->ctx, OHV_STATE_SYSREGS);
        ohv_rw(s->ctx)->regs.pc += 4;
        return true;
    }
    /*
     * TLBI, every form: CRn 8.  Trapped by HCR_EL2.TTLB (EL1 encodings) or by
     * NV (EL2 encodings) and performed by the kernel in each address space
     * this VM runs in -- see ohv_tlbi_replay.  Stepping over an EL1 TLBI, or
     * executing it natively under one VMID, is what left the other cores'
     * translations stale.
     */
    if (op0 == 1 && crn == 8 && ohv_tlbi_replay_on()) {
        uint64_t param = (rt == 31) ? 0 : ohv_rw(s->ctx)->regs.x[rt];

        ohv_tlbi_replay(s->id, op1, crm, op2, param);
        ohv_rw(s->ctx)->regs.pc += 4;
        return true;
    }
    if (op0 == 1 && op1 == 4) {
        ohv_rw(s->ctx)->regs.pc += 4;
        return true;
    }

    /*
     * A PSTATE field this host does not have.
     *
     * The kernel's thread switch writes S3_3_C4_C2_6 from a byte it keeps per
     * thread.  CRn 4 is where the PSTATE fields live, and a write to one the
     * silicon does not implement is UNDEFINED -- which is what the guest gets,
     * and handle_uncategorized turns it into a panic.  The firmware is built
     * for an A15 and the host is an M4; the field is simply not there.
     *
     * Swallowing it is the honest answer: there is no bit to set, so the guest
     * reads back what it wrote and nothing pretends otherwise.
     */
    if (op0 == 3 && op1 == 3 && crn == 4 && crm == 2 && op2 == 6) {
        ohv_rw_page_head_t *rw = ohv_rw(s->ctx);
        static uint64_t held;

        if (read) {
            if (rt != 31) rw->regs.x[rt] = held;
        } else {
            held = (rt == 31) ? 0 : rw->regs.x[rt];
        }
        rw->regs.pc += 4;
        return true;
    }

    /*
     * Everything else Apple defines at CRn 15.
     *
     * These are the hidden ID and chicken registers, and the kernel is not
     * shy with them: AMXIDR_EL1 decides whether it panics about AMX, EHID4 and
     * HID4 get a bit cleared and written back, ACNTVCT_EL0 is read inside
     * DebuggerXCallEnter.  Each one that goes unanswered is an exception the
     * guest has no handler for at that point, and the boot stops there --
     * answering them one run at a time costs a run each, so answer the class.
     *
     * A shadow is the honest model for the ID and chicken words: the guest
     * reads back what it wrote, and nothing pretends the silicon changed.  The
     * counters are the exception, since a counter that does not advance is
     * worse than one that is approximate.
     */
    /*
     * VM_TMR_FIQ_ENA_EL2, which is how Apple gates delivery of the guest's own
     * timers.  Linux names it SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2 = sys_reg(3, 5,
     * 15, 1, 3), with VM_TMR_FIQ_ENABLE_P in bit 0 and ..._V in bit 1, and its
     * AIC driver masks a guest timer FIQ by clearing the matching bit -- that
     * clear is the acknowledgement, there is no other end-of-interrupt.
     *
     * The guest writes it once, with zero, in the middle of bringing up its
     * own interrupt handling: "do not deliver guest timer interrupts".  Left
     * unanswered here the write went out to the VMM, which kept the value and
     * could do nothing with it, and ohv_expire_timers() carried on raising one
     * anyway -- which is the interrupt the kernel dies on, with no controller
     * line raised anywhere to explain it.  Answering it separates the two
     * phases on its own: iBoot never writes it and keeps what it relies on.
     */
    /*
     * The GL2 bank.  SPTM runs at GL2 and keeps its per-CPU block in
     * TPIDR_GL2 (c11_1); refused here it went out to the VMM, which kept the
     * value where nothing could reach it, and SPTM's guarded handler was left
     * reading a stack that was never its own.  Its own assertion names the
     * result: "[SPTM] Synchronous exception taken while SP0 selected in GL2".
     *
     * Answering these is not the same call as the GL1 bank next door.  Those
     * go to the extended registers the kernel loads into hardware, and
     * shadowing them would tell the guest something the silicon never heard.
     * For GL2 there is no such register to disagree with: the host's guest
     * state models GL1 and only GL1, so this is the only place the value can
     * live.
     */
    if (op0 == 3 && op1 == 6 && crn == 15 && crm == 11 && op2 < 8) {
        ohv_rw_page_head_t *rw = ohv_rw(s->ctx);

        if (read) {
            if (rt != 31) rw->regs.x[rt] = s->gl2_bank[op2];
        } else {
            s->gl2_bank[op2] = rt == 31 ? 0 : rw->regs.x[rt];
        }
        rw->regs.pc += 4;
        return true;
    }
    if (op0 == 3 && op1 == 5 && crn == 15 && crm == 1 && op2 == 3) {
        ohv_rw_page_head_t *rw = ohv_rw(s->ctx);

        if (read) {
            if (rt != 31) rw->regs.x[rt] = s->vm_tmr_fiq_ena;
        } else {
            uint64_t was = s->vm_tmr_fiq_ena;

            s->vm_tmr_fiq_ena = rt == 31 ? 0 : rw->regs.x[rt];
            /*
             * Every write, with nowhere to hide.  Clearing a bit here stops
             * ohv_expire_timers raising that timer at all, and the kernel
             * boot has been ending with the virtual bit clear and nothing
             * setting it back -- so what is worth knowing is which address
             * turns it off, and whether the same one ever turns it on.  These
             * writes are rare enough that a budget would only hide them.
             */
            if (ohv_trace_on(OHV_TRACE_TMRENA)) {
                fprintf(stderr, "[ohv] vm_tmr_fiq_ena %#llx -> %#llx"
                        " pc %#llx\n", (unsigned long long)was,
                        (unsigned long long)s->vm_tmr_fiq_ena,
                        (unsigned long long)rw->regs.pc);
            }
        }
        rw->regs.pc += 4;
        return true;
    }
    /*
     * The CTRR bank belongs here too, and did not reach it.
     *
     * SPTM writes CTRR_A_LWR/UPR/CTL/LOCK at op1 4, CRm 2 and XNU reads the
     * same silicon back as CTRR_A_LWR/UPR_EL2 at CRm 6.  Neither was covered
     * by the condition below -- it took only CRm 10 -- so the fold that puts
     * the two views in one place was written inside a block that never ran,
     * and what SPTM wrote was still not what XNU read:
     *
     *     zalloc_ro_mut failed: source (...) not from RO zone map (...),
     *     current stack (...) or const memory (phys 0 - 0)
     *
     * with pid 1 as the thread, because machine_init stashes those two
     * registers as the kernel's read-only region and every zalloc_ro_mut out
     * of the kernel's own const data is refused when that range is empty.
     */
    /*
     * The kernel's read-only region, which is one register with two names.
     *
     * SPTM programs it as CTRR_A_LWR/UPR_EL1 -- op1 4, CRn 15, CRm 2, op2 3
     * and 4 -- and XNU reads it back as CTRR_A_LWR/UPR_EL2, which are CRm 6,
     * op2 4 and 5.  Two encodings, one piece of silicon.  Kept apart, what
     * SPTM wrote was never what XNU read and machine_init stashed a range of
     * nothing:
     *
     *     zalloc_ro_mut failed: source (...) not from RO zone map (...),
     *     current stack (...) or const memory (phys 0 - 0)
     *
     * with pid 1 as the thread, because every zalloc_ro_mut out of the
     * kernel's own const data is refused when that range is empty.
     *
     * Only these six encodings, and not the CRm they sit in: the block next
     * door takes whole CRms, and taking CRm 2 that way stopped the machine
     * before iBSS ever answered its USB.
     */
    if (op0 == 3 && op1 == 4 && crn == 15 &&
        ((crm == 2 && op2 >= 2 && op2 <= 5) ||
         (crm == 6 && (op2 == 4 || op2 == 5)))) {
        ohv_rw_page_head_t *rw = ohv_rw(s->ctx);
        unsigned slot = (crm == 6) ? (op2 - 1) : op2;   /* 6/4 -> 2/3, 6/5 -> 2/4 */
        unsigned i;

        for (i = 0; i < s->ctrr_used; i++) {
            if (s->ctrr[i].sel == slot) break;
        }
        if (i == s->ctrr_used) {
            if (i >= sizeof(s->ctrr) / sizeof(s->ctrr[0])) {
                return false;
            }
            s->ctrr[i].sel = (uint8_t)slot;
            s->ctrr[i].value = 0;
            s->ctrr_used++;
        }
        if (read) {
            if (rt != 31) rw->regs.x[rt] = s->ctrr[i].value;
        } else {
            s->ctrr[i].value = (rt == 31) ? 0 : rw->regs.x[rt];
        }
        if (ohv_trace_on(OHV_TRACE_EXT)) {
            static bool once;

            if (!once) {
                once = true;
                for (unsigned k = 38; k < 62; k++) {
                    uint64_t v = *ohv_rw_u64(s->ctx, OHV_RW_EXTREGS + k * 8);

                    if (v != 0) {
                        fprintf(stderr, "[ohv] ext[%u] = %#llx\n", k,
                                (unsigned long long)v);
                    }
                }
            }
        }
        if (ohv_trace_on(OHV_TRACE_CTRR)) {
            fprintf(stderr, "[ohv] ctrr %s c%u_%u slot %u = %#llx pc %#llx\n",
                    read ? "read " : "write", crm, op2, slot,
                    (unsigned long long)s->ctrr[i].value,
                    (unsigned long long)rw->regs.pc);
        }
        rw->regs.pc += 4;
        return true;
    }
    /*
     * The three registers every thread switch touches.
     *
     * XNU's context switch writes KTRACE_MESSAGE (s3_5_c15_c1_4), HIST_TRIG
     * (s3_5_c15_c10_1) and JCTL_EL0 (s3_4_c15_c15_6) on the way through, and
     * each one left this library, crossed into the VMM, and was kept in a
     * register file nothing reads -- three exits per switch, on a machine
     * that switches threads to wait for everything.  It is why drivers report
     * starts of fifty seconds, and why AppleT8110PMGR's own timing assertion
     * fires:
     *
     *     _waitAPSCPending takes too long exeution time 8176 us domain 2
     *
     * with its counter at zero, meaning the register it waited on was ready
     * at once and only the wall clock ran over.
     *
     * The first two are trace: written zero every time, never read, and
     * answering them where the trap lands costs nothing and saves the
     * crossing.
     *
     * **JCTL_EL0 is not.**  thread_invoke reads it into the outgoing thread
     * and writes the incoming thread's value back, so it is real per-thread
     * state -- and it is the JIT control, whose extended registers include
     * japibkeylo/hi.  Held here it never reaches the silicon, the B key stops
     * being the one the kernel signed with, and the switch itself dies:
     *
     *     PAC failure from kernel with IB key at pc ... (thread_invoke)
     *
     * deterministically, at the same pc and lr every boot.  It goes out.
     */
    if (op0 == 3 && crn == 15 && op1 == 5 &&
        ((crm == 1 && op2 == 4) || (crm == 10 && op2 == 1))) {
        ohv_rw_page_head_t *rw = ohv_rw(s->ctx);
        unsigned slot = (crm == 1) ? 0 : 1;

        if (read) {
            if (rt != 31) rw->regs.x[rt] = s->ctx_trace[slot];
        } else {
            s->ctx_trace[slot] = (rt == 31) ? 0 : rw->regs.x[rt];
        }
        rw->regs.pc += 4;
        return true;
    }
    if (op0 == 3 && (op1 == 0 || (op1 == 4 && crm == 10))) {
        ohv_rw_page_head_t *rw = ohv_rw(s->ctx);

        /*
         * Op1 of six is left alone on purpose: that is the guarded bank and
         * the SPRR and GXF controls, which go to the extended registers the
         * kernel loads into hardware.  Shadowing those would answer the guest
         * while the silicon never heard, which is the whole failure this file
         * spends its length avoiding.
         */
        if (op1 == 4 && crm == 10 && (op2 == 5 || op2 == 6)) {
            if (read) {
                uint64_t v = mach_absolute_time() -
                    ohv_rw_controls(s->ctx)->virtual_timer_offset;

                if (rt != 31) rw->regs.x[rt] = v;
            }
            rw->regs.pc += 4;
            return true;
        }

        unsigned i;

        if (crn != 15) {
            return false;
        }
        for (i = 0; i < s->apple_shadow_used; i++) {
            if (s->apple_shadow[i].enc == enc) break;
        }
        if (i == s->apple_shadow_used) {
            if (i >= sizeof(s->apple_shadow) / sizeof(s->apple_shadow[0])) {
                return false;               /* out of room: let the VMM see it */
            }
            s->apple_shadow[i].enc = enc;
            s->apple_shadow[i].value = 0;
            s->apple_shadow_used++;
        }
        if (read) {
            if (rt != 31) rw->regs.x[rt] = s->apple_shadow[i].value;
        } else {
            s->apple_shadow[i].value = (rt == 31) ? 0 : rw->regs.x[rt];
        }
        if (ohv_trace_on(OHV_TRACE_IMPDEF)) {
            fprintf(stderr, "[ohv] impdef %s s3_%u_c15_c%u_%u = %#llx pc %#llx\n",
                    read ? "read " : "write", op1, crm, op2,
                    (unsigned long long)s->apple_shadow[i].value,
                    (unsigned long long)rw->regs.pc);
        }
        rw->regs.pc += 4;
        return true;
    }

    /*
     * The three registers that decide which key a pointer is signed with.
     *
     * TXM authenticates a static pointer out of its own image and takes an
     * FPAC -- the value is right, the signature is not:
     *
     *     [TXM/SK] Unhandled synchronous exception taken from GL0/GL1
     *     esr 0x72000000  (EC 0x1c)
     *
     * SPTM writes APCTL_EL1 eleven times and KERNELKEY once each, and XNU
     * writes KERNELKEY six times more; TXM writes none of them and only uses
     * what it was given.  These go out to the VMM rather than being answered
     * here, so nothing in this library sees them without asking.  What is
     * worth knowing is the order: which of them is written, with what, and
     * where the authentication that fails sits among them.
     */
    if (ohv_trace_on(OHV_TRACE_PAC) && op0 == 3 && op1 == 4 && crn == 15 &&
        ((crm == 0 && op2 == 4) || (crm == 1 && op2 < 2))) {
        static const char *const name[] = { "KERNELKEYLO", "KERNELKEYHI" };
        ohv_rw_page_head_t *rw = ohv_rw(s->ctx);

        fprintf(stderr, "[ohv] vcpu %llu pac %s %s = %#llx pc %#llx\n",
                (unsigned long long)s->id,
                read ? "read " : "write",
                crm == 0 ? "APCTL_EL1" : name[op2],
                (unsigned long long)((read || rt == 31) ? 0 : rw->regs.x[rt]),
                (unsigned long long)rw->regs.pc);
    }

    /*
     * TPIDR_EL2, which is one name over two storages.
     *
     * On the silicon the monitor runs at real EL2 and its per-CPU block goes
     * into the physical register, while the kernel -- the monitor's guest,
     * HCR_EL2.{NV,NV2} set -- keeps its arm_host_context_t in the VNCR page
     * and never touches the register.  Both are at hardware EL1 here and
     * both trap, so the pc has to say which layer this access belongs to.
     * Sent to the same VNCR slot, the monitor's install replaced the kernel's
     * host context, and the kernel's next guest exception read the monitor's
     * block, took a zero guest_context pointer from +0x90 and died on
     * `str x0, [x1, #0x370]` with far=0x370 (24A437, cpu 2,
     * _fleh_guest_synchronous).  The band the ROM hands over is the same
     * discriminator GXF_STATUS uses, and says the same thing: which layer is
     * running.
     */
    if (op0 == 3 && op1 == 4 && crn == 13 && crm == 0 && op2 == 2) {
        ohv_rw_page_head_t *rw = ohv_rw(s->ctx);
        uint64_t pc = rw->regs.pc;

        if (ohv_pc_guarded(pc)) {
            uint64_t v = read ? s->monitor_tpidr_el2
                              : ((rt == 31) ? 0 : rw->regs.x[rt]);

            if (read) {
                if (rt != 31) rw->regs.x[rt] = v;
            } else {
                s->monitor_tpidr_el2 = v;
            }
            if (ohv_trace_on(OHV_TRACE_TPIDR_EL2)) {
                fprintf(stderr, "[ohv] monitor TPIDR_EL2 %s = %#llx pc %#llx\n",
                        read ? "read " : "write",
                        (unsigned long long)v, (unsigned long long)pc);
            }
            rw->regs.pc += 4;
            return true;
        }
        if (ohv_trace_on(OHV_TRACE_TPIDR_EL2)) {
            static unsigned n;

            if (n < 64) {
                n++;
                fprintf(stderr, "[ohv] guest TPIDR_EL2 %s pc %#llx"
                        " (VNCR slot)\n", read ? "read " : "write",
                        (unsigned long long)pc);
            }
        }
        /* the kernel's own: the VNCR slot the fallback below gives it */
    }

    const Nv2Reg *r = (op1 == 4 && op0 == 3) ? nv2_lookup(enc) : nullptr;

    if (!r) {
        if (ohv_trace_on(OHV_TRACE_UNMATCHED)) {
            static unsigned n;

            if (n < 40) {
                n++;
                fprintf(stderr, "[ohv] unmatched sysreg %s op0=%u op1=%u"
                        " crn=%u crm=%u op2=%u rt=%u pc %#llx\n",
                        read ? "read" : "write", op0, op1, crn, crm, op2, rt,
                        (unsigned long long)ohv_rw(s->ctx)->regs.pc);
            }
        }
        return false;
    }
    volatile uint64_t *slot = ohv_rw_u64(s->ctx, r->ctx_off);
    ohv_rw_page_head_t *rw = ohv_rw(s->ctx);

    if (read) {
        uint64_t v = *slot;

        if (rt != 31) rw->regs.x[rt] = v;
    } else {
        *slot = (rt == 31) ? 0 : rw->regs.x[rt];
        if (r->banked) mark_dirty(s->ctx, OHV_STATE_SYSREGS);
    }
    rw->regs.pc += 4;
    return true;
}

/* Where in a vector table an exception from a lower AArch64 EL lands. */
#define OHV_VECT_LOWER64_SYNC 0x400

/*
 * Take an exception into the guest hypervisor's own EL2.  While the guest is
 * running the guest it hosts, HCR_EL2.NV is off and the hardware knows
 * nothing about the level the guest believes in, so the entry has to be built
 * here: the return state into the EL2 registers the guest reads, the reason
 * into ESR_EL2, and the program counter to the guest's own vector table.
 *
 * Without this the guest hypervisor can be left but never re-entered.  The
 * boot ROM drops itself to EL1 to do its work and comes back with an HVC to
 * hand the machine to the next stage; with nowhere to come back to, the HVC
 * leaves the guest for good and the payload is never entered.
 */
/*
 * Which SPSR values a hardware exception return refuses.  An illegal one does
 * not fault where it is written: the return completes, hardware sets
 * PSTATE.IL, and then the *next* instruction fetched anywhere raises EC 0x0e.
 * The report therefore names a victim three subsystems away from the cause --
 * a kext thunk whose first `stp` is illegal, with nothing wrong with the
 * thunk.  Checking the value at the moment it is written is the only way to
 * put the two together.
 *
 * M[4] is part of this: the software path below reads the mode with a 4-bit
 * mask, so an AArch32 SPSR would pass for a legal AArch64 one there.
 */
static const char *spsr_illegal_reason(uint64_t spsr) {
    if (spsr & 0x10ull) {
        return "AArch32, M[4] set";
    }
    switch ((unsigned)(spsr & 0xfull)) {
        case 0x0:   /* EL0t */
        case 0x4:   /* EL1t */
        case 0x5:   /* EL1h */
        case 0x8:   /* EL2t */
        case 0x9:   /* EL2h */
            return nullptr;
        case 0xc:
        case 0xd:
            return "EL3, which this guest does not have";
        default:
            return "reserved M[3:0]";
    }
}

/*
 * `from_el1` is the difference between the two paths.  The software one
 * rewrites EL2t/EL2h into the hardware EL1 pair before the guest sees it, so
 * those values are ordinary there.  The guarded one takes NV off and hands the
 * return to the silicon while the hardware is still at EL1 -- and a return
 * from EL1 to EL2 is illegal, whatever the guest believes its level to be.
 */
static void report_illegal_eret(VcpuSlot *s, const char *how, uint64_t elr, uint64_t spsr, bool from_el1) {
    const char *why = spsr_illegal_reason(spsr);
    unsigned m = (unsigned)(spsr & 0xfull);

    if (why == nullptr && from_el1 && (m == 0x8 || m == 0x9)) {
        why = "EL2 from hardware EL1, with NV off";
    }
    if (why == nullptr) {
        return;
    }
    fprintf(stderr, "[ohv] vcpu %llu illegal exception return (%s): spsr %#llx"
            " -- %s -- elr %#llx pc %#llx\n",
            (unsigned long long)s->id, how, (unsigned long long)spsr, why,
            (unsigned long long)elr,
            (unsigned long long)ohv_rw(s->ctx)->regs.pc);
}

/*
 * Whether a trapped ERET is a return into a guarded level, which is the only
 * kind the hardware may be handed with NV off.
 *
 * `SPSR_GL1 != 0` on its own is not that test.  The register does not clear
 * itself: once SPTM has entered a guarded level it keeps whatever was written
 * there, so every ordinary return that comes afterwards reads non-zero too.
 * Measured -- XNU's exception_return going back to its own EL2 with SPSR
 * 0x604003c8 was taken for a guarded one, handed to the silicon from hardware
 * EL1, and refused: a return to a higher EL sets PSTATE.IL, and the EC 0x0e
 * that follows lands on whatever instruction comes next.  It was a kext thunk
 * with nothing wrong with it, three subsystems from the cause.
 *
 * What the hardware can actually carry out from EL1 names EL0 or EL1.  A
 * return that names EL2 is the guest hypervisor going back into its own
 * guest, and rewriting that is the software path's job.
 */
static bool eret_is_guarded(VcpuSlot *s, uint64_t *spsr_out) {
    ohv_raw_trap(OHV_TRAP_VCPU_SYSREGS_SYNC, nullptr);

    uint64_t spsr = *ohv_rw_u64(s->ctx, OHV_RW_EXTREGS + 52 * 8);
    unsigned m = (unsigned)(spsr & 0xfull);

    if (spsr_out != nullptr) {
        *spsr_out = spsr;
    }
    return spsr != 0 && spsr_illegal_reason(spsr) == nullptr &&
           m != 0x8 && m != 0x9;
}

/*
 * Set once the guest has taken an exception inside the kernel image.  It is a
 * phase marker, not a sampling window: iBoot raises far more interrupts than
 * the kernel does, and a trace that spends its budget there never reaches the
 * part being looked at.  Nothing before this point is of interest to the
 * interrupt question.
 */
bool g_kernel_running;

static bool g_trace_armed;

/* Defined with the FIQ gate, used by the GXF probe well above it. */
static bool ohv_guest_in_monitor(VcpuSlot *s);

static void enter_guest_el2(VcpuSlot *s, uint64_t esr, uint64_t return_pc) {
    g_trace_armed = true;
    ohv_rw_page_head_t *rw = ohv_rw(s->ctx);
    uint64_t vbar = *ohv_rw_u64(s->ctx, OHV_VNCR_BASE + 0x250);

    /*
     * With the host extensions on, a guest hypervisor's ELR_EL2, SPSR_EL2,
     * ESR_EL2 and FAR_EL2 are the EL1 exception registers -- it is running at
     * EL1 and those are the ones its exceptions use.  Measured: a guest at
     * its EL2 writing each of them lands on the banked EL1 slots, while
     * VBAR_EL2 goes to the VNCR page.  Writing the VNCR copies instead left
     * the guest reading whatever was in them, and its own vector code turned
     * away because the syndrome did not name an HVC.
     */
    *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 3 * 8) = return_pc;
    *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 5 * 8) = esr;
    *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 14 * 8) = rw->regs.cpsr;
    mark_dirty(s->ctx, OHV_STATE_SYSREGS);

    rw->regs.pc = vbar + OHV_VECT_LOWER64_SYNC;
    /*
     * The guest believes it is at EL2; the hardware keeps it at EL1 and
     * HCR_EL2.NV is what makes the two agree.  DAIF is masked on entry, as
     * taking an exception does.
     */
    rw->regs.cpsr = 0x3c5;
    /*
     * Only for a guest that is still a hypervisor.
     *
     * This is the fourth place that sets NV, and it does it on every injected
     * exception -- which on a chain whose kernel runs at EL1 drags the
     * machine back to "the guest is at EL2" over and over.  Measured on
     * 19A348 entered at EL1: the handoff clears NV on every core (read back
     * from their pages at that instant, bit 42 clear), and cpu1..4 are
     * nonetheless at nv=1 by their first kernel instruction, while cpu0 and
     * cpu5 -- which happened not to come through here -- are at nv=0.  Cores
     * disagreeing about their own exception level is not a state XNU has code
     * for, and it ended in `Illegal instruction set exception ... class=14`
     * on whichever core got there first.
     *
     * `g_guest_left_el2` is set by the handoff ERET into the kernelcache, and
     * only for a chain with no monitor; 17 sends the ROM's monitor signal
     * instead and never sets it, so nothing here changes for SPTM.
     */
    if (!g_guest_left_el2.load(std::memory_order_relaxed) ||
        g_monitor_next.load(std::memory_order_relaxed)) {
        ohv_rw_controls(s->ctx)->hcr_el2 |= OHV_HCR_NV;
        mark_dirty(s->ctx, OHV_STATE_CONTROLS);
        s->guest_at_el2 = true;
    }
}

static ExitAction exit_from_ro(VcpuSlot *s) {
    volatile ohv_vmexit_info_t *e = ohv_exit_info(s->ctx);

    if (ohv_trace_on(OHV_TRACE_HCR)) {
        static unsigned shown[8];

        if (s->id < 8 && shown[s->id] < 40 && e->vmexit_reason != 6 &&
            e->vmexit_reason != 11) {
            shown[s->id]++;
            fprintf(stderr, "[ohv] vcpu %llu reason %u esr %#llx pc %#llx"
                    " cntv_ctl %#llx cntv_cval %#llx cntp_ctl %#llx"
                    " cntp_cval %#llx timer %#llx\n",
                    (unsigned long long)s->id,
                    (unsigned)e->vmexit_reason,
                    (unsigned long long)e->vmexit_esr,
                    (unsigned long long)ohv_rw(s->ctx)->regs.pc,
                    (unsigned long long)*ohv_rw_u64(s->ctx,
                        OHV_RW_BANKED_SYSREGS + 18 * 8),
                    (unsigned long long)*ohv_rw_u64(s->ctx,
                        OHV_RW_BANKED_SYSREGS + 9 * 8),
                    (unsigned long long)s->el2_shadow[OHV_SHADOW_CNTP_CTL],
                    (unsigned long long)*ohv_rw_u64(s->ctx,
                        OHV_RW_BANKED_SYSREGS + 10 * 8),
                    (unsigned long long)*ohv_rw_u64(s->ctx, OHV_RW_TIMER));
        }
    }
    if (ohv_trace_on(OHV_TRACE_ALL)) {
        uint64_t tpc = ohv_rw(s->ctx)->regs.pc;
        /*
         * Tracing every exit costs more than the guest does, so a run under it
         * never reaches the point worth looking at.  Hold the trace until the
         * firmware has had its uninteresting seconds.
         */
        static time_t t0;
        uint64_t after = ohv_cfg(trace_after);
        uint64_t only = ohv_cfg(trace_vcpu);
        bool armed = true;

        if (!t0) t0 = time(nullptr);
        if (after) armed = (uint64_t)(time(nullptr) - t0) >= after;
        static uint64_t emitted;

        if (armed && emitted < ohv_cfg(trace_max) &&
            tpc >= ohv_cfg(trace_from) &&
            (only >= kMaxVcpuIds || s->id == only)) {
            emitted++;
            fprintf(stderr, "[ohv] vcpu %llu exit reason %u esr %#llx pc %#llx"
                    " far %#llx ipa %#llx\n",
                    (unsigned long long)s->id,
                    (unsigned)e->vmexit_reason,
                    (unsigned long long)e->vmexit_esr,
                    (unsigned long long)tpc,
                    (unsigned long long)e->vmexit_far,
                    (unsigned long long)(e->vmexit_hpfar << 8));
        }
    }
    /*
     * Put NV back when the guest leaves the guarded state a hardware ERET
     * carried it into.  Inside it the guest is the monitor, not a hypervisor,
     * and trapping its returns there is what broke the entry in the first
     * place; outside it every ERET is a guest hypervisor's again.  The guarded
     * exit is the event that says which side of that line the guest is on --
     * the guarded level itself reads back zero here whatever it is.
     *
     * The GEXIT, not the whole of EC 0x3f: that is Apple's private-ISA class,
     * and WKDMC arrives under it too, as ISS 0x13.
     */
    if (s->nv_off_for_geret &&
        ((e->vmexit_esr >> 26) & 0x3f) == 0x3f &&
        (e->vmexit_esr & 0x1ffffffull) == 0x22) {
        ohv_rw_controls(s->ctx)->hcr_el2 |= OHV_HCR_NV;
        mark_dirty(s->ctx, OHV_STATE_CONTROLS);
        s->nv_off_for_geret = false;
        if (ohv_trace_on(OHV_TRACE_ERET)) {
            fprintf(stderr, "[ohv] guarded exit: NV restored at pc %#llx\n",
                    (unsigned long long)ohv_rw(s->ctx)->regs.pc);
        }
    }
    /*
     * What level the hardware actually returned into.  SPTM asks for guarded
     * with bit 12 of the value it writes; the bit is not kept, so the only way
     * to know where the guest landed is to look afterwards -- and SPTM's own
     * guarded lower-EL handler is the thing that notices when it is wrong.
     */
    if (ohv_trace_on(OHV_TRACE_GLVL) && s->nv_off_for_geret) {
        static unsigned n;

        if (n < 12) {
            n++;
            ohv_raw_trap(OHV_TRAP_VCPU_SYSREGS_SYNC, nullptr);
            fprintf(stderr, "[ohv] after geret: pc %#llx esr %#llx"
                    " aspsr %#llx apsts %#llx spsr_gl1 %#llx cpsr %#llx\n",
                    (unsigned long long)ohv_rw(s->ctx)->regs.pc,
                    (unsigned long long)e->vmexit_esr,
                    (unsigned long long)*ohv_rw_u64(s->ctx,
                        OHV_RW_EXTREGS + 47 * 8),
                    (unsigned long long)ohv_rw_controls(s->ctx)->apsts_el1,
                    (unsigned long long)*ohv_rw_u64(s->ctx,
                        OHV_RW_EXTREGS + 52 * 8),
                    (unsigned long long)ohv_rw(s->ctx)->regs.cpsr);
        }
    }
    /*
     * Keep the guest's EL2 return pair holding the guarded one.
     *
     * SPTM hands the monitor over with MSR ELR_GL1 / MSR SPSR_GL1 and an
     * ERET.  Those two writes are not trapped -- the hardware takes them --
     * and by then HCR_EL2.NV is usually off, so the ERET is not trapped
     * either: the hardware performs it at EL1, where it consumes ELR_EL1 and
     * SPSR_EL1, which under the host extensions are the pair the guest calls
     * its EL2 one.  Those still hold zero, so the monitor is entered at
     * address zero and takes an instruction abort on its first fetch --
     * measured, ESR_GL1 0x82000005 with FAR and ELR both zero.
     *
     * There is nowhere to intercept the writes, so mirror instead: whenever
     * the guarded bank names a return that exists, put it where a hardware
     * ERET will look.  The window is real -- SPTM touches SPRR_UPERM_EL0,
     * MDSCR_EL1, APCTL_EL1 and SCTLR_EL1 between setting the pair and the
     * ERET, and those do trap.
     */
    if (ohv_cfg(mirror_gl1) &&
        ((e->vmexit_esr >> 26) & 0x3f) == 0x18) {
        ohv_raw_trap(OHV_TRAP_VCPU_SYSREGS_SYNC, nullptr);
        uint64_t gelr = *ohv_rw_u64(s->ctx, OHV_RW_EXTREGS + 51 * 8);
        uint64_t gspsr = *ohv_rw_u64(s->ctx, OHV_RW_EXTREGS + 52 * 8);

        if (gelr != 0 && gspsr != 0) {
            volatile uint64_t *elr =
                ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 3 * 8);
            volatile uint64_t *spsr =
                ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 14 * 8);

            if (*elr != gelr || *spsr != gspsr) {
                *elr = gelr;
                *spsr = gspsr;
                mark_dirty(s->ctx, OHV_STATE_SYSREGS);
                if (ohv_trace_on(OHV_TRACE_ERET)) {
                    static unsigned n;

                    if (n < 8) {
                        n++;
                        fprintf(stderr, "[ohv] mirrored guarded return"
                                " %#llx/%#llx at pc %#llx\n",
                                (unsigned long long)gelr,
                                (unsigned long long)gspsr,
                                (unsigned long long)ohv_rw(s->ctx)->regs.pc);
                    }
                }
            }
        }
    }
    /*
     * Whether the kernel is carrying the guarded bank at all.  It only does so
     * while ARM_GUEST_STATE_GXF (bit 58) is in state_used, and it sets that
     * bit when it services a trapped GXF_CONFIG/ENTRY/PABENTRY access -- so
     * this says, in one word, whether the traps we asked for are happening.
     */
    if (ohv_trace_on(OHV_TRACE_GXFSTATE)) {
        static unsigned n;

        static uint64_t last = ~0ull;
        uint64_t now = *ohv_ro_u64(s->ctx, OHV_RO_STATE_USED);

        if (n < 60 && now != last) {
            last = now;
            n++;
            fprintf(stderr, "[ohv] state_used %#llx (GXF %s, SPRR %s)"
                    " hacr %#llx pc %#llx\n",
                    (unsigned long long)*ohv_ro_u64(s->ctx, OHV_RO_STATE_USED),
                    (*ohv_ro_u64(s->ctx, OHV_RO_STATE_USED) & (1ull << 58))
                        ? "yes" : "no",
                    (*ohv_ro_u64(s->ctx, OHV_RO_STATE_USED) & (1ull << 59))
                        ? "yes" : "no",
                    (unsigned long long)ohv_rw_controls(s->ctx)->hacr_el2,
                    (unsigned long long)ohv_rw(s->ctx)->regs.pc);
        }
    }
    /*
     * Put NV back on once the monitor is running.
     *
     * SPTM's handover to TXM is MSR ELR_GL1 / MSR SPSR_GL1 and an ERET.  Those
     * writes are never trapped, so the only chance to put that pair where a
     * hardware ERET will look for it -- the guest's EL2 pair, which under the
     * host extensions is the banked EL1 one -- is to trap the ERET itself, and
     * that needs HCR_EL2.NV.  iBoot leaves NV off: the emulation above clears
     * it whenever the guest hypervisor returns to its EL1, and iBoot enters
     * SPTM with a branch, not an ERET, so nothing turns it back on.
     *
     * Measured: with the ERET trapped the monitor is entered correctly and TXM
     * runs to its secure boot check; without, it is entered at zero and takes
     * an instruction abort on its first fetch.  The difference is only whether
     * NV happened to still be set, which is why it worked once and not again.
     *
     * ONLY FOR A CHAIN THAT HAS ONE.  The test below is otherwise nothing but
     * "the guest's PC is a kernel virtual address", which on 17 means SPTM and
     * on 15 and 16 means **XNU** -- so the whole kernel era ran with NV put
     * back on, one exit after the handoff had cleared it.  What that costs is
     * not the trap: with NV set the guest's `CurrentEL` reads EL2, so XNU's
     * `start.s` takes its E2H/TGE arm and configures itself as a VHE kernel
     * however the ROM returned to it, and the EL1 handoff has no effect at
     * all.  Measured on 19A348: 6.3M exits with NV set, SPSR_EL1 written by
     * the guest carrying M = EL2t, 682 trapped ERETs on cpu0 in one boot, and
     * one of those emulations leaving the guest at `preempt_underflow` on the
     * user's register file.
     *
     * This is identical for 17.  During the firmware era the PC is iBoot's,
     * not a kernel address, so the old test did not fire either; from the
     * handoff on, a chain with a monitor has sent the signal and the two
     * conditions agree.
     *
     * TRIED AND REVERTED 2026-09-09.  Gating this on ohv_monitor_told() --
     * so a chain with no monitor never re-arms -- is defensible on its face
     * and does **not** fix the ppl_exit underflow panic: same instruction,
     * same caller, and the exit mix got worse (NV set on 68.5M exits against
     * 6.3M before, of a larger total).  So NV re-arming is not what leaks the
     * guarded state.  Recorded here so the next reader does not spend the
     * experiment again.  The reasoning that led there, still unrefuted as a
     * description of the failure:
     *
     * The test below is nothing but "the guest's
     * PC is a kernel virtual address", which on a chain with a monitor means
     * SPTM -- and on 15.0.1, which has none, means **XNU**.  So the whole
     * kernel era ran with NV put back on, one exit after the handoff cleared
     * it: measured 6.3 million exits with NV set against 67.5 million without,
     * on a boot entered at EL1 precisely so that it would have none.
     *
     * What that costs is not the trap.  With NV set the guest's ERETs are
     * trapped and emulated here, and this side cannot lower the guarded
     * level (`hvf_gexit_no_bql` says so), so the guarded state survives the
     * return to EL0: userspace then runs guarded, its next `svc` vectors
     * through VBAR_GL1 into PPL's exception path, and `ppl_exit` runs on the
     * user's register file -- x16 still the syscall number, SP still the user
     * stack -- and panics in its own underflow check, "Preemption count
     * negative on thread".  Reproduced twice at the same instruction.
     *
     * `ohv_monitor_told()` is the ROM saying a monitor runs next, and the
     * ROM only says it when there is one (a `cbz` in its SPTM handoff path).
     * The ROM's own source predicted this: "arming a trap for a guarded ERET
     * that never comes leaves the kernel running with NV set".
     */
    if (ohv_cfg(monitor_nv) &&
        g_monitor_next.load(std::memory_order_relaxed) &&
        ohv_rw(s->ctx)->regs.pc >= 0xfffffff000000000ull &&
        (ohv_rw_controls(s->ctx)->hcr_el2 & OHV_HCR_NV) == 0) {
        ohv_rw_controls(s->ctx)->hcr_el2 |= OHV_HCR_NV;
        mark_dirty(s->ctx, OHV_STATE_CONTROLS);
        if (ohv_trace_on(OHV_TRACE_ERET)) {
            fprintf(stderr, "[ohv] NV re-armed for the monitor at pc %#llx\n",
                    (unsigned long long)ohv_rw(s->ctx)->regs.pc);
        }
    }
    /*
     * What the kernel is faulting on.  Once XNU is running its exceptions are
     * its own -- they never reach here -- so the only account of them is the
     * banked pair it took them with: ELR_EL1 where it faulted, FAR_EL1 the
     * address, ESR_EL1 why.  Printed when the reason changes, so a loop says
     * so once rather than a million times.
     */
    if (ohv_trace_on(OHV_TRACE_KFAULT) &&
        ohv_rw(s->ctx)->regs.pc >= 0xfffffff000000000ull) {
        static uint64_t last_esr = ~0ull;
        uint64_t esr = *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 5 * 8);

        if (esr != last_esr) {
            last_esr = esr;
            fprintf(stderr, "[ohv] kernel esr %#llx far %#llx elr %#llx"
                    " (pc %#llx)\n",
                    (unsigned long long)esr,
                    (unsigned long long)*ohv_rw_u64(s->ctx,
                        OHV_RW_BANKED_SYSREGS + 4 * 8),
                    (unsigned long long)*ohv_rw_u64(s->ctx,
                        OHV_RW_BANKED_SYSREGS + 3 * 8),
                    (unsigned long long)ohv_rw(s->ctx)->regs.pc);
        }
    }
    /*
     * The guest's own exception state, whenever it changes.
     *
     * A nested panic prints nothing: the first one has not reached a console
     * yet when the second halts the machine, so the halt tells you only that
     * it happened.  What the kernel took is in its banked EL1 registers, and
     * they are in the shared page -- ESR at slot 5, FAR at 4, ELR at 3.
     * Printing on change gives the first fault as well as the last.
     */
    {
        /*
         * Opened by the first exit taken anywhere in the kernel image, not by
         * the first fault there.  Gating on a fault opened it far too late:
         * the interrupt this is meant to catch is one the kernel takes before
         * it has faulted even once, so the trace stayed silent and read as
         * "no interrupt was delivered".
         */
        uint64_t pc_now = ohv_rw(s->ctx)->regs.pc;

        /*
         * Any kernel virtual address, not one release's window.
         *
         * This used to be the band 21A329's kernelcache happens to land in,
         * which on 19A348 -- text base 0xfffffff029adc000 -- is never
         * reached, so `g_kernel_running` stayed false for the whole run and
         * every trace gated on it printed nothing at all.  Read as "the timer
         * never fires" that is exactly the trap of arguing from an absent
         * line.  The firmware runs at 0x1fc0_0000-odd, well below this, so
         * the boundary the flag actually wants is the kernel half of the
         * address space.
         */
        if (pc_now >= 0xfffffff000000000ull) {
            g_kernel_running = true;
        }
        /*
         * What the timers look like as the kernel comes up, and for a few
         * exits after.  No software path delivers an interrupt in this era --
         * measured, on both the pending-interrupt call and the vGIC list
         * registers, with the AIC line never rising -- yet the kernel takes
         * one and dies dispatching it.  A timer the hardware still has armed
         * is the only source left, and this side keeps CNTP_CVAL in *host*
         * counter units with the guest's control word in a shadow, so a value
         * left over from before the handoff would fire at a moment nothing
         * expects.
         */
        /*
         * Any exit at which a virtual interrupt is pending, once the kernel is
         * up.  Measured at the kernel's first instructions, both are clear and
         * no controller, injection call or timer accounts for one -- so the
         * one it dies on appears later, and only a level check catches the
         * moment it does.
         */
        if (ohv_trace_on(OHV_TRACE_KTIMER)) {
            uint64_t h = ohv_rw_controls(s->ctx)->hcr_el2;

            /*
             * Bounded by where the guest is, not by a count.  SPTM services
             * USB the whole time with a virtual IRQ legitimately pending, and
             * a capped trace spends itself entirely on that before the kernel
             * ever runs -- the range is what separates the two.
             */
            if ((h & (3ull << 6)) != 0 &&
                pc_now >= 0xfffffff06b000000ull &&
                pc_now < 0xfffffff070000000ull) {
                fprintf(stderr, "[ohv] vint: pc %#llx VI %d VF %d\n",
                        (unsigned long long)pc_now,
                        (h & (1ull << 7)) ? 1 : 0, (h & (1ull << 6)) ? 1 : 0);
            }
        }
        if (ohv_trace_on(OHV_TRACE_KTIMER) && g_kernel_running) {
            static unsigned n;

            if (n < 8) {
                uint64_t pct;

                __asm__ volatile("mrs %0, cntpct_el0" : "=r"(pct));
                n++;
                /*
                 * VI and VF as a level, not as a transition.  A virtual
                 * interrupt left pending from before the kernel started is
                 * invisible to every edge-triggered check: no controller
                 * raises a line, no injection call changes state, and the
                 * guest still takes one the moment it unmasks.
                 */
                fprintf(stderr, "[ohv] ktimer %u: pc %#llx cntpct %#llx"
                        " hcr %#llx VI %d VF %d"
                        " p_ctl_shadow %#llx p_ctl_banked %#llx p_cval %#llx"
                        " v_ctl %#llx v_cval %#llx\n",
                        n, (unsigned long long)pc_now,
                        (unsigned long long)pct,
                        (unsigned long long)ohv_rw_controls(s->ctx)->hcr_el2,
                        (ohv_rw_controls(s->ctx)->hcr_el2 & (1ull << 7)) ? 1 : 0,
                        (ohv_rw_controls(s->ctx)->hcr_el2 & (1ull << 6)) ? 1 : 0,
                        (unsigned long long)s->el2_shadow[OHV_SHADOW_CNTP_CTL],
                        (unsigned long long)*ohv_rw_u64(s->ctx,
                            OHV_RW_BANKED_SYSREGS + 19 * 8),
                        (unsigned long long)*ohv_rw_u64(s->ctx,
                            OHV_RW_BANKED_SYSREGS + 10 * 8),
                        (unsigned long long)*ohv_rw_u64(s->ctx,
                            OHV_RW_BANKED_SYSREGS + 18 * 8),
                        (unsigned long long)*ohv_rw_u64(s->ctx,
                            OHV_RW_BANKED_SYSREGS + 9 * 8));
            }
        }
    }
    if (ohv_trace_on(OHV_TRACE_FAULT)) {
        static uint64_t last_esr, last_elr;
        uint64_t esr = *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 5 * 8);

        uint64_t felr = *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 3 * 8);

        /*
         * Only the monitor's and the kernel's own faults.  iBoot raises a
         * million supervisor calls on the way here, and printing them costs
         * more than the guest does -- enough to push the run into a stall
         * before it reaches the part worth seeing.
         */
        /*
         * A platform error is worth reporting whether or not the syndrome has
         * changed since the last exit.  XNU calls one of these fatal before it
         * looks at the exception class at all -- `is_platform_error` in
         * sleh_synchronous -- and the panic it raises names only the error
         * registers, not what was touched.  The syndrome that caused it is
         * usually overwritten by the abort the panic path takes next, so the
         * change-triggered print below never sees it.
         *
         * These are the fault codes XNU treats that way: a synchronous
         * external abort, the same on a translation table walk, and parity.
         */
        {
            uint64_t ec = (esr >> 26) & 0x3f;
            uint64_t fsc = esr & 0x3f;

            /*
             * EC 0x2f is the same story from the asynchronous side: XNU's
             * fleh_serror hands it to sleh_serror, which reports it as an
             * implementation specific error and panics.  Nothing here injects
             * a virtual SError -- hv_vcpu_set_serror answers HV_UNSUPPORTED --
             * so one arriving in the guest came from the machine.
             */
            if (ec == 0x2f ||
                ((ec == 0x20 || ec == 0x21 || ec == 0x24 || ec == 0x25) &&
                 (fsc == 0x10 || (fsc >= 0x14 && fsc <= 0x18) ||
                  (fsc >= 0x1c && fsc <= 0x1f)))) {
                fprintf(stderr, "[ohv] platform error: esr %#llx (ec %#llx"
                        " fsc %#llx) far %#llx elr %#llx pc %#llx\n",
                        (unsigned long long)esr, (unsigned long long)ec,
                        (unsigned long long)fsc,
                        (unsigned long long)*ohv_rw_u64(s->ctx,
                            OHV_RW_BANKED_SYSREGS + 4 * 8),
                        (unsigned long long)felr,
                        (unsigned long long)ohv_rw(s->ctx)->regs.pc);
            }
        }
        if ((esr != last_esr || felr != last_elr) && esr != 0 &&
            felr >= 0xfffffff000000000ull) {
            last_esr = esr;
            last_elr = felr;
            /*
             * TPIDR_EL1 comes along because the wall this is chasing is
             * XNU's own "TPIDR is corrupted?" case: the SP1 vector reads
             * thread->machine.CpuDatap and deadloops when it is null.
             * Whether the pointer looks like a thread decides between a
             * thread that simply is not current and a register the two
             * guest levels are sharing.
             */
            /*
             * NV comes along because the guest kernel believes it is at EL2
             * while the hardware has it at EL1, so every exception return it
             * writes names EL2t or EL2h.  Those are only legal because NV
             * traps them here to be rewritten.  With NV off the hardware runs
             * one for real, sees a return to a higher EL, and sets PSTATE.IL
             * -- which surfaces as EC 0x0e on whatever instruction comes
             * next.  The one thing that takes NV off and waits for something
             * else to put it back is the guarded ERET, so its flag is worth
             * seeing next to it.
             */
            fprintf(stderr, "[ohv] guest fault: esr %#llx (ec %#llx) far %#llx"
                    " elr %#llx pc %#llx spsr %#llx tpidr_el1 %#llx"
                    " nv %d geret_off %d\n",
                    (unsigned long long)esr,
                    (unsigned long long)((esr >> 26) & 0x3f),
                    (unsigned long long)*ohv_rw_u64(s->ctx,
                        OHV_RW_BANKED_SYSREGS + 4 * 8),
                    (unsigned long long)felr,
                    (unsigned long long)ohv_rw(s->ctx)->regs.pc,
                    (unsigned long long)*ohv_rw_u64(s->ctx,
                        OHV_RW_BANKED_SYSREGS + 14 * 8),
                    (unsigned long long)*ohv_rw_u64(s->ctx,
                        OHV_RW_SHARED_SYSREGS + 1 * 8),
                    (ohv_rw_controls(s->ctx)->hcr_el2 & OHV_HCR_NV) ? 1 : 0,
                    s->nv_off_for_geret ? 1 : 0);
        }
    }
    uint32_t reason = e->vmexit_reason;
    hv_vcpu_exit_t *out = &s->pub_exit;
    uint64_t hpfar = e->vmexit_hpfar;

    out->exception.syndrome = e->vmexit_esr;
    out->exception.virtual_address = e->vmexit_far;
    /*
     * The third word the kernel writes about a fault is the intermediate
     * physical address itself, not HPFAR_EL2: the framework hands it straight
     * to its MMIO handler as an address.  Only the page matters in it -- the
     * offset within the page comes from FAR -- and treating it as a register
     * to shift put the fault a couple of pages away from where it happened,
     * which is a device that is not there.
     */
    out->exception.physical_address =
        (hpfar & ~0xfffull) | (e->vmexit_far & 0xfff);

    /*
     * Note a guest stopped on WFI/WFE, so the interrupt gates can let a level
     * through to it.  Only a synchronous exit carries a syndrome worth
     * reading; anything else clears the flag rather than latching a stale one.
     */
    /*
     * in_wfx is not derived here any more.  A WFI or WFE never arrived as a
     * synchronous exit with EC 0x1 on this path -- traced over a whole boot,
     * 2.29 million withheld levels and the flag was zero in every one of them.
     * The VMM sees the WFx directly, as EC_WFX_TRAP, and says so through
     * ohv_vcpu_set_parked().
     */
    s->last_reason = reason;
    s->last_esr = e->vmexit_esr;

    /*
     * Once per vCPU, the first time it runs kernel code: which exception
     * level it believes it is at.  Only the core that executes the ROM's
     * handoff ERET has its NV cleared by the emulation; every other vCPU is
     * created with it set and nothing else lowers it, so this says whether
     * the cores disagree about their own level.
     */
    {
        static std::atomic<bool> said[64];
        unsigned slot = (unsigned)s->id < 64 ? (unsigned)s->id : 63;

        if (ohv_rw(s->ctx)->regs.pc >= 0xfffffff000000000ull &&
            !said[slot].exchange(true, std::memory_order_relaxed)) {
            fprintf(stderr, "[ohv] vcpu %llu first kernel pc %#llx rw_nv=%d"
                    " ro_nv=%d guest_at_el2=%d cpsr %#llx\n",
                    (unsigned long long)s->id,
                    (unsigned long long)ohv_rw(s->ctx)->regs.pc,
                    (ohv_rw_controls(s->ctx)->hcr_el2 & OHV_HCR_NV) ? 1 : 0,
                    ((*(volatile uint64_t *)((uint8_t *)s->ctx +
                        OHV_RO_CONTROLS)) & OHV_HCR_NV) ? 1 : 0,
                    s->guest_at_el2 ? 1 : 0,
                    (unsigned long long)ohv_rw(s->ctx)->regs.cpsr);
        }
    }

    /*
     * What the kernel actually reports, counted.
     *
     * The question this answers: the guest's virtual timer is armed in real
     * hardware -- the trapped CNTV writes land in banked slots 18 and 9, which
     * `_hv_load_guest_sysregs` writes into CNTV_CTL_EL02/CNTV_CVAL_EL02 on
     * every entry, and the compare value is kept in the host's counter for
     * exactly that reason -- and the kernel arms APL_INTENABLE_EL2 with all
     * timers before entering.  So reason 3/4 (IRQ/FIQ) ought to arrive when it
     * expires, and `HV_EXIT_REASON_VTIMER_ACTIVATED` ought to follow.  Measured
     * from the VMM side, neither ever does.  This says whether the kernel is
     * silent or the VMM is dropping it.
     */
    if (ohv_trace_on(OHV_TRACE_REASONS)) {
        static std::atomic<unsigned> counts[16];
        static std::atomic<unsigned> el_hist[16];
        static std::atomic<unsigned> msr_class[28];
        static const char *const msr_name[28] = {
            "cnt_ct", "cntv", "cntp", "cnt_other",
            "c1o0_SPRRCFG", "c1o1", "c1o2_GXFCFG", "c1o3", "c1o4",
            "c1o5_UPERM", "c1o6_PPERM", "c1o7",
            "c8o0_GXFSTAT", "c8o1_GXFENT", "c8o2_GXFPAB", "c8o3", "c8o4",
            "c8o5", "c8o6", "c8o7",
            "op1_4", "imp1_1", "imp1_5", "g_rest",
            "gic", "op0_1", "idreg", "other"
        };
        static std::atomic<uint64_t> last_report;
        uint64_t now = mach_absolute_time();
        uint64_t prev = last_report.load(std::memory_order_relaxed);

        counts[reason & 15].fetch_add(1, std::memory_order_relaxed);
        /*
         * And which exception level the guest was at, from PSTATE.M[3:0]:
         * 0 EL0t, 4 EL1t, 5 EL1h, 8 EL2t, 9 EL2h.  Under FEAT_NV2 a guest
         * hypervisor runs at hardware EL1 and is *told* it is at EL2, so
         * what shows here is what the guest believes, which is the thing
         * that decides where its monitor's guarded level lands.
         */
        el_hist[ohv_rw(s->ctx)->regs.cpsr & 15].fetch_add(
            1, std::memory_order_relaxed);
        /*
         * And whether the guest is being *told* it is at EL2: HCR_EL2.NV is
         * bit 42.  PSTATE above is the hardware truth (always EL1 under NV2);
         * this is what CurrentEL answers the guest, and it is what decides
         * whether its monitor's guarded level is GL1 -- which the host kernel
         * carries in hardware -- or GL2, which it does not carry at all.
         */
        el_hist[(ohv_rw_controls(s->ctx)->hcr_el2 >> 42) & 1 ? 14 : 15]
            .fetch_add(1, std::memory_order_relaxed);
        /*
         * And which register the MSR traps are for.  ESR EC 0x18's ISS:
         * [21:20] Op0, [19:17] Op2, [16:14] Op1, [13:10] CRn, [4:1] CRm.
         */
        if (reason == OHV_VMEXIT_MSR_TRAP) {
            uint64_t iss = e->vmexit_esr & 0x1ffffffull;
            unsigned op0 = (unsigned)((iss >> 20) & 3);
            unsigned op1 = (unsigned)((iss >> 14) & 7);
            unsigned crn = (unsigned)((iss >> 10) & 15);
            unsigned crm = (unsigned)((iss >> 1) & 15);
            unsigned op2 = (unsigned)((iss >> 17) & 7);
            unsigned k;

            if (crn == 14 && crm == 0) {
                k = 0;                          /* CNTxCT: the counter */
            } else if (crn == 14 && crm == 3) {
                k = 1;                          /* CNTV_*: the guest's timer */
            } else if (crn == 14 && crm == 2) {
                k = 2;                          /* CNTP_* */
            } else if (crn == 14) {
                k = 3;                          /* the rest of CRn 14 */
            } else if (op0 == 3 && op1 == 6 && crn == 15 && crm == 1) {
                k = 4 + op2;                    /* SPRR_CONFIG 0, GXF_CONFIG 2 */
            } else if (op0 == 3 && op1 == 6 && crn == 15 && crm == 8) {
                k = 12 + op2;                   /* GXF_STATUS 0, ENTRY 1, PAB 2 */
            } else if (op0 == 3 && op1 == 6 && (crn == 15 || crn == 11)) {
                k = 21;                         /* the rest of the guarded bank */
            } else if (op0 == 3 && op1 == 4 && (crn == 15 || crn == 11)) {
                k = 20;                         /* op1=4, mostly ACNTVCT */
            } else if (op0 == 3 && op1 == 1 && (crn == 15 || crn == 11)) {
                k = 21;
            } else if (op0 == 3 && op1 == 5 && (crn == 15 || crn == 11)) {
                k = 22;
            } else if (op0 == 3 && (crn == 15 || crn == 11)) {
                k = 23;
            } else if (crn == 12) {
                k = 24;                         /* GIC interface */
            } else if (op0 == 1) {
                k = 25;                         /* maintenance and AT */
            } else if (crn == 0) {
                k = 26;                         /* the ID registers */
            } else {
                k = 27;
            }
            msr_class[k].fetch_add(1, std::memory_order_relaxed);
        }
        /* 24 MHz counter; report about every five seconds, from whoever gets there. */
        if (now - prev > 120000000ull &&
            last_report.compare_exchange_strong(prev, now)) {
            char line[1536];
            int n = snprintf(line, sizeof(line), "[ohv] reasons:");

            for (unsigned i = 0; i < 16; i++) {
                unsigned c = counts[i].load(std::memory_order_relaxed);

                if (c != 0) {
                    n += snprintf(line + n, sizeof(line) - (size_t)n,
                                  " %u=%u", i, c);
                }
            }
            /*
             * The two words the kernel loads straight into the hardware
             * virtual timer, and the clock they are compared against.
             *
             * `_hv_load_guest_sysregs` writes banked slot 18 into
             * CNTV_CTL_EL02 and slot 9 into CNTV_CVAL_EL02 on every entry,
             * and the kernel reports a guest timer event only when the
             * hardware sets ISTATUS in that control word.  If ENABLE is
             * clear, or the compare value is not in the host counter, the
             * timer can never fire and no amount of arming APL_INTENABLE_EL2
             * will produce one -- which is the thing to rule out before
             * looking anywhere else for the missing VTIMER_ACTIVATED.
             */
            {
                uint64_t ctl = *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 18 * 8);
                uint64_t cval = *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 9 * 8);
                uint64_t now = mach_absolute_time();

                n += snprintf(line + n, sizeof(line) - (size_t)n,
                              " | cntv ctl=%#llx cval=%#llx now=%#llx due=%lld"
                              " tmask=%#llx vfire=%u",
                              (unsigned long long)ctl,
                              (unsigned long long)cval,
                              (unsigned long long)now,
                              (long long)((int64_t)(now - cval)),
                              (unsigned long long)*ohv_rw_u64(s->ctx,
                                  OHV_RW_TIMER),
                              g_vfire.load(std::memory_order_relaxed));
            }
            n += snprintf(line + n, sizeof(line) - (size_t)n, " | el:");
            for (unsigned i = 0; i < 16; i++) {
                unsigned c = el_hist[i].load(std::memory_order_relaxed);

                if (c != 0) {
                    n += snprintf(line + n, sizeof(line) - (size_t)n,
                                  " M%u=%u", i, c);
                }
            }
            n += snprintf(line + n, sizeof(line) - (size_t)n, " | msr:");
            for (unsigned i = 0; i < 28; i++) {
                unsigned c = msr_class[i].load(std::memory_order_relaxed);

                if (c != 0) {
                    n += snprintf(line + n, sizeof(line) - (size_t)n,
                                  " %s=%u", msr_name[i], c);
                }
            }
            fprintf(stderr, "%s\n", line);
        }
    }

    switch (reason) {
        case 0:
            /* The run came back with nothing to report. */
            out->reason = HV_EXIT_REASON_CANCELED;
            return EXIT_TO_VMM;

        case 2: case 7: case 11:
            /* The kernel dealt with it; go back in. */
            return EXIT_KEEP_RUNNING;

        case 12:
            return EXIT_KEEP_RUNNING;

        case 3: case 4: {
            if (ohv_trace_on(OHV_TRACE_IRQ)) {
                static unsigned n;

                if (n < 10) {
                    n++;
                    fprintf(stderr, "[ohv] vcpu %llu physical %s, cntv_ctl"
                            " %#llx timer %#llx\n", (unsigned long long)s->id,
                            reason == 3 ? "IRQ" : "FIQ",
                            (unsigned long long)*ohv_rw_u64(s->ctx,
                                OHV_RW_BANKED_SYSREGS + 18 * 8),
                            (unsigned long long)*ohv_rw_u64(s->ctx,
                                OHV_RW_TIMER));
                }
            }
            /*
             * A physical interrupt.  It is the virtual timer's only when the
             * guest's own timer says it fired and the mask is not already up;
             * anything else here is not this VMM's to be told about.
             */
            uint64_t cntv_ctl = *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS +
                offsetof(ohv_banked_sysregs_t, cntv_ctl_el0));
            uint64_t *timer = (uint64_t *)ohv_rw_u64(s->ctx, OHV_RW_TIMER);

            if ((*timer & OHV_TIMER_MASK) == 0 && cntv_ctl == 5) {
                *timer |= OHV_TIMER_MASK;
                out->reason = HV_EXIT_REASON_VTIMER_ACTIVATED;
                return EXIT_TO_VMM;
            }
            out->reason = HV_EXIT_REASON_UNKNOWN;
            return EXIT_TO_VMM;
        }

        case OHV_VMEXIT_MSR_TRAP:
            /*
             * A trapped register access.  If it names one of the guest
             * hypervisor's own EL2 registers, it is only here because the
             * redirection did not happen; carry it out and go back in rather
             * than handing the VMM a register it has no way to place.
             */
            if (((e->vmexit_esr >> 26) & 0x3f) == 0x18 &&
                service_nv2_access(s, e->vmexit_esr)) {
                return EXIT_KEEP_RUNNING;
            }
            /* fall through */
        case 1:
            /*
             * WFI, spun rather than slept.  A diagnostic: the VMM turns a
             * WFI exit into a halt and waits for work it can only learn
             * about through its own interrupt line, so a guest waiting on
             * something this library delivers never restarts.  Stepping over
             * the instruction says whether the guest is waiting to be woken
             * or waiting for something that never happens.
             */
            if (ohv_cfg(spin_wfi) &&
                ((e->vmexit_esr >> 26) & 0x3f) == 0x1) {
                ohv_rw(s->ctx)->regs.pc += 4;
                return EXIT_KEEP_RUNNING;
            }
            /*
             * A WFE, stepped over here -- which is all the VMM does with one:
             * the program counter moves on and the guest goes back in, and
             * the wake a WFE waits for is another core's store, not anything
             * the VMM holds.  ISS bit 0 is what separates it from a WFI (and
             * takes WFET along with it).  Only while ohv_vmm_line_settled():
             * XNU's idle wait is a WFE too, and the level that ends it may be
             * one only the VMM can raise.
             */
            if (ohv_cfg(wfe_inline) &&
                ((e->vmexit_esr >> 26) & 0x3f) == 0x1 &&
                (e->vmexit_esr & 1) != 0 && ohv_vmm_line_settled(s)) {
                s->in_wfx = true;
                ohv_rw(s->ctx)->regs.pc += 4;
                return EXIT_KEEP_RUNNING;
            }
            /*
             * An HVC out of the guest the guest hypervisor is hosting.  It is
             * that hypervisor's to service, not this library's and not the
             * VMM's, so it goes to its vector table.
             */
            if (((e->vmexit_esr >> 26) & 0x3f) == 0x16 && !s->guest_at_el2 &&
                ohv_cfg(el2_injection)) {
                enter_guest_el2(s, e->vmexit_esr, ohv_rw(s->ctx)->regs.pc + 4);
                if (ohv_trace_on(OHV_TRACE_ERET)) {
                    fprintf(stderr, "[ohv] vcpu %llu hvc -> guest EL2 vector"
                            " %#llx\n", (unsigned long long)s->id,
                            (unsigned long long)ohv_rw(s->ctx)->regs.pc);
                }
                return EXIT_KEEP_RUNNING;
            }
            if (ohv_trace_on(OHV_TRACE_GL1) &&
                ((e->vmexit_esr >> 26) & 0x3f) == 0x1a) {
                static unsigned n;
                /* Only the monitors' own returns; the earlier ones are the
                 * boot ROM's and iBoot's, and they run before GXF exists. */
                bool late = ohv_rw(s->ctx)->regs.pc >= 0xfffffff000000000ull;

                if (late && n < 4) {
                    n++;
                    /* The guarded bank is filled by hardware; ask for it. */
                    ohv_raw_trap(OHV_TRAP_VCPU_SYSREGS_SYNC, nullptr);
                    fprintf(stderr, "[ohv] gl1 dump at pc %#llx\n",
                            (unsigned long long)ohv_rw(s->ctx)->regs.pc);
                    for (unsigned i = 40; i < 62; i++) {
                        uint64_t v = *ohv_rw_u64(s->ctx, OHV_RW_EXTREGS + i * 8);

                        if (v) {
                            fprintf(stderr, "        ext[%u] = %#llx\n", i,
                                    (unsigned long long)v);
                        }
                    }
                }
            }
            if (ohv_trace_on(OHV_TRACE_ERET) &&
                ((e->vmexit_esr >> 26) & 0x3f) == 0x1a) {
                fprintf(stderr, "[ohv] vcpu %llu EC 0x1a: esr %#llx"
                        " at_el2 %d spsr_gl1 %#llx elr %#llx spsr %#llx"
                        " pc %#llx\n",
                        (unsigned long long)s->id,
                        (unsigned long long)e->vmexit_esr,
                        (int)s->guest_at_el2,
                        (unsigned long long)*ohv_rw_u64(s->ctx,
                                                        OHV_EXT_SPSR_GL1),
                        (unsigned long long)*ohv_rw_u64(s->ctx,
                            OHV_RW_BANKED_SYSREGS + 3 * 8),
                        (unsigned long long)*ohv_rw_u64(s->ctx,
                            OHV_RW_BANKED_SYSREGS + 14 * 8),
                        (unsigned long long)ohv_rw(s->ctx)->regs.pc);
            }
            /*
             * A guarded return, performed by the hardware rather than here.
             *
             * The guarded level is not something this side can restore: the
             * bit SPTM sets in the value it writes -- 0x13c0, EL0t *and
             * guarded* -- is not kept by SPSR_GL1, which reads back 0x3c0,
             * and the level being returned to lives somewhere only the
             * hardware's own ERET consults.  Completing the return by writing
             * PC and PSTATE therefore lands the monitor at plain EL0, where
             * the address it was given is not executable, and the guarded
             * prefetch-abort entry catches it: SPTM stops in its own dead
             * loop with the machine looking healthy.
             *
             * So put the pair where a hardware ERET at this level looks for
             * it -- the guest's own EL2 pair, which with the host extensions
             * on is the banked EL1 one -- take NV off so the instruction is
             * no longer trapped, and let it re-execute.  Everything the
             * guarded transition needs is then the silicon's to do.
             */
            /*
             * On by default: without it the trapped guarded ERET falls
             * through to a software completion that returns at EL0, and TXM
             * is entered there -- its first instruction fetch aborts from a
             * lower level and SPTM deadloops.  Letting the silicon do the
             * transition is the whole point, so the switch only turns it off.
             */
            if (ohv_cfg(hw_geret) &&
                ((e->vmexit_esr >> 26) & 0x3f) == 0x1a &&
                (e->vmexit_esr & 1) == 0) {
                uint64_t gspsr = 0;

                if (eret_is_guarded(s, &gspsr)) {
                    uint64_t gelr =
                        *ohv_rw_u64(s->ctx, OHV_RW_EXTREGS + 51 * 8);

                    report_illegal_eret(s, "guarded, left to the hardware", gelr, gspsr, true);
                    *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 3 * 8) = gelr;
                    *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 14 * 8) = gspsr;
                    mark_dirty(s->ctx, OHV_STATE_SYSREGS);
                    ohv_rw_controls(s->ctx)->hcr_el2 &= ~OHV_HCR_NV;
                    mark_dirty(s->ctx, OHV_STATE_CONTROLS);
                    s->nv_off_for_geret = true;
                    if (ohv_trace_on(OHV_TRACE_ERET)) {
                        fprintf(stderr, "[ohv] guarded ERET left to the"
                                " hardware: elr %#llx spsr %#llx pc %#llx\n",
                                (unsigned long long)gelr,
                                (unsigned long long)gspsr,
                                (unsigned long long)ohv_rw(s->ctx)->regs.pc);
                    }
                    return EXIT_KEEP_RUNNING;
                }
            }
            /*
             * A trapped ERET, which is a guest hypervisor returning into the
             * guest it hosts.  Carrying it out is not only PC and PSTATE: the
             * level the guest believes it is at changes with it, and that is
             * HCR_EL2.NV.  Left on, the guest arrives at its own EL1 and
             * every CurrentEL it reads still answers EL2 -- which the first
             * thing SEP's ROM does is check, and take the other branch on.
             */
            if (((e->vmexit_esr >> 26) & 0x3f) == 0x1a &&
                (e->vmexit_esr & 1) == 0 && s->guest_at_el2 &&
                !eret_is_guarded(s, nullptr) &&
                ohv_cfg(eret_emulation)) {
                ohv_rw_page_head_t *rw = ohv_rw(s->ctx);
                /*
                 * The return pair is the hardware's ELR_EL1 and SPSR_EL1, not
                 * the VNCR copies: with the host extensions on, the guest
                 * hypervisor's return registers are the ones it is actually
                 * running with.  Measured -- SEP's ROM leaves the address of
                 * its own next instruction in ELR_EL1 and 0x3c5 in SPSR_EL1
                 * before returning to its EL1.
                 *
                 * A guarded return is not this.  It comes out of the guarded
                 * bank, only the VMM can lower the guarded level, and it is
                 * left for the VMM to complete.
                 */
                uint64_t elr = *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 3 * 8);
                uint64_t spsr = *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + 14 * 8);
                uint32_t mode = (uint32_t)spsr & 0xf;

                /*
                 * Which level the guest is returning to decides whether it
                 * stops being a hypervisor.
                 *
                 * To its own EL1: yes, and HCR_EL2.NV comes off, or every
                 * CurrentEL it reads there still answers EL2.
                 *
                 * To EL0: no.  The guest hypervisor's EL0 tasks come back to
                 * it with an SVC, and that is an exception from EL0 to EL1 --
                 * hardware handles it end to end and nothing here sees it.
                 * Clearing NV on the way down would leave the guest running
                 * its own EL2 code without it, and the first Apple register
                 * only EL2 may touch becomes an undefined instruction: the
                 * payload takes a synchronous exception it has no business
                 * taking and panics.  NV means nothing at EL0 anyway, so it
                 * costs nothing to leave it on.
                 *
                 * To EL2 (EL2t or EL2h in the saved PSTATE): the guest
                 * hypervisor is returning to itself, and the hardware level
                 * stays EL1 underneath it.
                 */
                report_illegal_eret(s, "completed here", elr, spsr, false);
                rw->regs.pc = elr;
                rw->regs.cpsr = (uint32_t)spsr;
                if (mode == 0x4 || mode == 0x5) {
                    s->guest_at_el2 = false;
                    /*
                     * Only the handoff, not the ROM's own returns.
                     *
                     * start.S erets to EL1 during its own bring-up, long
                     * before any kernel exists, and taking those as the
                     * machine's answer clears NV for every application core
                     * while the ROM still needs EL2 -- measured, the boot
                     * stops before it prints a byte.  The handoff is the one
                     * whose target is a kernel virtual address.
                     */
                    if (elr >= 0xfffffff000000000ull) {
                        g_guest_left_el2.store(true, std::memory_order_relaxed);
                        /*
                         * Nothing to do for the other cores: they were never
                         * created as hypervisors.  Reaching into their pages
                         * from here was a data race and is gone.
                         */
                    }
                    ohv_rw_controls(s->ctx)->hcr_el2 &= ~OHV_HCR_NV;
                    mark_dirty(s->ctx, OHV_STATE_CONTROLS);
                    if (ohv_trace_on(OHV_TRACE_ERET)) {
                        fprintf(stderr, "[ohv] vcpu %llu eret -> %#llx spsr"
                                " %#llx, NV cleared, hcr now %#llx\n",
                                (unsigned long long)s->id,
                                (unsigned long long)elr,
                                (unsigned long long)spsr,
                                (unsigned long long)ohv_rw_controls(s->ctx)->hcr_el2);
                    }
                } else if (mode == 0x8 || mode == 0x9) {
                    /* Staying at EL2 means staying at hardware EL1. */
                    rw->regs.cpsr = (uint32_t)((spsr & ~0xfu) | (mode - 4));
                    if (ohv_trace_on(OHV_TRACE_ERET)) {
                        fprintf(stderr, "[ohv] vcpu %llu eret stays at EL2"
                                " -> %#llx spsr %#llx\n",
                                (unsigned long long)s->id,
                                (unsigned long long)elr,
                                (unsigned long long)spsr);
                    }
                }
                return EXIT_KEEP_RUNNING;
            }
            /* fall through */
        case 6:
            /*
             * A guest exception, which is the VMM's to service.  Two of the
             * three arrive without a syndrome the VMM could act on, so it is
             * built here: a trapped system register access out of the
             * instruction, and a guarded exit out of the exception class the
             * framework gives it.
             */
            /*
             * Only when the kernel left the syndrome empty.  It rarely does
             * now that it is read from the right place, and overwriting a
             * syndrome the kernel did supply with one decoded from an
             * instruction fetched at a guest virtual address -- read as if it
             * were physical -- is how a trapped register access turns into a
             * different register entirely once the guest MMU is on.
             */
            if (e->vmexit_esr == 0) {
                if (reason == OHV_VMEXIT_MSR_TRAP) {
                    synth_msr_trap_syndrome(s, out);
                } else if (reason == 1) {
                    synth_guarded_exit_syndrome(s, out);
                }
            }
            out->reason = HV_EXIT_REASON_EXCEPTION;
            return EXIT_TO_VMM;

        default:
            if (ohv_trace_on(OHV_TRACE_EXIT)) {
                fprintf(stderr, "openhyp: kernel vmexit reason %u, esr %#llx"
                        " far %#llx hpfar %#llx pc %#llx -- not classified\n",
                        reason, (unsigned long long)e->vmexit_esr,
                        (unsigned long long)e->vmexit_far,
                        (unsigned long long)hpfar,
                        (unsigned long long)ohv_rw(s->ctx)->regs.pc);
            }
            out->reason = HV_EXIT_REASON_UNKNOWN;
            return EXIT_TO_VMM;
    }
}

// ------------------------------------------------------------ create/free --
/*
 * What a core the ROM never runs on has to inherit in its *guest* HCR_EL2 --
 * the word at OHV_NESTED_HCR_EL2 in its VNCR page, which the guest reads and
 * writes, not the one this library runs the vCPU with.
 *
 * On the part every core resets into EL2 and the reset path leaves RW|APK|API
 * there; SPTM then adds E2H and TGE itself (`mrs x10, hcr_el2` /
 * `orr x10, x10, #0x8000000`, four sites) and checks the result against
 * RW|E2H|APK|API exactly.  Here only cpu0 runs the ROM, so only cpu0 inherits
 * anything: a fresh vCPU's word is the framework's bare RW, and measurement
 * says what each wrong answer costs.
 *
 *   bare RW             SPTM's TGE write was being sunk by the ROM, so TGE
 *                       stayed 0 and each of XNU's eight vector slots read
 *                       `CurrentEL == EL2 && TGE == 0` as "this exception
 *                       belongs to the guest I am running" -- under FEAT_NV the
 *                       first half is true by construction.  The core's first
 *                       exception of any class entered the hv guest handler and
 *                       panicked dereferencing TPIDR_EL2 (24A437).
 *   RW|E2H|TGE|APK|API  arranged here, ahead of SPTM, it also reaches SPTM's
 *                       own check, which then fails and takes the core into
 *                       SPTM's exception vector (past launchd's ignition,
 *                       then "cpu 1 failed to boot").
 *   RW|E2H|TGE          what SPTM's own write makes of a bare RW once the ROM
 *                       stops sinking it -- TGE right, APK|API lost, so the
 *                       guest's pointer-auth keys trap (the same
 *                       "cpu 1 failed to boot").
 *
 * So: the reset value, and nothing else.  ohv_set_nested_inherit(false) puts the bare
 * word back, for the A/B.
 */
static uint64_t ohv_nested_reset_hcr() {
    if (!ohv_cfg(nested_inherit)) {
        return OHV_HCR_RW;
    }
    return OHV_HCR_RW | OHV_HCR_APK | OHV_HCR_API;
}

/*
 * The layout this kernel's context pages have (ohv_context.h).  Set once, by
 * the first vCPU, under g_vcpus_mutex; every later vCPU is created under the
 * same mutex, so each sees it before it can run.
 */
const ohv_hv_layout_t *ohv_layout;

/*
 * Its row: by the version word, and by the build (kern.osversion) when the
 * word names none.  Kernels before macOS 26.4 keep no copy of the word for a
 * kit to be read for, so their rows carry ver 0 and are known only by the
 * builds whose kits they came from -- and a build's own kit is the layout,
 * whatever word it reports.
 */
static const ohv_hv_layout_t *ohv_layout_for(uint64_t ver) {
    for (const ohv_hv_layout_t &l : ohv_hv_layouts)
        if (l.ver == ver) return &l;

    char build[32] = {};
    size_t n = sizeof(build) - 1;

    if (sysctlbyname("kern.osversion", build, &n, nullptr, 0) != 0 || !build[0])
        return nullptr;

    size_t len = strlen(build);

    for (const ohv_hv_layout_t &l : ohv_hv_layouts)
        for (const char *p = l.builds; (p = strstr(p, build)) != nullptr; p += len)
            if ((p == l.builds || p[-1] == ' ') && (p[len] == ' ' || p[len] == '\0'))
                return &l;
    return nullptr;
}

extern "C" hv_return_t hv_vcpu_create(hv_vcpu_t *vcpu_out, hv_vcpu_exit_t **exit, hv_vcpu_config_t config) {
    if (!vcpu_out || !exit) return HV_BAD_ARGUMENT;
    if (!g_vm_alive) return HV_NO_DEVICE;
    if (tl_current_vcpu) return HV_BUSY; // one vcpu per thread

    pthread_mutex_lock(&g_vcpus_mutex);
    hv_vcpu_t id = kMaxVcpuIds;
    for (uint64_t i = 0; i < kMaxVcpuIds; i++)
        if (!g_vcpus[i].used) { id = i; break; }
    if (id == kMaxVcpuIds) { pthread_mutex_unlock(&g_vcpus_mutex); return HV_NO_RESOURCES; }

    ohv_vcpu_create_t args{ id, 0 };
    hv_return_t r = ohv_raw_trap(OHV_TRAP_VCPU_CREATE, &args);
    if (r != HV_SUCCESS) { pthread_mutex_unlock(&g_vcpus_mutex); return r; }

    void *ctx = (void *)(uintptr_t)args.interface;
    uint64_t ver = *(volatile uint64_t *)((uint8_t *)ctx + OHV_RO_VER);
    if ((ver >> 32) != OHV_STATE_VER_MAGIC) {
        ohv_raw_trap(OHV_TRAP_VCPU_DESTROY, nullptr);
        pthread_mutex_unlock(&g_vcpus_mutex);
        return HV_ERROR;
    }
    if (!ohv_layout) {
        ohv_layout = ohv_layout_for(ver);
        if (!ohv_layout) {
            fprintf(stderr, "[ohv] hv interface %llu.%llu.%llu (%#llx) has no row in"
                    " ohv_hv_layouts.h: refusing to guess at its context layout\n",
                    (unsigned long long)((ver >> 24) & 0xff),
                    (unsigned long long)((ver >> 16) & 0xff),
                    (unsigned long long)(ver & 0xffff), (unsigned long long)ver);
            ohv_raw_trap(OHV_TRAP_VCPU_DESTROY, nullptr);
            pthread_mutex_unlock(&g_vcpus_mutex);
            return HV_UNSUPPORTED;
        }
        fprintf(stderr, "[ohv] hv interface %llu.%llu.%llu: context layout %s\n",
                (unsigned long long)((ver >> 24) & 0xff),
                (unsigned long long)((ver >> 16) & 0xff),
                (unsigned long long)(ver & 0xffff), ohv_layout->id);
    }

    VcpuSlot &s = g_vcpus[id];
    s.used = true;
    s.ctx = ctx;
    s.id = id;
    s.owner = pthread_self();
    s.run_count = 0;
    if (ohv::g_vm_el2) {
        /*
         * Turn the guest into a guest hypervisor: NV, NV1 and NV2 in its
         * HCR_EL2, plus E2H when it is to see the host-extension form.  These
         * are what make an EL1 guest believe it is at EL2; without them the
         * kernel has an ordinary EL1 guest and refuses anything else.
         */
        volatile uint64_t *controls = (volatile uint64_t *)ohv_rw_controls(s.ctx);
        /*
         * Only the core that runs the firmware is a guest hypervisor.
         *
         * The ROM, LLB and iBoot all run at EL2 and only ever on the boot
         * core; the secondaries sit at the reset vector until the kernel
         * releases them, and by then a chain with no monitor is at EL1 and
         * they never need NV at all.  Giving it to them at creation, as a
         * property of the VM, is what made the cores disagree about their own
         * exception level: measured on 19A348 entered at EL1, cpu0 at nv=0
         * and cpu1..4 at nv=1 by their first kernel instruction, ending in
         * `Illegal instruction set exception ... class=14`.  Clearing it
         * afterwards was chased through four separate setters and a
         * cross-thread write into their pages; not handing it out is the
         * shorter answer.
         *
         * A chain that does have a monitor gets it back when the ROM says so
         * -- the same signal that arms NV on this core -- and the secondaries
         * are still parked at that moment, which is why writing their pages
         * from there is safe where doing it later is not.
         */
        uint64_t nested = ohv_cfg(hcr_nested_mask);
        uint64_t hcr = controls[0] | (id == 0 ? nested :
                                      (nested & ~(OHV_HCR_NV | OHV_HCR_NV2)));

        if (ohv::g_vm_vhe) {
            hcr |= OHV_HCR_E2H;
        } else {
            hcr &= ~OHV_HCR_E2H;
        }
        /*
         * What the framework leaves on a vCPU of its own, on top of what the
         * kernel hands out: two more traps in HCR_EL2 and one bit in
         * HACR_EL2, which is Apple's own hypervisor control and has no
         * architected meaning to go by.  Measured against a framework vCPU
         * side by side with one of ours, where these were the only controls
         * that differed.
         */
        hcr |= OHV_HCR_TID3 | OHV_HCR_TSC;
        /*
         * Trap the stage-1 TLB maintenance instructions.  With one nested
         * address space -- one VMID -- per vCPU, a TLBI the guest executes
         * natively reaches no other core's translations; each one has to be
         * performed by the kernel in every space instead (ohv_tlbi_replay).
         */
        if (ohv_tlbi_replay_on() && !(hcr & OHV_HCR_NV)) {
            hcr |= OHV_HCR_TTLB;
        }
        /*
         * Route the physical exceptions to EL2, which is what makes HCR_EL2.VI
         * and VF -- the only way anything here has of handing the guest an
         * interrupt -- mean anything at all.  The kernel forces all three on
         * anyway (they are in its fixed HCR set), so this changes no bit on
         * the way in; it is here so the value we ask for says what we rely on
         * rather than leaving it to a default we do not own.
         */
        hcr |= OHV_HCR_AMO | OHV_HCR_IMO | OHV_HCR_FMO;
        /*
         * Trap WFE, so a parked core is a core this side can hear from.
         *
         * The interrupt gates are evaluated at exits.  A WFI exits, but a WFE
         * without HCR_EL2.TWE does not: the core simply stops inside the
         * guest and nothing on this side runs again for it.  XNU's idle wait
         * is a WFE --
         *
         *     mrs x13, ISR_EL1 ; cbnz x13, out ; wfe ; cmn x1, #1 ; b.eq loop
         *
         * -- and it leaves only when ISR_EL1 goes non-zero, which is to say
         * only when the level this side is withholding goes up.  Without the
         * trap that is a closed circle: the level is held because PSTATE has
         * the mask bit set, and the mask bit can never change because the
         * core is not running.  Measured at a stall: the panicking core sent
         * the debugger's cross-call to all five others and only the one whose
         * FIQ line was still clear answered; the other four had a pending
         * IPI_SR bit from an earlier one they had never been able to take.
         *
         * With the trap, the WFE is the exit, the VMM reports it through
         * ohv_vcpu_set_parked(), and a parked core is exactly the case the
         * gate can always say yes to.  ohv_set_trap_wfe(false) puts the old behaviour
         * back.
         */
        if (ohv_cfg(trap_wfe)) {
            hcr |= OHV_HCR_TWE;
        }
        /*
         * ohv_set_hcr_tidcp(false) hands the Apple registers back to the kernel.
         *
         * The kernel's own default for a new vCPU is HCR_TIDCP | HCR_API |
         * HCR_APK, and this library inherits it.  With TIDCP standing, every
         * implementation-defined MSR is punted to the VMM before the kernel's
         * handler ever looks at it -- including APCTL_EL1, JCTL and the
         * JITBox keys, which are the ones it knows how to carry into the
         * silicon.  What the VMM does with them instead is keep them in a
         * register file of its own, and the state block they belong to is
         * never marked used, so the hardware keeps whatever the last thing on
         * that physical core left.  With one core that is invisible; with six
         * it is "PAC failure from kernel with IB key" on a thread that signed
         * its return address on one core and returned on another.
         *
         * Cleared, the kernel services the registers it recognises and marks
         * ARM_GUEST_STATE_PTRAUTH_APPLE, JITBOX, SPRR, GXF and CTRR used, so
         * they are saved and restored per vCPU; everything it does not
         * recognise still falls through to the VMM.
         */
        if (ohv_cfg_given(hcr_tidcp)) {
            if (!ohv_cfg(hcr_tidcp)) {
                hcr &= ~OHV_HCR_TIDCP;
            } else {
                hcr |= OHV_HCR_TIDCP;
            }
        }
        /*
         * Which vCPUs keep it -- a bitmap, one bit per vCPU id, and it wins
         * over the switch above.
         *
         * TIDCP is not one decision for the machine.  Clearing it everywhere
         * is what lets the host kernel claim the guest's GXF and SPRR state
         * and carry the guarded bank in hardware, which is worth ~269,000
         * traps a second on the application cores -- but the SEP is a
         * different guest on the same VM, running its own ROM and firmware
         * out of the Apple implementation-defined space, and it is the one
         * that stops working when the registers stop coming here.
         *
         * `ohv_set_tidcp_vcpus(0x40)` keeps it for vCPU 6 alone, which on this
         * machine is the SEP; unset, every vCPU keeps whatever the switch
         * above or the kernel's default gave it.  The line printed per vCPU
         * is how you check the numbering rather than assuming it.
         */
        if (ohv_cfg_given(tidcp_vcpus)) {
            uint64_t keep = ohv_cfg(tidcp_vcpus);

            if (id < 64 && ((keep >> id) & 1) != 0) {
                hcr |= OHV_HCR_TIDCP;
            } else {
                hcr &= ~OHV_HCR_TIDCP;
            }
            fprintf(stderr, "[ohv] vcpu %llu tidcp %s\n",
                    (unsigned long long)id,
                    (hcr & OHV_HCR_TIDCP) != 0 ? "on" : "off");
        }
        /*
         * HCR_EL2.APK is left standing.
         *
         * Taking it off makes the guest's key registers trap here, which is
         * where they would have to land for this library's copy to be the
         * authority -- but measured, the machine
         * then stops in the ROM before a single boot task: the architected
         * encodings are not `hvf_sysreg_is_impdef` (op0 3, CRn 11 or 15), so
         * QEMU's forward path never offers them to the accelerator and the
         * access is lost.  Trapping them needs that route opened first.
         * `ohv_set_trap_pac_keys(true)` takes APK off again.
         */
        if (ohv_cfg(trap_pac_keys)) {
            hcr &= ~OHV_HCR_APK;
        }
        {
            uint64_t m = OHV_HCR_AMO | OHV_HCR_IMO | OHV_HCR_FMO;

            hcr = (hcr & ~m) | (ohv_cfg(hcr_xmo) & m);
        }
        controls[0] = hcr;
        controls[1] = OHV_HACR_APPLE_DEFAULT;
        if (ohv_cfg(hacr_tactl0)) {
            /*
             * The trap that decides whether the kernel or this library owns
             * APCTL_EL1 -- and with it whether the Apple pointer-auth
             * registers are ever carried into the silicon.  The kernel marks
             * ARM_GUEST_STATE_PTRAUTH_APPLE used, and so loads APCTL and
             * KERNKEY, only when it services that trap itself; it declines to
             * whenever this bit is standing.  Settable so the two can be
             * measured against each other.
             */
            controls[1] |= 1ull;
        }
        /*
         * This cannot be used to catch a GENTER, which is what it was tried
         * for.  HACR_EL2.TGXF is already fixed to one in the kernel's own
         * capability set, and what it traps is a GXF *register* access, not
         * the instruction: measured with it asked for explicitly, the boot ran
         * to the same place with the same console and not one exit of an
         * unfamiliar shape appeared.  The GENTER boundary is not observable
         * from this side.
         */
        if (ohv_cfg(trap_gxf)) {
            controls[1] |= OHV_HACR_TGXF;
        }
        /*
         * The fine-grained traps the framework leaves on its own vCPUs, on
         * top of what the kernel hands out.  Measured side by side: these
         * three are the only controls it sets that were still zero here.
         */
        ohv_rw_controls(s.ctx)->hfgrtr_el2 |= 0x2600ull;
        ohv_rw_controls(s.ctx)->hfgwtr_el2 |= 0x2000ull;
        ohv_rw_controls(s.ctx)->hfgitr_el2 |= 0x3f000ull;
        /*
         * The physical timer has to trap.  The guest arms CNTP_CTL_EL0 and
         * waits; left open by CNTHCTL_EL2 that write reaches the real timer,
         * whose interrupt is the host's -- taken by the kernel, with no way
         * back to a guest that is only ever offered virtual ones.  Trapping
         * the timer registers (EL1PTEN, bit 11) puts the compare value in the
         * banked slots where ohv_expire_timers can see it come due and raise
         * HCR_EL2.VI; the counter (EL1PCTEN, bit 10) stays open, since
         * reading it costs nothing and firmware reads it in loops.
         */
        {
            volatile uint64_t *ch = &ohv_rw_controls(s.ctx)->cnthctl_el2;
            /*
             * EL1NVPCT/EL1NVVCT are the ones that matter here.  Clearing
             * EL1PTEN alone is not enough for a guest running under NV: the
             * hardware does not trap its CNTP_* accesses, it redirects them
             * to the EL2 timers, whose interrupt belongs to the host.  These
             * two bits (FEAT_ECV) say trap instead of redirect, which is what
             * puts the compare value somewhere ohv_expire_timers can see it.
             * EL1TVT/EL1TVCT do the same for the virtual pair, and leaving
             * EL1PCTEN clear keeps the counter reads coming here too, so the
             * guest stays on the VMM's clock rather than the host's raw one.
             */
            /*
             * EL1TVCT (bit 14) is **not** in the default any more.
             *
             * It was, and trapping the counter was how the guest was kept on
             * the VMM's clock rather than the host's raw one.  That reasoning
             * no longer applies: the two are the same clock.  The library
             * answers a trapped CNTVCT as `mach_absolute_time()` minus the
             * vCPU's `virtual_timer_offset`, and that word is what
             * `hv_vcpu_set_vtimer_offset` puts in CNTVOFF_EL2 -- exactly what
             * the hardware subtracts for a native read.
             *
             * Leaving it set is now actively expensive.  The ROM rewrites all
             * 92 of XNU's ACNTVCT_EL0 reads to CNTVCT_EL0 at the kernel
             * handoff (ACNTVCT can never be native -- HACR_EL2.TACNT is fixed
             * in the host kernel's capability set), so every
             * `mach_absolute_time`, scheduler decision, lock timeout and trace
             * point lands here: measured **1,278,101 a second, 80% of every
             * MSR trap on the machine**, against 320,000 for everything else
             * put together.
             *
             * EL1TVT stays, so the guest's timer registers still trap into
             * `ohv_expire_timers`; EL1PCTEN stays clear, so the physical
             * counter is still the VMM's.  `ohv_set_cnthctl()` overrides the whole
             * word.
             */
            uint64_t v = (*ch & ~0x1fc00ull) | 0x1a000ull;

            if (ohv_cfg_given(cnthctl)) {
                v = ohv_cfg(cnthctl);
            }
            if (ohv_trace_on(OHV_TRACE_TIMER)) {
                fprintf(stderr, "[ohv] cnthctl_el2 %#llx -> %#llx\n",
                        (unsigned long long)*ch, (unsigned long long)v);
            }
            *ch = v;
        }
        mark_dirty(s.ctx, OHV_STATE_CONTROLS);
        /*
         * Tell the kernel to carry the Apple state classes, without waiting
         * for a trap it will never see.
         *
         * `hv_vcpu_run` folds whatever the VMM leaves in `rw.state_dirty`
         * straight into `state_used` on the way in (`hv_vcpu.c:4848`):
         *
         *     rw_state_dirty_supported = rw.state_dirty
         *                              & arm_guest_state_dirty_supported(vcpu);
         *     ro.state_dirty |= rw_state_dirty_supported;
         *     ro.state_used  |= rw_state_dirty_supported;
         *
         * -- and `arm_guest_state_dirty_supported` is `arm_guest_state_all()`,
         * which carries GXF, SPRR, AMX, JITBOX and PTRAUTH_APPLE.  The other
         * way in is the MSR trap handler, and that never runs here:
         * `HVF_APPLE_CONTROL_0_HOST_EC18_BIT` routes every EC 0x18 to the VMM
         * before `hv_handle_msr_trap` is reached, which is why clearing
         * HCR_EL2.TIDCP and not asking for HACR_EL2.TGXF both measured as
         * changing nothing at all.
         *
         * Once the state is used, `_hv_load_guest_gxf_regs` writes the whole
         * GL1 bank -- SP_GL1, TPIDR_GL1, ASPSR_GL12, VBAR_GL12, FAR_GL12,
         * ESR_GL12, ELR_GL12, SPSR_GL12 -- into real hardware on every entry.
         * That is a prerequisite for ever letting those accesses run natively:
         * without it the bank is not carried at all and the copy in the shared
         * page reads zero however often it is asked.
         *
         * Done here, at vCPU setup, because the load takes the shared page's
         * copy and that copy is only trustworthy before the guest has built
         * any guarded state -- which at this point it has not.
         *
         * **CTRR is deliberately not in the set.** `restricted_state_mask`
         * carries it whenever AIDR_EL1's CTRR version is outside v2..v3, and a
         * dirty bit that is in that mask makes `hv_vcpu_run` fail the whole
         * entry with HV_UNSUPPORTED rather than ignore it.
         */
        {
            /*
             * On by default.  `ohv_set_claim_state(0)` turns it off; any other
             * value is an explicit mask.
             */
            uint64_t want = ohv_cfg(claim_state);
            if (want != 0) {
                mark_dirty(s.ctx, want);
                fprintf(stderr, "[ohv] vcpu %llu claiming guest state %#llx\n",
                        (unsigned long long)id, (unsigned long long)want);
            }
        }
        if (ohv_trace_on(OHV_TRACE_HACR)) {
            fprintf(stderr, "[ohv] hacr asked %#llx\n",
                    (unsigned long long)controls[1]);
        }
        if (ohv_trace_on(OHV_TRACE_USED)) {
            /*
             * What the kernel says it is carrying.  The Apple pointer-auth
             * registers reach the silicon only from
             * _hv_load_guest_apple_ptrauth_regs, and that runs only when
             * ARM_GUEST_STATE_PTRAUTH_APPLE -- bit sixty -- is in this word.
             */
            fprintf(stderr, "[ohv] state_used %#llx  ptrauth_apple %s"
                    "  gxf %s sprr %s\n",
                    (unsigned long long)*ohv_ro_u64(s.ctx, OHV_RO_STATE_USED),
                    (*ohv_ro_u64(s.ctx, OHV_RO_STATE_USED) & (1ull << 60)) ? "yes" : "no",
                    (*ohv_ro_u64(s.ctx, OHV_RO_STATE_USED) & (1ull << 58)) ? "yes" : "no",
                    (*ohv_ro_u64(s.ctx, OHV_RO_STATE_USED) & (1ull << 59)) ? "yes" : "no");
        }

        /*
         * The guest hypervisor's own HCR_EL2 -- the one it reads and writes,
         * which is not the one above -- starts with RW set, because the guest
         * it will run is AArch64.  The framework leaves this word at
         * 0x80000000 on a fresh vCPU; zero says the guest's EL1 is AArch32,
         * and a VMM that reads the register back and puts it into its own CPU
         * model refuses the value rather than building a 32-bit guest.
         *
         * E2H|TGE|APK|API come with it, because on this machine nothing else
         * gives them to a core other than cpu0.  XNU has no `MSR HCR_EL2`
         * anywhere in its kernelcache -- not in 24A437, not in 19A348 -- so it
         * inherits the EL2 configuration from whatever ran before it.  On the
         * part that is the monitor; here SPTM's own writes are sent to a sink
         * by the ROM's handoff patcher (each MSR HCR_EL2 rewritten to an
         * implementation-defined sink) because SPTM is built to own EL2.  The
         * ROM's entry code does write exactly this value -- RW|APK|API at entry, E2H|TGE before
         * the payload handoff -- but the ROM runs on cpu0 alone.
         *
         * What breaks without it: each of XNU's eight vector slots reads
         * HCR_EL2 and takes `CurrentEL == EL2 && TGE == 0` to mean "this
         * exception belongs to the guest I am running", so a secondary core's
         * first exception of any class enters the hv guest handler, whose first
         * act is `MRS X1, TPIDR_EL2 / LDR X1,[X1,#0x90]`.  With no guest there
         * is no host context: it aborts at far 0x90 and panics "Synchronous
         * exception taken while SP1 selected".  Measured on 24A437: cpu0 held 0x30488000000 and lived, every other
         * core held 0x80000000 and died four seconds into launchd.  Under
         * FEAT_NV the first half of that test is true by construction, so TGE
         * is the whole of it.
         *
         * ohv_nested_reset_hcr() holds the value and the measurements.
         */
        *ohv_rw_u64(s.ctx, OHV_NESTED_HCR_EL2) = ohv_nested_reset_hcr();
        if (ohv_cfg_given(try_14c8)) {
            *ohv_rw_u64(s.ctx, 0x14c8) = ohv_cfg(try_14c8);
        }
    }
    /*
     * With an interrupt controller in the machine the guest talks to it
     * through system registers, and those only answer while the virtual CPU
     * interface is enabled.  Left off, every ICC_* access the guest makes
     * leaves the guest instead -- and a VMM told its controller is in the
     * kernel has no case for being asked.
     */
    s.guest_at_el2 = ohv::g_vm_el2;
    if (ohv::g_gic && s.ctx) {
        ohv_rw_controls(s.ctx)->ich_hcr_el2 |= 1ull;
        mark_dirty(s.ctx, OHV_STATE_GIC | OHV_STATE_CONTROLS);
    }
    tl_current_vcpu = &s;

    /*
     * A vCPU that will run a guest hypervisor has to be in one of the nested
     * address spaces the VM stood up; the framework assigns one through the
     * same trap.  Without it the kernel has nowhere to put guest EL2 and
     * refuses the first run as illegal guest state.
     */
    uint64_t joined_space = 0;   /* the default space, unless a nested one is joined */

    if (ohv::g_vm_el2 && ohv_cfg(nested_space)) {
        /*
         * Every vCPU joins nested space 0, so the VM has one VMID; the comment
         * above ohv_tlbi_replay_on() says why that is the default and what one
         * space per vCPU cost.  ohv_set_one_space(false) gives each vCPU its own space
         * again, which the VM still stands up either way.
         *
         * If the old symptom of sharing a space returns -- the second core's
         * VBAR_EL2 write lost and its exception landing at zero -- the VNCR
         * page is where to look, not the space: guest EL2 state is per vCPU
         * (`vcpu->kif->rw.vncr`, named by a host address), not per space.
         */
        uint64_t asid = ohv_nested_asid(ohv_cfg(one_space) ? 0 :
                                        (unsigned)s.id);

        if (!asid) {
            fprintf(stderr, "[ohv] no nested space left for vcpu %llu;"
                            " guest EL2 will share another core's\n",
                    (unsigned long long)s.id);
            asid = ohv_nested_asid(0);
        }
        if (ohv_trace_on(OHV_TRACE_NESTED)) {
            fprintf(stderr, "[ohv] vcpu %llu joining nested space %#llx\n",
                    (unsigned long long)s.id, (unsigned long long)asid);
        }
        if (asid) {
            hv_return_t sr = ohv_raw_trap(OHV_TRAP_VCPU_SET_ADDRESS_SPACE, (void *)(uintptr_t)asid);

            if (ohv_trace_on(OHV_TRACE_NESTED)) {
                fprintf(stderr, "[ohv] join rc %#x\n", sr);
            }
            if (sr == HV_SUCCESS) {
                joined_space = asid;
            }
            if (sr != HV_SUCCESS) {
                fprintf(stderr, "[ohv] vcpu could not join nested space"
                                " %#llx (%#x)\n",
                        (unsigned long long)asid, sr);
            }
        }
    }
    /*
     * The nested-VHE seed again, after the join.
     *
     * OHV_TRAP_VCPU_SET_ADDRESS_SPACE is where the kernel gives this vCPU its
     * nested address space, and a page it hands back does not carry what was
     * written before: seeded above and read back on the frozen machine, every
     * secondary core held 0x80000000 again -- the value
     * a fresh VNCR page starts with -- and its first exception went down the
     * guest path.  So it is written once more here, after the last thing that
     * touches the page, and both read-backs are printed under
     * OHV_TRACE_NESTED so which write the guest sees is measured, not assumed.
     */
    if (ohv::g_vm_el2) {
        uint64_t after_join = *ohv_rw_u64(s.ctx, OHV_NESTED_HCR_EL2);

        *ohv_rw_u64(s.ctx, OHV_NESTED_HCR_EL2) = ohv_nested_reset_hcr();
        if (ohv_trace_on(OHV_TRACE_NESTED)) {
            fprintf(stderr, "[ohv] vcpu %llu nested hcr: after join %#llx,"
                            " reseeded %#llx\n",
                    (unsigned long long)s.id,
                    (unsigned long long)after_join,
                    (unsigned long long)*ohv_rw_u64(s.ctx,
                                                    OHV_NESTED_HCR_EL2));
        }
    }
    /* The space this vCPU's translations live in; every TLBI is replayed there. */
    ohv_tlbi_note_space(joined_space);
    *vcpu_out = id;
    *exit = &s.pub_exit;
    pthread_mutex_unlock(&g_vcpus_mutex);
    return HV_SUCCESS;
}

extern "C" hv_return_t hv_vcpu_destroy(hv_vcpu_t id) {
    VcpuSlot *s = find_vcpu(id);
    if (!s) return HV_BAD_ARGUMENT;
    hv_return_t r = ohv_raw_trap(OHV_TRAP_VCPU_DESTROY, nullptr);
    pthread_mutex_lock(&g_vcpus_mutex);
    if (tl_current_vcpu == s) tl_current_vcpu = nullptr;
    s = nullptr;
    /* Rebuilt in place: a slot holds an atomic and cannot be assigned. */
    g_vcpus[id].~VcpuSlot();
    new (&g_vcpus[id]) VcpuSlot();
    pthread_mutex_unlock(&g_vcpus_mutex);
    return r;
}

// ------------------------------------------------------------- GPR / SIMD --
extern "C" hv_return_t hv_vcpu_get_reg(hv_vcpu_t id, hv_reg_t reg, uint64_t *value) {
    VcpuSlot *s = owned_vcpu(id);
    if (!s || !value) return HV_BAD_ARGUMENT;
    ohv_rw_page_head_t *rw = ohv_rw(s->ctx);
    switch (reg) {
        case HV_REG_CPSR: *value = rw->regs.cpsr; break;
        case HV_REG_FPCR: *value = rw->neon.fpcr; break;
        case HV_REG_FPSR: *value = rw->neon.fpsr; break;
        default: {
            unsigned n = (unsigned)reg;
            switch (n) {
                case 29: *value = rw->regs.fp; break;
                case 30: *value = rw->regs.lr; break;
                case 31: *value = rw->regs.pc; break;
                default:
                    if (n > 31) return HV_BAD_ARGUMENT;
                    *value = rw->regs.x[n];
            }
        }
    }
    return HV_SUCCESS;
}

extern "C" hv_return_t hv_vcpu_set_reg(hv_vcpu_t id, hv_reg_t reg, uint64_t value) {
    VcpuSlot *s = owned_vcpu(id);
    if (!s) return HV_BAD_ARGUMENT;
    ohv_rw_page_head_t *rw = ohv_rw(s->ctx);
    switch (reg) {
        case HV_REG_CPSR: {
            /*
             * A guest hypervisor does not run at hardware EL2, so PSTATE must
             * not say EL2.  A caller describes its guest the way the guest
             * sees itself and hands us EL2h; writing that through asks the
             * kernel to return into a level the guest does not have, which it
             * refuses as illegal guest state.  Translate the level and leave
             * the rest alone -- the framework does the same, visibly: give it
             * EL2h and its context reads back EL1h.
             */
            uint32_t pstate = (uint32_t)value;

            if (ohv::g_vm_el2) {
                uint32_t mode = pstate & 0xf;

                if (mode == 0x8 || mode == 0x9) {   /* EL2t, EL2h */
                    pstate = (pstate & ~0xfu) | (mode - 4);
                    /*
                     * And the level itself, which is NV, not PSTATE.
                     *
                     * A caller hands us EL2 when it has put the core there --
                     * a reset into EL2 for a second start -- and the guest
                     * may have left EL2 since its first, taking NV and
                     * guest_at_el2 with it.  Translated alone, the core then
                     * starts at its EL1 believing EL1, its ROM's eret to EL1
                     * is not the emulated one, and it stops on its own
                     * CurrentEL check: the SEP's second warm reset on 21A329
                     * halted in the SEP's boot ROM at 0x020001f0 with CurrentEL still reading EL2 after the
                     * eret.  Same rule as an injected exception, and only
                     * for a core that has run: a first start is the boot's
                     * own and stays exactly as it was.
                     */
                    if (s->run_count != 0 &&
                        (!g_guest_left_el2.load(std::memory_order_relaxed) ||
                         g_monitor_next.load(std::memory_order_relaxed))) {
                        ohv_rw_controls(s->ctx)->hcr_el2 |= OHV_HCR_NV;
                        mark_dirty(s->ctx, OHV_STATE_CONTROLS);
                        s->guest_at_el2 = true;
                    }
                }
            }
            rw->regs.cpsr = pstate;
            break;
        }
        case HV_REG_FPCR: rw->neon.fpcr = (uint32_t)value; break;
        case HV_REG_FPSR: rw->neon.fpsr = (uint32_t)value; break;
        default: {
            unsigned n = (unsigned)reg;
            switch (n) {
                case 29: rw->regs.fp = value; break;
                case 30: rw->regs.lr = value; break;
                case 31: rw->regs.pc = value; break;
                default:
                    if (n > 31) return HV_BAD_ARGUMENT;
                    rw->regs.x[n] = value;
            }
        }
    }
    return HV_SUCCESS;
}

extern "C" hv_return_t hv_vcpu_get_simd_fp_reg(hv_vcpu_t id, hv_simd_fp_reg_t reg, hv_simd_fp_uchar16_t *value) {
    VcpuSlot *s = owned_vcpu(id);
    if (!s || !value || (unsigned)reg > 31) return HV_BAD_ARGUMENT;
    __builtin_memcpy(value, (void *)&ohv_rw(s->ctx)->neon.q[(unsigned)reg], 16);
    return HV_SUCCESS;
}
extern "C" hv_return_t hv_vcpu_set_simd_fp_reg(hv_vcpu_t id, hv_simd_fp_reg_t reg, hv_simd_fp_uchar16_t value) {
    VcpuSlot *s = owned_vcpu(id);
    if (!s || (unsigned)reg > 31) return HV_BAD_ARGUMENT;
    __builtin_memcpy((void *)&ohv_rw(s->ctx)->neon.q[(unsigned)reg], &value, 16);
    return HV_SUCCESS;
}

// ---------------------------------------------------------------- sysreg --
static hv_return_t sysreg_access(hv_vcpu_t id, uint16_t enc, uint64_t *value, bool write) {
    VcpuSlot *s = owned_vcpu(id);
    if (!s || !value) return HV_BAD_ARGUMENT;
    /*
     * The fast IPI's registers have one owner, and with ohv_set_ipi_inline()
     * on it is this library: the VMM asking for them, when it took the exit
     * because its FIQ line was not settled, gets the same answer the guest
     * would have got here.
     */
    if (ohv_cfg(ipi_inline) && ohv_ipi_access(s, enc, value, write)) {
        return HV_SUCCESS;
    }
    const SysRegDesc *d = sysreg_lookup(enc);
    if (!d) {
        /*
         * An Apple private register this library has no descriptor for.
         *
         * `hvf_sysreg_is_impdef` is "op0 3, CRn 11 or 15", and QEMU's answer
         * for one it cannot name is `hvf_impdef_slot`: a per-vCPU slot keyed
         * by selector, allocated on first touch and zero until the guest
         * writes it.  Keeping the same slot here instead answers identically
         * and lets the access be served without leaving the library --
         * measured, the ones that still went out were JCTL_EL0 16,242 a
         * second, `s3_2_c15_c1_0` and `_c0_0` 14,305 each, PMCR0 11,556,
         * `s3_4_c15_c10_4` 9,183, `s3_7_c15_c1_1` 9,123 and seven `*_3` at
         * 4,784 apiece.
         *
         * The shadow must have exactly one owner.  With this in place QEMU's
         * table is never reached for these, because the access no longer gets
         * that far.  `ohv_set_impdef_shadow(false)` gives them back.
         */
        unsigned e_op0 = (enc >> 14) & 3;
        unsigned e_crn = (enc >> 7) & 15;

        if (!ohv_cfg(impdef_shadow) || e_op0 != 3 ||
            (e_crn != 11 && e_crn != 15)) {
            return HV_UNSUPPORTED;
        }
        for (unsigned i = 0; i < sizeof(s->impdef_key) / sizeof(s->impdef_key[0]);
             i++) {
            if (s->impdef_key[i] == 0) {
                s->impdef_key[i] = enc;
            }
            if (s->impdef_key[i] != enc) {
                continue;
            }
            if (write) {
                s->impdef_val[i] = *value;
            } else {
                *value = s->impdef_val[i];
            }
            return HV_SUCCESS;
        }
        return HV_UNSUPPORTED;    /* table full; the VMM keeps this one */
    }
    /*
     * TPIDR_EL2, which is one name over two storages.
     *
     * On the silicon the monitor keeps its per-CPU block in the physical
     * register, while the kernel -- the monitor's guest, HCR_EL2.{NV,NV2} set
     * -- has its own use of the name redirected into its VNCR page and never
     * reaches the register at all.  Both arrive on this selector: the monitor
     * because the firmware it runs is patched to ask the VMM for it
     * (s3_7_c15_c15_6, forwarded here by the guest-EL2 dispatch) and the
     * kernel by its own trapped access.  Held in the one VNCR slot, the
     * monitor's per-CPU install replaced the kernel's arm_host_context_t, and
     * the kernel's next guest exception read the monitor's block, took a zero
     * guest_context pointer from +0x90 and died on `str x0, [x1, #0x370]`
     * with far=0x370 -- measured 24A437, `_fleh_guest_synchronous`, cpu 2,
     * and again on cpu 3 after the same boot with the same values.
     *
     * The pc says which layer this is, the same question GXF_STATUS answers:
     * the monitor runs inside the band the boot ROM hands over, the kernel
     * from its own text outside it.  The pc is the trapping instruction --
     * neither side has advanced it yet, and for the monitor's request that
     * instruction is the request itself.
     */
    if (enc == 0xe682) {
        uint64_t pc = ohv_rw(s->ctx)->regs.pc;

        if (ohv_pc_guarded(pc)) {
            uint64_t v = write ? *value : s->monitor_tpidr_el2;

            if (write) {
                s->monitor_tpidr_el2 = *value;
            } else {
                *value = v;
            }
            if (ohv_trace_on(OHV_TRACE_TPIDR_EL2)) {
                fprintf(stderr, "[ohv] monitor TPIDR_EL2 %s = %#llx pc %#llx\n",
                        write ? "write" : "read ",
                        (unsigned long long)v, (unsigned long long)pc);
            }
            return HV_SUCCESS;
        }
        if (ohv_trace_on(OHV_TRACE_TPIDR_EL2)) {
            static unsigned n;

            if (n < 64) {
                n++;
                fprintf(stderr, "[ohv] guest TPIDR_EL2 %s = %#llx pc %#llx"
                        " (VNCR slot)\n", write ? "write" : "read ",
                        (unsigned long long)*value, (unsigned long long)pc);
            }
        }
        /* the kernel's own: the descriptor's VNCR slot, below */
    }
    uint8_t *base = (uint8_t *)s->ctx;
    // Generic slot resolution by region base + index.
    uint64_t region = 0;
    switch (d->kind) {
        /*
         * Kind 0 is the shared block and kind 1 the banked one, which is what
         * the generator emits and what the declaration in ohv_internal.h
         * says.  These two were the other way round here, so every register
         * in either block was read and written eight-and-a-bit registers away
         * from itself: VBAR_EL1 landed on a shared slot, came back as 2, and
         * a VMM that checks its own register file against the accelerator
         * stopped the machine over it.
         */
        case 0: region = OHV_RW_SHARED_SYSREGS; break;
        case 1: region = OHV_RW_BANKED_SYSREGS; break;
        case 2: region = OHV_RW_EXTREGS; break;
        /*
         * The breakpoint and watchpoint pairs and MDCCINT_EL1.  Until the table
         * said kind 3 for the pairs they were kind 5, an ID register with no
         * ID slot, so a VMM's write was answered HV_SUCCESS and dropped: every
         * hardware breakpoint and watchpoint QEMU's gdb stub set never reached
         * the hardware.  The block's base depends on the kernel's layout.
         */
        case 3: region = OHV_RW_DBGREGS; break;
        case 5: {   /* the ID registers: host's to describe, VMM's to set */
            int slot = ohv_id_slot(enc);

            if (slot < 0) {
                if (write) return HV_SUCCESS;
                *value = 0;
                return HV_SUCCESS;
            }
            if (!s->id_regs_loaded) {
                static ohv_capabilities_t caps{};
                static bool have = false;

                if (!have) {
                    ohv_raw_trap(OHV_TRAP_CAPABILITIES, &caps);
                    have = true;
                }
                for (unsigned i = 0; i < 18; i++) {
                    s->id_regs[i] = ohv_id_reg_for(&caps, i, false);
                }
                s->id_regs[OHV_ID_SLOT_MIDR] = ohv_caps_field(&caps, HV_SYS_REG_MIDR_EL1);
                s->id_regs[OHV_ID_SLOT_MPIDR] = 0;
                s->id_regs_loaded = true;
            }
            if (write) s->id_regs[slot] = *value;
            else *value = s->id_regs[slot];
            return HV_SUCCESS;
        }
        case 6: region = 0; break;  /* index is the context offset itself */
        case 9: region = OHV_RW_CONTROLS; break;  /* a run-controls word */
        /*
         * Kind 8 is the _EL12 view of a register this table already carries
         * under its plain name: the same architectural thing, named from the
         * level above.  A read answers out of the one slot; a write is not
         * carried.
         *
         * The read is the part that was wrong.  With no descriptor at all
         * these encodings fell to the per-vCPU impdef shadow, which is zero
         * until something writes it, so `MRS Xn, FOO_EL12` invented a zero for
         * a register the hardware holds a value in.  24A437's SPTM saves the
         * whole of the level below -- SPRR, GXF, the GL bank, CTRR -- through
         * exactly these views on a root-table switch (one routine issues
         * seventeen MRS in a row into one structure) and restores it from
         * there, so the first address-space switch after userspace starts
         * recorded zeros for all of it.  That is the panic at `xpcproxy`:
         * `[SPTM Dispatch] Synchronous exception taken while SP1 selected`
         * with `lr` inside sptm_switch_root.
         *
         * The write stays uncarried, which is what it already was.  One
         * physical bank is all the kernel's guest state has -- there is no
         * second level in `arm_guest_extregs_t` -- so letting both names reach
         * it makes the guarded set inconsistent: measured, the monitor's own
         * GXF_ENTRY_EL1 is overwritten by the zero it writes through
         * GXF_ENTRY_EL12 and `hv_vcpu_run` refuses the vCPU with
         * HV_ILLEGAL_GUEST_STATE before the kernel prints a line.  Dropping it costs nothing here: what the
         * monitor writes back through these views is what it read through
         * them a moment earlier, so with the read answering truthfully the
         * pair is a no-op.
         */
        case 8:
            if (write) {
                return HV_SUCCESS;
            }
            region = OHV_RW_EXTREGS;
            break;
        case 7: {                   /* no context slot; see VcpuSlot::el2_shadow */
            if (d->index >= sizeof(s->el2_shadow) / sizeof(s->el2_shadow[0]))
                return HV_UNSUPPORTED;
            if (!write) { *value = s->el2_shadow[d->index]; return HV_SUCCESS; }
            s->el2_shadow[d->index] = *value;
            return HV_SUCCESS;
        }
        default: return HV_UNSUPPORTED;
    }
    volatile uint64_t *p = (volatile uint64_t *)(base + region + (uint64_t)d->index * 8);
    /*
     * Sync when the kernel says this part of the shared copy is not current.
     * The per-entry sync_before below is the stronger statement -- always
     * sync, whatever the mask says -- and is kept for the guarded bank, which
     * the hardware fills without going through here at all.
     */
    if (!d->sync_before) {
        uint64_t need = 0;

        switch (d->kind) {
            case 0: case 1: need = 1ull << 0;  break;   /* system registers */
            case 3: need = OHV_STATE_DEBUG;    break;
            case 2: need = 1ull << 61;         break;   /* extended registers */
            case 6: case 9: need = OHV_STATE_CONTROLS; break;
            default: break;
        }
        if (need && (*ohv_ro_u64(s->ctx, OHV_RO_STATE_VALID) & need) == 0) {
            hv_return_t r = ohv_raw_trap(OHV_TRAP_VCPU_SYSREGS_SYNC, nullptr);

            if (r != HV_SUCCESS) return r;
        }
    }
    if (d->sync_before) {
        /*
         * Both directions, not just writes.  A read is where a stale mirror
         * shows: the guarded bank is filled by the hardware on GENTER, and a
         * read that skips the sync answers whatever the context happened to
         * hold -- zero, where the return address should be.  Before a write
         * it keeps the rest of the block from being carried back stale.
         *
         * Once per exit, not once per access.  `ohv_set_sync_once(true)`.
         *
         * This is a Mach trap, and QEMU makes it with the Big QEMU Lock held:
         * `hvf_sysreg_forward_read`/`_write` call `hv_vcpu_get/set_sys_reg`
         * from inside `hvf_handle_exception`.  The guarded bank is the busiest
         * thing on the machine -- 20,824 guarded transitions a second at eight
         * register accesses each, `s3_6_c15_c10_3` and `_4` alone at 62,000
         * apiece -- so that is eight syscalls per transition, serialised
         * against five other vCPUs.
         *
         * What the sync exists for is hardware filling the bank behind this
         * library's back, and hardware only does that while the guest is
         * executing.  Between one exit and the next entry the copy cannot go
         * stale, so the eight accesses of one `gtr_*` save/restore need one
         * sync between them, not eight.  `run_count` is incremented in
         * `hv_vcpu_run` immediately after the run trap returns, which makes it
         * exactly the generation this wants -- and it is read and written on
         * the vCPU's own thread, so it needs no atomics.
         */
        if (!ohv_cfg(sync_once) || s->synced_run != s->run_count) {
            hv_return_t r = ohv_raw_trap(OHV_TRAP_VCPU_SYSREGS_SYNC, nullptr);
            if (r != HV_SUCCESS) return r;
            s->synced_run = s->run_count;
        }
    }
    if (write) {
        uint64_t out = *value;

        /*
         * CPTR_EL2 has bits the kernel put there for its own reasons, and a
         * VMM writing the register from outside does not know about them: it
         * writes what its own CPU model holds, which is zero, and the trap
         * configuration the hypervisor needs goes with it.  The framework
         * filters this write; keeping the bits is the same answer.
         */
        if (enc == 0xe08a) {
            out |= 0x300000ull;
        }
        /*
         * Every pointer-auth key write that reaches this library, under
         * `-accel ohv,trace=pac`: what the slot held before it, and what is
         * going in.  It had no switch while the panic below was being chased,
         * and once that was done it cost 19 MB of launcher.log a minute --
         * enough to slow the guest's own disk writes down.
         *
         * The `PAC failure from kernel with IB key` panic is a key that
         * changed between a `PACIBSP` and its `RETAB`.  Read off a frozen
         * machine, XNU's own per-core cache (`cpu_data + 0x1F8`, written by
         * Switch_context right after the MSR) and the key in the vCPU state
         * disagree on every core -- and XNU writes the pair as (P, P+1) while
         * the state holds two unrelated words.  So the value the guest wrote
         * is not the value the vCPU runs with, and XNU cannot notice: its
         * cache says the core already holds that key, so the MSR is skipped.
         *
         * These entries all carry `sync_before`, so `*p` here is the silicon's
         * value, not a mirror.  One line therefore says both halves: whether
         * the write arrives at all, and what it is displacing.
         *
         * KERNKEY (0xe788/9) is Apple private and traps through TIDCP; the
         * architected keys may not trap at all.  They are written twenty
         * instructions apart in the same function
         * (`Switch_context`, guest 0xfffffff06c870c40), so the two together
         * say which of them is being lost.
         */
        uint64_t had = *p;

        switch (enc) {
            case 0xc108: case 0xc109:   /* APIAKeyLo/Hi_EL1 */
            case 0xc10a: case 0xc10b:   /* APIBKeyLo/Hi_EL1 */
            case 0xc110: case 0xc111:   /* APDAKeyLo/Hi_EL1 */
            case 0xc112: case 0xc113:   /* APDBKeyLo/Hi_EL1 */
            case 0xe788: case 0xe789:   /* KERNKEYLO/HI_EL1 */
                if (ohv_trace_on(OHV_TRACE_PAC)) {
                    fprintf(stderr, "[key] vcpu %llu enc %#06x had %#018llx "
                            "<- %#018llx pc %#llx run %llu\n",
                            (unsigned long long)s->id, (unsigned)enc,
                            (unsigned long long)had, (unsigned long long)out,
                            (unsigned long long)ohv_rw(s->ctx)->regs.pc,
                            (unsigned long long)s->run_count);
                }
                break;
            default: break;
        }
        *p = out;
        /*
         * The key the guest's pointer authentication actually uses.
         *
         * A guest under this hypervisor does not get the part's kernel key.
         * The host keeps a key per virtual machine -- VMKEYLO/HI_EL2, loaded
         * from ro.controls and copied there out of rw.controls, which is the
         * VMM's to write and starts at zero -- and that is what the guest's
         * signing and authenticating are diversified with.  KERNKEYLO/HI_EL1
         * are carried into the silicon and change nothing, which is what a
         * probe measured: changing the architected APIAKey under a signed
         * pointer breaks its authentication, and changing KERNKEY does not,
         * with the signature coming out byte-identical every time.
         *
         * SPTM installs a kernel key and hands TXM images whose pointers are
         * signed under it; TXM authenticates them and takes an FPAC with the
         * value intact and the signature wrong.  So the guest's kernel key is
         * put where the guest's keys live.
         */
        /*
         * The mirror is off; ohv_set_vmkey_mirror(true) puts it back.
         *
         * It was added because TXM authenticated a pointer out of its own
         * image and took an FPAC, and it is what made the boot core and the
         * cores released later diversify differently.  The boot core writes
         * APIBKey while the VM key is still zero and writes KERNKEY after it;
         * a core released at fifty seconds writes its APIBKey with the mirror
         * already standing, so it signs with a different key.  Read back per
         * vCPU the split is exact and repeats every boot -- the boot core
         * keeps 0xaf39aabf231a2fa2, every secondary lands on
         * 0x7544742432da937f -- and a thread that signs its return address on
         * one and returns on the other dies in thread_invoke's RETAB:
         *
         *     panic(cpu N ...): PAC failure from kernel with IB key
         *
         * Without the mirror all six cores hold one key, the panic is gone,
         * and TXM comes up regardless: whatever it needed is being met by
         * something else now.
         */
        if ((enc == 0xe788 || enc == 0xe789) &&
            ohv_cfg(vmkey_mirror)) {
            volatile ohv_controls_t *c = ohv_rw_controls(s->ctx);

            if (enc == 0xe788) {
                c->vmkeylo_el2 = out;
            } else {
                c->vmkeyhi_el2 = out;
            }
            mark_dirty(s->ctx, OHV_STATE_CONTROLS);
            if (ohv_trace_on(OHV_TRACE_PAC)) {
                fprintf(stderr, "[ohv] vcpu %llu vmkey %s <- %#llx\n",
                        (unsigned long long)s->id,
                        enc == 0xe788 ? "lo" : "hi",
                        (unsigned long long)out);
            }
        }
        if (d->dirty_bit) mark_dirty(s->ctx, d->dirty_bit);
    } else {
        *value = *p;
    }
    if (ohv_cfg(trace_sysreg) <= 0xffff) {
        uint64_t want = ohv_cfg(trace_sysreg);

        if (enc == want) {
            fprintf(stderr, "openhyp: %s %#06x kind %u index %u at +%#llx"
                    " value %#llx valid %#llx runs %llu\n",
                    write ? "write" : "read", enc, d->kind, d->index,
                    (unsigned long long)(region + (uint64_t)d->index * 8),
                    (unsigned long long)*value,
                    (unsigned long long)*ohv_ro_u64(s->ctx, OHV_RO_STATE_VALID),
                    (unsigned long long)s->run_count);
        }
    }
    return HV_SUCCESS;
}

extern "C" hv_return_t hv_vcpu_get_sys_reg(hv_vcpu_t id, hv_sys_reg_t reg, uint64_t *value) {
    return sysreg_access(id, (uint16_t)reg, value, false);
}
/*
 * A refused system register is otherwise invisible from the outside: the
 * caller sees only the return code, and qemu turns that straight into an
 * assertion naming its own source line.  OHV_TRACE_SYSREG says which register
 * it was.
 */
static void trace_sysreg_refusal(const char *what, uint16_t reg, uint64_t value, hv_return_t r) {
    if (r == HV_SUCCESS || !ohv_trace_on(OHV_TRACE_SYSREG)) {
        return;
    }
    fprintf(stderr, "openhyp: %s of sysreg %#06x (op0=%u op1=%u crn=%u crm=%u"
            " op2=%u) value %#llx refused: %#x\n", what, reg,
            (reg >> 14) & 3, (reg >> 11) & 7, (reg >> 7) & 0xf,
            (reg >> 3) & 0xf, reg & 7, (unsigned long long)value, r);
}

extern "C" hv_return_t hv_vcpu_set_sys_reg(hv_vcpu_t id, hv_sys_reg_t reg, uint64_t value) {
    hv_return_t r = sysreg_access(id, (uint16_t)reg, &value, true);

    trace_sysreg_refusal("write", (uint16_t)reg, value, r);
    /*
     * ohv_set_survey_sysreg(true) is for finding out what a caller needs in one run
     * rather than one register per run: the write is dropped instead of
     * refused, so the caller carries on and every gap gets named.  It leaves
     * the guest missing that state, so it is a survey and nothing else.
     */
    if (r == HV_UNSUPPORTED && ohv_cfg(survey_sysreg)) {
        return HV_SUCCESS;
    }
    return r;
}

// --------------------------------------------- interrupts / timers / misc --
extern "C" hv_return_t hv_vcpu_get_serror(hv_vcpu_t id, bool *pending) {
    VcpuSlot *s = owned_vcpu(id);
    if (!s || !pending) return HV_BAD_ARGUMENT;
    *pending = ohv_exit_info(s->ctx)->vmexit_reason == OHV_VMEXIT_SERROR;
    return HV_SUCCESS;
}
extern "C" hv_return_t hv_vcpu_set_serror(hv_vcpu_t, bool) {
    // Injection path requires the VGIC model; see ohv_gic.cpp notes.
    return HV_UNSUPPORTED;
}

/*
 * A pending interrupt is a bit in HCR_EL2: VI for an IRQ and VF for an FIQ,
 * the two the architecture provides for a hypervisor to raise an interrupt in
 * its guest.  The framework keeps them beside its vCPU and pushes them into
 * HCR_EL2 on the way into the guest, comparing the pair each time; writing
 * them straight into the controls and marking them dirty is the same thing
 * one step earlier.
 *
 * This used to answer "unsupported", which is not a distinction a caller
 * makes: QEMU raises every interrupt its machine model produces through here, so
 * nothing the guest waits on ever arrived -- it got as far as loading the
 * next stage over USB and then waited forever for the transfer to complete.
 */
/* Defined beside the timers, and used by the injection call below. */
static void ohv_set_fiq_level(VcpuSlot *s);
static void ohv_set_irq_level(VcpuSlot *s);

#define OHV_HCR_VF (1ull << 6)
#define OHV_HCR_VI (1ull << 7)

static uint64_t pending_bit(hv_interrupt_type_t type) {
    return type == HV_INTERRUPT_TYPE_FIQ ? OHV_HCR_VF : OHV_HCR_VI;
}

extern "C" hv_return_t hv_vcpu_get_pending_interrupt(hv_vcpu_t id, hv_interrupt_type_t type, bool *pending) {
    VcpuSlot *s = owned_vcpu(id);
    if (!s || !pending) return HV_BAD_ARGUMENT;
    *pending = (ohv_rw_controls(s->ctx)->hcr_el2 & pending_bit(type)) != 0;
    return HV_SUCCESS;
}
extern "C" hv_return_t hv_vcpu_set_pending_interrupt(hv_vcpu_t id, hv_interrupt_type_t type, bool pending) {
    VcpuSlot *s = owned_vcpu(id);
    if (!s) return HV_BAD_ARGUMENT;

    /*
     * The first interrupts the kernel is handed, and only the transitions:
     * the VMM re-asserts the same level on every entry, so logging each call
     * buries the one that matters.  What this is for is XNU's sleh_irq
     * dereferencing a null global -- the object it dispatches an interrupt
     * through is published by IOKit, and anything delivered before that is
     * fatal.  Whether the first one is an IRQ or an FIQ says whether it came
     * from the interrupt controller or from the CPU timer this side drives.
     */
    if (ohv_trace_on(OHV_TRACE_KIRQ)) {
        static bool was[64][2];
        static unsigned n;
        unsigned slot = (unsigned)s->id < 64 ? (unsigned)s->id : 0;
        unsigned kind = type == HV_INTERRUPT_TYPE_FIQ ? 0u : 1u;
        uint64_t pc = ohv_rw(s->ctx)->regs.pc;

        if (pending && !was[slot][kind] && g_kernel_running && n < 40) {
            n++;
            fprintf(stderr, "[ohv] kernel irq %u: vcpu %llu %s raised at"
                    " pc %#llx\n", n, (unsigned long long)s->id,
                    kind == 0 ? "FIQ" : "IRQ", (unsigned long long)pc);
            if (n == 40) {
                fprintf(stderr, "[ohv] kernel irq: 40 shown, no more\n");
            }
        }
        was[slot][kind] = pending;
    }
    if (type == HV_INTERRUPT_TYPE_FIQ) {
        s->vmm_fiq = pending;
        ohv_set_fiq_level(s);
    } else {
        s->vmm_irq = pending;
        ohv_set_irq_level(s);
    }
    /*
     * Every transition, uncapped, both ways.  The VMM re-asserts the same
     * level on most entries, so logging each call buries the edge; and a
     * budget hides the one at the end, which is the only one a stall is
     * about.
     */
    if (ohv_trace_on(OHV_TRACE_IRQ)) {
        static bool was[64][2];
        unsigned slot = (unsigned)s->id < 64 ? (unsigned)s->id : 0;
        unsigned kind = type == HV_INTERRUPT_TYPE_FIQ ? 0u : 1u;

        if (was[slot][kind] != pending) {
            was[slot][kind] = pending;
            fprintf(stderr, "[ohv] vcpu %llu %s %s pc %#llx hcr %#llx\n",
                    (unsigned long long)s->id,
                    kind == 0 ? "FIQ" : "IRQ", pending ? "on " : "off",
                    (unsigned long long)ohv_rw(s->ctx)->regs.pc,
                    (unsigned long long)ohv_rw_controls(s->ctx)->hcr_el2);
        }
    }
    return HV_SUCCESS;
}

// -------------------------------------------------------------------- run --
/*
 * The guest's own timers, counted here.
 *
 * A timer that expires is a PPI, and a PPI needs an interrupt controller to
 * arrive at.  This one is modelled in the library, so nothing in the kernel
 * has anywhere to deliver it: the guest arms CNTP_CTL_EL0 with the enable bit
 * and waits, and the hypervisor never hears about it.  Comparing the compare
 * value against the clock the guest was given, and raising the virtual
 * interrupt when it has passed, is the delivery -- the same thing the
 * controller would have done.
 */
#define OHV_CNT_ENABLE  (1ull << 0)
#define OHV_CNT_IMASK   (1ull << 1)
#define OHV_CNT_ISTATUS (1ull << 2)

/*
 * Whether the guest is running one of the monitor images rather than the
 * kernel.  See VcpuSlot::sptm_base for why one address settles all three.
 */
/*
 * Learn where the monitor images are.  Called on every exit, because the
 * first kernel-VA the guest is seen at has to be SPTM's -- it runs for a long
 * time before XNU exists -- and sampling only when a timer happens to be due
 * gets XNU's instead and inverts the whole test.  Measured: with the capture
 * inside the timer path the one raise of a boot landed at
 * 0xfffffff04bbd0118, which is SPTM, in a mode that exists to avoid exactly
 * that.
 *
 * The three images are linked 0x10000000 apart and share one slide, so the
 * lowest 0x10000000 band the guest has ever executed in is SPTM's, the next
 * TXM's, and the one after XNU's.
 */
/*
 * Where the monitor images are is a property of the machine, not of a core.
 *
 * Kept per vCPU it was right for the boot core and wrong for every other one:
 * a core released at fifty seconds runs its whole SPTM entry at physical
 * addresses, which this declines to learn from, so its band stayed zero -- and
 * a band of zero is what makes the FIQ gate answer "raise it" unconditionally.
 * Every secondary therefore had no gate at all across the part of its life
 * that is entirely inside the monitor.
 */
static std::atomic<uint64_t> g_monitor_band{0};

static void ohv_note_image_band(VcpuSlot *s) {
    uint64_t pc = ohv_rw(s->ctx)->regs.pc;
    uint64_t band;

    /*
     * The guarded per-CPU register, watched for the moment it goes away.
     *
     * ext[46] is TPIDR_GL1 in the kernel's copy of the guarded bank.  The
     * guest writes it once and it is carried from then on -- except that
     * something later puts it back to zero, and the only way to say what is
     * to look at every exit and print the transitions.
     */
    if (ohv_trace_on(OHV_TRACE_EXT)) {
        static uint64_t was[16];
        uint64_t now = *ohv_rw_u64(s->ctx, OHV_RW_EXTREGS + 46 * 8);
        unsigned slot = (unsigned)s->id < 16 ? (unsigned)s->id : 0;

        if (now != was[slot]) {
            fprintf(stderr, "[ohv] vcpu %llu TPIDR_GL1 %#llx -> %#llx at"
                    " pc %#llx esr %#llx\n", (unsigned long long)s->id,
                    (unsigned long long)was[slot], (unsigned long long)now,
                    (unsigned long long)pc,
                    (unsigned long long)s->last_esr);
            was[slot] = now;
        }
    }

    if (ohv_monitor_told()) {
        return;
    }
    if (s->sptm_base == 0) {
        s->sptm_base = g_monitor_band.load(std::memory_order_relaxed);
    }
    if (pc < 0xfffffff000000000ull) {
        return;
    }
    band = pc & ~0xfffffffull;
    if (s->sptm_base == 0 || band < s->sptm_base) {
        if (ohv_trace_on(OHV_TRACE_BAND)) {
            fprintf(stderr, "[ohv] vcpu %llu monitor band %#llx"
                    " (from pc %#llx)\n", (unsigned long long)s->id,
                    (unsigned long long)band, (unsigned long long)pc);
        }
        s->sptm_base = band;
        for (;;) {
            uint64_t seen = g_monitor_band.load(std::memory_order_relaxed);

            if (seen != 0 && seen <= band) {
                break;
            }
            if (g_monitor_band.compare_exchange_weak(seen, band,
                                                     std::memory_order_relaxed)) {
                break;
            }
        }
    }
}

static bool ohv_guest_in_monitor(VcpuSlot *s) {
    uint64_t pc = ohv_rw(s->ctx)->regs.pc;
    uint64_t apstate = ohv_rw(s->ctx)->shared_sysregs.apstate;

    /*
     * The guarded execution level itself, which beats any address range.
     *
     * APSTATE is the Apple state register that carries it: zero outside
     * guarded state and one inside, and the kernel writes the same state
     * through APSTS_EL12 on the way in.  A range can only cover the guarded
     * code somebody knew to name -- and on 19A348 that turned out to be two
     * places, __PPLTEXT and a page of __TEXT_EXEC holding
     * _gxf_ppl_entry_handler, ppl_exit and the four fleh_*_from_ppl handlers
     * -- whereas this is the machine answering the question directly.
     *
     * Bit zero, not the whole word and not merely non-zero.  This firmware
     * leaves 2 in the slot before GXF has been touched at all, and treating
     * that as guarded holds every interrupt from reset -- but the word is a
     * bitfield, not an enum, and an equality test drops every value that has
     * bit zero set beside something else.  Measured on 24A437 with six cores
     * running: 0, 1, 2, 4, 6 and 7 all appear at the same instant, so 
     * calls a core carrying 5 or 7 unguarded while it is in the monitor.  The
     * ranges stay as well, because they are sound on their own and cost
     * nothing.
     */
    if ((apstate & 1) != 0) {
        return true;
    }
    if (ohv_monitor_told()) {
        /*
         * Whether the two ever disagree, which is the only way to find out
         * that a range is missing a page -- or that APSTATE is not what it is
         * taken to be here.
         */
        if (ohv_trace_on(OHV_TRACE_BAND)) {
            static uint64_t seen[16];
            static unsigned seen_n;

            if (ohv_pc_guarded(pc)) {
                unsigned i;

                for (i = 0; i < seen_n; i++) {
                    if (seen[i] == pc) break;
                }
                if (i == seen_n) {
                    if (seen_n < 16) seen[seen_n++] = pc;
                    fprintf(stderr, "[ohv] guarded by range but APSTATE %#llx"
                            " at pc %#llx\n", (unsigned long long)apstate,
                            (unsigned long long)pc);
                }
            }
        }
        return ohv_pc_guarded(pc);
    }
    if (s->sptm_base == 0) {
        return false;
    }
    return pc >= s->sptm_base && pc < s->sptm_base + 0x20000000ull;
}

/*
 * A chain with a monitor of its own cannot be handed a level while it is in it.
 *
 * SPTM's guarded vectors live in a bank this machine has no third home for
 * (there are two guarded levels in the silicon and the firmware wants three),
 * so an interrupt taken in guarded state is delivered through VBAR_EL1 --
 * XNU's table -- XNU services it and returns the only way it knows, GENTER 1,
 * and SPTM's entry assertion that its nesting depth is zero spins for ever at
 * `return_from_sptm_exception`.  Measured on 21A329 five boots running: the
 * last gate line before the spin is `FIQ on pc 0xfffffff04bbceec0`, which is
 * inside SPTM, and the guest then parks at link 0xfffffff007060770 with the
 * depth at one.
 *
 * Held only on that chain.  `g_monitor_next` is the boot ROM's
 * s3_6_c15_c15_7 write, which only a handover to a separate monitor sends, so
 * 19A348 keeps exactly the behaviour it has today -- where withholding was
 * unbounded and wrong: PPL carries the guarded bank natively, makes no exits
 * to re-evaluate this on, and `cpu_broadcast_xcall` waits six seconds and
 * panics.  On 17.0 that worry does not arise, because the guarded bank is not
 * carried: ~20k guarded transitions a second at eight trapped register
 * accesses each means an exit to put the level back up is microseconds away.
 *
 * ohv_set_monitor_level_gate(false) turns it off.
 */
static bool ohv_level_held_in_monitor(VcpuSlot *s) {
    return g_monitor_next.load(std::memory_order_relaxed) &&
           ohv_cfg(monitor_level_gate) &&
           ohv_guest_in_monitor(s);
}

/*
 * Whether a timer that has come due may be delivered right now.
 *
 * ohv_set_timer_gate() picks the rule, so the three can be compared without a
 * rebuild between them:
 *
 *   0  VM_TMR_FIQ_ENA_EL2.  What this used to do, and wrong -- see the long
 *      note in ohv_expire_timers.  The guest's timed sleeps never wake.
 *   1  no gate at all: any due, unmasked timer is delivered.
 *   2  no gate, except while the guest is running as its own hypervisor.
 *      Useless: guest_at_el2 is never cleared once the guarded-ERET path has
 *      run, so this reads the same as mode 0.
 *   3  no gate, except while the guest's PC is in a monitor image.  Does not
 *      work either, and why is the whole story -- see case 4.
 *   4  the default: raised only when the guest will take it at once.
 *
 * Measured end to end, kernel console bytes to the wedge or panic:
 * mode 0 -> 13613 and a hang, mode 1 -> 625, mode 3 -> 33, mode 4 -> 25515
 * and a named driver panic, with the whole kext list loaded on the way.
 */
static bool ohv_timer_fiq_wanted(VcpuSlot *s) {
    bool v = s->timer_fired_v, p = s->timer_fired_p;

    switch ((unsigned)ohv_cfg(timer_gate)) {
    case 1:
        return v || p;
    case 2:
        return (v || p) && !s->guest_at_el2 && !s->nv_off_for_geret;
    case 3:
        /*
         * Held while the monitor is running.  Measured with mode 1: of the
         * timer FIQs raised once the kernel is up, all but two were taken at
         * a kernelcache PC and serviced; the two that were not landed in
         * SPTM at 0xfffffff0070604ec and _4d4, inside the dispatch that runs
         * a call on XNU's behalf with XNU's own DAIF restored.  That
         * dispatch reads the nesting depth from the per-CPU block (+0x30);
         * at depth one it copies the caller's DAIF bits into DAIF and then
         * branches to the call, at any other depth it masks everything.
         * The boot then stops in the guarded entry SPTM reaches from
         * there, whose first act is to assert that the same depth (read
         * through S3_6_C15_C11_1) is zero, spinning in place otherwise.
         *
         * So the FIQ is not being refused by SPTM, it is arriving down a
         * path SPTM only uses for exceptions from below.  Holding it until
         * the guest is back in the kernel is what this mode tests.
         */
        return (v || p) && !ohv_guest_in_monitor(s);
    case 0:
        /* bit 0 is the physical timer, bit 1 the virtual one */
        return (p && (s->vm_tmr_fiq_ena & 1u)) ||
               (v && (s->vm_tmr_fiq_ena & 2u));
    default:
        /*
         * Raised only at a moment the guest will take it at once: in the
         * kernel, with FIQ unmasked.
         *
         * Mode 3 -- hold it while the monitor runs -- does not work, and why
         * it does not is the whole answer.  HCR_EL2.VF is a level, and the
         * guest crosses into SPTM with GENTER, which the hardware carries out
         * without an exit; there is no moment in between at which this side
         * could take the level down.  Measured: 469 edges and the boot ends
         * in the same place as with no gate at all.
         *
         * What happens there, from the wedged stack:
         *
         *     PC  return_from_sptm_exception   (spinning; depth == 1)
         *     #0  _sptm_dispatch_asm_wrapper+0x58
         *     #2  XNU
         *
         * XNU masks FIQ and GENTERs into SPTM, which takes depth 0 -> 1 and
         * then deliberately restores the caller's DAIF around the call it is
         * making on XNU's behalf:
         *
         *     and x8, x8, #0x3c0 ; msr DAIF, x8 ; blraaz x11
         *
         * A pending virtual FIQ is taken right there -- and at hardware EL1
         * it is delivered through VBAR_EL1, which is XNU's vector table, not
         * _GuardedExceptionVectorBase where an exception inside SPTM belongs.
         * XNU services it, returns the only way it knows, GENTER 1
         * (return_from_sptm_exception), and that asserts the nesting depth is
         * zero while SPTM's dispatch frame is still open.
         *
         * So the level must never be left standing across a GENTER.  Raising
         * it only when the guest is in the kernel with F clear means the
         * guest takes it on the next entry, before it can reach one.
         */
        if (!(v || p)) {
            return false;
        }
        /*
         * Before the monitor exists there is no GENTER to leave a level
         * standing across, and the firmware needs the level standing: its
         * main loop at 0x1fc146094 finds its timer by reading ISR_EL1.F,
         * which reports a pending virtual FIQ whether or not PSTATE.F would
         * let it be taken.  Withholding the level while the firmware has FIQ
         * masked leaves that bit reading zero and the firmware never services
         * its timer at all.
         *
         * sptm_base is zero until the guest has executed a kernel VA, which
         * is exactly that boundary.
         */
        /*
         * The register the hardware itself gates on, and no more.
         *
         * S3_5_C15_C1_3 is the guest saying which of the two timers may raise
         * its FIQ -- ignoring it is the spurious interrupt that used to kill
         * the kernel -- and it resets to 3, so the firmware's level stands
         * from the first instruction.  Everything that used to be tested
         * beside it (the monitor, the guarded PC range, PSTATE.F) is gone for
         * the reasons written against the VMM's own line below.
         */
        return (p && (s->vm_tmr_fiq_ena & 1u)) ||
               (v && (s->vm_tmr_fiq_ena & 2u));
    }
}

/*
 * Which cores take a due timer as an IRQ instead of an FIQ.
 *
 * SEPOS's two FIQ vectors are both an unconditional halt, so a timer
 * delivered to the SEP as an FIQ stops it dead -- before it has touched a
 * device, and with nothing on the wire to say why.  What the machine sees is
 * a SEP that accepts its firmware, consumes the shared-buffer message, and
 * then never announces that it is alive.
 *
 * Which vcpu that is, is something only the machine knows, so it says so:
 * ohv_set_timer_irq_vcpus() takes a mask of vcpu ids whose timer is raised as VI.
 * Anything not named there keeps the FIQ it has always had.
 */
static bool ohv_timer_as_irq(VcpuSlot *s) {
    return s->id < 64 && ((ohv_cfg(timer_irq_vcpus) >> s->id) & 1) != 0;
}

/*
 * The guest's virtual IRQ, under the same rule as its FIQ.
 *
 * HCR_EL2.VI is a level too, and a level standing at a GENTER is taken inside
 * SPTM through VBAR_EL1 -- XNU's vector table -- exactly as a standing VF is,
 * with the same end: XNU services it, returns by GENTER 1, and SPTM's entry
 * assertion that the nesting depth is zero spins forever.  The FIQ has been
 * gated for this since the timer work; the IRQ never was, because with one
 * core and the interrupt controller pointed at it the two were never separate
 * enough to notice.
 *
 * Deferring costs nothing: the AIC keeps its own pending set until the guest
 * takes the event, so an interrupt held back until the guest is out of the
 * monitor is delivered late, not lost.
 */
static void ohv_set_irq_level(VcpuSlot *s) {
    uint64_t hcr = ohv_rw_controls(s->ctx)->hcr_el2;
    /* The same rule as the FIQ above, and for the same reasons. */
    bool want_irq = s->vmm_irq && !ohv_level_held_in_monitor(s);
    uint64_t want = want_irq ? (1ull << 7) : 0;

    /*
     * The one line that says why a level is being withheld.  OHV_TRACE_GATE,
     * capped, because the question is only ever about the first few.
     */
    if (s->vmm_irq && !want_irq && ohv_trace_on(OHV_TRACE_GATE)) {
        {
            /*
             * Every one of them.  A budget hides the edge at the end, which is
             * the only one a stall is about.
             */
            fprintf(stderr, "[ohv] gate vcpu %llu IRQ held: wfx %d mon %d"
                    " pc %#llx cpsr %#x reason %u esr %#llx\n",
                    (unsigned long long)s->id, (int)s->in_wfx,
                    ohv_guest_in_monitor(s) ? 1 : 0,
                    (unsigned long long)ohv_rw(s->ctx)->regs.pc,
                    (unsigned)ohv_rw(s->ctx)->regs.cpsr,
                    s->last_reason, (unsigned long long)s->last_esr);
        }
    }
    if ((hcr & (1ull << 7)) == want) {
        return;
    }
    ohv_rw_controls(s->ctx)->hcr_el2 = (hcr & ~(1ull << 7)) | want;
    mark_dirty(s->ctx, OHV_STATE_CONTROLS);
}

/* The guest's virtual FIQ is whichever of its two halves is asserted. */
static void ohv_set_fiq_level(VcpuSlot *s) {
    uint64_t hcr = ohv_rw_controls(s->ctx)->hcr_el2;

    s->timer_fiq = ohv_timer_fiq_wanted(s) && !ohv_timer_as_irq(s);

    /*
     * The VMM's own FIQ gets the same gate the timer's does.
     *
     * It did not, and with one core that never showed: nothing else was
     * signalling it.  With six, cpu0's fast IPIs land on cores that are
     * inside SPTM, and each one that arrives there wedges that core's nesting
     * depth for good -- one core is lost on every boot, and the panic path
     * can then never stop it, which is why no stackshot has ever come out.
     *
     * Holding the level costs nothing: the IPI itself is latched in the
     * VMM's IPI_SR until the guest acknowledges it, so a delivery deferred
     * until the guest is back in the kernel is a delivery, not a loss.
     */
    /*
     * Exactly what the VMM asked for.
     *
     * This used to be withheld while the guest was inside SPTM or PPL, on the
     * theory that a level standing across a GENTER would be taken there and
     * land in XNU's vector table rather than the guarded one.  The monitors
     * say otherwise themselves: SPTM's `_GuardedExceptionVectorBase`, which
     * `_gxf_finalize` writes into VBAR_GL1, carries
     * `guarded_same_sp0_irq_vector`, `guarded_same_sp0_fiq_vector`,
     * `guarded_same_sp1_irq_vector`, `guarded_same_sp1_fiq_vector`,
     * `guarded_lower_irq_vector_64` and `guarded_lower_fiq_vector_64`, and
     * 19A348's PPL has the same table at `_GuardedExceptionVectorsBase` with
     * a real handler in every slot -- `gtr_irq`, `gtr_fiq`,
     * `gl1_sp1_irq_vector`, `gl1_sp1_fiq_vector`, `gl0_irq`, `gl0_fiq` -- and
     * not one deadloop among them.  A monitor does not write six asynchronous
     * vectors for exceptions it never expects to take.  jprx/qemu-sptm models
     * the hardware the same way: in `arm_cpu_do_interrupt_aarch64` an
     * EXCP_IRQ or EXCP_FIQ taken in guarded state uses `vbar_gl[el]` and the
     * GL bank like any other exception, and nothing anywhere consults DAIF or
     * the guarded flag when deciding to *raise* a line.  Masking decides only
     * whether an exception is taken.
     *
     * Withholding it was also unbounded, which is what made the failures come
     * and go.  A GENTER and a GEXIT at guest EL1 are carried out by the
     * hardware without an exit, so nothing re-evaluated this when the guest
     * left the monitor: the level went back up only at the next exit that
     * happened for some other reason.  On a busy machine that is immediate;
     * on an idle one it is never, and `cpu_broadcast_xcall` waits six seconds
     * and panics.
     */
    /*
     * And a fast IPI this library carries: a pending IPI_SR bit is the FIQ
     * the VMM would have asked for on its behalf, so it rides the same gate.
     */
    bool asked = s->vmm_fiq || ohv_ipi_pending(s);
    bool vmm = asked && !ohv_level_held_in_monitor(s);
    /*
     * The timer is not folded in here.
     *
     * `s->timer_fiq` is still worked out above because the trace reads it,
     * but the line carries exactly one thing: what the VMM asked for.  QEMU
     * takes the guest's timers through `ohv_vcpu_timer_state` and
     * `ohv_vcpu_timer_deadline` -- the first says what is due now, the second
     * how long a core may sleep -- and asks for the FIQ like any other
     * interrupt, so one side owns that decision instead of two.
     */
    uint64_t want = vmm ? (1ull << 6) : 0;

    if (asked && !vmm && ohv_trace_on(OHV_TRACE_GATE)) {
        {
            fprintf(stderr, "[ohv] gate vcpu %llu FIQ held: wfx %d mon %d"
                    " pc %#llx cpsr %#x reason %u esr %#llx\n",
                    (unsigned long long)s->id, (int)s->in_wfx,
                    ohv_guest_in_monitor(s) ? 1 : 0,
                    (unsigned long long)ohv_rw(s->ctx)->regs.pc,
                    (unsigned)ohv_rw(s->ctx)->regs.cpsr,
                    s->last_reason, (unsigned long long)s->last_esr);
        }
    }

    if ((hcr & (1ull << 6)) == want) {
        return;
    }
    /*
     * OHV_TRACE_VF_K narrows this to the kernel era.  The firmware works its
     * timer thousands of times before the kernel exists, and one line per
     * edge there is both the wrong question and slow enough to change the
     * answer.  el2/ger say where the guest is, which is what decides whether
     * gate mode 2 could have held this edge back.
     */
    if (ohv_trace_on(OHV_TRACE_VF) &&
        (!ohv_trace_on(OHV_TRACE_VF_K) || g_kernel_running)) {
        fprintf(stderr, "[ohv] VF %s: pc %#llx mon %#llx cpsr %#x vmm %d"
                " timer %d el2 %d ger %d p_ctl %#llx p_cval %#llx now %#llx\n",
                want ? "up  " : "down",
                (unsigned long long)ohv_rw(s->ctx)->regs.pc,
                (unsigned long long)s->sptm_base,
                (unsigned)ohv_rw(s->ctx)->regs.cpsr,
                (int)s->vmm_fiq, (int)s->timer_fiq,
                (int)s->guest_at_el2, (int)s->nv_off_for_geret,
                (unsigned long long)s->el2_shadow[OHV_SHADOW_CNTP_CTL],
                (unsigned long long)*ohv_rw_u64(s->ctx,
                    OHV_RW_BANKED_SYSREGS + 10 * 8),
                (unsigned long long)mach_absolute_time());
    }
    ohv_rw_controls(s->ctx)->hcr_el2 = (hcr & ~(1ull << 6)) | want;
    mark_dirty(s->ctx, OHV_STATE_CONTROLS);
}

/*
 * The VMM says the guest has stopped on a WFI or a WFE.
 *
 * Which is the one moment an interrupt level can always be handed over: a WFx
 * is never in the middle of a GENTER, so nothing can carry the level into the
 * monitor, and waking is the whole reason the level exists.  Without this the
 * cores that most need it were the ones the gate would not answer -- XNU's
 * idle wait comes out of WFE only when ISR_EL1 goes non-zero, and a core
 * parked there with DAIF masked can neither be woken nor answer the
 * debugger's cross-call.
 *
 * Cleared by the VMM on the next exception that is not a WFx.
 */
extern "C" void ohv_vcpu_set_parked(hv_vcpu_t id, bool parked) {
    VcpuSlot *s = owned_vcpu(id);

    if (!s) {
        return;
    }
    if (s->in_wfx == parked) {
        return;
    }
    s->in_wfx = parked;
    ohv_set_fiq_level(s);
    ohv_set_irq_level(s);
}

extern "C" hv_return_t ohv_vcpu_set_ipi_affinity(hv_vcpu_t id, uint64_t affinity) {
    VcpuSlot *s = find_vcpu(id);

    if (!s || (affinity != OHV_IPI_AFFINITY_NONE && affinity > 0xffff)) {
        return HV_BAD_ARGUMENT;
    }
    s->ipi_aff.store(affinity, std::memory_order_release);
    return HV_SUCCESS;
}

extern "C" void ohv_set_vcpu_wake_handler(ohv_vcpu_wake_fn fn, void *opaque) {
    g_wake_opaque.store(opaque, std::memory_order_relaxed);
    g_wake_fn.store(fn, std::memory_order_release);
}

extern "C" bool ohv_vcpu_interrupt_pending(hv_vcpu_t id) {
    VcpuSlot *s = find_vcpu(id);

    return s != nullptr && ohv_ipi_pending(s);
}

/*
 * What the guest's own timers say, for the VMM to decide about.
 *
 * The register emulation has to live here: under NV2 the guest's CNTP and
 * CNTV accesses are redirected to the VNCR page, so the banked slots this
 * side maintains are the only place the *guest's* view of those timers
 * exists -- asking the framework for CNTP_CTL_EL0 returns EL2's copy.  What
 * does not belong here is the decision that follows, which is a statement
 * about the machine rather than about the vcpu, so it is made in QEMU beside
 * the interrupt controller and the fast IPI.
 *
 * Bit 0: the physical timer is due and unmasked.  Bit 1: the virtual one is.
 * Bits 3:2: S3_5_C15_C1_3, the guest's own per-timer FIQ enable, which this
 * side traps and stores so the guest can read it back but no longer acts on.
 */
/*
 * Bits 0 and 1 of ohv_vcpu_timer_state(): the physical and the virtual
 * timer, each enabled, unmasked and past its compare value at `now`.
 */
static uint32_t ohv_timer_due_bits(VcpuSlot *s, uint64_t now) {
    uint32_t state = 0;

    for (unsigned which = 0; which < 2; which++) {
        /* which 0 is the virtual timer, 1 the physical one. */
        unsigned ctl_index = which ? 19 : 18;
        unsigned cval_index = which ? 10 : 9;
        volatile uint64_t *ctl = which
            ? (volatile uint64_t *)&s->el2_shadow[OHV_SHADOW_CNTP_CTL]
            : ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + ctl_index * 8);
        uint64_t cval =
            *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + cval_index * 8);

        if ((*ctl & OHV_CNT_ENABLE) == 0 || (*ctl & OHV_CNT_IMASK) != 0) {
            continue;
        }
        if ((int64_t)(now - cval) >= 0) {
            state |= which ? 1u : 2u;
        }
    }
    return state;
}

extern "C" uint32_t ohv_vcpu_timer_state(hv_vcpu_t id) {
    VcpuSlot *s = owned_vcpu(id);
    uint64_t now = mach_absolute_time();
    uint32_t state;

    if (!s) {
        return 0;
    }
    /*
     * Worked out here rather than reported from `timer_fired_p/v`.
     *
     * Those flags are only refreshed by `ohv_expire_timers`, which runs on
     * the way *into* the guest, so a caller asking after an exit reads the
     * judgement made at the previous entry.  A timer that came due while the
     * guest was running would then not be seen until the exit after next --
     * and a core that halts on a WFI has no next exit at all, which is
     * exactly how `sleep(20)` in the ramdisk stopped returning.
     */
    /*
     * The architectural rule, and only that.
     *
     * S3_5_C15_C1_3 is still reported in bits 3:2 for whoever wants it, but
     * it is not what decides delivery.  Making it the gate is what stopped
     * every timed wait: measured with the ramdisk's own `sleep`, three cores
     * sat in XNU's `cpu_idle` at
     *
     *     mrs x9, ISR_EL1 ; cbnz x9, out ; ... ; wfe ; b back
     *
     * sampled twelve times out of twelve on the `b` after the WFE, with
     * ISR_EL1 reading zero -- the guest was waiting for a level that this
     * side had decided not to raise, because XNU clears that register and
     * never sets it again.  A timer that is enabled, unmasked and past its
     * compare value is due; that is what the architecture says and what the
     * guest is waiting on.
     */
    state = ohv_timer_due_bits(s, now);
    /*
     * What the VMM's line now carries for the timers; see
     * ohv_vmm_line_settled().
     */
    s->timer_seen = state;
    return state | (uint32_t)(s->vm_tmr_fiq_ena & 3u) << 2;
}

/*
 * When the guest's next timer is due, in the host's counter.
 *
 * The state above answers "is it due"; a core that halts on a WFI needs the
 * other half -- "when" -- because no exit happens while it sleeps and the
 * wakeup has to be armed in advance.  QEMU used to read CNTP_CVAL_EL0 from
 * the library for that, which under FEAT_NV2 is EL2's copy and not the
 * guest's, so once this side stopped raising the timer itself a sleeping core
 * had nothing left that could wake it: `sleep(20)` in the ramdisk never
 * returned.
 *
 * Zero means nothing is armed that would raise a FIQ, so the caller should
 * halt and wait for an interrupt instead.
 */
extern "C" uint64_t ohv_vcpu_timer_deadline(hv_vcpu_t id) {
    VcpuSlot *s = owned_vcpu(id);
    uint64_t best = 0;

    if (!s) {
        return 0;
    }
    for (unsigned which = 0; which < 2; which++) {
        /* which 0 is the virtual timer, 1 the physical one, as above. */
        unsigned ctl_index = which ? 19 : 18;
        unsigned cval_index = which ? 10 : 9;
        volatile uint64_t *ctl = which
            ? (volatile uint64_t *)&s->el2_shadow[OHV_SHADOW_CNTP_CTL]
            : ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + ctl_index * 8);
        uint64_t cval =
            *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + cval_index * 8);

        /*
         * Enabled is the whole test.  IMASK and S3_5_C15_C1_3 decide whether
         * the expiry is *delivered* as a FIQ; they say nothing about when the
         * timer comes due, and ISTATUS is set either way for the guest to
         * poll.  Requiring them here returned zero for a timer that was
         * plainly armed, so a halting core was given no wakeup at all and
         * `sleep(20)` never came back.
         */
        if ((*ctl & OHV_CNT_ENABLE) == 0) {
            continue;
        }
        if (best == 0 || (int64_t)(cval - best) < 0) {
            best = cval;
        }
    }
    return best;
}

static void ohv_expire_timers(VcpuSlot *s) {
    /* The compare values in the banked slots are in the host's counter. */
    uint64_t now = mach_absolute_time();
    bool raise = false;

    ohv_note_image_band(s);

    for (unsigned which = 0; which < 2; which++) {
        unsigned ctl_index = which ? 19 : 18;   /* CNTP_CTL, CNTV_CTL */
        unsigned cval_index = which ? 10 : 9;
        volatile uint64_t *ctl = which
            ? (volatile uint64_t *)&s->el2_shadow[OHV_SHADOW_CNTP_CTL]
            : ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + ctl_index * 8);
        uint64_t cval =
            *ohv_rw_u64(s->ctx, OHV_RW_BANKED_SYSREGS + cval_index * 8);

        bool fired = false;

        /*
         * ohv_set_sw_vtimer_istatus(false): leave the virtual timer's control word alone.
         *
         * Slot 18 is not this library's scratch space -- it is the word the
         * kernel loads into CNTV_CTL_EL02 and, in `_hv_pending_vtimer`, the
         * word it *believes* whenever `state_valid & ARM_GUEST_STATE_SYSREGS`
         * is set, reading the hardware only when it is not.  Rewriting it here
         * every entry with a software ISTATUS is therefore a candidate for why
         * the kernel has never once reported a guest timer event, at either
         * exception level.  Delivery is untouched: `fired` is decided by IMASK,
         * not by this bit.
         */
        bool sw_istatus = !(which == 0 && !ohv_cfg(sw_vtimer_istatus));

        if ((*ctl & OHV_CNT_ENABLE) != 0) {
            if ((int64_t)(now - cval) >= 0) {
                /*
                 * How often this side finds the guest's timer already due.
                 * The kernel can only report a hardware event if a host
                 * interrupt lands while it is expired; if this count is far
                 * above the host's interrupt rate, software always gets there
                 * first and hardware never has a window.
                 */
                if (which == 0) {
                    g_vfire.fetch_add(1, std::memory_order_relaxed);
                }
                if (sw_istatus && (*ctl & OHV_CNT_ISTATUS) == 0) {
                    *ctl |= OHV_CNT_ISTATUS;
                    mark_dirty(s->ctx, OHV_STATE_SYSREGS);
                }
                /*
                 * ISTATUS is maintained whatever the delivery rule decides:
                 * the firmware polls it to find out its timer expired, and
                 * skipping the whole timer when delivery is off takes that
                 * away -- measured, the boot stops partway through the
                 * upload with the firmware waiting on a bit that never sets.
                 *
                 * IMASK is the timer's own mask and belongs here.  Whether a
                 * timer that is due and unmasked may actually be delivered is
                 * a question about the guest, not the timer, and is answered
                 * in ohv_timer_fiq_wanted().
                 */
                /*
                 * ohv_set_sw_vtimer(false): maintain the timer but do not deliver it.
                 *
                 * The kernel reports a guest timer event only when a physical
                 * interrupt is taken *while the guest runs* and the guest's
                 * CNTV_CTL_EL02 shows ISTATUS at that instant
                 * (`hv_vcpu.c:2604`); a host interrupt with nothing pending is
                 * handled and the guest re-entered without the VMM ever being
                 * told.  This side runs `ohv_expire_timers` on every entry --
                 * a million times a second -- while host interrupts arrive a
                 * thousand times a second, so software raises VF and XNU
                 * re-arms long before hardware can be caught expired.  Whether
                 * that is why `VTIMER_ACTIVATED` has never once fired is what
                 * this switch is for.  ISTATUS is still maintained: the guest
                 * polls it.
                 */
                fired = (*ctl & OHV_CNT_IMASK) == 0 &&
                        !(which == 0 && !ohv_cfg(sw_vtimer));
            } else if (sw_istatus && (*ctl & OHV_CNT_ISTATUS) != 0) {
                *ctl &= ~OHV_CNT_ISTATUS;
                mark_dirty(s->ctx, OHV_STATE_SYSREGS);
            }
        }
        if (which) {
            s->timer_fired_p = fired;
        } else {
            s->timer_fired_v = fired;
        }
        raise = raise || fired;
    }
    /*
     * Only once the kernel is up, and then without a budget.  The firmware
     * arms these timers thousands of times before the kernel exists, and a
     * trace that spends itself there answers about the wrong era -- while
     * still being heavy enough, at one write to stderr per exit, to slow the
     * upload it is printing through to a crawl.
     */
    if (ohv_trace_on(OHV_TRACE_TIMER) && g_kernel_running) {
        fprintf(stderr, "[ohv] vcpu %llu timers now %#llx cntp_ctl %#llx"
                " cntp_cval %#llx cntv_ctl %#llx raise %d\n",
                (unsigned long long)s->id, (unsigned long long)now,
                (unsigned long long)*ohv_rw_u64(s->ctx,
                    OHV_RW_BANKED_SYSREGS + 19 * 8),
                (unsigned long long)*ohv_rw_u64(s->ctx,
                    OHV_RW_BANKED_SYSREGS + 10 * 8),
                (unsigned long long)*ohv_rw_u64(s->ctx,
                    OHV_RW_BANKED_SYSREGS + 18 * 8),
                (int)raise);
    }
    /*
     * Delivered on the virtual FIQ, as a level, because that is where both
     * the firmware and the kernel look for it.
     *
     * iBoot's main loop at 0x1fc146094 reads ISR_EL1 and dispatches on two
     * bits: bit 6, F, goes to the routine that reads CNTP_CTL and services
     * the timer; bit 7, I, goes to the interrupt controller.  Linux's
     * irq-apple-aic agrees from the other side -- the CPU timers are read in
     * aic_handle_fiq, never as an AIC source.  Raised on the virtual IRQ, as
     * this was, the timer arrives with F clear and I set, so the firmware
     * skips its own service routine and goes looking for a controller
     * interrupt that is not there.
     *
     * This needed the VMM's side of the same line sorted out first: three
     * places there wrote CPU_INTERRUPT_FIQ from their own partial view of it,
     * and one of them raised without ever lowering, so the line was latched
     * high before this side could contribute anything.
     *
     * The gate on VM_TMR_FIQ_ENA_EL2 above is kept, and it is wrong.  Linux's
     * irq-apple-aic handles cntp_ctl_el0 and cntv_ctl_el0 -- which is what
     * the banked pair here is -- with no gate at all, and consults that
     * register only for the _EL02 pair, the guest timers a VHE host sees; its
     * aic_init_cpu() clears both bits on every core exactly as SPTM's
     * common_start does.  Obeying it silences the guest's own timers for the
     * whole boot: twenty million passes through this function once the kernel
     * is up and not one raise, so every timed sleep in the kernel blocks
     * forever.
     *
     * It is kept anyway because removing it, with the line and the edges both
     * already right, breaks the boot earlier still -- the kernel reaches
     * AppleImage4 and SPTM then spins in return_from_sptm_exception:
     *
     *     mrs x8, TPIDR_GL2 ; ldr x9, [x8, #0x30] ; cbnz x9, .
     *
     * which is its "still nested inside an exception" assertion.  So the
     * timer FIQ is arriving at a moment SPTM cannot take one.  The
     * architectural shape of that is the thing to fix: HCR_EL2.VF raises a
     * virtual FIQ *for EL1*, and SPTM believes it is at EL2 -- but its EL2 is
     * emulated on the hardware's EL1 here, so it receives one anyway.  The
     * timer must not be raised while the guest is in its own EL2, and this
     * side already knows when that is.
     */
    ohv_set_fiq_level(s);
    /*
     * And the IRQ, on the same beat: a level held back because the guest was
     * in the monitor has to be offered again once it is not, and this is the
     * only place that runs on every turn of the vCPU.
     */
    ohv_set_irq_level(s);
}


static hv_return_t hv_vcpu_run_inner(hv_vcpu_t id);

/*
 * A read-only look at a vCPU's EL1 and guarded banks when the VMM stops it.
 *
 * Opt-in and inert unless asked for: DIAG_SYSREGS_ON_STOP names a file, and
 * while that file exists every vCPU that comes back from a run as CANCELED --
 * which is what a QMP `stop` does to each of them -- prints its own registers
 * once, read through the same path the VMM uses, on its own thread (the only
 * thread allowed to ask).  It writes nothing.  The core this was written for
 * is the SEP's, whose exception state no other path can see: the gdb stub's
 * register numbering does not fit its CPU model and `info registers` shows
 * general registers only.
 */
static void ohv_diag_sysregs_on_stop(VcpuSlot *s, hv_vcpu_t id) {
    static const struct { uint16_t enc; const char *name; } regs[] = {
        {0xc290, "ESR_EL1"},  {0xc201, "ELR_EL1"},   {0xc300, "FAR_EL1"},
        {0xc200, "SPSR_EL1"}, {0xc080, "SCTLR_EL1"}, {0xc100, "TTBR0_EL1"},
        {0xc101, "TTBR1_EL1"}, {0xc102, "TCR_EL1"},  {0xc600, "VBAR_EL1"},
        {0xc510, "MAIR_EL1"}, {0xc3a0, "PAR_EL1"},   {0xc208, "SP_EL0"},
        {0xe208, "SP_EL1"},   {0xc684, "TPIDR_EL1"},
        {0xf7d5, "ESR_GL1"},  {0xf7d6, "ELR_GL1"},   {0xf7d7, "FAR_GL1"},
        {0xf7d3, "SPSR_GL1"}, {0xf7d2, "VBAR_GL1"},
    };
    static std::atomic<uint64_t> done{0};
    const char *path = getenv("DIAG_SYSREGS_ON_STOP");

    if (path == nullptr || path[0] == '\0' || s->id >= 64 ||
        (done.load(std::memory_order_relaxed) >> s->id) & 1) {
        return;
    }
    if (access(path, F_OK) != 0) {
        return;
    }
    done.fetch_or(1ull << s->id, std::memory_order_relaxed);
    char line[2048];
    int n = snprintf(line, sizeof(line), "[ohv-diag] vcpu %llu pc %#llx cpsr %#llx"
                     " hcr %#llx guest_at_el2 %d one_space %d",
                     (unsigned long long)s->id,
                     (unsigned long long)ohv_rw(s->ctx)->regs.pc,
                     (unsigned long long)ohv_rw(s->ctx)->regs.cpsr,
                     (unsigned long long)ohv_rw_controls(s->ctx)->hcr_el2,
                     (int)s->guest_at_el2, (int)ohv_cfg(one_space));
    for (unsigned i = 0; i < sizeof(regs) / sizeof(regs[0]) && n > 0 &&
         n < (int)sizeof(line); i++) {
        uint64_t v = 0;
        hv_return_t r = hv_vcpu_get_sys_reg(id, (hv_sys_reg_t)regs[i].enc, &v);

        n += snprintf(line + n, sizeof(line) - (size_t)n, " %s=%s%#llx",
                      regs[i].name, r == HV_SUCCESS ? "" : "!",
                      (unsigned long long)v);
    }
    /*
     * And the Apple lock and protection registers, which no descriptor names
     * and so cannot be asked for by encoding: read straight out of the
     * extended block after a sync.  These are the state a reset does not
     * touch -- arm_set_cpu_on() rewrites the architected file only -- so they
     * are what tells a core reset into the low vectors from a fresh one.
     */
    {
        static const struct { unsigned idx; const char *name; } ext[] = {
            {27, "VMSA_LOCK_EL1"}, {3, "CTRR_CTL_EL1"}, {4, "CTRR_LOCK_EL1"},
            {42, "GXF_CONFIG_EL1"}, {55, "SPRR_CONFIG_EL1"}, {29, "APCTL_EL1"},
        };
        bool ok = (*ohv_ro_u64(s->ctx, OHV_RO_STATE_VALID) & (1ull << 61)) != 0 ||
                  ohv_raw_trap(OHV_TRAP_VCPU_SYSREGS_SYNC, nullptr) == HV_SUCCESS;

        for (unsigned i = 0; i < sizeof(ext) / sizeof(ext[0]) && n > 0 &&
             n < (int)sizeof(line); i++) {
            n += snprintf(line + n, sizeof(line) - (size_t)n, " %s=%s%#llx",
                          ext[i].name, ok ? "" : "!",
                          (unsigned long long)*ohv_rw_u64(
                              s->ctx, OHV_RW_EXTREGS + ext[i].idx * 8));
        }
    }
    fprintf(stderr, "%s\n", line);
}

extern "C" hv_return_t hv_vcpu_run(hv_vcpu_t id) {
    hv_return_t r = hv_vcpu_run_inner(id);
    VcpuSlot *s = owned_vcpu(id);

    if (r == HV_SUCCESS && s != nullptr &&
        s->pub_exit.reason == HV_EXIT_REASON_CANCELED) {
        ohv_diag_sysregs_on_stop(s, id);
    }
    return r;
}

static hv_return_t hv_vcpu_run_inner(hv_vcpu_t id) {
    VcpuSlot *s = owned_vcpu(id);
    if (!s) return HV_BAD_ARGUMENT;
    /*
     * Inside this call, for a fast IPI sent from another vCPU: see
     * ohv_ipi_notify().  Every way out of it clears it again.
     */
    struct InRun {
        VcpuSlot *s;
        explicit InRun(VcpuSlot *v) : s(v) {
            s->in_run.store(true, std::memory_order_seq_cst);
        }
        ~InRun() { s->in_run.store(false, std::memory_order_seq_cst); }
    } in_run(s);
    /*
     * One call from the caller is as many entries into the guest as the
     * kernel asks for: it returns for things that are its own business, and
     * the framework goes straight back in rather than passing them up.
     */
    for (;;) {
        uint64_t t0 = mach_absolute_time();
        hv_return_t r;

        /*
         * A core released after the handoff inherits the machine's answer.
         * Without this only the core that performed the handoff ERET is an
         * EL1 guest and the rest still believe they are hypervisors.
         */
        /*
         * Except the vCPUs named by ohv_set_nv_keep_vcpus().
         *
         * The SEP is a second guest on the same VM: it runs its own ROM,
         * which checks CurrentEL and takes a different arm on the answer, and
         * the application processors' decision to stop being a hypervisor is
         * not a statement about it.  Measured: clearing NV on every vCPU
         * stops the boot in the ROM's SEP handshake, 1692 bytes of console.
         * `ohv_set_nv_keep_vcpus(0x40)` leaves vCPU 6 alone -- the same shape as
         * ohv_set_tidcp_vcpus(), and for the same reason.
         */
        uint64_t nv_keep = ohv_cfg(nv_keep_vcpus);
        if (g_guest_left_el2.load(std::memory_order_relaxed) &&
            !g_monitor_next.load(std::memory_order_relaxed) &&
            !(s->id < 64 && ((nv_keep >> s->id) & 1)) &&
            (ohv_rw_controls(s->ctx)->hcr_el2 & OHV_HCR_NV) != 0) {
            ohv_rw_controls(s->ctx)->hcr_el2 &= ~OHV_HCR_NV;
            mark_dirty(s->ctx, OHV_STATE_CONTROLS);
            s->guest_at_el2 = false;
        }
        /*
         * TTLB follows NV (see ohv_tlbi_replay): a guest hypervisor's TLBIs
         * are issued from a guarded level this machine cannot resume, so they
         * run natively; a kernel at EL1 has them trapped and replayed.  NV
         * changes hands at the handoff and at the cores' release, so the bit
         * is settled here, on the way in, rather than at each of those sites.
         */
        {
            uint64_t h = ohv_rw_controls(s->ctx)->hcr_el2;
            uint64_t want = (ohv_tlbi_replay_on() && !(h & OHV_HCR_NV)) ?
                            OHV_HCR_TTLB : 0;

            if ((h & OHV_HCR_TTLB) != want) {
                ohv_rw_controls(s->ctx)->hcr_el2 = (h & ~OHV_HCR_TTLB) | want;
                mark_dirty(s->ctx, OHV_STATE_CONTROLS);
            }
        }
        /*
         * The guest's own HCR_EL2, once more, on the way in.
         *
         * The seed at vCPU creation survives the address-space join -- measured
         * on a boot that printed 0x30488000000 for all seven --
         * but by the time the guest reads the register a secondary core sees
         * 0x80000000 again, so the kernel initialises the VNCR page somewhere
         * past that point.  Rather than find where, the word is put back here,
         * under a guard that can only match the framework's own fresh value:
         * the exact bare RW word.  Nothing in this chain ever writes that --
         * the ROM's entry code writes RW|APK|API and then E2H|TGE on top, SPTM's
         * writes are sent to a sink by the ROM's handoff patcher, and XNU has
         * no `MSR HCR_EL2` at all -- so a value the guest chose is never
         * overwritten here.
         *
         * Why it matters: each of XNU's eight vector slots reads HCR_EL2 and
         * treats `CurrentEL == EL2 && TGE == 0` as "this exception is my
         * guest's".  Under FEAT_NV the first half is true by construction, so a
         * core whose TGE reads 0 sends its first exception of any class into
         * the hv guest handler and dies dereferencing TPIDR_EL2.
         */
        {
            volatile uint64_t *nh = ohv_rw_u64(s->ctx, OHV_NESTED_HCR_EL2);

            if (*nh != s->nested_hcr_seen) {
                if (ohv_trace_on(OHV_TRACE_NESTED)) {
                    fprintf(stderr, "[ohv] vcpu %llu guest HCR_EL2 %#llx ->"
                                    " %#llx\n",
                            (unsigned long long)s->id,
                            (unsigned long long)s->nested_hcr_seen,
                            (unsigned long long)*nh);
                }
                s->nested_hcr_seen = *nh;
            }
            if (*nh == OHV_HCR_RW && ohv_cfg(nested_inherit)) {
                *nh = ohv_nested_reset_hcr();
                s->nested_hcr_seen = *nh;
                if (ohv_trace_on(OHV_TRACE_NESTED)) {
                    fprintf(stderr, "[ohv] vcpu %llu guest HCR_EL2 reseeded"
                                    " %#llx\n",
                            (unsigned long long)s->id,
                            (unsigned long long)*nh);
                }
            }
        }
        ohv_expire_timers(s);
        r = ohv_raw_trap(OHV_TRAP_VCPU_RUN, nullptr);
        uint64_t t1 = mach_absolute_time();

        s->wfi_ticks += (t1 - t0);
        s->run_count++;
        /*
         * The first handful of exits of a vcpu other than the first one.
         *
         * A core released into the kernel parks on a load that fetches a zero
         * from memory which is demonstrably not zero, and every layer above
         * this one has been ruled out by measurement.  What has never been
         * watched is the vcpu itself as it starts: whether it enters at the
         * address it was given, what it faults on, and whether its early exits
         * look like the first one's.
         */
        if (ohv_trace_on(OHV_TRACE_FIRSTRUN) &&
            (ohv_ro(s->ctx)->exit.vmexit_reason == OHV_VMEXIT_HANDLED_FAULT ||
             ohv_ro(s->ctx)->exit.vmexit_reason == OHV_VMEXIT_UNHANDLED_FAULT) &&
            s->kernel_exits++ < 60) {
            ohv_rw_page_head_t *rw = ohv_rw(s->ctx);
            ohv_vmexit_info_t *e = &ohv_ro(s->ctx)->exit;

            fprintf(stderr, "[ohv] vcpu %llu run #%llu -> %d, pc %#llx,"
                    " reason %u, esr %#llx, far %#llx,"
                    " ttbr1 %#llx, tcr %#llx, sctlr %#llx\n",
                    (unsigned long long)s->id,
                    (unsigned long long)s->run_count, (int)r,
                    (unsigned long long)rw->regs.pc,
                    (unsigned)e->vmexit_reason,
                    (unsigned long long)e->vmexit_esr,
                    (unsigned long long)e->vmexit_far,
                    (unsigned long long)*ohv_rw_u64(s->ctx,
                        OHV_RW_BANKED_SYSREGS + 1 * 8),
                    (unsigned long long)*ohv_rw_u64(s->ctx,
                        OHV_RW_BANKED_SYSREGS + 2 * 8),
                    (unsigned long long)*ohv_rw_u64(s->ctx,
                        OHV_RW_BANKED_SYSREGS + 12 * 8));
        }
        if (r != HV_SUCCESS) {
            return r;
        }
        /*
         * A cancel that was asked for while the guest was running, and that
         * the run trap did not report.  It is still standing here, and this
         * is the first chance to act on it -- waiting for the turnaround
         * check below would carry it past exit_from_ro, which may decide the
         * exit was its own business and re-enter without ever telling the VMM.
         */
        if (s->exit_requested.exchange(false, std::memory_order_acq_rel)) {
            if (ohv_trace_on(OHV_TRACE_KICK)) {
                fprintf(stderr, "[ohv] vcpu %llu cancel after run at pc %#llx"
                        "\n", (unsigned long long)s->id,
                        (unsigned long long)ohv_rw(s->ctx)->regs.pc);
            }
            s->pub_exit.reason = HV_EXIT_REASON_CANCELED;
            return HV_SUCCESS;
        }
        /*
         * A cancel nobody is waiting on: one this library sent to bring the
         * vCPU in for a fast IPI, or the kernel's latch of a VMM cancel that
         * has already been served.  There is nothing in it for the VMM, so go
         * back in -- the level goes up on the way.
         */
        if (ohv_cfg(ipi_inline) &&
            ohv_exit_info(s->ctx)->vmexit_reason == OHV_VMEXIT_NONE) {
            continue;
        }
        if (exit_from_ro(s) == EXIT_TO_VMM) {
            /*
             * The VMM re-reads everything it cares about on the way back in,
             * so a cancel still standing here has already been served.
             */
            s->exit_requested.store(false, std::memory_order_release);
            return HV_SUCCESS;
        }
        /*
         * About to re-enter without telling the VMM.  This is the turnaround a
         * cancel gets lost in: the run trap can only deliver one to a vCPU
         * that is inside it, and this one is not.  Honour it here instead --
         * anything the VMM wanted to inject is injected on the way back.
         */
        if (s->exit_requested.exchange(false, std::memory_order_acq_rel)) {
            if (ohv_trace_on(OHV_TRACE_KICK)) {
                fprintf(stderr, "[ohv] vcpu %llu cancel honoured at pc %#llx"
                        " hcr %#llx\n", (unsigned long long)s->id,
                        (unsigned long long)ohv_rw(s->ctx)->regs.pc,
                        (unsigned long long)ohv_rw_controls(s->ctx)->hcr_el2);
            }
            s->pub_exit.reason = HV_EXIT_REASON_CANCELED;
            return HV_SUCCESS;
        }
    }
}

extern "C" hv_return_t hv_vcpus_exit(hv_vcpu_t *vcpus, uint32_t count) {
    if (!vcpus && count) return HV_BAD_ARGUMENT;
    uint64_t mask = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (vcpus[i] >= kMaxVcpuIds) return HV_BAD_ARGUMENT;
        mask |= 1ull << vcpus[i];
    }
    /*
     * Latched before the trap, so a cancel that lands while the vCPU is
     * between entries -- which the trap alone cannot deliver -- is still
     * seen.  See VcpuSlot::exit_requested.
     */
    for (uint32_t i = 0; i < count; i++) {
        g_vcpus[vcpus[i]].exit_requested.store(true, std::memory_order_release);
    }
    return ohv_raw_trap(OHV_TRAP_VCPU_RUN_CANCEL, (void *)mask);
}
