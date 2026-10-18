// The Apple private system registers, which no SDK header describes and the
// generator therefore cannot see.  Kept beside the generated table rather than
// inside it, so regenerating does not throw them away.
//
// The encodings are s3_<op1>_c15_<CRm>_<op2>, read off a live monitor by
// matching logged accesses against its own disassembly.  The indices are into
// ohv_extregs_t; the GL1 bank sits there in the order sp, tpidr, aspsr, vbar,
// far, esr, elr, spsr, which is not the order of its CRm encodings and is
//
// Every one of these is read back after the hardware has written it -- the GL1
// bank is filled by GENTER itself -- so each access syncs first; a stale mirror
// answers zero where the return address should be.
// confirmed by the context offsets those members are anchored to.
#include "ohv_internal.h"

namespace ohv {

#define EXT(n) 2, (n)
/* The _EL12 view of the same slot: reads answer from it, writes are
 * not carried.  See `case 8` in ohv_vcpu.cpp for why. */
#define EXT12(n) 8, (n)

static const SysRegDesc kAppleTable[] = {
    /*
     * The architected _EL12 views, which the generated table has no source for.
     *
     * At EL2 with HCR_EL2.E2H set, `FOO_EL1` is the level that is executing and
     * `FOO_EL12` is the level below.  This guest's EL2 runs on hardware EL1, so
     * the silicon applies neither redirection: the plain names reach the real
     * EL1 registers, which is what makes the monitor's own writes take effect
     * and is why the machine boots at all, and the _EL12 names reach nothing --
     * no descriptor here, and `service_nv2_access` only shadows CRn 11 and 15,
     * so they leave as HV_UNSUPPORTED and are dropped.
     *
     * Dropping them is what hurts.  24A437's SPTM saves and restores the
     * kernel's translation context across a root-table switch through these
     * views -- one routine writes TTBR0_EL12 and TTBR1_EL12, and a second
     * reads them back -- so with the writes going nowhere
     * the kernel keeps whatever the monitor last put in the registers for its
     * own use.  Its text is then mapped the monitor's way, not executable at
     * EL1, and the next instruction the kernel fetches aborts on a stage-1
     * permission fault at level 3: `[SPTM Dispatch] Synchronous exception taken
     * while SP1 selected` at the kernel's own text base, with `lr` inside
     * sptm_switch_root.
     *
     * One physical set is all there is, so the two views share a slot and the
     * last writer wins.  That is the order the monitor already uses -- its own
     * while it works, the kernel's through the _EL12 view just before it hands
     * back -- so the register holds the right value at each point.  Unlike the
     * guarded set, nothing validates these as a group, so sharing cannot make
     * the state inconsistent the way GXF_ENTRY_EL12 did.
     *
     * Selectors taken out of the image's own MRS/MSR, not worked out by hand:
     * SCTLR_EL12 e880, TTBR0_EL12 e900, TTBR1_EL12 e901, TCR_EL12 e902,
     * MAIR_EL12 ed10, AMAIR_EL12 ed18, CNTKCTL_EL12 ef08.  There is no
     * VBAR_EL12 -- SPTM names VBAR_EL1 and nothing else -- and CPACR_EL12 is
     * left out because the generated table has no slot for CPACR_EL1 either.
     * Indices are the banked ones that table already uses for the plain names:
     * SCTLR_EL1 12, TTBR0_EL1 0, TTBR1_EL1 1, TCR_EL1 2, MAIR_EL1 6,
     * AMAIR_EL1 7, CNTKCTL_EL1 20.
     */
#define BANK12(n) 1, (n)
    {0xe880, BANK12(12), OHV_STATE_SYSREGS, true},  /* SCTLR_EL12 */
    {0xe900, BANK12(0),  OHV_STATE_SYSREGS, true},  /* TTBR0_EL12 */
    {0xe901, BANK12(1),  OHV_STATE_SYSREGS, true},  /* TTBR1_EL12 */
    {0xe902, BANK12(2),  OHV_STATE_SYSREGS, true},  /* TCR_EL12   */
    {0xed10, BANK12(6),  OHV_STATE_SYSREGS, true},  /* MAIR_EL12   */
    {0xed18, BANK12(7),  OHV_STATE_SYSREGS, true},  /* AMAIR_EL12  */
    {0xef08, BANK12(20), OHV_STATE_SYSREGS, true},  /* CNTKCTL_EL12 */

    /* SPRR: the permission remapping the guarded levels are described by. */
    {0xf788, EXT(55), OHV_STATE_SPRR, true},   /* SPRR_CONFIG_EL1  c1_0 */
    {0xf78d, EXT(58), OHV_STATE_SPRR, true},   /* SPRR_UPERM_EL0   c1_5 */
    {0xf78e, EXT(57), OHV_STATE_SPRR, true},   /* SPRR_PPERM_EL1   c1_6 */

    /*
     * AMX, the matrix coprocessor.  The guest's own trap handler answers an
     * AMX-disabled exception by setting bit 63 of AMX_CONFIG_EL1 and retrying
     * the AMXSET; if that write does not survive, the retry traps again and
     * XNU panics -- "thread %p already has AMX saved state" at pcb.c:729,
     * which is what SpringBoard hit the first time it ran.
     *
     * It cannot survive as a shadow.  The kernel writes AMX_CONFIG_EL12 from
     * this extreg on *every* entry (unused state is treated as dirty), so a
     * value kept anywhere else is overwritten before the guest runs again.
     * Named here, the write lands in the register the kernel reloads from,
     * and the AMX instruction that follows takes the ARM_VMEXIT_REASON_AMX_
     * DISABLED exit the kernel handles by itself.
     *
     * HCR_EL2.TIDCP is why these have to come this way rather than being
     * serviced in the kernel's own MSR handler: hv_handle_msr_trap() returns
     * before its switch for any implementation-defined access while TIDCP
     * stands, and clearing TIDCP wholesale costs the SEP its stage-1 boot.
     */
    {0xe78b, EXT(0), OHV_STATE_AMX, true},     /* AMX_STATE_T_EL1  c1_3 */
    {0xe78c, EXT(1), OHV_STATE_AMX, true},     /* AMX_CONFIG_EL1   c1_4 */

    /* GXF: the guarded execution feature itself. */
    {0xf78a, EXT(42), OHV_STATE_GXF, true},    /* GXF_CONFIG_EL1   c1_2 */
    {0xf7c1, EXT(43), OHV_STATE_GXF, true},    /* GXF_ENTRY_EL1    c8_1 */
    {0xf7c2, EXT(44), OHV_STATE_GXF, true},    /* GXF_ABORT_EL1    c8_2 */

    /* The GL1 bank, s3_6_c15_c10_*. */
    {0xf7d0, EXT(45), OHV_STATE_GXF, true},    /* SP_GL1     c10_0 */
    {0xf7d1, EXT(46), OHV_STATE_GXF, true},    /* TPIDR_GL1  c10_1 */
    {0xf7d2, EXT(48), OHV_STATE_GXF, true},    /* VBAR_GL1   c10_2 */
    {0xf7d3, EXT(52), OHV_STATE_GXF, true},    /* SPSR_GL1   c10_3 */
    {0xf7d4, EXT(47), OHV_STATE_GXF, true},    /* ASPSR_GL1  c10_4 */
    {0xf7d5, EXT(50), OHV_STATE_GXF, true},    /* ESR_GL1    c10_5 */
    {0xf7d6, EXT(51), OHV_STATE_GXF, true},    /* ELR_GL1    c10_6 */
    {0xf7d7, EXT(49), OHV_STATE_GXF, true},    /* FAR_GL1    c10_7 */

    /*
     * The _EL12 / _EL02 views.  Selectors taken out of the MRS/MSR that both
     * SPTM images carry, cross-checked against the plain views above
     * (SPRR_PPERM_EL1 0xf78e, GXF_ENTRY_EL1 0xf7c1, SPSR_GL1 0xf7d3,
     * TPIDR_GL2 0xf7d9 all came out as this table already has them).
     * SP_GL12 is 0xf7d0, which is the row named SP_GL1 above, so it already
     * answers from the bank and needs nothing here.
     */
    {0xf7f9, EXT12(42), OHV_STATE_GXF,  true},  /* GXF_CONFIG_EL12      c15_1 */
    {0xf7fa, EXT12(43), OHV_STATE_GXF,  true},  /* GXF_ENTRY_EL12       c15_2 */
    {0xf7fb, EXT12(44), OHV_STATE_GXF,  true},  /* GXF_PABENTRY_EL12    c15_3 */
    {0xf7ca, EXT12(48), OHV_STATE_GXF,  true},  /* VBAR_GL12            c9_2  */
    {0xf7fc, EXT12(55), OHV_STATE_SPRR, true},  /* SPRR_CONFIG_EL12     c15_4 */
    {0xf7fd, EXT12(56), OHV_STATE_SPRR, true},  /* SPRR_AMRANGE_EL12    c15_5 */
    {0xf7ff, EXT12(57), OHV_STATE_SPRR, true},  /* SPRR_PPERM_EL12      c15_7 */
    {0xe7aa, EXT12(58), OHV_STATE_SPRR, true},  /* SPRR_UPERM_EL02    4_c15_c5_2 */
    {0xf7b0, EXT12(59), OHV_STATE_SPRR, true},  /* SPRR_PMPRR_EL12      c6_0  */
    {0xe7c0, EXT12(60), OHV_STATE_SPRR, true},  /* SPRR_UMPRR_EL12    4_c15_c8_0 */
    {0xf7b1, EXT12(61), OHV_STATE_SPRR, true},  /* SPRR_PPERM_SH1_EL12  c6_1  */
    {0xf7b2, EXT12(62), OHV_STATE_SPRR, true},  /* SPRR_PPERM_SH2_EL12  c6_2  */
    {0xf7b3, EXT12(63), OHV_STATE_SPRR, true},  /* SPRR_PPERM_SH3_EL12  c6_3  */
    {0xe7c1, EXT12(68), OHV_STATE_SPRR, true},  /* SPRR_UPERM_SH1_EL12 4_c15_c8_1 */
    {0xe7c2, EXT12(69), OHV_STATE_SPRR, true},  /* SPRR_UPERM_SH2_EL12 4_c15_c8_2 */
    {0xe7c3, EXT12(70), OHV_STATE_SPRR, true},  /* SPRR_UPERM_SH3_EL12 4_c15_c8_3 */
    {0xe7cc, EXT12(3),  OHV_STATE_CTRR, true},  /* CTRR_CTL_EL12      4_c15_c9_4 */
    {0xe7cd, EXT12(4),  OHV_STATE_CTRR, true},  /* CTRR_LOCK_EL12     4_c15_c9_5 */
    {0xe7c8, EXT12(5),  OHV_STATE_CTRR, true},  /* CTRR_A_LWR_EL12    4_c15_c9_0 */
    {0xe7c9, EXT12(6),  OHV_STATE_CTRR, true},  /* CTRR_A_UPR_EL12    4_c15_c9_1 */
    {0xe7ca, EXT12(7),  OHV_STATE_CTRR, true},  /* CTRR_B_LWR_EL12    4_c15_c9_2 */
    {0xe7cb, EXT12(8),  OHV_STATE_CTRR, true},  /* CTRR_B_UPR_EL12    4_c15_c9_3 */
};

#undef EXT

/*
 * The EL2 registers, and the Apple private ones the generator has no source
 * for either.  Every offset below was measured, not derived: each register
 * was written through the framework with a value nothing else would hold and
 * the private context searched for where it landed.
 *
 * Three groups come out of that.  Some are already inside a region this
 * library describes -- VPIDR_EL2 and VMPIDR_EL2 are run controls, the s3_6
 * encodings are extended registers -- and are named by index there.  Some sit
 * in a nested-EL2 block just past every region at 0x1000, and are named by
 * raw context offset.  The rest the framework accepts while the context shows
 * nothing at all: under NV2 those are the guest's own, reached through its
 * VNCR page, and they go to the shadow.
 */
#ifndef EXT
#define EXT(n) 2, (n)
#endif
#define RAW(off) 6, ((off) / 8)
#define SHADOW(n) 7, (n)
/*
 * A word of the run controls, by its place in ohv_controls_t.  The block
 * moves with the interface -- 0x6a8 under 3.0.0, 0x920 from 3.0.2 -- and the
 * three below used to be RAW(0x930/0x940/0x948), which is right only where it
 * starts at 0x920.  Under 3.0.0 those offsets are inside the extended
 * registers, on ELR_GL1, PMCR1_GL1 and AFSR1_GL1: every state sync of the
 * guest's CPTR_EL2 overwrote the guarded level's exception return address,
 * and the 19A348 restore kernel died on all six cores at once with
 * "PAC failure from kernel" in restored_external (2026-10-15).  Resolved
 * against the layout row at run time, so from 3.0.2 on the address is the
 * one RAW() named.
 */
#define CTRL(field) 9, (offsetof(ohv_controls_t, field) / 8)

static const SysRegDesc kEl2Table[] = {
    /*
     * Run controls.  Named by raw offset like the block below, not by an
     * index into a region: there is no kind for the controls, and the two
     * kinds that take an index are the shared and banked system registers --
     * which is where these three landed, on top of registers that had nothing
     * to do with them.
     */
    {0xe000, CTRL(vpidr_el2),  OHV_STATE_CONTROLS, false},   /* VPIDR_EL2  */
    {0xe005, CTRL(vmpidr_el2), OHV_STATE_CONTROLS, false},   /* VMPIDR_EL2 */
    {0xe08a, CTRL(cptr_el2),   OHV_STATE_CONTROLS, false},   /* CPTR_EL2   */
    /*
     * MDCR_EL2 is two registers wearing one name here, and mapping the guest's
     * onto the host's cost every breakpoint this accelerator can set.
     *
     * The controls word at 0x938 is the *VMM's* monitor debug configuration --
     * `hv_vcpu_set_trap_debug_exceptions` sets TDE in it so a debug exception
     * the guest takes comes out as a VM exit.  The register a VMM syncs under
     * HV_SYS_REG_MDCR_EL2 is the *guest hypervisor's* own MDCR_EL2, which under
     * NV2 is not in the VNCR page and so arrives as a trap, is kept in the
     * VMM's register file, and is written back on every state sync.  With both
     * on the same word, qemu wrote the guest's zero over TDE about fourteen
     * thousand times a boot and no software breakpoint ever fired: the BRK
     * was delivered to the guest, which reported it as its own
     * "ARM synchronous abort".
     *
     * So the guest's copy gets a shadow slot -- nothing in the guest reaches
     * it through hardware anyway -- and the control stays the accelerator's.
     */
    {0xe089, SHADOW(14), 0, false},                    /* MDCR_EL2 (guest's) */

    /* the nested-EL2 block */
    {0xe088, RAW(0x1078), OHV_STATE_CONTROLS, false},  /* HCR_EL2     */
    {0xe108, RAW(0x1020), OHV_STATE_CONTROLS, false},  /* VTTBR_EL2   */
    {0xe10a, RAW(0x1040), OHV_STATE_CONTROLS, false},  /* VTCR_EL2    */
    {0xe703, RAW(0x1060), OHV_STATE_CONTROLS, false},  /* CNTVOFF_EL2 */
    {0xe682, RAW(0x1090), OHV_STATE_CONTROLS, false},  /* TPIDR_EL2   */

    /* Apple private, inside the extended registers */
    /*
     * These seven asked for a state the kernel does not have.
     *
     * ARM_GUEST_STATE_APPLE is bit sixty-three and its own header says "this
     * state is not currently used": nothing in hv_vcpu.c ever tests it.  So a
     * write here landed in the context, read straight back, and was never
     * carried into the silicon -- the same shape as the guarded bank's old
     * problem, and the same cause.
     *
     * What each one wants is the state whose loader carries it, and the
     * extended-register index says which that is:
     *
     *   29 apctl_el1, 40 kernkeyhi_el1, 41 kernkeylo_el1
     *        -> _hv_load_guest_apple_ptrauth_regs, ARM_GUEST_STATE_PTRAUTH_APPLE
     *   53 pmcr1_gl1, 54 afsr1_gl1
     *        -> _hv_load_guest_gxf_regs, ARM_GUEST_STATE_GXF
     *   56 sprr_amrange_el1, 59 sprr_pmprr_el1
     *        -> _hv_load_guest_sprr_regs, ARM_GUEST_STATE_SPRR
     *
     * The first three are what TXM dies on.  SPTM writes APCTL_EL1 ninety-three
     * times and KERNKEY once, TXM authenticates a pointer out of its own image
     * under the key that should have installed, and takes an FPAC with the
     * value intact and the signature wrong.  Measured with a probe: changing
     * the architected APIAKey under a signed pointer breaks its authentication,
     * and changing APCTL_EL1 or KERNKEY does not -- the signature came out
     * byte-identical every time, which is a key that never moved.
     */
    {0xe784, EXT(29), OHV_STATE_PTRAUTH_APPLE, true},   /* APCTL_EL1        */
    {0xe789, EXT(40), OHV_STATE_PTRAUTH_APPLE, true},   /* KERNKEYHI_EL1    */
    {0xe788, EXT(41), OHV_STATE_PTRAUTH_APPLE, true},   /* KERNKEYLO_EL1    */
    {0xf7c7, EXT(53), OHV_STATE_GXF, true},             /* PMCR1_GL1        */
    {0xf781, EXT(54), OHV_STATE_GXF, true},             /* AFSR1_GL1        */
    {0xf78b, EXT(56), OHV_STATE_SPRR, true},            /* SPRR_AMRANGE_EL1 */
    {0xf799, EXT(59), OHV_STATE_SPRR, true},            /* SPRR_PMPRR_EL1   */

    /*
     * The JITBox bank, which is where the B key really lives.
     *
     * XNU's thread_invoke reads JCTL_EL0 out of the outgoing thread and writes
     * the incoming one's value back on every switch, and JCTL is the control
     * whose extended registers are JAPIAKey and JAPIBKey.  Refused here, the
     * VMM's forwarding fell back to a register file of its own and none of it
     * reached the silicon: every core signed with whatever the last thing on
     * that physical core had left in the bank.  With one core running that was
     * invisible.  With six, a thread signs its return address on one core and
     * returns on another, and the kernel takes
     *
     *     PAC failure from kernel with IB key at pc ... (thread_invoke)
     *
     * on a RETAB whose pointer value is perfectly intact.
     *
     *   76 jrange_el1, 77 jctl_el1, 78/79 japiakeyhi/lo, 80/81 japibkeyhi/lo
     *        -> _hv_load_guest_jitbox_regs, ARM_GUEST_STATE_JITBOX
     *
     * JCTL_EL0 has no place of its own in the block -- the kernel restores
     * JCTL through JCTL_EL12 -- so it is not listed here and stays with the
     * VMM.
     */
    {0xe7f9, EXT(76), OHV_STATE_JITBOX, true},          /* JRANGE_EL1       */
    {0xe7fc, EXT(77), OHV_STATE_JITBOX, true},          /* JCTL_EL1         */
    {0xe7ed, EXT(78), OHV_STATE_JITBOX, true},          /* JAPIAKEYHI_EL1   */
    {0xe7ec, EXT(79), OHV_STATE_JITBOX, true},          /* JAPIAKEYLO_EL1   */
    {0xe7ef, EXT(80), OHV_STATE_JITBOX, true},          /* JAPIBKEYHI_EL1   */
    {0xe7ee, EXT(81), OHV_STATE_JITBOX, true},          /* JAPIBKEYLO_EL1   */

    /* accepted by the framework, held nowhere it can be seen */
    {0xe080, SHADOW(0),  0, false},   /* SCTLR_EL2   */
    {0xe100, SHADOW(2),  0, false},   /* TTBR0_EL2   */
    {0xe101, SHADOW(3),  0, false},   /* TTBR1_EL2   */
    {0xe102, SHADOW(4),  0, false},   /* TCR_EL2     */
    {0xe200, SHADOW(5),  0, false},   /* SPSR_EL2    */
    {0xe201, SHADOW(6),  0, false},   /* ELR_EL2     */
    {0xe290, SHADOW(7),  0, false},   /* ESR_EL2     */
    {0xe300, SHADOW(8),  0, false},   /* FAR_EL2     */
    {0xe304, SHADOW(9),  0, false},   /* HPFAR_EL2   */
    {0xe510, SHADOW(10), 0, false},   /* MAIR_EL2    */
    {0xe600, SHADOW(11), 0, false},   /* VBAR_EL2    */
    {0xe708, SHADOW(12), 0, false},   /* CNTHCTL_EL2 */
    {0xf208, SHADOW(13), 0, false},   /* s3_6_c4_c1_0 */
};

const SysRegDesc *sysreg_lookup_apple(uint16_t enc) {
    for (const SysRegDesc &d : kAppleTable) {
        if (d.encoding == enc) {
            return &d;
        }
    }
    for (const SysRegDesc &d : kEl2Table) {
        if (d.encoding == enc) {
            return &d;
        }
    }
    return nullptr;
}

} // namespace ohv
