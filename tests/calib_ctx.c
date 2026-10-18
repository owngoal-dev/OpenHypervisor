// calib_ctx.c - where each write lands in the vCPU context, and what it marks dirty.
//
// Built twice from this one source: against Hypervisor.framework, which is
// right for whatever kernel it ships with, and against libopenhyp.  Each
// control field and each readable system register is written with a changed
// value; the program prints the context offsets that changed and the bits
// the write raised in the state dirty word.  Any line where the two builds
// disagree is a place this library is wrong on the running kernel.
//
//   calib_ctx <dirty-offset> [vhe 0|1]        (0x788 under 3.0.0, 0xa00 3.0.2/3, 0xa08 3.0.4)
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <Hypervisor/Hypervisor.h>

#include <dlfcn.h>

/* Private surface, looked up so a framework without one still runs: 26.x
 * has no _hv_vm_config_set_vhe_enabled at all. */
static hv_return_t (*set_isa)(hv_vm_config_t, uint32_t);
static hv_return_t (*set_vhe)(hv_vm_config_t, bool);
static void *(*get_context)(hv_vcpu_t);
static hv_return_t (*get_control)(hv_vcpu_t, uint32_t, uint64_t *);
static hv_return_t (*set_control)(hv_vcpu_t, uint32_t, uint64_t);
#define LOOK(var, sym) (var = (__typeof__(var))dlsym(RTLD_DEFAULT, sym), \
                        var ? 0 : printf("[no %s] ", sym))

#define CTX 0x8000

static uint8_t before[CTX];

static void report(const char *what, const uint8_t *ctx, size_t dirty_off) {
    uint64_t was, now;
    memcpy(&was, before + dirty_off, 8);
    memcpy(&now, ctx + dirty_off, 8);
    printf("%-22s", what);
    int n = 0;
    for (size_t off = 0; off < CTX; off += 8) {
        if (off == dirty_off) continue;
        if (memcmp(before + off, ctx + off, 8) != 0) {
            if (n++ < 4) printf(" @0x%zx", off);
        }
    }
    if (n > 4) printf(" (+%d)", n - 4);
    if (!n) printf(" (no change)");
    printf("  dirty +0x%llx\n", (unsigned long long)(now & ~was));
}

int main(int argc, char **argv) {
    size_t dirty_off = argc > 1 ? strtoul(argv[1], NULL, 0) : 0x788;
    setvbuf(stdout, NULL, _IONBF, 0);

    LOOK(set_isa, "_hv_vm_config_set_isa");
    LOOK(set_vhe, "_hv_vm_config_set_vhe_enabled");
    LOOK(get_context, "_hv_vcpu_get_context");
    LOOK(get_control, "_hv_vcpu_get_control_field");
    LOOK(set_control, "_hv_vcpu_set_control_field");
    int want_vhe = argc > 2 ? atoi(argv[2]) : 1;
    hv_vm_config_t cfg = hv_vm_config_create();
    if (set_isa) printf("isa=%d ", set_isa(cfg, 4));
    printf("el2=%d ", hv_vm_config_set_el2_enabled(cfg, true));
    if (set_vhe && want_vhe) printf("vhe=%d ", set_vhe(cfg, true));
    hv_return_t r = hv_vm_create(cfg);
    printf("vm=%d ", r);
    if (r) return 1;
    hv_gic_config_t gc = hv_gic_config_create();
    hv_gic_config_set_distributor_base(gc, 0x2000000ull);
    hv_gic_config_set_redistributor_base(gc, 0x2100000ull);
    printf("gic=%d ", hv_gic_create(gc));
    hv_vcpu_t vcpu;
    hv_vcpu_exit_t *ex;
    r = hv_vcpu_create(&vcpu, &ex, hv_vcpu_config_create());
    printf("vcpu=%d\n", r);
    if (r) return 2;

    uint8_t *ctx = get_context(vcpu);
    uint64_t ver;
    memcpy(&ver, ctx + 0x4000, 8);
    printf(
        "ver=0x%llx dirty@0x%zx=0x%llx\n",
        (unsigned long long)ver,
        dirty_off,
        (unsigned long long)*(uint64_t *)(ctx + dirty_off)
    );

    for (uint32_t f = 0; f < 24; f++) {
        uint64_t v = 0;
        if (!get_control || get_control(vcpu, f, &v) != HV_SUCCESS) continue;
        char name[32];
        snprintf(name, sizeof(name), "control %u", f);
        memcpy(before, ctx, CTX);
        uint64_t w = v ^ (1ull << 20);
        hv_return_t s = set_control(vcpu, f, w);
        if (s != HV_SUCCESS) { printf("%-22s set -> %d\n", name, s); continue; }
        report(name, ctx, dirty_off);
        set_control(vcpu, f, v);
    }

    for (unsigned op1 = 0; op1 < 8; op1++)
    for (unsigned crn = 0; crn < 16; crn++)
    for (unsigned crm = 0; crm < 16; crm++)
    for (unsigned op2 = 0; op2 < 8; op2++) {
        hv_sys_reg_t sel = (hv_sys_reg_t)((3u << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2);
        uint64_t v = 0;
        if (hv_vcpu_get_sys_reg(vcpu, sel, &v) != HV_SUCCESS) continue;
        char name[32];
        snprintf(name, sizeof(name), "sys 0x%04x", (unsigned)sel);
        memcpy(before, ctx, CTX);
        hv_return_t s = hv_vcpu_set_sys_reg(vcpu, sel, v ^ 0x1000);
        if (s != HV_SUCCESS) { printf("%-22s set -> %d (value 0x%llx)\n", name, s, (unsigned long long)v); continue; }
        report(name, ctx, dirty_off);
        hv_vcpu_set_sys_reg(vcpu, sel, v);
    }
    return 0;
}
