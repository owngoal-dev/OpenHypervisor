# API

## Linking

Build or install the library, then compile with `-I<prefix>/include` and
link with `-L<prefix>/lib -lopenhyp -Wl,-rpath,<prefix>/lib` (the install
name is `@rpath/libopenhyp.dylib`). Sign the resulting binary with the
hypervisor entitlement (see [Internals](internals.md#entitlements)).
Alternatively link the objects in statically, as `tests/smoke_static` does
(add `-lobjc`).

## Apple-compatible C API

```c
#include "openhyp/hv_compat_protos.h"

hv_vm_config_t cfg = hv_vm_config_create();
hv_vm_config_set_el2_enabled(cfg, true);
hv_vm_create(cfg);
```

`hv_compat_enums.h` / `hv_compat_protos.h` declare the same types, constants
and functions as the SDK's `<Hypervisor/Hypervisor.h>`, so existing code
changes only its include (or keeps the SDK headers and links this library
instead of `-framework Hypervisor`).

## Beyond Apple's API

### C++ API

`openhyp/openhyp.hpp`:

```cpp
#include "openhyp/openhyp.hpp"
using namespace openhyp;

Vm::Config c; c.set_isa(3).set_el2(true).set_vhe(true); // vhe goes beyond Apple's public surface
Vm vm(c);
Vcpu vcpu;
vcpu.set_regs({{HV_REG_PC, entry}, {HV_REG_X0, arg}});
vcpu.run_loop([](const ExitInfo& e) {
    if (e.reason == HV_EXIT_REASON_EXCEPTION) return Vcpu::Action::Stop;
    return Vcpu::Action::Continue;
});
auto snap = vcpu.snapshot({HV_SYS_REG_SCTLR_EL1});   // snapshot/restore
vcpu.restore(snap);
Vcpu::raw_trap(42, nullptr);                          // raw trap passthrough
```

It adds batched register access, context snapshot/restore, a callback-driven
run loop, raw trap passthrough, a data-abort monitoring wrapper, error
strings and SMP broadcast helpers.

### Switches and traces

`openhyp/ohv_config.h`. Everything the library lets a VMM turn on or off,
and every trace it can print, is a call -- nothing is read from the
environment, so a VMM can expose them on its own command line and a run's
argv records them:

```c
#include "openhyp/ohv_config.h"
ohv_set_bank_inline(false);
ohv_set_tidcp_vcpus(0x40);
ohv_set_trace(OHV_TRACE_BAND, true);
```

Each setting is one word, read relaxed on the vCPU threads; the ones that
shape a vCPU at creation say so in the header and must be set before
`hv_vcpu_create()`. Not calling a setter keeps the default. As an example of
a consumer, a QEMU accelerator built on this library can map them onto
accelerator properties
(`-accel ohv,bank-inline=off,tidcp-vcpus=0x40,trace=band:eret`).

### VMM extensions

`openhyp/ohv_vmm.h`, versioned by `ohv_api_version()`:

1. `ohv_vcpu_timer_state`, `ohv_vcpu_timer_deadline`, `ohv_vcpu_set_parked`
2. the `ohv_config.h` switches, plus what carrying the fast IPI inside the
   library needs (`ohv_set_ipi_inline()`): the affinity each vCPU answers
   IPIs at, a hook through which the library asks the VMM to wake a vCPU it
   has halted, and the query a VMM makes before halting one
3. `ohv_hv_layout()`, the vCPU context layout the running kernel uses
