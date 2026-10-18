# Internals

## Toolchain

| Tool | Used for |
| --- | --- |
| `clang`, `clang++`, `make` (Xcode Command Line Tools) | the library, the tests and `tools/offset_probe` |
| `codesign` | ad-hoc signing the test binaries with `HV_ENT` |
| Python 3 | only the generators, `tools/gen_*.py` |

Nothing outside this repository is needed to build the library, the tests or
`offset_probe`. Header dependencies are tracked automatically (`-MMD -MP`).

## Host support

- arm64 (Apple silicon) macOS only.
- Offsets inside the framework's and kernel's private structures are pinned
  in the source. The vCPU context layout is selected per kernel at run time
  from `include/openhyp/ohv_hv_layouts.h`; a kernel with no row there is
  refused rather than guessed at. `tools/offset_probe` re-derives the
  remaining pinned constants from the installed `Hypervisor.framework` (see
  below), so run it first on any new OS build.
- Inside a virtual machine (`sysctl kern.hv_support` = 0) everything builds
  and every probe runs, but `hv_vm_create` returns `HV_UNSUPPORTED`
  (0xfae9400f).

## Entitlements

The library makes no entitlement or SecTask checks in user space (neither
does Apple's framework). The check happens **in the kernel**: XNU's hv trap
asks AMFI whether the calling process holds `com.apple.security.hypervisor`.
So any binary that uses this library needs the same entitlements a binary
using `Hypervisor.framework` would.

The test binaries are ad-hoc signed by the Makefile with `HV_ENT`:

| file | entitlements | use it when |
|---|---|---|
| `tests/hv.ent` (default) | `com.apple.private.hypervisor`, `com.apple.security.hypervisor`, `com.apple.security.cs.disable-library-validation` | the host's AMFI policy is relaxed so an ad-hoc binary may keep a private entitlement; on a stock host the binary is killed at exec (exit 137) |
| `tests/hv-public.ent` | `com.apple.security.hypervisor`, `com.apple.security.cs.disable-library-validation` | a stock host |

```sh
make HV_ENT=tests/hv-public.ent tests
make HV_ENT=tests/hv-public.ent check
```

`disable-library-validation` is what lets a hardened binary load the ad-hoc
signed `libopenhyp.dylib`; `smoke_static` links the library in statically
and does not need it. Notes from development:

- `amfi_get_out_of_my_way=1` lets unsigned processes create VMs where the
  boot-arg is honoured, but on macOS 27 it was observed to be blocked by
  boot-arg restrictions.
- amfidont (`--spoof-apple`, `--allow-all`) affects only amfid's user-space
  checks; it does nothing for the kernel's hv gate.

## Tests

Everything under `tests/` is a standalone program that needs only an arm64
Mac able to create VMs; nothing depends on a guest image.

| binary | what it does |
|---|---|
| `smoke_static`, `smoke_bin` | `smoke.cpp`: capabilities, VM/vCPU lifecycle and a run through the C++ API, linked statically and against the dylib |
| `mini6` .. `mini10`, `dump_ctx_raw` | probes that call the kernel's hv trap directly, with neither the framework nor this library |
| `mini12`, `fw_el2`, `dump_ctx_fw`, `calib_ctx` | probes written against the Hypervisor.framework API, linked against Apple's framework |
| `*_ohv` | the same four linked against `libopenhyp.dylib`, to run and diff side by side with the framework build |

Test binaries find `libopenhyp.dylib` beside themselves (`@executable_path`
rpath; the build copies it into `tests/`).

`tools/run-tests.sh [timeout]` (what `make check` runs) runs each test once
and prints its exit status and last line of output; it exits non-zero if any
test failed or was not built. A probe the kernel refuses still "ran".

`tools/run-smoke.sh` is a convenience for hosts that handle AMFI with
amfidont: it rebuilds, signs, starts an amfidont daemon for the two smoke
binaries (needs passwordless `sudo`; set `AMFIDONT` to its path) and runs
both.

## Runtime offset matching: `tools/offset_probe`

The pinned offsets (config fields, vCPU context layout, kernel trap ids) are
observations of one framework build. `tools/offset_probe` re-derives them on
the running OS: it `dlopen()`s the installed `Hypervisor.framework`, treats
the mapped `__TEXT` as bytes, follows call edges from the public entry points
through a small AArch64 decoder, and compares every immediate it finds with
the pinned constants.

```sh
make offset_probe && ./tools/offset_probe
```

Verdicts per pin: MATCH (direct site reachable from an exported function),
INDIR (offset referenced somewhere in `__TEXT`, reached through a function
pointer), MISS / DRIFT. The exit status is non-zero unless every pin
matched, so it can gate CI. On macOS 26A5388g (arm64) all config fields, the
whole register block and 14 of 18 trap ids verify directly; nothing drifted.

Why the layout table exists, how a row is chosen and how far `offset_probe`
could replace it: [case-study-hv-layouts.md](case-study-hv-layouts.md).

## Generated sources and tools

| file | purpose |
|---|---|
| `tools/offset_probe.cpp` | the runtime offset matcher (`make offset_probe`) |
| `tools/run-tests.sh` | runs every built test once (`make check`) |
| `tools/run-smoke.sh` | smoke-test flow for hosts that use amfidont |
| `tools/gen_compat.py [sdk-headers] [out-dir]` | regenerates `include/openhyp/hv_compat_enums.h` and `hv_compat_protos.h` from the SDK's `Hypervisor.framework/Headers` (default: `xcrun --show-sdk-path`, or `$HV_SDK_HEADERS`) |
| `tools/gen_sysreg_table.py [repo-root]` | regenerates `src/ohv_sysreg_table.cpp` from `hv_compat_enums.h` |

The generated files are committed; the build does not run the generators.
`include/openhyp/ohv_hv_layouts.h` is generated outside this repository, by
lbr77/hv-layouts.

## Development context

The library was developed against a VMM booting Apple's own iPhone firmware
(boot ROM, iBoot, SPTM/PPL, SEP, XNU) as a nested EL2 guest, and many
comments explain behaviour in those terms. In them, "the ROM" is the guest's
boot ROM the VMM runs at reset, and numbers such as 19A348, 21A329 and
24A437 are the iOS guest builds a measurement was taken on. Those comments
record why a behaviour is the way it is; none of it is required to use the
library for other guests.

## Source layout

```text
include/openhyp/    public headers, installed to <prefix>/include/openhyp
  hv_compat_*.h       the Apple-compatible C API (generated)
  openhyp.hpp         the C++ API
  ohv_config.h        switches and traces
  ohv_vmm.h           VMM extensions
  ohv_context.h       the kernel-mapped vCPU context, shared positions
  ohv_hv_layouts.h    per-version block offsets (from lbr77/hv-layouts)
src/                the library (ohv_*.cpp; ohv_sysreg_table.cpp generated)
tests/              standalone probes, smoke test and the entitlement files
tools/              offset_probe, test runners and the generators
docs/               this documentation
```
