# Open items

## Run the hv tests on bare metal

`make check` has so far only been built, not run to completion: the
development host was itself a virtual machine (`kern.hv_support = 0`), where
every VM creation returns `HV_UNSUPPORTED`. A run on an Apple-silicon Mac
that is not a VM is still owed. Use `HV_ENT=tests/hv-public.ent` unless AMFI
is relaxed for the private entitlement in `tests/hv.ent`.

## Layout table

- The `builds` column of `include/openhyp/ohv_hv_layouts.h` is unreachable
  on every kernel in the table, and some of the listed builds are seed
  (beta) builds. Proposed: drop the column. Background and the derivation
  fallback: [case-study-hv-layouts.md](case-study-hv-layouts.md).
- The tested host named in the README's compatibility table and in
  [internals.md](internals.md), 26A5388g, is a seed build; re-test on a
  release build and update both.
