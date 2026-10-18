#!/bin/sh
# run-tests.sh - run every built test binary once and report how each ended.
# Usage: tools/run-tests.sh [timeout-seconds]   (default 30; `make check` runs it)
#
# Arguments are the defaults each probe picks with none given.  A probe that
# the kernel refuses still "ran": the line shows its exit status and the last
# thing it printed.  Exit 137 straight away means the binary was killed at
# exec, usually AMFI rejecting an entitlement in its signature (see docs/internals.md).
cd "$(dirname "$0")/../tests" || exit 2
LIMIT=${1:-30}
fail=0
for t in smoke_static smoke_bin \
         mini6 mini7 mini8 mini9 mini10 dump_ctx_raw \
         mini12 mini12_ohv fw_el2 fw_el2_ohv dump_ctx_fw dump_ctx_fw_ohv \
         calib_ctx calib_ctx_ohv; do
  if [ ! -x "./$t" ]; then
    echo "SKIP $t (not built)"; fail=1; continue
  fi
  out=$(perl -e 'alarm shift; exec @ARGV or die "exec: $!\n"' "$LIMIT" "./$t" 2>&1)
  rc=$?
  last=$(printf '%s\n' "$out" | tail -n 1)
  echo "$t: exit=$rc | $last"
  [ $rc -eq 0 ] || fail=1
done
exit $fail
