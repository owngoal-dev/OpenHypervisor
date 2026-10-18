#!/bin/zsh
# run-smoke.sh - smoke-test flow for OpenHypervisor on an arm64 Mac whose
# AMFI is handled by amfidont.
# Usage: ./tools/run-smoke.sh   (set AMFIDONT to the daemon's path if needed)
set -e
cd "$(dirname "$0")/.."
LOG=/tmp/amfidont-openhyp.log

# 1) fresh build
make -j8 >/dev/null

# 2) sign everything that will touch the hypervisor
for f in tests/smoke_static tests/smoke_bin tests/libopenhyp.dylib; do
  codesign --force --sign - --entitlements "${HV_ENT:-tests/hv.ent}" "$f"
done

# 3) one amfidont daemon spoofing both test binaries (needs passwordless sudo)
sudo -n pkill -f "amfidont" 2>/dev/null || true
sleep 1
nohup sudo -n "${AMFIDONT:-amfidont}" daemon --spoof-apple \
      --path "$PWD/tests/smoke_static" --path "$PWD/tests/smoke_bin" \
      >"$LOG" 2>&1 &
for i in {1..30}; do
  grep -q "daemon started" "$LOG" 2>/dev/null && break
  sleep 0.5
done
grep -q "daemon started" "$LOG" || { echo DAEMON_FAILED; tail -5 "$LOG"; exit 9; }
sleep 1

# 4) run both variants
echo "== smoke_static (single binary, no dyld) =="
./tests/smoke_static
echo "== smoke_bin (dylib-linked) =="
DYLD_LIBRARY_PATH=$PWD/tests ./tests/smoke_bin
echo "== ALL DONE =="
