# OpenHypervisor - reimplementation of the Hypervisor.framework API (arm64)
# SPDX-License-Identifier: MIT
CC      := clang++
CCC     := clang
ARCH    := arm64
CXXFLAGS := -std=c++17 -O2 -g -Wall -Wextra -arch $(ARCH) -fno-omit-frame-pointer \
            -Iinclude -Isrc -D_GNU_SOURCE -MMD -MP
CFLAGS  := -std=gnu11 -O1 -g -arch $(ARCH) -fno-omit-frame-pointer
LDFLAGS := -arch $(ARCH) -lobjc -dynamiclib -install_name @rpath/libopenhyp.dylib \
           -Wl,-headerpad_max_install_names
# Test binaries find libopenhyp.dylib next to themselves (tests/), so the
# build tree's absolute path is never baked into a binary.
TEST_RPATH := -Wl,-rpath,@executable_path -Wl,-headerpad_max_install_names
# tests/hv.ent carries com.apple.private.hypervisor, which AMFI only lets an
# ad-hoc binary keep on a host whose AMFI policy is relaxed; elsewhere the
# binary is killed at exec.  `make HV_ENT=tests/hv-public.ent` signs with the
# public entitlement only.
HV_ENT  ?= tests/hv.ent
SIGN    := codesign --force --sign - --entitlements $(HV_ENT)

SRCS := src/ohv_object.cpp src/ohv_alias.cpp src/ohv_trap.cpp src/ohv_state.cpp src/ohv_vm.cpp src/ohv_vcpu.cpp \
        src/ohv_vcpu_debug_timer.cpp src/ohv_vcpu_control.cpp \
        src/ohv_gic.cpp src/ohv_misc.cpp src/ohv_sysreg_apple.cpp src/ohv_sysreg_table.cpp \
        src/ohv_caps_field.cpp src/ohv_extras.cpp src/ohv_config.cpp
OBJS := $(SRCS:.cpp=.o)
DEPS := $(OBJS:.o=.d)

# Probes that talk to the kernel's hv trap directly (no framework, no library).
RAW_TESTS := mini6 mini7 mini8 mini9 mini10 dump_ctx_raw
# Probes written against the Hypervisor.framework API.  Each is built twice:
# tests/<name> against Apple's framework, tests/<name>_ohv against
# libopenhyp.dylib, so the two can be run side by side and diffed.
FW_TESTS  := mini12 fw_el2 dump_ctx_fw calib_ctx

RAW_BINS := $(addprefix tests/,$(RAW_TESTS))
FW_BINS  := $(addprefix tests/,$(FW_TESTS))
OHV_BINS := $(addsuffix _ohv,$(FW_BINS))

all: libopenhyp.dylib smoke smoke_static

tests: smoke smoke_static $(RAW_BINS) $(FW_BINS) $(OHV_BINS)

libopenhyp.dylib: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.cpp
	$(CC) $(CXXFLAGS) -c $< -o $@

-include $(DEPS)

tests/libopenhyp.dylib: libopenhyp.dylib
	cp -f $< $@
	$(SIGN) $@

# Single-binary variant: no dyld involvement at all (library validation proof).
smoke_static: tests/smoke_static
tests/smoke_static: $(OBJS) tests/smoke.cpp
	$(CC) $(CXXFLAGS) -lobjc -o $@ tests/smoke.cpp $(OBJS)
	$(SIGN) $@

# Dylib-linked variant. Loading an ad-hoc dylib requires disabling library
# validation in the entitlements (tests/hv.ent); see tools/run-smoke.sh.
smoke: tests/smoke_bin
tests/smoke_bin: tests/smoke.cpp tests/libopenhyp.dylib
	$(CC) $(CXXFLAGS) $(TEST_RPATH) -o $@ tests/smoke.cpp -L. -lopenhyp
	$(SIGN) $@

$(RAW_BINS): tests/%: tests/%.c
	$(CCC) $(CFLAGS) -o $@ $<
	$(SIGN) $@

$(FW_BINS): tests/%: tests/%.c
	$(CCC) $(CFLAGS) -o $@ $< -framework Hypervisor
	$(SIGN) $@

$(OHV_BINS): tests/%_ohv: tests/%.c tests/libopenhyp.dylib
	$(CCC) $(CFLAGS) $(TEST_RPATH) -o $@ $< -L. -lopenhyp
	$(SIGN) $@

# Runtime offset matcher: maps the original Hypervisor.framework, walks its
# __TEXT as raw bytes and re-derives every offset pinned in ohv_context.h /
# ohv_vm.cpp on the running OS. Exit 1 = drift or missing evidence.
offset_probe: tools/offset_probe
tools/offset_probe: tools/offset_probe.cpp
	$(CC) -std=c++17 -O1 -Wall -Wextra -arch $(ARCH) -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) libopenhyp.dylib tests/libopenhyp.dylib \
	      tests/smoke_bin tests/smoke_static tests/*.d \
	      $(RAW_BINS) $(FW_BINS) $(OHV_BINS) tools/offset_probe
	rm -rf tests/*.dSYM tools/*.dSYM

# Build every test, then run each once (tools/run-tests.sh).
check: tests
	tools/run-tests.sh

# Install the library and its headers.  Headers go to $(PREFIX)/include/openhyp
# (they include each other as "openhyp/..."), the dylib to $(PREFIX)/lib.  Its
# install name is @rpath/libopenhyp.dylib, so a consumer links with
# -L$(PREFIX)/lib -lopenhyp -Wl,-rpath,$(PREFIX)/lib.
PREFIX  ?= /usr/local
INCDIR  := $(DESTDIR)$(PREFIX)/include/openhyp
LIBDIR  := $(DESTDIR)$(PREFIX)/lib
HEADERS := $(wildcard include/openhyp/*.h include/openhyp/*.hpp)

install: libopenhyp.dylib
	install -d $(INCDIR) $(LIBDIR)
	install -m 644 $(HEADERS) $(INCDIR)
	install -m 755 libopenhyp.dylib $(LIBDIR)

uninstall:
	rm -f $(LIBDIR)/libopenhyp.dylib
	rm -rf $(INCDIR)

.PHONY: all tests check clean smoke smoke_static offset_probe install uninstall
