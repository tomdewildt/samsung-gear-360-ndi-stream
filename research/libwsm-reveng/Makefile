TOOLCHAIN := arm-linux-musleabi-cross
CROSS     := $(TOOLCHAIN)/bin/arm-linux-musleabi-gcc
SYSROOT   := $(TOOLCHAIN)/arm-linux-musleabi
LIBDIR    := $(abspath ../apk-reveng/sources/samsung-accessory-service/resources/lib/armeabi)

SRC_DIR    := src
TARGET_DIR := target
STUB          := $(SRC_DIR)/bionic_stub.c
STUB_LIBS_SRC := $(SRC_DIR)/stub_libs.c

# One binary per C source, minus the two stub sources.
SOURCES := $(filter-out $(STUB) $(STUB_LIBS_SRC),$(wildcard $(SRC_DIR)/*.c))
TOOLS   := $(patsubst $(SRC_DIR)/%.c,$(TARGET_DIR)/%,$(SOURCES))

# Stub liblog.so / libstdc++.so (Android libs missing under musl) so qemu can  load libwsm.so.
STUB_LIBS := $(LIBDIR)/liblog.so $(LIBDIR)/libstdc++.so

CFLAGS  := --sysroot=$(SYSROOT)
LDFLAGS := -Wl,--dynamic-linker=$(abspath $(SYSROOT)/lib/libc.so) \
           -Wl,-rpath,$(LIBDIR) -L $(LIBDIR)
LDLIBS  := -lwsm -lm

.PHONY: init build build/binary build/tables patch/lib clean
init:
	scripts/download.sh

build: $(TOOLS)

build/binary: $(TARGET_DIR)/wsm_helper

build/tables: $(TARGET_DIR)/wsm_nonce_dump

patch/lib:
	python3 scripts/patch_libwsm.py "$(LIBDIR)/libwsm.so"

$(TARGET_DIR)/%: $(SRC_DIR)/%.c $(STUB) | $(TARGET_DIR) $(STUB_LIBS) patch/lib
	@test -x "$(CROSS)" || { echo "toolchain missing — run 'make init'"; exit 1; }
	$(CROSS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(STUB) $(LDLIBS)

$(LIBDIR)/liblog.so: $(STUB_LIBS_SRC)
	@test -x "$(CROSS)" || { echo "toolchain missing — run 'make init'"; exit 1; }
	$(CROSS) $(CFLAGS) -shared -fPIC -nostdlib -Wl,-soname,liblog.so -o $@ $<

$(LIBDIR)/libstdc++.so: $(STUB_LIBS_SRC)
	@test -x "$(CROSS)" || { echo "toolchain missing — run 'make init'"; exit 1; }
	$(CROSS) $(CFLAGS) -shared -fPIC -nostdlib -Wl,-soname,libstdc++.so -o $@ $<

$(TARGET_DIR):
	mkdir -p $(TARGET_DIR)

clean:
	rm -rf $(TARGET_DIR)
	rm -f $(STUB_LIBS)
