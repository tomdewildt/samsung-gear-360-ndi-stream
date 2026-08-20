TOOLCHAIN := arm-linux-musleabi-cross
CROSS     := $(TOOLCHAIN)/bin/arm-linux-musleabi-gcc
SYSROOT   := $(TOOLCHAIN)/arm-linux-musleabi
LIBDIR    := $(abspath ../apk-reveng/sources/samsung-accessory-service/resources/lib/armeabi)

SRC_DIR    := src
TARGET_DIR := target
STUB       := $(SRC_DIR)/bionic_stub.c

# One binary per C source, except the shared bionic stub.
SOURCES := $(filter-out $(STUB),$(wildcard $(SRC_DIR)/*.c))
TOOLS   := $(patsubst $(SRC_DIR)/%.c,$(TARGET_DIR)/%,$(SOURCES))

CFLAGS  := --sysroot=$(SYSROOT)
LDFLAGS := -Wl,--dynamic-linker=$(abspath $(SYSROOT)/lib/libc.so) \
           -Wl,-rpath,$(LIBDIR) -L $(LIBDIR)
LDLIBS  := -lwsm -lm

.PHONY: init build build/binary build/tables clean
init:
	scripts/download.sh

build: $(TOOLS)

build/binary: $(TARGET_DIR)/wsm_helper

build/tables: $(TARGET_DIR)/wsm_nonce_dump

$(TARGET_DIR)/%: $(SRC_DIR)/%.c $(STUB) | $(TARGET_DIR)
	@test -x "$(CROSS)" || { echo "toolchain missing — run 'make init'"; exit 1; }
	$(CROSS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(STUB) $(LDLIBS)

$(TARGET_DIR):
	mkdir -p $(TARGET_DIR)

clean:
	rm -rf $(TARGET_DIR)
