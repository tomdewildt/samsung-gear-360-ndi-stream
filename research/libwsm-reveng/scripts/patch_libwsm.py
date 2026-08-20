import struct
import sys

PROGRAM_HEADERS_OFFSET_FIELD = 0x1C
PROGRAM_HEADER_SIZE_FIELD = 0x2A
PROGRAM_HEADER_COUNT_FIELD = 0x2C

DYNAMIC_SEGMENT_TYPE = 2

DYNAMIC_END_TAG = 0
INIT_ARRAY_SIZE_TAG = 27
FINI_ARRAY_SIZE_TAG = 28
ARRAY_SIZE_TAGS = {
    INIT_ARRAY_SIZE_TAG: "DT_INIT_ARRAYSZ",
    FINI_ARRAY_SIZE_TAG: "DT_FINI_ARRAYSZ",
}


def find_dynamic_offset(elf):
    """File offset of the PT_DYNAMIC segment in a 32-bit little-endian ELF."""
    table_offset = struct.unpack_from("<I", elf, PROGRAM_HEADERS_OFFSET_FIELD)[0]
    entry_size = struct.unpack_from("<H", elf, PROGRAM_HEADER_SIZE_FIELD)[0]
    entry_count = struct.unpack_from("<H", elf, PROGRAM_HEADER_COUNT_FIELD)[0]
    for index in range(entry_count):
        header = table_offset + index * entry_size
        segment_type, segment_offset = struct.unpack_from("<II", elf, header)
        if segment_type == DYNAMIC_SEGMENT_TYPE:
            return segment_offset
    raise ValueError("no PT_DYNAMIC segment")


def patch_library(path):
    """Zero the init/fini array sizes so the musl loader skips libwsm.so's Android constructors (they segfault under
    qemu)."""
    with open(path, "rb") as file:
        elf = bytearray(file.read())
    if elf[:4] != b"\x7fELF" or elf[4] != 1 or elf[5] != 1:
        raise ValueError(f"{path}: not a 32-bit little-endian ELF")

    changed = []
    entry = find_dynamic_offset(elf)
    while True:
        # Each Elf32_Dyn entry is 8 bytes: d_tag (int32) then d_un (uint32).
        tag, value = struct.unpack_from("<iI", elf, entry)
        if tag == DYNAMIC_END_TAG:
            break
        if tag in ARRAY_SIZE_TAGS and value != 0:
            struct.pack_into("<I", elf, entry + 4, 0)  # Zero d_un (the size)
            changed.append(ARRAY_SIZE_TAGS[tag])
        entry += 8

    if changed:
        with open(path, "wb") as file:
            file.write(elf)
    return changed


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <libwsm.so>")
        return 1

    path = sys.argv[1]
    changed = patch_library(path)
    if changed:
        print(f"patched {path}: zeroed {', '.join(changed)}")
    else:
        print(f"{path}: already patched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
