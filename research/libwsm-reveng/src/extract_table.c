#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

const char _ctype_[257] = {
    0,
    0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
    0x20,0x28,0x28,0x28,0x28,0x28,0x20,0x20,
    0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
    0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
    0x88,0x10,0x10,0x10,0x10,0x10,0x10,0x10,
    0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,
    0x44,0x44,0x44,0x44,0x44,0x44,0x44,0x44,
    0x44,0x44,0x10,0x10,0x10,0x10,0x10,0x10,
    0x10,0x41,0x41,0x41,0x41,0x41,0x41,0x01,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x01,0x01,0x01,0x10,0x10,0x10,0x10,0x10,
    0x10,0x42,0x42,0x42,0x42,0x42,0x42,0x02,
    0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
    0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
    0x02,0x02,0x02,0x10,0x10,0x10,0x10,0x20,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
};

void __cxa_call_unexpected(void* h) { }
void __cxa_begin_cleanup(void* h) { }
int __cxa_type_match(void* e, void* t, int r, void** a) { return 0; }
void* __gnu_Unwind_Find_exidx(void* pc, int* cnt) { if(cnt)*cnt=0; return 0; }

int __android_log_print(int prio, const char* tag, const char* fmt, ...) { return 0; }

extern int cbc_wb_decrypt_nopadding(unsigned char *output, const unsigned char *input,
                                     int size);

/*
 * The encrypted PSK table is at a known offset in libwsm.so's .data section.
 * At runtime, we find the table by scanning /proc/self/maps for libwsm.so's
 * writable mapping (the .data section), then reading from the known offset.
 *
 * Table structure: starts at VA 0x33004 (= .data base 0x33000 + 0x4)
 * internal_74e0 adds 0x10 to the base, so effective table starts at +0x14
 * Each "entry" for CBC decrypt is 32 bytes: [16B IV][16B ciphertext]
 * Entry N: IV at table + N*16, ciphertext at table + 0x10 + N*16
 * 128 entries total (indexed by nonce_byte >> 1)
 */

int main(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { perror("fopen maps"); return 1; }

    char line[512];
    uintptr_t data_base = 0;
    uintptr_t text_base = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libwsm.so")) {
            uintptr_t start, end;
            sscanf(line, "%lx-%lx", (unsigned long*)&start, (unsigned long*)&end);
            fprintf(stderr, "libwsm.so mapping: %s", line);
            if (strstr(line, "r-xp") && !text_base) {
                text_base = start;
            }
        }
    }
    fclose(f);

    if (!text_base) {
        fprintf(stderr, "Could not find libwsm.so text section\n");
        return 1;
    }

    /*
     * text_base is where VA 0x0 (first PT_LOAD) is mapped.
     * The GOT entry at VA 0x32f0c has a RELATIVE relocation, so at runtime
     * its value = text_base + original_value = text_base + 0x33004.
     *
     * The table data is at VA 0x33004 in the ELF, so at runtime:
     * table_address = text_base + 0x33004
     */

    uintptr_t table_ptr = text_base + 0x33004;
    fprintf(stderr, "load base: 0x%lx\n", (unsigned long)text_base);
    fprintf(stderr, "table ptr: 0x%lx\n", (unsigned long)table_ptr);

    unsigned char *table = (unsigned char *)table_ptr;

    fprintf(stderr, "Table base: 0x%lx\n", (unsigned long)table);
    fprintf(stderr, "First 32 bytes of raw table:\n");
    for (int i = 0; i < 32; i++)
        fprintf(stderr, "%02x ", table[i]);
    fprintf(stderr, "\n");

    /* Decrypt each of the 128 entries.
     * Entry i: IV at table + i*16, ciphertext at table + 0x10 + i*16
     * cbc_wb_decrypt_nopadding(output, ciphertext, 16) with IV at ciphertext-16
     *
     * But the function signature might need the IV. Let's try calling it
     * with the input pointing to the ciphertext and hope it reads IV from
     * the 16 bytes before it (standard CBC pattern). */

    printf("# WSM PSK lookup table - 128 entries, 16 bytes each (decrypted)\n");
    printf("# Entry i is selected by nonce_byte >> 1\n");
    printf("# First 8 bytes selected when nonce_byte & 1 == 0\n");
    printf("# Second 8 bytes selected when nonce_byte & 1 == 1\n\n");

    for (int i = 0; i < 128; i++) {
        unsigned char *iv = table + i * 16;
        unsigned char *ct = table + 0x10 + i * 16;
        unsigned char output[16];
        memset(output, 0, 16);

        /* The cbc_wb_decrypt_nopadding reads from [ct-16..ct+15] for one block
         * where ct-16 is the IV */
        int ret = cbc_wb_decrypt_nopadding(output, ct, 16);

        fprintf(stderr, "entry[%3d] ret=%d: ", i, ret);
        for (int j = 0; j < 16; j++)
            fprintf(stderr, "%02x", output[j]);
        fprintf(stderr, "\n");

        printf("entry[%3d] = ", i);
        for (int j = 0; j < 16; j++)
            printf("%02x", output[j]);
        printf("\n");
    }

    return 0;
}
