#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

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

extern long WSM_Client_init(const char*, const char*, const void*);
extern int WSM_destroy(long);

static void (*real_free_fn)(void*) = NULL;
static uintptr_t wsm_data_start = 0;
static uintptr_t wsm_data_end = 0;
static uintptr_t wsm_text_base = 0;

static void safe_free(void *ptr) {
    if (ptr == NULL) return;
    uintptr_t p = (uintptr_t)ptr;
    if (p >= wsm_data_start && p < wsm_data_end) return;
    real_free_fn(ptr);
}

static void find_wsm_segments(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libwsm.so")) {
            uintptr_t start, end;
            sscanf(line, "%lx-%lx", (unsigned long*)&start, (unsigned long*)&end);
            if (strstr(line, "r-xp") && !wsm_text_base)
                wsm_text_base = start;
            if (strstr(line, "rw-p")) {
                wsm_data_start = start;
                wsm_data_end = end;
            }
        }
    }
    fclose(f);

    if (wsm_data_start) {
        uintptr_t free_ptr_addr = wsm_data_start + (0x33834 - 0x33000);
        void (**slot)(void*) = (void (**)(void*))free_ptr_addr;
        real_free_fn = *slot;
        *slot = safe_free;
    }
}

typedef void (*expand_fn_t)(const uint8_t* input, uint8_t* output);

int main(void) {
    find_wsm_segments();

    long handle = WSM_Client_init("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", NULL);
    if (handle <= 0) {
        fprintf(stderr, "WSM_Client_init failed: %ld\n", handle);
        _exit(1);
    }

    if (!wsm_text_base) {
        fprintf(stderr, "Could not find libwsm.so text base\n");
        _exit(1);
    }

    /* expand_nonce function is at offset 0x74e0 in libwsm.so (Thumb) */
    expand_fn_t expand = (expand_fn_t)(wsm_text_base + 0x74e0 + 1);

    fprintf(stderr, "libwsm.so text base: %p\n", (void*)wsm_text_base);
    fprintf(stderr, "expand function at: %p\n", (void*)expand);
    fprintf(stderr, "Dumping nonce expansion table...\n");

    /* Header */
    fwrite("NONCE_TABLE\n", 1, 12, stdout);

    /* Dump table for first byte (output[0:8]) and second byte (output[8:16])
     * Each byte value 0-255 maps to 8 bytes of expanded output.
     * We dump 256 entries for byte0 (first half) then 256 for byte1 (second half).
     */
    for (int b = 0; b < 256; b++) {
        uint8_t input[2] = {(uint8_t)b, 0};
        uint8_t output[16];
        memset(output, 0, 16);
        expand(input, output);
        /* First 8 bytes are determined by byte0 */
        fwrite(output, 1, 8, stdout);
    }

    for (int b = 0; b < 256; b++) {
        uint8_t input[2] = {0, (uint8_t)b};
        uint8_t output[16];
        memset(output, 0, 16);
        expand(input, output);
        /* Last 8 bytes are determined by byte1 */
        fwrite(output + 8, 1, 8, stdout);
    }

    fflush(stdout);

    WSM_destroy(handle);
    fprintf(stderr, "Done. Table dumped: 12 + 256*8 + 256*8 = %d bytes\n",
            12 + 256*8 + 256*8);
    _exit(0);
}
