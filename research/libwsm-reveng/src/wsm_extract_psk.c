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

static void safe_free(void *ptr) {
    if (ptr == NULL) return;
    uintptr_t p = (uintptr_t)ptr;
    if (p >= wsm_data_start && p < wsm_data_end) return;
    real_free_fn(ptr);
}

static void patch_wsm_free(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return;
    char line[512];
    uintptr_t text_base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libwsm.so")) {
            uintptr_t start, end;
            sscanf(line, "%lx-%lx", (unsigned long*)&start, (unsigned long*)&end);
            if (strstr(line, "r-xp") && !text_base)
                text_base = start;
            if (strstr(line, "rw-p")) {
                wsm_data_start = start;
                wsm_data_end = end;
            }
        }
    }
    fclose(f);
    if (!wsm_data_start) return;
    uintptr_t free_ptr_addr = wsm_data_start + (0x33834 - 0x33000);
    void (**slot)(void*) = (void (**)(void*))free_ptr_addr;
    real_free_fn = *slot;
    *slot = safe_free;
}

int main(void) {
    patch_wsm_free();

    long handle = WSM_Client_init("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", NULL);
    if (handle <= 0) { fprintf(stderr, "WSM_Client_init failed\n"); _exit(1); }

    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    uintptr_t text_base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libwsm.so") && strstr(line, "r-xp") && !text_base) {
            sscanf(line, "%lx", (unsigned long*)&text_base);
        }
    }
    fclose(f);

    typedef void (*fn_74e0_t)(const unsigned char *nonce, unsigned char *output);
    fn_74e0_t fn_74e0 = (fn_74e0_t)(text_base + 0x74E0 + 1);

    /* Extract all 128 entries by calling internal_74e0 with nonce = (2*i, 2*i+1)
     * This gives us the full 16 bytes for each entry:
     *   nonce[0] = 2*i -> entry = i, half = 0 (first 8 bytes)
     *   nonce[1] = 2*i+1 -> entry = i, half = 1 (second 8 bytes)
     */
    fprintf(stderr, "# PSK lookup table - 128 entries x 16 bytes\n");
    fprintf(stderr, "# Extracted via internal_74e0 after WSM_Client_init\n\n");

    /* Output as Python dict for embedding */
    printf("PSK_TABLE = [\n");

    for (int i = 0; i < 128; i++) {
        unsigned char nonce[2] = { (unsigned char)(2*i), (unsigned char)(2*i + 1) };
        unsigned char output[16];
        memset(output, 0, 16);
        fn_74e0(nonce, output);

        fprintf(stderr, "entry[%3d]: ", i);
        for (int j = 0; j < 16; j++) fprintf(stderr, "%02x", output[j]);
        fprintf(stderr, "\n");

        printf("    bytes.fromhex('");
        for (int j = 0; j < 16; j++) printf("%02x", output[j]);
        printf("'),  # entry %d\n", i);
    }
    printf("]\n");

    /* Verify determinism with a second run */
    fprintf(stderr, "\n# Verification with second init\n");
    long handle2 = WSM_Client_init("XX:YY:ZZ:00:11:22", "33:44:55:66:77:88", NULL);

    int all_same = 1;
    for (int i = 0; i < 128; i++) {
        unsigned char nonce[2] = { (unsigned char)(2*i), (unsigned char)(2*i + 1) };
        unsigned char output1[16], output2[16];
        memset(output1, 0, 16);
        memset(output2, 0, 16);

        fn_74e0(nonce, output1);
        fn_74e0(nonce, output2);

        if (memcmp(output1, output2, 16) != 0) {
            fprintf(stderr, "MISMATCH at entry %d!\n", i);
            all_same = 0;
        }
    }
    fprintf(stderr, "Deterministic: %s\n", all_same ? "YES" : "NO");

    WSM_destroy(handle);
    WSM_destroy(handle2);
    _exit(0);
}
