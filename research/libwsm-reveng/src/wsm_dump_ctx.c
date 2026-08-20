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
extern int WSM_Client_checkAndGenerateServerChallenge(long, const unsigned char*, unsigned char*);
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

    const char *server_id = "AA:BB:CC:DD:EE:FF";
    const char *client_id = "11:22:33:44:55:66";

    fprintf(stderr, "=== WSM Context Dump ===\n");

    long handle = WSM_Client_init(server_id, client_id, NULL);
    fprintf(stderr, "Handle: %ld\n", handle);
    if (handle <= 0) { fprintf(stderr, "init failed\n"); _exit(1); }

    /* Craft challenge with generator G */
    unsigned char challenge[70];
    challenge[0] = 0x00; challenge[1] = 0x00; challenge[2] = 0x46; challenge[3] = 0x04;
    unsigned char Gx[] = {
        0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,
        0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
        0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,
        0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96
    };
    unsigned char Gy[] = {
        0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,
        0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
        0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,
        0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5
    };
    memcpy(challenge + 4, Gx, 32);
    memcpy(challenge + 36, Gy, 32);
    challenge[68] = 0x42; challenge[69] = 0x43;

    unsigned char response[102];
    memset(response, 0, 102);
    int ret = WSM_Client_checkAndGenerateServerChallenge(handle, challenge, response);
    fprintf(stderr, "ret=%d\n", ret);

    fprintf(stderr, "\nRESPONSE:\n");
    fprintf(stderr, "  header:  %02x %02x %02x\n", response[0], response[1], response[2]);
    fprintf(stderr, "  pubkey:  ");
    for (int i = 3; i < 68; i++) fprintf(stderr, "%02x", response[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "  nonce:   %02x%02x\n", response[68], response[69]);
    fprintf(stderr, "  hmac:    ");
    for (int i = 70; i < 102; i++) fprintf(stderr, "%02x", response[i]);
    fprintf(stderr, "\n");

    /* Find text_base and context */
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    uintptr_t text_base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libwsm.so") && strstr(line, "r-xp") && !text_base) {
            sscanf(line, "%lx", (unsigned long*)&text_base);
        }
    }
    fclose(f);

    typedef unsigned char* (*find_ctx_fn)(long handle);
    find_ctx_fn find_ctx = (find_ctx_fn)(text_base + 0x7EB4 + 1);
    unsigned char *ctx = find_ctx(handle);
    if (!ctx) { fprintf(stderr, "ctx not found\n"); _exit(1); }

    fprintf(stderr, "\nCONTEXT at %p (text_base=0x%lx):\n", ctx, (unsigned long)text_base);

    /* Dump 256 bytes in 16-byte rows with hex and ASCII */
    for (int row = 0; row < 16; row++) {
        int off = row * 16;
        fprintf(stderr, "  +0x%02x: ", off);
        for (int i = 0; i < 16; i++)
            fprintf(stderr, "%02x ", ctx[off + i]);
        fprintf(stderr, " |");
        for (int i = 0; i < 16; i++) {
            unsigned char c = ctx[off + i];
            fprintf(stderr, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        fprintf(stderr, "|\n");
    }

    /* Follow the 4 pointers at +0x60 through +0x6C (EC key objects) */
    fprintf(stderr, "\nEC POINTERS:\n");
    for (int off = 0x60; off <= 0x6C; off += 4) {
        uint32_t val = *(uint32_t*)(ctx + off);
        if (val >= 0x40000000 && val < 0x50000000) {
            unsigned char *ptr = (unsigned char*)(uintptr_t)val;
            fprintf(stderr, "  +0x%02x -> 0x%08x:\n", off, val);
            for (int row = 0; row < 8; row++) {
                fprintf(stderr, "    +%02x: ", row*16);
                for (int i = 0; i < 16; i++) fprintf(stderr, "%02x ", ptr[row*16 + i]);
                fprintf(stderr, "\n");
            }
        }
    }

    /* Also follow the pointer at +0x00 */
    uint32_t p0 = *(uint32_t*)(ctx + 0x00);
    if (p0 >= 0x40000000 && p0 < 0x50000000) {
        unsigned char *ptr = (unsigned char*)(uintptr_t)p0;
        fprintf(stderr, "\n+0x00 -> 0x%08x:\n", p0);
        for (int row = 0; row < 4; row++) {
            fprintf(stderr, "    +%02x: ", row*16);
            for (int i = 0; i < 16; i++) fprintf(stderr, "%02x ", ptr[row*16 + i]);
            fprintf(stderr, "\n");
        }
    }

    /* Follow ptr at +0x0C — this is the REAL context struct */
    uint32_t p0c = *(uint32_t*)(ctx + 0x0C);
    if (p0c >= 0x40000000 && p0c < 0x50000000) {
        unsigned char *real = (unsigned char*)(uintptr_t)p0c;
        fprintf(stderr, "\nREAL CONTEXT at 0x%08x:\n", p0c);
        for (int row = 0; row < 12; row++) {
            int off = row * 16;
            fprintf(stderr, "    +0x%02x: ", off);
            for (int i = 0; i < 16; i++) fprintf(stderr, "%02x ", real[off + i]);
            fprintf(stderr, " |");
            for (int i = 0; i < 16; i++) {
                unsigned char c = real[off + i];
                fprintf(stderr, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
            }
            fprintf(stderr, "|\n");
        }

        /* Follow ID string pointers */
        uint32_t id1_ptr = *(uint32_t*)(real + 0x18);
        uint32_t id2_ptr = *(uint32_t*)(real + 0x1C);
        fprintf(stderr, "\n  +0x18 -> 0x%08x: \"%s\"\n", id1_ptr, (char*)(uintptr_t)id1_ptr);
        fprintf(stderr, "  +0x1C -> 0x%08x: \"%s\"\n", id2_ptr, (char*)(uintptr_t)id2_ptr);

        fprintf(stderr, "\n  ECDH secret (+0x20, 32B): ");
        for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", real[0x20 + i]);
        fprintf(stderr, "\n");

        fprintf(stderr, "  Server nonce (+0x70, 2B): %02x%02x\n", real[0x70], real[0x71]);
        fprintf(stderr, "  Client nonce (+0x80, 2B): %02x%02x\n", real[0x80], real[0x81]);
        fprintf(stderr, "  PSK table (+0x90, 16B): ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", real[0x90 + i]);
        fprintf(stderr, "\n");
        fprintf(stderr, "  State A0 (+0xA0, 16B): ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", real[0xA0 + i]);
        fprintf(stderr, "\n");
    }

    WSM_destroy(handle);
    _exit(0);
}
