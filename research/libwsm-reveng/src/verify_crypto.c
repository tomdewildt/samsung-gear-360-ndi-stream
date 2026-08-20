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

extern long WSM_Client_init(const char*, const char*, const void*);
extern int WSM_Client_checkAndGenerateServerChallenge(long, const unsigned char*, unsigned char*);
extern int WSM_Client_checkClientResponse(long, const unsigned char*);
extern int WSM_destroy(long);
extern int cbc_wb_decrypt_nopadding(unsigned char *output, const unsigned char *input, int size);
extern int cbc_wb_decrypt(unsigned char *output, const unsigned char *input, int size);
extern int ecb_wb_decrypt(unsigned char *output, const unsigned char *input, int size);

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

static void hexdump(const char *label, const unsigned char *data, int len) {
    fprintf(stderr, "%s: ", label);
    for (int i = 0; i < len; i++) fprintf(stderr, "%02x", data[i]);
    fprintf(stderr, "\n");
}

int main(void) {
    patch_wsm_free();

    /* First init WSM to make sure all globals are set up */
    fprintf(stderr, "=== Initializing WSM ===\n");
    long handle = WSM_Client_init("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", NULL);
    fprintf(stderr, "WSM_Client_init handle=%ld\n", handle);

    if (handle <= 0) {
        fprintf(stderr, "WSM_Client_init failed\n");
        return 1;
    }

    /* Find text base for table lookup */
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    uintptr_t text_base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libwsm.so") && strstr(line, "r-xp") && !text_base) {
            sscanf(line, "%lx", (unsigned long*)&text_base);
        }
    }
    fclose(f);

    unsigned char *table = (unsigned char *)(text_base + 0x33004);

    fprintf(stderr, "\n=== Testing WB-AES decrypt functions ===\n");

    /* Test cbc_wb_decrypt_nopadding with entry 0 */
    unsigned char ct_buf[32];
    unsigned char output[16];

    memcpy(ct_buf, table, 32); /* IV + ciphertext for entry 0 */
    hexdump("entry0_iv  ", ct_buf, 16);
    hexdump("entry0_ct  ", ct_buf + 16, 16);

    /* Try 1: cbc_wb_decrypt_nopadding(output, ciphertext, 16) */
    memset(output, 0xAA, 16);
    int ret = cbc_wb_decrypt_nopadding(output, ct_buf + 16, 16);
    fprintf(stderr, "cbc_wb_decrypt_nopadding(output, ct, 16) ret=%d\n", ret);
    hexdump("  result   ", output, 16);

    /* Try 2: cbc_wb_decrypt_nopadding(output, iv+ct, 32) — include IV */
    memset(output, 0xAA, 16);
    ret = cbc_wb_decrypt_nopadding(output, ct_buf, 32);
    fprintf(stderr, "cbc_wb_decrypt_nopadding(output, iv+ct, 32) ret=%d\n", ret);
    hexdump("  result   ", output, 16);

    /* Try 3: ecb_wb_decrypt(output, ciphertext, 16) */
    memset(output, 0xAA, 16);
    ret = ecb_wb_decrypt(output, ct_buf + 16, 16);
    fprintf(stderr, "ecb_wb_decrypt(output, ct, 16) ret=%d\n", ret);
    hexdump("  result   ", output, 16);

    /* Try 4: cbc_wb_decrypt(output, ct, 16) — with padding */
    unsigned char output32[32];
    memset(output32, 0xAA, 32);
    ret = cbc_wb_decrypt(output32, ct_buf + 16, 16);
    fprintf(stderr, "cbc_wb_decrypt(output, ct, 16) ret=%d\n", ret);
    hexdump("  result   ", output32, 32);

    /* Try 5: cbc_wb_decrypt(output, iv+ct, 32) */
    memset(output32, 0xAA, 32);
    ret = cbc_wb_decrypt(output32, ct_buf, 32);
    fprintf(stderr, "cbc_wb_decrypt(output, iv+ct, 32) ret=%d\n", ret);
    hexdump("  result   ", output32, 32);

    /* Now test: send a crafted challenge to checkAndGenerateServerChallenge */
    fprintf(stderr, "\n=== Testing with crafted challenge ===\n");

    /* P-256 test public key (valid point on the curve) */
    /* Using the generator point G of P-256 */
    unsigned char challenge[70];
    challenge[0] = 0x00; /* version */
    challenge[1] = 0x00; /* type */
    challenge[2] = 0x46; /* length = 70 */

    /* P-256 generator point (uncompressed) */
    challenge[3] = 0x04; /* uncompressed point prefix */
    /* Gx */
    unsigned char Gx[] = {
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
        0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
        0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
        0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96
    };
    /* Gy */
    unsigned char Gy[] = {
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
        0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
        0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
        0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
    };
    memcpy(challenge + 4, Gx, 32);
    memcpy(challenge + 36, Gy, 32);

    challenge[68] = 0x42; /* nonce byte 0 */
    challenge[69] = 0x43; /* nonce byte 1 */

    hexdump("challenge  ", challenge, 70);

    unsigned char response[102];
    memset(response, 0, 102);
    ret = WSM_Client_checkAndGenerateServerChallenge(handle, challenge, response);
    fprintf(stderr, "checkAndGenerateServerChallenge ret=%d\n", ret);

    if (ret > 0) {
        hexdump("resp_hdr   ", response, 3);
        hexdump("resp_pubkey", response + 3, 65);
        hexdump("resp_nonce ", response + 68, 2);
        hexdump("resp_hmac  ", response + 70, 32);
    }

    /* Now try again with same challenge but new handle to verify determinism */
    long handle2 = WSM_Client_init("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", NULL);
    fprintf(stderr, "\nSecond init handle=%ld\n", handle2);

    unsigned char response2[102];
    memset(response2, 0, 102);
    ret = WSM_Client_checkAndGenerateServerChallenge(handle2, challenge, response2);
    fprintf(stderr, "checkAndGenerateServerChallenge ret=%d\n", ret);

    if (ret > 0) {
        hexdump("resp2_pubkey", response2 + 3, 65);
        hexdump("resp2_nonce ", response2 + 68, 2);
        hexdump("resp2_hmac  ", response2 + 70, 32);
    }

    fprintf(stderr, "\nPubkeys differ: %s\n",
            memcmp(response+3, response2+3, 65) ? "yes" : "no");
    fprintf(stderr, "Nonces differ: %s\n",
            memcmp(response+68, response2+68, 2) ? "yes" : "no");
    fprintf(stderr, "HMACs differ: %s\n",
            memcmp(response+70, response2+70, 32) ? "yes" : "no");

    WSM_destroy(handle);
    WSM_destroy(handle2);

    return 0;
}
