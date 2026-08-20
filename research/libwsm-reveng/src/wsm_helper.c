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
extern int WSM_Client_checkClientResponse(long, const unsigned char*);
extern int WSM_destroy(long);

/*
 * libwsm.so calls free() through an internal function pointer at VA 0x33834.
 * Some crypto paths free pointers into the library's own .data segment.
 * bionic silently ignores these; musl crashes. Patch the pointer at runtime.
 */
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

int main(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: wsm_helper <cmd> <server_id> <client_id>\n");
        _exit(1);
    }

    patch_wsm_free();

    fprintf(stderr, "init(%s, %s)\n", argv[2], argv[3]);
    long handle = WSM_Client_init(argv[2], argv[3], NULL);
    fprintf(stderr, "handle=%ld\n", handle);
    if (handle <= 0) {
        fprintf(stderr, "WSM_Client_init failed: %ld\n", handle);
        _exit(1);
    }

    unsigned char challenge[70];
    size_t n = fread(challenge, 1, 70, stdin);
    if (n != 70) {
        fprintf(stderr, "need 70 bytes on stdin, got %zu\n", n);
        _exit(1);
    }

    fprintf(stderr, "challenge hex: ");
    for (int i = 0; i < 70; i++) fprintf(stderr, "%02x", challenge[i]);
    fprintf(stderr, "\n");

    fprintf(stderr, "generating response...\n");
    unsigned char response[102];
    memset(response, 0xAA, sizeof(response));
    int ret = WSM_Client_checkAndGenerateServerChallenge(handle, challenge, response);
    fprintf(stderr, "ret=%d\n", ret);

    fprintf(stderr, "response hex: ");
    for (int i = 0; i < 102; i++) fprintf(stderr, "%02x", response[i]);
    fprintf(stderr, "\n");

    if (ret <= 0) {
        fprintf(stderr, "checkAndGenerateServerChallenge failed: %d\n", ret);
        fwrite(response, 1, 102, stdout);
        fflush(stdout);
        _exit(1);
    }

    fwrite(response, 1, 102, stdout);
    fflush(stdout);

    if (strcmp(argv[1], "full_auth") == 0) {
        unsigned char confirm[35];
        n = fread(confirm, 1, 35, stdin);
        if (n != 35) {
            fprintf(stderr, "need 35 bytes for confirm, got %zu\n", n);
            _exit(1);
        }
        ret = WSM_Client_checkClientResponse(handle, confirm);
        if (ret <= 0) {
            fprintf(stderr, "checkClientResponse failed: %d\n", ret);
            _exit(1);
        }
        fprintf(stderr, "auth OK\n");
    }

    _exit(0);
}
