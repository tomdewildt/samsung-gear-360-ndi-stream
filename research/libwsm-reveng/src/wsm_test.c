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

extern long WSM_Server_init(const char*, const char*, const void*);
extern int WSM_Server_generateClientChallenge(long, unsigned char*);
extern int WSM_Server_checkAndGenerateClientResponse(long, const unsigned char*, unsigned char*);
extern long WSM_Client_init(const char*, const char*, const void*);
extern int WSM_Client_checkAndGenerateServerChallenge(long, const unsigned char*, unsigned char*);
extern int WSM_Client_checkClientResponse(long, const unsigned char*);
extern int WSM_getESAPKey(long, unsigned char*);
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

static void hex_dump(const char *label, const unsigned char *data, int len) {
    fprintf(stderr, "%s (%d bytes): ", label, len);
    for (int i = 0; i < len; i++) fprintf(stderr, "%02x", data[i]);
    fprintf(stderr, "\n");
}

int main(int argc, char** argv) {
    const char *server_id = "C8:38:70:3F:97:75";
    const char *client_id = "A8:3B:76:BA:B2:FE";

    if (argc >= 3) {
        server_id = argv[1];
        client_id = argv[2];
    }

    patch_wsm_free();

    fprintf(stderr, "=== WSM Auth Test ===\n");
    fprintf(stderr, "Server ID (camera): %s\n", server_id);
    fprintf(stderr, "Client ID (phone):  %s\n", client_id);

    /* Step 1: Init server and generate challenge */
    fprintf(stderr, "\n--- Server Init + Challenge ---\n");
    long server = WSM_Server_init(server_id, client_id, NULL);
    if (server <= 0) {
        fprintf(stderr, "WSM_Server_init failed: %ld\n", server);
        _exit(1);
    }
    fprintf(stderr, "Server handle: %ld\n", server);

    unsigned char challenge[70];
    memset(challenge, 0, sizeof(challenge));
    int ret = WSM_Server_generateClientChallenge(server, challenge);
    if (ret <= 0) {
        fprintf(stderr, "generateClientChallenge failed: %d\n", ret);
        _exit(1);
    }
    hex_dump("Challenge", challenge, 70);

    /* Step 2: Init client and process challenge */
    fprintf(stderr, "\n--- Client Init + Response ---\n");
    long client = WSM_Client_init(server_id, client_id, NULL);
    if (client <= 0) {
        fprintf(stderr, "WSM_Client_init failed: %ld\n", client);
        _exit(1);
    }
    fprintf(stderr, "Client handle: %ld\n", client);

    unsigned char response[102];
    memset(response, 0xAA, sizeof(response));
    ret = WSM_Client_checkAndGenerateServerChallenge(client, challenge, response);
    if (ret <= 0) {
        fprintf(stderr, "checkAndGenerateServerChallenge failed: %d\n", ret);
        _exit(1);
    }
    hex_dump("Response", response, 102);

    /* Step 3: Server processes response, generates confirm */
    fprintf(stderr, "\n--- Server Confirm ---\n");
    unsigned char confirm[35];
    memset(confirm, 0, sizeof(confirm));
    ret = WSM_Server_checkAndGenerateClientResponse(server, response, confirm);
    if (ret <= 0) {
        fprintf(stderr, "checkAndGenerateClientResponse failed: %d\n", ret);
        _exit(1);
    }
    hex_dump("Confirm", confirm, 35);

    /* Step 4: Client verifies confirm */
    fprintf(stderr, "\n--- Client Verify ---\n");
    ret = WSM_Client_checkClientResponse(client, confirm);
    if (ret <= 0) {
        fprintf(stderr, "checkClientResponse failed: %d\n", ret);
        _exit(1);
    }
    fprintf(stderr, "Auth PASSED!\n");

    /* Step 5: Extract ESAP keys from both sides */
    fprintf(stderr, "\n--- ESAP Keys ---\n");
    unsigned char server_key[48], client_key[48];
    memset(server_key, 0, sizeof(server_key));
    memset(client_key, 0, sizeof(client_key));

    ret = WSM_getESAPKey(server, server_key);
    fprintf(stderr, "Server getESAPKey ret: %d\n", ret);
    hex_dump("Server ESAP Key", server_key, 48);

    ret = WSM_getESAPKey(client, client_key);
    fprintf(stderr, "Client getESAPKey ret: %d\n", ret);
    hex_dump("Client ESAP Key", client_key, 48);

    if (memcmp(server_key, client_key, 48) == 0)
        fprintf(stderr, "ESAP keys MATCH!\n");
    else
        fprintf(stderr, "ESAP keys MISMATCH!\n");

    /* Output binary test vector to stdout */
    fwrite("CHAL", 1, 4, stdout);
    fwrite(challenge, 1, 70, stdout);
    fwrite("RESP", 1, 4, stdout);
    fwrite(response, 1, 102, stdout);
    fwrite("CONF", 1, 4, stdout);
    fwrite(confirm, 1, 35, stdout);
    fwrite("SKEY", 1, 4, stdout);
    fwrite(server_key, 1, 48, stdout);
    fwrite("CKEY", 1, 4, stdout);
    fwrite(client_key, 1, 48, stdout);
    fflush(stdout);

    WSM_destroy(server);
    WSM_destroy(client);

    fprintf(stderr, "\nDone. Test vector written to stdout (%d bytes)\n",
            4+70 + 4+102 + 4+35 + 4+48 + 4+48);
    _exit(0);
}
