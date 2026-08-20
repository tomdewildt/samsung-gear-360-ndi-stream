/* No-op stubs for the symbols libwsm.so imports from Android's liblog.so and libstdc++.so. The Makefile compiles this
 * into stub .so files so libwsm.so loads under musl. The auth path never calls them. */

int __android_log_print(int prio, const char* tag, const char* fmt, ...) {
    return 0;
}

const char _ctype_[384] = {0};

void __cxa_pure_virtual(void) {}
void __cxa_call_unexpected(void* thrown) {}
void __cxa_begin_cleanup(void* exc) {}
void __cxa_type_match(void) {}
int __gnu_Unwind_Find_exidx(void) { return 0; }
