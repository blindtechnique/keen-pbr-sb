// Compile against the actual Entware xtables headers. Syscalls are stubbed
// here; kernel COMMIT acceptance must additionally run on a real Keenetic.
#include "../../src/keenetic/connndmmark_compat.c"
#include <assert.h>
#include <stdarg.h>
#include <errno.h>

static int supported, original_calls, parser_calls;
static struct xtables_match* registered;
static struct xtables_match* supplied;
static void fail(enum xtables_exittype status, const char* fmt, ...) __attribute__((noreturn));
static void fail(enum xtables_exittype status, const char* fmt, ...) {
    (void)status;
    (void)fmt;
    exit(2);
}
static struct xtables_globals globals = {.exit_err = fail};
struct xtables_globals* xt_params = &globals;
struct xtables_match* xtables_find_match(const char* name, enum xtables_tryload mode,
                                        struct xtables_rule_match** matches) {
    assert(strcmp(name, "connndmmark") == 0 && mode == XTF_DONT_LOAD && !matches);
    return supplied;
}
void xtables_register_match(struct xtables_match* match) { registered = match; }
void xtables_option_parse(struct xt_option_call* cb) { (void)cb; parser_calls++; }
int __wrap_socket(int family, int type, int protocol) {
    assert(family == AF_INET && type == SOCK_RAW && protocol == IPPROTO_RAW);
    return 42;
}
int __wrap_getsockopt(int fd, int level, int name, void* value, socklen_t* size) {
    assert(fd == 42 && level == IPPROTO_IP && name == IPT_SO_GET_REVISION_MATCH);
    const struct xt_get_revision* query = value;
    assert(strcmp(query->name, "connndmmark") == 0 && query->revision == 1);
    assert(*size == sizeof(*query));
    errno = supported ? 0 : EPROTONOSUPPORT;
    return supported ? 0 : -1;
}
int __wrap_close(int fd) { assert(fd == 42); return 0; }
static void original_init(void) { original_calls++; }
void* __wrap_dlsym(void* handle, const char* name) {
    assert(handle == RTLD_NEXT && strcmp(name, "init_extensions") == 0);
    return (void*)original_init;
}

int main(int argc, char** argv) {
    struct xtables_match native = {.revision = 1};
    init_extensions();
    assert(original_calls == 1 && registered == NULL);
    supported = 1;
    supplied = &native;
    init_extensions();
    assert(original_calls == 2 && registered == NULL);
    native.revision = 0;
    init_extensions();
    assert(original_calls == 3 && registered != NULL);
    assert(registered->revision == 1 && registered->family == NFPROTO_UNSPEC);
    assert(registered->size == XT_ALIGN(12) && registered->userspacesize == XT_ALIGN(12));
    assert(registered->x6_options[0].type == XTTYPE_MARKMASK32);
    assert(registered->x6_options[0].flags == (XTOPT_MAND | XTOPT_INVERT));
    struct xt_entry_match* match = calloc(1, sizeof(*match) + registered->size);
    assert(match);
    match->u.user.match_size = sizeof(*match) + registered->size;
    match->u.user.revision = 1;
    if (argc == 2 && strcmp(argv[1], "bad-size") == 0) match->u.user.match_size--;
    if (argc == 2 && strcmp(argv[1], "bad-revision") == 0) match->u.user.revision = 0;
    struct xt_option_call cb = {.data = match->data};
    cb.val.mark = 0x20; cb.val.mask = 0x20; cb.invert = true;
    registered->x6_parse(&cb);
    const uint32_t expected[] = {0x20, 0x20, 1};
    assert(parser_calls == 1 && memcmp(match->data, expected, sizeof(expected)) == 0);
    registered->save(NULL, match);
    puts("");
    cb.val.mark = 0x12340000; cb.val.mask = 0xffff0000; cb.invert = false;
    registered->x6_parse(&cb);
    const uint32_t wide[] = {0x12340000, 0xffff0000, 0};
    assert(memcmp(match->data, wide, sizeof(wide)) == 0);
    registered->save(NULL, match);
    puts("");
    cb.val.mark = 0; cb.val.mask = 0xffffffff; cb.invert = true;
    registered->x6_parse(&cb);
    registered->save(NULL, match);
    puts("");
    free(match);
    puts("ABI, inversion, wide masks, kernel capability and native-update deferral: PASS");
    return 0;
}
