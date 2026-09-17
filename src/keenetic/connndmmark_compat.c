// Process-local adapter for Entware libxtables.so.10. Used ONLY by the
// nfqws TCP helper; never replace firmware/Entware libraries or export a
// system-wide LD_PRELOAD. Register a read-only match, not an NDM mark target.
// Keenetic ABI: include/uapi/linux/netfilter/xt_connndmmark.h and
// net/netfilter/xt_connndmmark.c in keenetic/kernel-49 (revision 1).
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <xtables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

typedef struct {
    uint32_t mark;
    uint32_t mask;
    uint32_t invert;
} NdmMatchV1;
_Static_assert(sizeof(NdmMatchV1) == 12, "Keenetic revision 1 has three u32 fields");
_Static_assert(offsetof(NdmMatchV1, mask) == 4 && offsetof(NdmMatchV1, invert) == 8,
              "Do not reuse Entware's revision 0 three-u8 layout");

static const struct xt_option_entry* options(void) {
    static struct xt_option_entry entries[2] = {0};
    entries[0].name = "mark";
    entries[0].id = 0;
    entries[0].type = XTTYPE_MARKMASK32;
    entries[0].flags = XTOPT_MAND | XTOPT_INVERT;
    return entries;
}

static void parse(struct xt_option_call* cb) {
    xtables_option_parse(cb);
    NdmMatchV1* info = cb->data;
    info->mark = cb->val.mark;
    info->mask = cb->val.mask;
    info->invert = cb->invert ? 1U : 0U;
}

static const NdmMatchV1* data(const struct xt_entry_match* match) {
    if (match->u.user.revision != 1 ||
        match->u.match_size != sizeof(struct xt_entry_match) + XT_ALIGN(sizeof(NdmMatchV1))) {
        xtables_error(PARAMETER_PROBLEM, "connndmmark: unexpected Keenetic match ABI");
    }
    return (const void*)match->data;
}

static void save(const void* ip, const struct xt_entry_match* match) {
    (void)ip;
    const NdmMatchV1* info = data(match);
    if (info->invert) printf(" !");
    printf(" --mark 0x%x/0x%x", info->mark, info->mask);
}

static void print(const void* ip, const struct xt_entry_match* match, int numeric) {
    (void)numeric;
    printf(" connndmmark");
    save(ip, match);
}

static bool kernel_supports_v1(void) {
    const int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) return false;
    struct xt_get_revision query = {0};
    strcpy(query.name, "connndmmark");
    query.revision = 1;
    socklen_t size = sizeof(query);
    const int result = getsockopt(fd, IPPROTO_IP, IPT_SO_GET_REVISION_MATCH, &query, &size);
    close(fd);
    return result == 0;
}

static void register_match(void) {
    if (!kernel_supports_v1()) return;
    const struct xtables_match* existing = xtables_find_match("connndmmark", XTF_DONT_LOAD, NULL);
    // A future Entware update with native support wins; do not double-register
    // the same revision or intercept its implementation.
    if (existing != NULL && existing->revision >= 1) return;
    static struct xtables_match match = {0};
    match.version = XTABLES_VERSION;
    match.name = "connndmmark";
    match.revision = 1;
    match.family = NFPROTO_UNSPEC;
    match.size = XT_ALIGN(sizeof(NdmMatchV1));
    match.userspacesize = XT_ALIGN(sizeof(NdmMatchV1));
    match.print = print;
    match.save = save;
    match.x6_parse = parse;
    match.x6_options = options();
    xtables_register_match(&match);
}

__attribute__((visibility("default"))) void init_extensions(void) {
    typedef void (*Init)(void);
    const Init original = (Init)dlsym(RTLD_NEXT, "init_extensions");
    if (original == NULL) {
        fprintf(stderr, "keen-pbr connndmmark: Entware extension initializer unavailable\n");
        exit(2);
    }
    original();
    register_match();
}
