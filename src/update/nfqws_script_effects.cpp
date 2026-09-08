#include "nfqws_script_effects.hpp"

namespace keen_pbr3 {

std::vector<std::string> nfqws_known_script_effect_paths() {
    // Evidence: locally retained nfqws2-keenetic 1.2.3 control scripts,
    // upstream source cdae51414565c8871559f68a1651936e92666544. This is a
    // finite known-effects inventory, not verification of incoming scripts.
    // preinst can overwrite an earlier migration copy; postinst rewrites the
    // active config and consumes the install-type marker. The explicit list
    // migration branch is dormant (NEED_MIGRATION_LIST=0) in that source.
    // The held init has its own recovery owner. Architecture staging leaves
    // come from data.tar.gz; its directories are never cleanup targets here.
    return {
        "/opt/etc/nfqws2/lists/user.list-old",
        "/opt/etc/nfqws2/nfqws2.conf",
        "/opt/etc/nfqws2/nfqws2.conf-old",
        "/opt/tmp/nfqws2_install_type",
    };
}

} // namespace keen_pbr3
