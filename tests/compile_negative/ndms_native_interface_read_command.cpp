#include "../../src/keenetic/ndms_native_interface_read_production.hpp"

using namespace keen_pbr3;

bool forbidden_command_capability() {
    auto dependencies = ndms_native_interface_read_production_dependencies();
    return dependencies.run_command("interface Wireguard5 no");
}
