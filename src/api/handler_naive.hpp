#pragma once

#ifdef WITH_API

#include "handlers.hpp"

namespace keen_pbr3 {

// GET/POST /api/system/naive-component — состояние и установка libcronet.so,
// без которого sing-box не умеет naive.
void register_naive_component_handler(ApiServer& server, ApiContext& ctx);

} // namespace keen_pbr3

#endif // WITH_API
