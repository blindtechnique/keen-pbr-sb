#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>

namespace keen_pbr3::ipc {

bool emit_resolver_fallback(std::ostream& output,
                            const std::string& fallback_path,
                            const std::string& reason_code,
                            std::int64_t timestamp);

} // namespace keen_pbr3::ipc
