#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

#ifdef KEEN_PBR3_TESTING
#include "../util/nfqws_file_writer.hpp"
#include "../util/nfqws_strategy_assets.hpp"

#include <functional>
#include <string>
#include <vector>
#endif

namespace keen_pbr3 {
void register_nfqws_handler(ApiServer& server, ApiContext& ctx);

#ifdef KEEN_PBR3_TESTING
struct NfqwsApplyStrategyTestHooks {
    std::function<bool()> installed;
    std::function<std::vector<ConfigValidationIssue>(
        const std::string&, const std::string&)>
        validate;
    std::function<NfqwsStrategyAssetSync(const std::string&)> provision;
    std::function<NfqwsFileWriteResult(const std::string&)> write_active;
    std::function<std::string(int&)> restart;
};

void register_nfqws_handler_for_test(
    ApiServer& server,
    ApiContext& ctx,
    NfqwsApplyStrategyTestHooks hooks);
#endif
}

#endif
