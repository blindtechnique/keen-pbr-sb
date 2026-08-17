// Roadmap: «P1. Добавить fuzzing после санитайзеров. Отдельные libFuzzer
// targets сначала для `.srs` … задать лимиты размера/глубины/времени, короткий
// budget на PR и длинный nightly corpus run с сохраняемым corpus.»
//
// `.srs` — первая мишень не случайно: формат бинарный, приходит из внешнего
// каталога, разбирается собственным декодером и проходит через zlib. Это ровно
// тот вход, где ошибка разбора превращается в чтение за границей буфера.
//
// Декодер обязан на любом входе либо вернуть результат, либо бросить
// SrsDecodeError. Всё остальное — падение, зависание, чужое исключение — дефект.

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>

#include "lists/srs_decoder.hpp"

namespace {

// Лимиты нарочно на несколько порядков ниже боевых. Фаззеру нужна скорость
// обхода, а не проверка того, что 64 МиБ действительно распаковываются: с
// боевыми лимитами один вход мог бы занять минуты и съесть весь бюджет.
keen_pbr3::SrsDecodeLimits fuzz_limits() {
    keen_pbr3::SrsDecodeLimits limits;
    limits.max_compressed_bytes = 1U << 16;
    limits.max_decompressed_bytes = 1U << 20;
    limits.max_rules = 512;
    limits.max_logical_depth = 8;
    limits.max_rule_items = 16;
    limits.max_values = 4096;
    limits.max_string_bytes = 512;
    limits.max_total_string_bytes = 1U << 16;
    limits.max_trie_words = 4096;
    limits.max_trie_labels = 16384;
    limits.max_trie_nodes = 16385;
    limits.max_ip_ranges = 4096;
    limits.max_output_entries = 4096;
    limits.max_output_string_bytes = 1U << 16;
    return limits;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // Отсечка сверху дублирует лимит декодера: без неё фаззер тратит время на
    // всё более длинные входы, которые декодер всё равно отвергнет по размеру.
    if (size > (1U << 16)) {
        return 0;
    }

    std::string payload(reinterpret_cast<const char*>(data), size);
    std::istringstream input(payload, std::ios::binary);

    try {
        const auto result = keen_pbr3::decode_srs(input, fuzz_limits());
        // Результат нужно потрогать, иначе оптимизатор вправе выбросить разбор.
        volatile std::size_t sink = result.domains.size() +
                                    result.domain_suffixes.size() +
                                    result.ip_cidrs.size() + result.skipped_rules;
        (void)sink;
    } catch (const keen_pbr3::SrsDecodeError&) {
        // Единственный ожидаемый способ отказа.
    }
    return 0;
}
