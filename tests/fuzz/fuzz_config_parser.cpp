// Roadmap: «P1. Добавить fuzzing после санитайзеров. Отдельные libFuzzer
// targets сначала для `.srs`, затем JSON-конфигурации, текстовых списков и
// текстовых парсеров conntrack/iptables …»
//
// Вторая мишень. `config.json` пользователь правит руками, восстанавливает из
// резервной копии и переносит между версиями; конфигурация из будущей версии
// или из чужого backup — вполне обычный вход, а не выдумка.
//
// Контракт, который проверяем: `parse_and_validate_config` на любом входе либо
// возвращает конфигурацию, либо бросает `ConfigError` (в том числе
// `ConfigValidationError`, наследника). Всё остальное — падение, зависание,
// чужое исключение, `std::bad_alloc` от невалидированного размера — дефект.

#include <cstddef>
#include <cstdint>
#include <string>

#include "config/config.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // Конфигурации таких размеров в природе не встречаются, а фаззеру длинный
    // вход стоит времени и не даёт нового покрытия.
    if (size > (1U << 18)) {
        return 0;
    }

    const std::string document(reinterpret_cast<const char*>(data), size);

    try {
        const auto config = keen_pbr3::parse_and_validate_config(document);
        // Трогаем результат, иначе оптимизатор вправе выбросить разбор целиком.
        volatile std::size_t sink =
            (config.outbounds ? config.outbounds->size() : 0U) +
            (config.lists ? config.lists->size() : 0U);
        (void)sink;
    } catch (const keen_pbr3::ConfigError&) {
        // Единственный ожидаемый способ отказа; ConfigValidationError сюда же.
    }
    return 0;
}
