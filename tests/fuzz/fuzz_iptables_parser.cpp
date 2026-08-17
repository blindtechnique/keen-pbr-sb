// Roadmap: «P1. Добавить fuzzing после санитайзеров. Отдельные libFuzzer
// targets сначала для `.srs`, затем JSON-конфигурации, текстовых списков и
// текстовых парсеров conntrack/iptables …»
//
// Четвёртая мишень: разбор вывода `iptables-save`. Вход не пользовательский, а
// от чужой программы, и это не делает его безопаснее: версия iptables на
// роутере не наша, формат между версиями менялся, а на BusyBox бывает
// урезанный вывод. Падение разбора здесь означает, что не работает проверка
// состояния файрвола.
//
// Контракт: `parse_iptables_s` разбирает любой текст без падения и без
// исключений. Непонятная строка — пропущенная строка.

#include <cstddef>
#include <cstdint>
#include <string>

#include "firewall/iptables_verifier.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > (1U << 16)) {
        return 0;
    }

    const std::string output(reinterpret_cast<const char*>(data), size);
    const auto state = keen_pbr3::parse_iptables_s(output);

    volatile std::size_t sink = state.rules.size();
    (void)sink;
    return 0;
}
