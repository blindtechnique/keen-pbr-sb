// Roadmap: «P1. Добавить fuzzing после санитайзеров. Отдельные libFuzzer
// targets … и текстовых парсеров conntrack/iptables …»
//
// Пятая мишень: разбор снимка conntrack. Вход приходит от утилиты `conntrack`,
// то есть от чужой программы: формат между версиями менялся, на BusyBox бывает
// урезанным, а сама таблица заполняется трафиком, которого мы не выбираем.
//
// Важное свойство этой мишени: она не потребовала ни одной правки production —
// разбор достигается через штатный внедряемый `SnapshotReader`, тот же самый,
// которым пользуются существующие тесты. Выносить внутреннюю функцию из
// анонимного пространства имён ради фаззинга не пришлось.
//
// Контракт: `delete_forwarded_destination_flows` на любом снимке не падает и не
// бросает наружу. Непонятная строка — пропущенная строка; удаление выполняется
// только по точной паре адресов и полной метке, поэтому мусор во входе не может
// превратиться в широкий flush.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "runtime/conntrack_manager.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > (1U << 16)) {
        return 0;
    }

    const std::string snapshot(reinterpret_cast<const char*>(data), size);

    // Команды не выполняются: раннер только считает попытки удаления. Фаззеру
    // интересен разбор, а не сам вызов `conntrack -D`.
    std::size_t deletions = 0;
    keen_pbr3::ConntrackManager manager(
        [&deletions](const std::vector<std::string>&) {
            ++deletions;
            return keen_pbr3::ConntrackManager::CommandResult{0, {}};
        },
        [&snapshot](std::size_t) {
            return std::optional<keen_pbr3::ConntrackManager::Snapshot>(
                keen_pbr3::ConntrackManager::Snapshot{snapshot, false});
        });

    keen_pbr3::ConntrackForwardedFlowCleanupOptions options;
    options.budget = std::chrono::milliseconds{50};
    options.max_flows = 64;
    options.max_snapshot_lines = 512;

    const auto summary = manager.delete_forwarded_destination_flows(
        {"198.51.100.0/24"},
        {"203.0.113.0/24"},
        {"192.0.2.1"},
        0xff00U,
        options);

    volatile std::size_t sink = deletions + summary.matched + summary.attempted;
    (void)sink;
    return 0;
}
