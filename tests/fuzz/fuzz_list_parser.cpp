// Roadmap: «P1. Добавить fuzzing после санитайзеров. Отдельные libFuzzer
// targets сначала для `.srs`, затем JSON-конфигурации, текстовых списков и
// текстовых парсеров conntrack/iptables …»
//
// Третья мишень. Текстовый список — самый «внешний» вход из всех: он
// скачивается по URL из чужого каталога, и его содержимое не контролирует
// никто из нас. `.srs` хотя бы бинарный и с заголовком; здесь — произвольный
// текст произвольной длины.
//
// Контракт: `ListParser::stream_parse` разбирает любой ввод без падения и без
// исключений. Непонятная строка — это пропущенная строка, а не отказ: список
// на десять тысяч доменов не должен целиком отвергаться из-за одной кривой
// записи посередине.

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>

#include "config/list_parser.hpp"
#include "lists/list_entry_visitor.hpp"

namespace {

// Считает записи по типам и трогает содержимое, чтобы разбор нельзя было
// выбросить как не имеющий эффекта.
class CountingVisitor final : public keen_pbr3::ListEntryVisitor {
public:
    void on_entry(keen_pbr3::EntryType type, std::string_view entry) override {
        switch (type) {
        case keen_pbr3::EntryType::Ip:
            ips_ += entry.size();
            break;
        case keen_pbr3::EntryType::Cidr:
            cidrs_ += entry.size();
            break;
        case keen_pbr3::EntryType::Domain:
            domains_ += entry.size();
            break;
        }
    }

    std::size_t total() const {
        return ips_ + cidrs_ + domains_;
    }

private:
    std::size_t ips_ = 0;
    std::size_t cidrs_ = 0;
    std::size_t domains_ = 0;
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // Списки бывают большими, но фаззеру длина не даёт нового покрытия: те же
    // ветви разбора проходятся на десятке строк.
    if (size > (1U << 16)) {
        return 0;
    }

    const std::string payload(reinterpret_cast<const char*>(data), size);
    std::istringstream input(payload);
    CountingVisitor visitor;

    keen_pbr3::ListParser::stream_parse(input, visitor, "fuzz");

    volatile std::size_t sink = visitor.total();
    (void)sink;
    return 0;
}
