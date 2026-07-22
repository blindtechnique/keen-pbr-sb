#include "base64.hpp"

#include <cstdint>
#include <stdexcept>

namespace keen_pbr3 {
namespace {

constexpr std::string_view kAlphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int decode_character(char value) {
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '+') return 62;
    if (value == '/') return 63;
    return -1;
}

} // namespace

std::string base64_encode(std::string_view input) {
    std::string output;
    output.reserve(((input.size() + 2U) / 3U) * 4U);

    for (std::size_t offset = 0; offset < input.size(); offset += 3U) {
        const auto first = static_cast<std::uint8_t>(input[offset]);
        const bool has_second = offset + 1U < input.size();
        const bool has_third = offset + 2U < input.size();
        const auto second = has_second ? static_cast<std::uint8_t>(input[offset + 1U]) : 0U;
        const auto third = has_third ? static_cast<std::uint8_t>(input[offset + 2U]) : 0U;
        const std::uint32_t block = (static_cast<std::uint32_t>(first) << 16U) |
                                    (static_cast<std::uint32_t>(second) << 8U) |
                                    static_cast<std::uint32_t>(third);

        output.push_back(kAlphabet[(block >> 18U) & 0x3FU]);
        output.push_back(kAlphabet[(block >> 12U) & 0x3FU]);
        output.push_back(has_second ? kAlphabet[(block >> 6U) & 0x3FU] : '=');
        output.push_back(has_third ? kAlphabet[block & 0x3FU] : '=');
    }

    return output;
}

std::string base64_decode(std::string_view input) {
    if (input.size() % 4U != 0U) throw std::invalid_argument("invalid base64 length");

    std::string output;
    output.reserve((input.size() / 4U) * 3U);
    for (std::size_t offset = 0; offset < input.size(); offset += 4U) {
        const bool last_block = offset + 4U == input.size();
        const bool pad_third = input[offset + 2U] == '=';
        const bool pad_fourth = input[offset + 3U] == '=';
        const int first = decode_character(input[offset]);
        const int second = decode_character(input[offset + 1U]);
        const int third = pad_third ? 0 : decode_character(input[offset + 2U]);
        const int fourth = pad_fourth ? 0 : decode_character(input[offset + 3U]);

        if (first < 0 || second < 0 || third < 0 || fourth < 0 ||
            (!last_block && (pad_third || pad_fourth)) || (pad_third && !pad_fourth)) {
            throw std::invalid_argument("invalid base64 data");
        }

        const std::uint32_t block = (static_cast<std::uint32_t>(first) << 18U) |
                                    (static_cast<std::uint32_t>(second) << 12U) |
                                    (static_cast<std::uint32_t>(third) << 6U) |
                                    static_cast<std::uint32_t>(fourth);
        output.push_back(static_cast<char>((block >> 16U) & 0xFFU));
        if (!pad_third) output.push_back(static_cast<char>((block >> 8U) & 0xFFU));
        if (!pad_fourth) output.push_back(static_cast<char>(block & 0xFFU));
    }

    return output;
}

} // namespace keen_pbr3
