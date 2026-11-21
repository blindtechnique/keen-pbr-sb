#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace keen_pbr3 {

// Unaligned network-order reads. Callers validate packet length first.
inline uint16_t load_be16(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}

inline uint32_t load_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

inline uint64_t load_be64(const uint8_t* p) {
    return (static_cast<uint64_t>(load_be32(p)) << 32) | load_be32(p + 4);
}

class ByteView {
public:
    ByteView() = default;

    ByteView(const uint8_t* data, std::size_t size)
        : data_(data)
        , size_(size) {}

    const uint8_t* data() const { return data_; }
    std::size_t size() const { return size_; }

    const uint8_t& operator[](std::size_t index) const {
        if (index >= size_) {
            throw std::out_of_range("ByteView::operator[] out of range");
        }
        return data_[index];
    }

    const uint8_t* begin() const { return data_; }
    const uint8_t* end() const { return data_ + size_; }

    ByteView subspan(std::size_t offset, std::size_t count) const {
        if (offset > size_ || count > size_ - offset) {
            throw std::out_of_range("ByteView::subspan out of range");
        }
        return ByteView(data_ + offset, count);
    }

private:
    const uint8_t* data_{nullptr};
    std::size_t size_{0};
};

} // namespace keen_pbr3
