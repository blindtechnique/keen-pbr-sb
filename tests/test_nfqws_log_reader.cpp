#include "../src/log/nfqws_log_reader.hpp"

#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

namespace {
struct NfqwsLogReaderFixture {
    std::filesystem::path directory;
    std::filesystem::path path;

    NfqwsLogReaderFixture() {
        char pattern[] = "/tmp/keen-pbr-nfqws-log-reader-XXXXXX";
        const auto created = ::mkdtemp(pattern);
        if (created == nullptr) throw std::runtime_error("mkdtemp failed");
        directory = created;
        path = directory / "nfqws2.log";
    }
    ~NfqwsLogReaderFixture() {
        std::error_code error;
        std::filesystem::remove_all(directory, error);
    }
    void write(const std::string& content) const {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output << content;
        REQUIRE(output.good());
    }
};
} // namespace

TEST_CASE("nfqws log reader keeps small and empty files complete") {
    NfqwsLogReaderFixture file;
    for (const auto& content : {std::string{}, std::string{"first\nlast\n"}}) {
        file.write(content);
        const auto tail = keen_pbr3::read_nfqws_log_tail(file.path, 64U);
        CHECK(tail.content == content);
        CHECK_FALSE(tail.truncated);
    }
}

TEST_CASE("nfqws log reader preserves an exact size boundary and trims a partial first record") {
    NfqwsLogReaderFixture file;
    file.write("older\nnewest\n");
    const auto complete = keen_pbr3::read_nfqws_log_tail(file.path, 13U);
    CHECK(complete.content == "older\nnewest\n");
    CHECK_FALSE(complete.truncated);
    const auto aligned = keen_pbr3::read_nfqws_log_tail(file.path, 7U);
    CHECK(aligned.content == "newest\n");
    CHECK(aligned.truncated);
    const auto partial = keen_pbr3::read_nfqws_log_tail(file.path, 9U);
    CHECK(partial.content == "newest\n");
    CHECK(partial.truncated);
}

TEST_CASE("nfqws log reader shows a single oversized record instead of an empty tail") {
    NfqwsLogReaderFixture file;
    for (const auto& ending : {std::string{}, std::string{"\n"}}) {
        file.write(std::string(32U, 'x') + "latest" + ending);
        const auto tail = keen_pbr3::read_nfqws_log_tail(file.path, 10U);
        CHECK(tail.truncated);
        CHECK(tail.content == std::string(4U - ending.size(), 'x') + "latest" + ending);
        CHECK(tail.content.size() == 10U);
    }
}

TEST_CASE("nfqws log reader skips a split UTF-8 code point at a tail boundary") {
    NfqwsLogReaderFixture file;
    file.write(std::string("old") + "\xd0\xaf" + "newest");
    const auto tail = keen_pbr3::read_nfqws_log_tail(file.path, 7U);
    CHECK(tail.truncated);
    CHECK(tail.content == "newest");
}

TEST_CASE("nfqws log reader bounds a large sparse file to its newest records") {
    NfqwsLogReaderFixture file;
    {
        std::ofstream output(file.path, std::ios::binary);
        output.seekp(64U * 1024U * 1024U);
        output << "\nlatest record\n";
        REQUIRE(output.good());
    }
    const auto tail = keen_pbr3::read_nfqws_log_tail(file.path, 2U * 1024U * 1024U);
    CHECK(tail.truncated);
    CHECK(tail.content == "latest record\n");
}

TEST_CASE("nfqws log reader reports missing files and invalid limits") {
    NfqwsLogReaderFixture file;
    CHECK_THROWS_AS(keen_pbr3::read_nfqws_log_tail(file.path, 64U), std::runtime_error);
    file.write("present\n");
    CHECK_THROWS_AS(keen_pbr3::read_nfqws_log_tail(file.path, 0U), std::invalid_argument);
}

TEST_CASE("nfqws log display reverses short and empty records in place") {
    struct Example { std::string input; std::string expected; };
    for (const auto& example : {
             Example{"", ""},
             Example{"\n", "\n"},
             Example{"one", "one\n"},
             Example{"one\ntwo\n", "two\none\n"},
             Example{"one\ntwo", "two\none\n"},
             Example{"one\n\ntwo\n", "two\n\none\n"},
             Example{"\none\n\n", "\none\n\n"},
             Example{"one\r\ntwo\r\n", "two\r\none\r\n"}}) {
        auto content = example.input;
        keen_pbr3::reverse_nfqws_log_lines(content);
        CHECK(content == example.expected);
    }
    std::string short_records(2U * 1024U * 1024U, '\n');
    const auto* storage = short_records.data();
    const auto capacity = short_records.capacity();
    keen_pbr3::reverse_nfqws_log_lines(short_records);
    CHECK(short_records.size() == 2U * 1024U * 1024U);
    CHECK(short_records.data() == storage);
    CHECK(short_records.capacity() == capacity);
}
