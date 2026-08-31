#include "cache_manager.hpp"
#include "../config/config_writer.hpp"
#include "../config/list_parser.hpp"
#include "../crypto/sha256.hpp"
#include "../lists/list_shrink_guard.hpp"
#include "../lists/srs_decoder.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstring>
#include <fstream>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <nlohmann/json.hpp>
#include <set>
#include <sstream>
#include <string_view>
#include <sys/stat.h>
#include <unordered_map>
#include <unordered_set>
#include <unistd.h>
#include <utility>

namespace keen_pbr3 {

struct CacheGenerationPinState final {
    explicit CacheGenerationPinState(std::filesystem::path directory)
        : cache_dir(std::move(directory)) {}

    void release(const std::string& name,
                 const std::string& filename,
                 const std::filesystem::path& path) noexcept;

    std::filesystem::path cache_dir;
    std::mutex mutex;
    std::unordered_map<std::string, std::size_t> pin_counts;
    std::unordered_set<std::string> retired;
};

namespace {

using CacheChunkWriter = std::function<void(std::string_view)>;

enum class CacheBodyKind {
    Current,
    Previous,
    Legacy,
};

struct ResolvedCacheBody {
    std::filesystem::path path;
    api::CacheGeneration generation;
    CacheBodyKind kind{CacheBodyKind::Legacy};
};

struct CacheMetadataDocument {
    CacheMetadata metadata;
    bool parsed{false};
};

class CacheGenerationLease final {
public:
    CacheGenerationLease(std::shared_ptr<CacheGenerationPinState> state,
                         std::string name,
                         std::string filename,
                         std::filesystem::path path)
        : state_(std::move(state))
        , name_(std::move(name))
        , filename_(std::move(filename))
        , path_(std::move(path)) {}

    ~CacheGenerationLease() {
        state_->release(name_, filename_, path_);
    }

private:
    std::shared_ptr<CacheGenerationPinState> state_;
    std::string name_;
    std::string filename_;
    std::filesystem::path path_;
};

class StringViewInputBuffer final : public std::streambuf {
public:
    explicit StringViewInputBuffer(std::string_view body) {
        static char empty = '\0';
        auto* begin = body.empty() ? &empty : const_cast<char*>(body.data());
        setg(begin, begin, begin + body.size());
    }
};

std::atomic<unsigned int> cache_generation_sequence{0};

static std::string current_time_iso() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&time_t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

CacheDownloadResult download_failed(std::string message,
                                    std::optional<long> http_status_code = std::nullopt,
                                    bool retryable = false) {
    CacheDownloadResult result;
    result.status = CacheDownloadStatus::Failed;
    result.error_message = std::move(message);
    result.http_status_code = http_status_code;
    result.retryable = retryable;
    return result;
}

CacheDownloadResult download_cancelled() {
    CacheDownloadResult result;
    result.status = CacheDownloadStatus::Cancelled;
    result.error_message = "download cancelled";
    return result;
}

bool cancellation_requested(const CacheDownloadOptions& options) {
    return options.cancellation &&
           options.cancellation->load(std::memory_order_relaxed);
}

void commit_cache_files(const CacheDownloadOptions& options,
                        const std::function<void()>& commit) {
    if (options.commit) {
        options.commit(commit);
    } else {
        commit();
    }
}

std::string clean_download_error_message(const std::exception& error) {
    constexpr std::string_view prefix = "HTTP request failed: ";
    std::string message = error.what();
    if (message.rfind(prefix, 0) == 0) {
        message.erase(0, prefix.size());
    }
    return message;
}

bool is_srs_rule_set_url(const std::string& url) {
    const auto end = url.find_first_of("?#");
    std::string path = url.substr(0, end);
    std::transform(path.begin(), path.end(), path.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return path.size() >= 4 && path.compare(path.size() - 4, 4, ".srs") == 0;
}

std::size_t saturating_multiply(std::size_t value, std::size_t multiplier) {
    if (value > std::numeric_limits<std::size_t>::max() / multiplier) {
        return std::numeric_limits<std::size_t>::max();
    }
    return value * multiplier;
}

bool valid_sha256(std::string_view value) {
    return value.size() == 64U &&
           std::all_of(value.begin(), value.end(), [](unsigned char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

bool generation_filename_is_safe(const std::string& name,
                                 const std::string& filename,
                                 bool allow_legacy) {
    if (filename.empty() ||
        std::filesystem::path(filename).filename().string() != filename) {
        return false;
    }
    if (allow_legacy && filename == name + ".txt") {
        return true;
    }
    const std::string prefix = name + ".g-";
    constexpr std::string_view suffix = ".txt";
    if (filename.size() <= prefix.size() + suffix.size() ||
        filename.rfind(prefix, 0) != 0 ||
        filename.compare(filename.size() - suffix.size(),
                         suffix.size(), suffix) != 0) {
        return false;
    }

    const std::string_view generation(
        filename.data() + prefix.size(),
        filename.size() - prefix.size() - suffix.size());
    const auto first_separator = generation.find('-');
    const auto second_separator =
        first_separator == std::string_view::npos
            ? std::string_view::npos
            : generation.find('-', first_separator + 1U);
    if (first_separator == std::string_view::npos ||
        second_separator == std::string_view::npos ||
        generation.find('-', second_separator + 1U) != std::string_view::npos) {
        return false;
    }
    const auto digits_only = [](std::string_view part) {
        return !part.empty() &&
               std::all_of(part.begin(), part.end(), [](unsigned char value) {
                   return value >= '0' && value <= '9';
               });
    };
    return digits_only(generation.substr(0, first_separator)) &&
           digits_only(generation.substr(
               first_separator + 1U,
               second_separator - first_separator - 1U)) &&
           digits_only(generation.substr(second_separator + 1U));
}

void write_all(int descriptor, std::string_view body) {
    std::size_t offset = 0;
    while (offset < body.size()) {
        const ssize_t written = ::write(
            descriptor, body.data() + offset, body.size() - offset);
        if (written < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(
                std::string("failed to write cache generation: ") +
                std::strerror(errno));
        }
        if (written == 0) {
            throw std::runtime_error(
                "failed to write cache generation: short write");
        }
        offset += static_cast<std::size_t>(written);
    }
}

std::optional<api::CacheGeneration> inspect_cache_file(
    const std::filesystem::path& path,
    const std::string& filename,
    std::size_t max_file_size_bytes,
    const std::optional<api::CacheGeneration>& expected = std::nullopt) {
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int descriptor = ::open(path.c_str(), flags);
    if (descriptor < 0) {
        return std::nullopt;
    }

    const auto close_descriptor = [&]() { (void)::close(descriptor); };
    struct stat metadata {};
    if (::fstat(descriptor, &metadata) != 0 ||
        !S_ISREG(metadata.st_mode) || metadata.st_size < 0 ||
        static_cast<std::uintmax_t>(metadata.st_size) > max_file_size_bytes ||
        static_cast<std::uintmax_t>(metadata.st_size) >
            static_cast<std::uintmax_t>(
                std::numeric_limits<std::int64_t>::max())) {
        close_descriptor();
        return std::nullopt;
    }

    const auto size = static_cast<std::uintmax_t>(metadata.st_size);
    if (expected.has_value()) {
        if (expected->filename != filename || expected->size < 0 ||
            static_cast<std::uintmax_t>(expected->size) != size ||
            !valid_sha256(expected->sha256)) {
            close_descriptor();
            return std::nullopt;
        }
    }

    Sha256 digest;
    std::array<char, 8192> buffer {};
    std::uintmax_t total = 0;
    while (true) {
        const ssize_t count = ::read(descriptor, buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) continue;
            close_descriptor();
            return std::nullopt;
        }
        if (count == 0) break;
        total += static_cast<std::uintmax_t>(count);
        if (total > size || total > max_file_size_bytes) {
            close_descriptor();
            return std::nullopt;
        }
        digest.update(buffer.data(), static_cast<std::size_t>(count));
    }
    close_descriptor();
    if (total != size) {
        return std::nullopt;
    }

    api::CacheGeneration result;
    result.filename = filename;
    result.size = static_cast<std::int64_t>(size);
    result.sha256 = digest.hex_digest();
    if (expected.has_value() && result.sha256 != expected->sha256) {
        return std::nullopt;
    }
    return result;
}

CacheMetadataDocument read_metadata_document(
    const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    try {
        CacheMetadataDocument document;
        document.metadata =
            nlohmann::json::parse(input).get<CacheMetadata>();
        document.parsed = true;
        return document;
    } catch (const nlohmann::json::exception&) {
        return {};
    }
}

std::optional<ResolvedCacheBody> resolve_cache_body(
    const std::filesystem::path& cache_dir,
    const std::string& name,
    std::size_t max_file_size_bytes,
    const CacheMetadataDocument& document) {
    const auto inspect_generation =
        [&](const std::optional<api::CacheGeneration>& generation,
            CacheBodyKind kind) -> std::optional<ResolvedCacheBody> {
        if (!generation.has_value() ||
            !generation_filename_is_safe(name, generation->filename, true)) {
            return std::nullopt;
        }
        auto inspected = inspect_cache_file(
            cache_dir / generation->filename,
            generation->filename,
            max_file_size_bytes,
            generation);
        if (!inspected.has_value()) return std::nullopt;
        return ResolvedCacheBody{
            cache_dir / generation->filename, *inspected, kind};
    };

    if (document.parsed) {
        if (auto current = inspect_generation(
                document.metadata.current, CacheBodyKind::Current)) {
            return current;
        }
        if (auto previous = inspect_generation(
                document.metadata.previous, CacheBodyKind::Previous)) {
            return previous;
        }
        if (document.metadata.current.has_value() ||
            document.metadata.previous.has_value()) {
            return std::nullopt;
        }
    }

    const std::string legacy_filename = name + ".txt";
    auto legacy = inspect_cache_file(
        cache_dir / legacy_filename,
        legacy_filename,
        max_file_size_bytes);
    if (!legacy.has_value()) return std::nullopt;
    return ResolvedCacheBody{
        cache_dir / legacy_filename, *legacy, CacheBodyKind::Legacy};
}

std::string next_generation_filename(const std::filesystem::path& cache_dir,
                                     const std::string& name) {
    const auto ticks = std::chrono::duration_cast<std::chrono::microseconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
    for (unsigned int attempt = 0; attempt < 128U; ++attempt) {
        const auto sequence = cache_generation_sequence.fetch_add(
            1U, std::memory_order_relaxed);
        const std::string filename =
            name + ".g-" + std::to_string(ticks) + "-" +
            std::to_string(static_cast<long long>(::getpid())) + "-" +
            std::to_string(sequence) + ".txt";
        std::error_code error;
        const bool exists = std::filesystem::exists(
            cache_dir / filename, error);
        if (!error && !exists) return filename;
    }
    throw std::runtime_error(
        "failed to allocate an immutable cache generation filename");
}

api::CacheGeneration write_cache_generation(
    const std::filesystem::path& cache_dir,
    const std::string& name,
    std::size_t max_file_size_bytes,
    const std::function<void(const CacheChunkWriter&)>& populate) {
    const std::string filename = next_generation_filename(cache_dir, name);
    const std::filesystem::path path = cache_dir / filename;
    Sha256 digest;
    std::size_t size = 0;

    AtomicFileWriteOptions options;
    options.create_parent_directories = true;
    options.default_file_mode = 0600;
    write_file_atomically_with(
        path.string(),
        [&](int descriptor) {
            const CacheChunkWriter writer =
                [&](std::string_view chunk) {
                    if (chunk.size() > max_file_size_bytes - size) {
                        throw std::runtime_error(
                            "cache generation exceeds configured file size limit");
                    }
                    write_all(descriptor, chunk);
                    digest.update(chunk.data(), chunk.size());
                    size += chunk.size();
                };
            populate(writer);
        },
        options);

    api::CacheGeneration generation;
    generation.filename = filename;
    generation.size = static_cast<std::int64_t>(size);
    generation.sha256 = digest.hex_digest();
    return generation;
}

void garbage_collect_generations(
    const std::filesystem::path& cache_dir,
    const std::string& name,
    const std::shared_ptr<CacheGenerationPinState>& pin_state) noexcept {
    try {
        std::lock_guard<std::mutex> lock(pin_state->mutex);
        const CacheMetadataDocument document = read_metadata_document(
            cache_dir / (name + ".meta.json"));
        if (!document.parsed) return;

        std::set<std::string> keep;
        if (document.metadata.current.has_value() &&
            generation_filename_is_safe(
                name, document.metadata.current->filename, true)) {
            keep.insert(document.metadata.current->filename);
        }
        if (document.metadata.previous.has_value() &&
            generation_filename_is_safe(
                name, document.metadata.previous->filename, true)) {
            keep.insert(document.metadata.previous->filename);
        }

        // Capture and collection share this mutex. A generation is therefore
        // either pinned before GC considers it or removed before a later
        // capture can resolve it; there is no check-then-unlink race.
        for (const auto& filename : keep) {
            // A restored/rolled-back generation is live again and must no
            // longer be removed when an older lease is released.
            pin_state->retired.erase(filename);
        }

        std::error_code error;
        std::filesystem::directory_iterator iterator(cache_dir, error);
        if (error) return;
        for (const auto& entry : iterator) {
            const std::string filename = entry.path().filename().string();
            if (keep.count(filename) != 0U ||
                !generation_filename_is_safe(name, filename, false)) {
                continue;
            }
            const auto pinned = pin_state->pin_counts.find(filename);
            if (pinned != pin_state->pin_counts.end() &&
                pinned->second != 0U) {
                pin_state->retired.insert(filename);
                continue;
            }
            std::filesystem::remove(entry.path(), error);
            if (!error) {
                pin_state->retired.erase(filename);
            }
            error.clear();
        }
    } catch (...) {
        // GC is best effort. In particular, allocation failure while recording
        // a deferred deletion must retain data rather than affect refresh.
    }
}

void write_cache_metadata_file(const std::filesystem::path& path,
                               const CacheMetadata& metadata,
#ifdef KEEN_PBR3_TESTING
                               const std::function<void(AtomicFileWriteStage)>&
                                   fault_injector = {}
#else
                               std::nullptr_t = nullptr
#endif
) {
    AtomicFileWriteOptions options;
    options.create_parent_directories = true;
    options.default_file_mode = 0600;
#ifdef KEEN_PBR3_TESTING
    options.fault_injector = fault_injector;
#endif
    write_file_atomically(
        path.string(), nlohmann::json(metadata).dump(2) + "\n", options);
}

bool is_usable_converted_cache(const std::filesystem::path& path,
                               std::size_t max_file_size_bytes) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || !std::filesystem::is_regular_file(status)) {
        return false;
    }
    const auto file_size = std::filesystem::file_size(path, error);
    if (error || file_size > max_file_size_bytes) {
        return false;
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return false;
    }

    EntryCounter entries;
    std::string line;
    while (std::getline(input, line)) {
        if (line.size() > 4096U) {
            return false;
        }
        const auto first = std::find_if_not(
            line.begin(), line.end(),
            [](unsigned char value) { return std::isspace(value) != 0; });
        const auto last = std::find_if_not(
            line.rbegin(), line.rend(),
            [](unsigned char value) { return std::isspace(value) != 0; })
                              .base();
        if (first == line.end() || first >= last || *first == '#') {
            continue;
        }
        const std::string_view value(
            &*first, static_cast<std::size_t>(last - first));
        if (!ListParser::classify_entry(value, entries)) {
            return false;
        }
    }
    return input.eof();
}

SrsDecodeLimits srs_decode_limits(std::size_t max_file_size_bytes) {
    constexpr std::size_t kRouterTrieNodeCap = 1000000U;
    SrsDecodeLimits limits;
    limits.max_compressed_bytes =
        std::max<std::size_t>(1U, std::min(limits.max_compressed_bytes,
                                           max_file_size_bytes));
    limits.max_decompressed_bytes =
        std::max<std::size_t>(
            1U,
            std::min(limits.max_decompressed_bytes,
                     saturating_multiply(max_file_size_bytes, 4U)));
    limits.max_total_string_bytes =
        std::min(limits.max_total_string_bytes, limits.max_decompressed_bytes);
    limits.max_trie_labels =
        std::min({limits.max_trie_labels,
                  limits.max_decompressed_bytes,
                  kRouterTrieNodeCap - 1U});
    limits.max_trie_nodes =
        std::min({limits.max_trie_nodes,
                  limits.max_trie_labels + 1U,
                  kRouterTrieNodeCap});
    limits.max_output_string_bytes =
        std::min(limits.max_output_string_bytes, max_file_size_bytes);
    limits.max_output_entries =
        std::min(limits.max_output_entries,
                 std::max<std::size_t>(1U, max_file_size_bytes / 32U));
    return limits;
}

std::optional<std::string> decode_srs_native(
    std::istream& input,
    const CacheChunkWriter& write_chunk,
    std::size_t max_output_bytes,
    std::string& warning_message,
    std::string& diagnostic_message) {
    try {
        auto decoded = decode_srs(input, srs_decode_limits(max_output_bytes));

        std::size_t output_bytes = 0;
        std::size_t output_entries = 0;
        std::size_t exact_domains_mapped = 0;
        std::size_t invalid_domains_skipped = 0;
        const auto write_entry = [&](std::string_view prefix,
                                     std::string_view value)
            -> std::optional<std::string> {
            const std::size_t line_bytes = prefix.size() + value.size() + 1U;
            if (line_bytes > max_output_bytes - output_bytes) {
                return "converted SRS list exceeds configured file size limit";
            }
            write_chunk(prefix);
            write_chunk(value);
            write_chunk("\n");
            output_bytes += line_bytes;
            ++output_entries;
            return std::nullopt;
        };

        for (const auto& domain : decoded.domains) {
            if (domain.rfind("*.", 0) == 0 || (!domain.empty() && domain.front() == '.')) {
                ++invalid_domains_skipped;
                continue;
            }
            const auto normalized = ListParser::normalize_domain(domain);
            if (!normalized.has_value()) {
                ++invalid_domains_skipped;
                continue;
            }
            if (const auto error = write_entry({}, *normalized); error.has_value()) {
                return error;
            }
            ++exact_domains_mapped;
        }
        for (const auto& suffix : decoded.domain_suffixes) {
            if (suffix.rfind("*.", 0) == 0 || (!suffix.empty() && suffix.front() == '.')) {
                ++invalid_domains_skipped;
                continue;
            }
            const auto normalized = ListParser::normalize_domain(suffix);
            if (!normalized.has_value()) {
                ++invalid_domains_skipped;
                continue;
            }
            if (const auto error = write_entry("*.", *normalized); error.has_value()) {
                return error;
            }
        }
        for (const auto& cidr : decoded.ip_cidrs) {
            if (const auto error = write_entry({}, cidr); error.has_value()) {
                return error;
            }
        }

        if (output_entries == 0U &&
            (decoded.skipped_rules != 0U ||
             decoded.unsupported_fields != 0U ||
             invalid_domains_skipped != 0U)) {
            return "SRS contains no safely representable domain, domain suffix or IP/CIDR entries";
        }

        std::vector<std::string> warning_parts;
        if (exact_domains_mapped != 0U) {
            warning_parts.push_back(
                "mapped " + std::to_string(exact_domains_mapped) +
                " exact domain(s) to keen-pbr root-and-subdomain semantics");
        }
        if (decoded.unsupported_fields != 0U) {
            warning_parts.push_back(
                "skipped " + std::to_string(decoded.unsupported_fields) +
                " unsupported condition(s)");
        }
        if (decoded.skipped_rules != 0U) {
            auto part =
                "skipped " + std::to_string(decoded.skipped_rules) + " rule(s)";
            if (decoded.inverted_rules != 0U) {
                part += ", including " + std::to_string(decoded.inverted_rules) +
                        " inverted rule(s)";
            }
            warning_parts.push_back(std::move(part));
        }
        if (invalid_domains_skipped != 0U) {
            warning_parts.push_back(
                "skipped " + std::to_string(invalid_domains_skipped) +
                " invalid domain value(s)");
        }
        if (!warning_parts.empty()) {
            std::ostringstream warning;
            warning << "SRS import is lossy: ";
            for (std::size_t index = 0; index < warning_parts.size(); ++index) {
                if (index != 0U) {
                    warning << "; ";
                }
                warning << warning_parts[index];
            }
            // An unsupported destination alternative can be discarded while
            // the same rule still contributes safe domains/IP ranges. Keep
            // that fact in the journal without turning a successful refresh
            // into a bell incident. Dropping a complete rule or an invalid
            // domain is materially lossy and remains a warning.
            if (decoded.skipped_rules == 0U &&
                invalid_domains_skipped == 0U) {
                diagnostic_message = warning.str();
            } else {
                warning_message = warning.str();
            }
        }
        return std::nullopt;
    } catch (const SrsDecodeError& error) {
        if (error.kind() == SrsDecodeErrorKind::UnsupportedVersion) {
            return std::string(error.what()) +
                   "; update keen-pbr-sb to add support before importing this file";
        }
        return error.what();
    } catch (const std::exception& error) {
        return std::string("failed to decode SRS: ") + error.what();
    }
}

} // namespace

void CacheGenerationPinState::release(
    const std::string& name,
    const std::string& filename,
    const std::filesystem::path& path) noexcept {
    try {
        std::lock_guard<std::mutex> lock(mutex);
        const auto pinned = pin_counts.find(filename);
        if (pinned == pin_counts.end()) return;
        if (pinned->second > 1U) {
            --pinned->second;
            return;
        }
        pin_counts.erase(pinned);
        if (retired.count(filename) == 0U ||
            path.parent_path() != cache_dir) {
            return;
        }

        // Metadata publication uses this mutex too. Revalidate before unlink
        // so a generation restored as current/previous after an earlier GC
        // decision cannot be removed by the last old lease.
        const auto document = read_metadata_document(
            cache_dir / (name + ".meta.json"));
        if (!document.parsed) return;
        const auto references_filename = [&](const auto& generation) {
            return generation.has_value() &&
                   generation_filename_is_safe(
                       name, generation->filename, true) &&
                   generation->filename == filename;
        };
        if (references_filename(document.metadata.current) ||
            references_filename(document.metadata.previous)) {
            retired.erase(filename);
            return;
        }

        std::error_code error;
        std::filesystem::remove(path, error);
        if (!error) {
            retired.erase(filename);
        }
    } catch (...) {
        // A lease destructor must never terminate the daemon. A failed
        // deferred removal is harmless and a later GC pass can retry it.
    }
}

CacheGenerationHandle::CacheGenerationHandle(
    std::filesystem::path path,
    api::CacheGeneration generation,
    std::shared_ptr<const void> lease)
    : path_(std::move(path))
    , generation_(std::move(generation))
    , lease_(std::move(lease)) {}

bool ListCacheGenerationSnapshot::contains(const std::string& name) const {
    return entries_.find(name) != entries_.end();
}

const CacheGenerationHandle* ListCacheGenerationSnapshot::find(
    const std::string& name) const {
    const auto entry = entries_.find(name);
    if (entry == entries_.end() || !entry->second.has_value()) {
        return nullptr;
    }
    return &*entry->second;
}

std::map<std::string, std::string>
ListCacheGenerationSnapshot::fingerprints() const {
    std::map<std::string, std::string> result;
    for (const auto& [name, handle] : entries_) {
        result.emplace(
            name, handle.has_value() ? handle->generation().sha256
                                     : std::string{});
    }
    return result;
}

CacheManager::CacheManager(const std::filesystem::path& cache_dir,
                           size_t max_file_size_bytes,
                           std::shared_ptr<HttpTransport> transport)
    : cache_dir_(cache_dir)
    , max_file_size_bytes_(max_file_size_bytes)
    , http_client_(std::move(transport))
    , generation_pin_state_(
          std::make_shared<CacheGenerationPinState>(cache_dir)) {
    http_client_.set_max_response_size(max_file_size_bytes);
}

void CacheManager::ensure_dir() {
    struct stat metadata {};
    if (::lstat(cache_dir_.c_str(), &metadata) == 0) {
        if (!S_ISDIR(metadata.st_mode) || S_ISLNK(metadata.st_mode)) {
            throw std::runtime_error(
                "cache path is not a real directory");
        }
        return;
    }
    if (errno != ENOENT) {
        throw std::runtime_error(
            std::string("failed to inspect cache directory: ") +
            std::strerror(errno));
    }

    // Let the common durable writer create and fsync the complete directory
    // chain. The private marker avoids a non-durable create_directories()
    // pre-step that would otherwise be invisible to the writer.
    AtomicFileWriteOptions options;
    options.create_parent_directories = true;
    options.default_file_mode = 0600;
    write_file_atomically(
        (cache_dir_ / ".cache-directory").string(), "keen-pbr-cache\n", options);
}

void CacheManager::set_max_file_size(size_t bytes) {
    max_file_size_bytes_ = bytes;
    http_client_.set_max_response_size(bytes);
}

void CacheManager::record_refresh_failure(
    const std::string& name,
    const std::string& url,
    const std::string& error_message,
    const std::optional<std::string>& detour) {
    CacheMetadata metadata = load_metadata(name);
    metadata.last_refresh_attempt = current_time_iso();
    metadata.last_refresh_error = error_message;
    metadata.last_refresh_url = url;
    metadata.last_refresh_detour = detour;
    save_metadata(name, metadata);
}

CacheDownloadResult CacheManager::download(const std::string& name,
                                           const std::string& url,
                                           const CacheDownloadOptions& options) {
    if (cancellation_requested(options)) {
        return download_cancelled();
    }
    const bool srs = is_srs_rule_set_url(url);
    const CacheMetadataDocument existing_document =
        read_metadata_document(meta_path(name));
    CacheMetadata existing = existing_document.metadata;
    const auto existing_body = resolve_cache_body(
        cache_dir_, name, max_file_size_bytes_, existing_document);
    const bool same_source =
        existing.url.has_value() && *existing.url == url;
    const bool current_srs_revision =
        !srs ||
        (existing.srs_decoder_revision.has_value() &&
         *existing.srs_decoder_revision == kSrsDecoderRevision);
    const bool use_conditionals =
        same_source && current_srs_revision && existing_body.has_value() &&
        existing_body->kind != CacheBodyKind::Previous;
    const auto save_download_metadata =
        [this, &name, &options](const CacheMetadata& metadata) {
            std::lock_guard<std::mutex> lock(
                generation_pin_state_->mutex);
            write_cache_metadata_file(
                meta_path(name),
                metadata
#ifdef KEEN_PBR3_TESTING
                ,
                options.metadata_fault_injector
#endif
            );
        };
    const auto failed_attempt =
        [this, &name, &url, &options](
            std::string message,
            std::optional<long> http_status_code = std::nullopt,
            bool retryable = false) {
            if (cancellation_requested(options)) {
                return download_cancelled();
            }
            auto result =
                download_failed(
                    std::move(message), http_status_code, retryable);
            try {
#ifdef KEEN_PBR3_TESTING
                if (options.before_failure_metadata_persist) {
                    options.before_failure_metadata_persist();
                }
#endif
                record_refresh_failure(
                    name, url, result.error_message, options.detour);
            } catch (const std::exception& metadata_error) {
                result.error_message +=
                    "; failed to persist refresh metadata: ";
                result.error_message += metadata_error.what();
            }
            return result;
        };

    ConditionalDownloadResult result;
    try {
        result = http_client_.download_conditional(
            url,
            use_conditionals ? existing.etag.value_or("") : "",
            use_conditionals ? existing.last_modified.value_or("") : "",
            HttpRequestOptions{options.fwmark, options.cancellation});
    } catch (const HttpRequestCancelled&) {
        return download_cancelled();
    } catch (const HttpError& e) {
        if (e.status_code() > 0) {
            return failed_attempt(
                "HTTP " + std::to_string(e.status_code()),
                e.status_code(),
                true);
        }
        return failed_attempt(
            clean_download_error_message(e), std::nullopt, true);
    } catch (const std::exception& e) {
        return failed_attempt(e.what(), std::nullopt, true);
    }

    if (cancellation_requested(options)) {
        return download_cancelled();
    }

    if (result.not_modified && !use_conditionals) {
        return failed_attempt(
            "HTTP 304 received without a matching local cache validator",
            304);
    }
    if (result.not_modified) {
        const std::string successful_at = current_time_iso();
        existing.download_time = successful_at;
        existing.last_refresh_attempt = successful_at;
        existing.last_refresh_error.reset();
        existing.last_refresh_url = url;
        existing.last_refresh_detour = options.detour;
        try {
            save_download_metadata(existing);
        } catch (const std::exception& error) {
            const auto visible = read_metadata_document(meta_path(name));
            if (visible.parsed &&
                visible.metadata.download_time == existing.download_time &&
                visible.metadata.url == existing.url) {
                CacheDownloadResult not_modified;
                not_modified.status = CacheDownloadStatus::NotModified;
                not_modified.warning_message =
                    std::string("cache metadata is visible but its final "
                                "durability check failed: ") +
                    error.what();
                return not_modified;
            }
            return failed_attempt(
                std::string("failed to persist cache metadata: ") +
                error.what());
        }

        CacheDownloadResult not_modified;
        not_modified.status = CacheDownloadStatus::NotModified;
        return not_modified;
    }

    std::string conversion_warning;
    std::string conversion_diagnostic;
    api::CacheGeneration generation;
    try {
        if (srs) {
            StringViewInputBuffer input_buffer(result.body);
            std::istream compressed(&input_buffer);
            generation = write_cache_generation(
                cache_dir_,
                name,
                max_file_size_bytes_,
                [&](const CacheChunkWriter& write_chunk) {
                    auto conversion_error = decode_srs_native(
                        compressed,
                        write_chunk,
                        max_file_size_bytes_,
                        conversion_warning,
                        conversion_diagnostic);
                    if (conversion_error.has_value()) {
                        throw std::runtime_error(*conversion_error);
                    }
                });
        } else {
            generation = write_cache_generation(
                cache_dir_,
                name,
                max_file_size_bytes_,
                [&](const CacheChunkWriter& write_chunk) {
                    write_chunk(result.body);
                });
        }
    } catch (const std::exception& error) {
        garbage_collect_generations(
            cache_dir_, name, generation_pin_state_);
        return failed_attempt(error.what());
    }

    if (cancellation_requested(options)) {
        std::error_code remove_error;
        std::filesystem::remove(
            cache_dir_ / generation.filename, remove_error);
        return download_cancelled();
    }

    // What this body will actually contribute, counted the way the streamer
    // will later read it. Recorded whatever the verdict below: a count is a
    // fact about the body, and the next download needs it to have anything to
    // compare against.
    ListEntryCounts candidate_counts;
    {
        std::ifstream body_for_counting(
            cache_dir_ / generation.filename, std::ios::binary);
        if (body_for_counting.is_open()) {
            candidate_counts = count_list_entries(body_for_counting);
        }
    }

    // A source that came back with most of its contents gone is far more
    // likely to have broken than to have changed. Publishing it would unroute
    // everything it carried, and the download itself succeeded, so nothing
    // else would say a word.
    //
    // Only compared against the same URL: counts from a different source
    // answer a different question.
    if (same_source) {
        ListEntryCounts previous_counts;
        previous_counts.domains = existing.domains.value_or(0);
        previous_counts.cidrs = existing.cidrs.value_or(0);
        previous_counts.ips = existing.ips.value_or(0);

        const auto shrink =
            decide_list_shrink(previous_counts, candidate_counts);
        if (shrink.verdict == ListShrinkVerdict::refuse) {
            // The body is dropped and the metadata is left untouched, which
            // matters more than it looks: keeping the old ETag is what makes
            // the next refresh fetch the source again instead of being told
            // it is already up to date.
            std::error_code remove_error;
            std::filesystem::remove(
                cache_dir_ / generation.filename, remove_error);
            garbage_collect_generations(
                cache_dir_, name, generation_pin_state_);
            return failed_attempt(shrink.reason);
        }
    }

    const std::string successful_at = current_time_iso();
    CacheMetadata meta;
    meta.domains = candidate_counts.domains;
    meta.cidrs = candidate_counts.cidrs;
    meta.ips = candidate_counts.ips;
    meta.etag = result.etag;
    meta.last_modified = result.last_modified;
    meta.url = url;
    meta.download_time = successful_at;
    meta.last_refresh_attempt = successful_at;
    meta.last_refresh_url = url;
    meta.last_refresh_detour = options.detour;
    meta.current = generation;
    if (same_source && existing_body.has_value()) {
        meta.previous = existing_body->generation;
    }
    if (srs) {
        meta.srs_decoder_revision = kSrsDecoderRevision;
    }

    if (cancellation_requested(options)) {
        std::error_code remove_error;
        std::filesystem::remove(
            cache_dir_ / generation.filename, remove_error);
        return download_cancelled();
    }

    // The immutable body is already durable. Replacing this one fixed metadata
    // file is the only commit point: readers see either the complete old
    // generation or the complete new one, never a body/metadata mixture.
    try {
        commit_cache_files(options, [&]() {
            save_download_metadata(meta);
        });
    } catch (const std::exception& e) {
        const auto visible_document =
            read_metadata_document(meta_path(name));
        const auto visible_body = resolve_cache_body(
            cache_dir_, name, max_file_size_bytes_, visible_document);
        const bool generation_is_published =
            visible_document.parsed &&
            visible_document.metadata.current.has_value() &&
            visible_document.metadata.current->filename ==
                generation.filename;
        if (generation_is_published &&
            visible_body.has_value() &&
            visible_body->kind == CacheBodyKind::Current &&
            visible_body->generation.filename == generation.filename) {
            // rename(2) already made the sole commit point visible. Returning a
            // failure here would suppress the caller's runtime apply while
            // readers already consume the new generation. Continue as an
            // update and surface the weaker durability guarantee explicitly.
            garbage_collect_generations(
                cache_dir_, name, generation_pin_state_);
            CacheDownloadResult updated;
            updated.status = CacheDownloadStatus::Updated;
            updated.diagnostic_message =
                std::move(conversion_diagnostic);
            updated.warning_message =
                std::string("cache metadata is visible but its final "
                            "durability check failed: ") +
                e.what();
            if (srs && !conversion_warning.empty()) {
                updated.warning_message += "; ";
                updated.warning_message += conversion_warning;
            }
            return updated;
        }
        // Only a body that was never published may be reclaimed here. Free its
        // space before persisting the failed-attempt metadata: on ENOSPC,
        // doing this in the opposite order makes the error timestamp fail for
        // the same reason as the original commit.
        std::error_code remove_error;
        if (!generation_is_published) {
            std::filesystem::remove(
                cache_dir_ / generation.filename, remove_error);
        }
        auto failure_message =
            std::string("failed to commit cache metadata: ") + e.what();
        if (remove_error) {
            failure_message += "; failed to remove uncommitted cache body: ";
            failure_message += remove_error.message();
        }
        auto failed = failed_attempt(std::move(failure_message));
        garbage_collect_generations(
            cache_dir_,
            name,
            generation_pin_state_);
        return failed;
    }

    garbage_collect_generations(
        cache_dir_,
        name,
        generation_pin_state_);

    CacheDownloadResult updated;
    updated.status = CacheDownloadStatus::Updated;
    if (srs) {
        updated.diagnostic_message =
            std::move(conversion_diagnostic);
        updated.warning_message = std::move(conversion_warning);
    }
    return updated;
}

bool CacheManager::has_cache(const std::string& name) const {
    const auto document = read_metadata_document(meta_path(name));
    return resolve_cache_body(
               cache_dir_, name, max_file_size_bytes_, document)
        .has_value();
}

bool CacheManager::has_current_cache(const std::string& name,
                                     const std::string& url) const {
    const auto document = read_metadata_document(meta_path(name));
    const CacheMetadata& metadata = document.metadata;
    if (!metadata.url.has_value() || *metadata.url != url) {
        return false;
    }

    const auto body = resolve_cache_body(
        cache_dir_, name, max_file_size_bytes_, document);
    if (!body.has_value() || body->kind == CacheBodyKind::Previous) {
        return false;
    }

    return !is_srs_rule_set_url(url) ||
           (metadata.srs_decoder_revision.has_value() &&
            *metadata.srs_decoder_revision == kSrsDecoderRevision);
}

bool CacheManager::has_usable_same_source_cache(
    const std::string& name,
    const std::string& url) const {
    const auto document = read_metadata_document(meta_path(name));
    const CacheMetadata& metadata = document.metadata;
    if (!metadata.url.has_value() || *metadata.url != url) {
        return false;
    }
    const auto body = resolve_cache_body(
        cache_dir_, name, max_file_size_bytes_, document);
    return body.has_value() &&
           is_usable_converted_cache(body->path, max_file_size_bytes_);
}

std::filesystem::path CacheManager::cache_path(const std::string& name) const {
    const auto document = read_metadata_document(meta_path(name));
    if (auto body = resolve_cache_body(
            cache_dir_, name, max_file_size_bytes_, document)) {
        return body->path;
    }
    return cache_dir_ / (name + ".txt");
}

std::shared_ptr<const ListCacheGenerationSnapshot>
CacheManager::capture_generation(
    const std::vector<std::string>& names) const {
    auto snapshot = std::make_shared<ListCacheGenerationSnapshot>();
    struct Reservation {
        std::string name;
        ResolvedCacheBody body;
        bool pin_owned{false};
    };
    std::vector<Reservation> reservations;
    reservations.reserve(names.size());

    try {
        {
            // Metadata publication and GC use the same mutex. Hold it for the
            // complete name set so no refresh can split the snapshot between
            // two generations. Each verified body is reserved before unlock.
            std::lock_guard<std::mutex> lock(generation_pin_state_->mutex);
            for (const auto& name : names) {
                auto [entry, inserted] = snapshot->entries_.try_emplace(
                    name, std::nullopt);
                if (!inserted) continue;

                const auto document = read_metadata_document(meta_path(name));
                auto body = resolve_cache_body(
                    cache_dir_, name, max_file_size_bytes_, document);
                if (!body.has_value()) {
                    // Keep the explicit null entry: this name must remain
                    // cache-missing for the lifetime of the snapshot.
                    continue;
                }

                reservations.push_back(
                    Reservation{name, std::move(*body), false});
                auto& reservation = reservations.back();
                ++generation_pin_state_->pin_counts[
                    reservation.body.generation.filename];
                reservation.pin_owned = true;
            }
        }

        for (auto& reservation : reservations) {
            std::shared_ptr<CacheGenerationLease> lease;
            try {
                lease = std::make_shared<CacheGenerationLease>(
                    generation_pin_state_,
                    reservation.name,
                    reservation.body.generation.filename,
                    reservation.body.path);
            } catch (...) {
                generation_pin_state_->release(
                    reservation.name,
                    reservation.body.generation.filename,
                    reservation.body.path);
                reservation.pin_owned = false;
                throw;
            }
            // Ownership transfers to the lease before constructing the public
            // handle. Any later exception releases through the lease itself.
            reservation.pin_owned = false;
            CacheGenerationHandle handle(
                std::move(reservation.body.path),
                std::move(reservation.body.generation),
                std::move(lease));
            snapshot->entries_.at(reservation.name).emplace(
                std::move(handle));
        }
    } catch (...) {
        for (const auto& reservation : reservations) {
            if (!reservation.pin_owned) continue;
            generation_pin_state_->release(
                reservation.name,
                reservation.body.generation.filename,
                reservation.body.path);
        }
        throw;
    }
    return snapshot;
}

std::filesystem::path CacheManager::meta_path(const std::string& name) const {
    return cache_dir_ / (name + ".meta.json");
}

CacheMetadata CacheManager::load_metadata(const std::string& name) const {
    return read_metadata_document(meta_path(name)).metadata;
}

void CacheManager::save_metadata(const std::string& name, const CacheMetadata& meta) {
    std::lock_guard<std::mutex> lock(generation_pin_state_->mutex);
    write_cache_metadata_file(meta_path(name), meta);
}

} // namespace keen_pbr3
