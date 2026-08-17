#include "ndms_native_secret_snapshot.hpp"

#include "ndms_wireguard_identity.hpp"

#include "../config/config_writer.hpp"
#include "../crypto/chacha20poly1305.hpp"

#include <cstring>
#include <fstream>
#include <stdexcept>
#include <system_error>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

constexpr char kMagic[] = "keen-pbr-secret-snapshot-v1\n";
constexpr std::size_t kMagicBytes = sizeof(kMagic) - 1U;
constexpr std::size_t kMaximumSnapshotBytes = 64U * 1024U;

bool claimable_interface(const std::string& name) {
    const auto identity = parse_ndms_wireguard_identity(name);
    return identity.has_value() &&
           ndms_wireguard_identity_is_managed_candidate(*identity) &&
           identity->canonical_name() == name;
}

bool identity_valid(const std::string& interface_name,
                    const std::string& transaction_id,
                    const std::string& marker) {
    return claimable_interface(interface_name) &&
           transaction_id.size() == 32U &&
           marker == "kpbr-ni-v1-" + transaction_id;
}

// The identity triple as authenticated data, length-prefixed so no two
// triples can concatenate to the same bytes.
std::string bind_aad(const std::string& interface_name,
                     const std::string& transaction_id,
                     const std::string& marker) {
    std::string aad = "keen-pbr.ndms-native-secret.v1";
    for (const auto* part :
         {&interface_name, &transaction_id, &marker}) {
        aad.push_back('\0');
        aad += std::to_string(part->size());
        aad.push_back('\0');
        aad += *part;
    }
    return aad;
}

bool read_urandom(unsigned char* out, const std::size_t size) {
    const int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    std::size_t got = 0U;
    while (got < size) {
        const auto count = ::read(fd, out + got, size - got);
        if (count <= 0) {
            if (count < 0 && errno == EINTR) continue;
            ::close(fd);
            return false;
        }
        got += static_cast<std::size_t>(count);
    }
    return ::close(fd) == 0;
}

bool read_small_file(const std::filesystem::path& path,
                     std::string& out,
                     const std::size_t maximum) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (!std::filesystem::status_known(status) ||
        !std::filesystem::is_regular_file(status)) {
        return false;
    }
    const auto size = std::filesystem::file_size(path, error);
    if (error || size > maximum) return false;
    std::ifstream input(path, std::ios::binary);
    if (!input) return false;
    out.assign((std::istreambuf_iterator<char>(input)),
               std::istreambuf_iterator<char>());
    return !input.bad();
}

} // namespace

NdmsNativeSecretSnapshotStore::NdmsNativeSecretSnapshotStore(
    std::filesystem::path key_path,
    std::filesystem::path state_directory)
    : key_path_(std::move(key_path)),
      state_directory_(std::move(state_directory)) {}

namespace {

// Loads the master key, creating it on first use. Missing is the only state
// that may create; a key that exists and fails validation must surface, not
// be replaced - a regenerated key orphans every snapshot sealed before it.
bool load_or_create_key(
    const std::filesystem::path& path,
    unsigned char (&key)[kChaCha20Poly1305KeyBytes],
    const bool allow_create) {
    std::string bytes;
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (std::filesystem::status_known(status) &&
        !std::filesystem::exists(status)) {
        if (!allow_create) return false;
        if (!read_urandom(key, sizeof(key))) return false;
        AtomicFileWriteOptions options;
        options.create_parent_directories = true;
        options.created_directory_mode = 0700;
        options.default_file_mode = 0600;
        options.file_mode = static_cast<mode_t>(0600);
        write_file_atomically(
            path.string(),
            std::string(reinterpret_cast<const char*>(key),
                        sizeof(key)),
            options);
        return true;
    }
    if (!read_small_file(path, bytes, 4096U) ||
        bytes.size() != kChaCha20Poly1305KeyBytes) {
        return false;
    }
    std::memcpy(key, bytes.data(), sizeof(key));
    return true;
}

} // namespace

void NdmsNativeSecretSnapshotStore::publish(
    const std::string& interface_name,
    const std::string& transaction_id,
    const std::string& marker,
    const std::string& secret) {
    if (!identity_valid(interface_name, transaction_id, marker) ||
        secret.empty() || secret.size() > kMaximumSnapshotBytes / 2U) {
        throw std::runtime_error(
            "native secret snapshot is not publishable");
    }
    unsigned char key[kChaCha20Poly1305KeyBytes];
    if (!load_or_create_key(key_path_, key, /*allow_create=*/true)) {
        throw std::runtime_error(
            "native secret master key is unavailable and must not be "
            "regenerated");
    }
    unsigned char nonce[kChaCha20Poly1305NonceBytes];
    if (!read_urandom(nonce, sizeof(nonce))) {
        throw std::runtime_error(
            "kernel randomness is unavailable for the snapshot nonce");
    }

    std::string body(kMagic, kMagicBytes);
    body.append(reinterpret_cast<const char*>(nonce), sizeof(nonce));
    body += chacha20poly1305_seal(
        key, nonce, bind_aad(interface_name, transaction_id, marker),
        secret);

    AtomicFileWriteOptions options;
    options.create_parent_directories = true;
    options.created_directory_mode = 0700;
    options.default_file_mode = 0600;
    options.file_mode = static_cast<mode_t>(0600);
    write_file_atomically(
        (state_directory_ / interface_name).string(), body, options);
}

NdmsNativeSecretReadResult NdmsNativeSecretSnapshotStore::read(
    const std::string& interface_name,
    const std::string& transaction_id,
    const std::string& marker) const {
    NdmsNativeSecretReadResult result;
    if (!identity_valid(interface_name, transaction_id, marker)) {
        return result;
    }
    const auto path = state_directory_ / interface_name;
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (!std::filesystem::status_known(status)) return result;
    if (!std::filesystem::exists(status)) {
        result.state = NdmsNativeSecretReadState::absent;
        return result;
    }

    std::string body;
    if (!read_small_file(path, body, kMaximumSnapshotBytes)) return result;
    if (body.size() < kMagicBytes + kChaCha20Poly1305NonceBytes +
                          kChaCha20Poly1305TagBytes ||
        std::memcmp(body.data(), kMagic, kMagicBytes) != 0) {
        return result;
    }

    unsigned char key[kChaCha20Poly1305KeyBytes];
    if (!load_or_create_key(key_path_, key, /*allow_create=*/false)) {
        // A snapshot exists and its key does not: the one state that must
        // reach a human, reported as damage rather than absence.
        return result;
    }
    unsigned char nonce[kChaCha20Poly1305NonceBytes];
    std::memcpy(nonce, body.data() + kMagicBytes, sizeof(nonce));

    auto opened = chacha20poly1305_open(
        key, nonce, bind_aad(interface_name, transaction_id, marker),
        std::string_view(body).substr(kMagicBytes + sizeof(nonce)));
    if (!opened) return result;
    result.secret = std::move(*opened);
    result.state = NdmsNativeSecretReadState::valid;
    return result;
}

bool NdmsNativeSecretSnapshotStore::remove_exact(
    const std::string& interface_name,
    const std::string& transaction_id,
    const std::string& marker) {
    if (read(interface_name, transaction_id, marker).state !=
        NdmsNativeSecretReadState::valid) {
        return false;
    }
    std::error_code error;
    std::filesystem::remove(state_directory_ / interface_name, error);
    if (error) return false;
    return read(interface_name, transaction_id, marker).state ==
           NdmsNativeSecretReadState::absent;
}

const char* ndms_native_secret_read_state_name(
    const NdmsNativeSecretReadState state) noexcept {
    switch (state) {
    case NdmsNativeSecretReadState::absent:
        return "absent";
    case NdmsNativeSecretReadState::valid:
        return "valid";
    case NdmsNativeSecretReadState::unreadable:
        return "unreadable";
    }
    return "unreadable";
}

} // namespace keen_pbr3
