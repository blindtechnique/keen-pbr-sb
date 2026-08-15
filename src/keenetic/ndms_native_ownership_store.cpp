#include "ndms_native_ownership_store.hpp"

#include "ndms_wireguard_identity.hpp"

#include "../config/config_writer.hpp"
#include "../crypto/sha256.hpp"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <system_error>

namespace keen_pbr3 {

namespace {

constexpr const char* kHeader = "keen-pbr-native-ownership-v1";
constexpr std::size_t kMaximumRecordBytes = 4096U;

bool lower_hex(const std::string& value, const std::size_t size) {
    return value.size() == size &&
           std::all_of(value.begin(), value.end(), [](const char ch) {
               return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
           });
}

// Only a managed candidate may ever be claimed. Enforced on every path, so a
// corrupted or hand-edited store cannot even assert ownership of a protected
// slot, let alone authorize an action against one.
bool claimable_interface(const std::string& name) {
    const auto identity = parse_ndms_wireguard_identity(name);
    return identity.has_value() &&
           ndms_wireguard_identity_is_managed_candidate(*identity) &&
           identity->canonical_name() == name;
}

bool record_fields_valid(const NdmsNativeOwnershipRecord& record) {
    return claimable_interface(record.interface_name) &&
           lower_hex(record.transaction_id, 32U) &&
           record.marker == "kpbr-ni-v1-" + record.transaction_id &&
           !record.target_full_revision.empty() &&
           record.target_full_revision.size() <= 256U &&
           record.target_full_revision.find('\n') == std::string::npos;
}

void update_field(Sha256& hasher, const std::string_view value) {
    const auto size = static_cast<std::uint64_t>(value.size());
    unsigned char length[8];
    for (std::size_t index = 0U; index < 8U; ++index) {
        length[index] =
            static_cast<unsigned char>(size >> (56U - index * 8U));
    }
    hasher.update(reinterpret_cast<const char*>(length), sizeof(length));
    hasher.update(value.data(), value.size());
}

const char* kind_name(const NdmsNativeTunnelImportKind kind) {
    return kind == NdmsNativeTunnelImportKind::amnezia_wireguard
               ? "amnezia_wireguard"
               : "wireguard";
}

std::string serialize(const NdmsNativeOwnershipRecord& record) {
    std::ostringstream body;
    body << kHeader << '\n'
         << record.interface_name << '\n'
         << record.transaction_id << '\n'
         << record.marker << '\n'
         << kind_name(record.kind) << '\n'
         << record.target_full_revision << '\n';
    return body.str();
}

std::optional<NdmsNativeOwnershipRecord> parse(const std::string& body) {
    std::istringstream input(body);
    std::string header;
    NdmsNativeOwnershipRecord record;
    std::string kind;
    std::string extra;
    if (!std::getline(input, header) || header != kHeader ||
        !std::getline(input, record.interface_name) ||
        !std::getline(input, record.transaction_id) ||
        !std::getline(input, record.marker) ||
        !std::getline(input, kind) ||
        !std::getline(input, record.target_full_revision) ||
        std::getline(input, extra)) {
        return std::nullopt;
    }
    if (kind == "wireguard") {
        record.kind = NdmsNativeTunnelImportKind::wireguard;
    } else if (kind == "amnezia_wireguard") {
        record.kind = NdmsNativeTunnelImportKind::amnezia_wireguard;
    } else {
        return std::nullopt;
    }
    if (!record_fields_valid(record)) return std::nullopt;
    return record;
}

} // namespace

bool NdmsNativeOwnershipRecord::operator==(
    const NdmsNativeOwnershipRecord& other) const noexcept {
    return interface_name == other.interface_name &&
           transaction_id == other.transaction_id &&
           marker == other.marker && kind == other.kind &&
           target_full_revision == other.target_full_revision;
}

std::string ndms_native_ownership_revision(
    const NdmsNativeOwnershipRecord& record) {
    Sha256 hasher;
    update_field(hasher, "keen-pbr.ndms-native-ownership.revision.v1");
    update_field(hasher, record.interface_name);
    update_field(hasher, record.transaction_id);
    update_field(hasher, record.marker);
    update_field(hasher, kind_name(record.kind));
    update_field(hasher, record.target_full_revision);
    return hasher.hex_digest();
}

NdmsNativeOwnershipStore::NdmsNativeOwnershipStore(
    std::filesystem::path state_directory)
    : state_directory_(std::move(state_directory)) {}

std::string NdmsNativeOwnershipStore::publish(
    const NdmsNativeOwnershipRecord& record) {
    if (!record_fields_valid(record)) {
        throw std::runtime_error(
            "native ownership record is not publishable");
    }
    AtomicFileWriteOptions options;
    options.create_parent_directories = true;
    options.created_directory_mode = 0700;
    options.default_file_mode = 0600;
    options.file_mode = static_cast<mode_t>(0600);
    write_file_atomically(
        (state_directory_ / record.interface_name).string(),
        serialize(record), options);
    return ndms_native_ownership_revision(record);
}

NdmsNativeOwnershipReadResult NdmsNativeOwnershipStore::read(
    const std::string& interface_name) const {
    NdmsNativeOwnershipReadResult result;
    if (!claimable_interface(interface_name)) return result;

    const auto path = state_directory_ / interface_name;
    std::error_code error;
    const auto file_status = std::filesystem::symlink_status(path, error);
    // Decided on the returned status, not on the error code: libstdc++ sets
    // ec=ENOENT while returning a perfectly known not_found status, and
    // reading that as an I/O failure turned every honest absence into
    // "unreadable" - measured here when remove_exact could not confirm its
    // own successful removal. A status that is not known at all (EACCES and
    // friends) stays unreadable.
    if (!std::filesystem::status_known(file_status)) return result;
    if (!std::filesystem::exists(file_status)) {
        result.state = NdmsNativeOwnershipReadState::absent;
        return result;
    }
    if (!std::filesystem::is_regular_file(file_status)) return result;
    error.clear();
    const auto size = std::filesystem::file_size(path, error);
    if (error || size > kMaximumRecordBytes) return result;

    std::ifstream input(path, std::ios::binary);
    if (!input) return result;
    std::string body((std::istreambuf_iterator<char>(input)),
                     std::istreambuf_iterator<char>());
    if (input.bad()) return result;

    auto record = parse(body);
    if (!record || record->interface_name != interface_name) return result;
    result.revision = ndms_native_ownership_revision(*record);
    result.record = std::move(record);
    result.state = NdmsNativeOwnershipReadState::valid;
    return result;
}

bool NdmsNativeOwnershipStore::remove_exact(
    const NdmsNativeOwnershipRecord& expected) {
    const auto current = read(expected.interface_name);
    if (current.state != NdmsNativeOwnershipReadState::valid ||
        !(*current.record == expected)) {
        return false;
    }
    std::error_code error;
    std::filesystem::remove(state_directory_ / expected.interface_name,
                            error);
    if (error) return false;
    // The claim must be gone, confirmed by the same validating read that
    // guards every other decision here.
    return read(expected.interface_name).state ==
           NdmsNativeOwnershipReadState::absent;
}

const std::filesystem::path&
NdmsNativeOwnershipStore::state_directory() const noexcept {
    return state_directory_;
}

const char* ndms_native_ownership_read_state_name(
    const NdmsNativeOwnershipReadState state) noexcept {
    switch (state) {
    case NdmsNativeOwnershipReadState::absent:
        return "absent";
    case NdmsNativeOwnershipReadState::valid:
        return "valid";
    case NdmsNativeOwnershipReadState::unreadable:
        return "unreadable";
    }
    return "unreadable";
}

} // namespace keen_pbr3
