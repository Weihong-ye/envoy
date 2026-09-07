#pragma once

#include <cstdint>

#include "source/common/common/statusor.h"

#include "absl/container/flat_hash_set.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Network {

using UbCopyIpv4AddressSet = absl::flat_hash_set<uint32_t>;

// Builds the IPv4 address set that selects the UB copy socket path. The four historical
// deployment addresses are always included. extra_ips is an optional comma-separated list.
StatusOr<UbCopyIpv4AddressSet> buildUbCopyIpv4AddressSet(absl::string_view extra_ips);

// Returns whether address is in the supplied UB copy address set.
bool isUbCopyIpv4Address(uint32_t address, const UbCopyIpv4AddressSet& addresses);

// Returns whether address is selected by the built-in addresses or ENVOY_UB_EXTRA_IPS. The
// environment variable is parsed once per process; an invalid non-empty value is rejected.
bool isConfiguredUbCopyIpv4Address(uint32_t address);

} // namespace Network
} // namespace Envoy
