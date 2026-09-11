#include "source/common/network/ub_address_selector.h"

#include <cstdlib>
#include <string>
#include <utility>

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/common/network/ip_address_parsing.h"

#include "absl/status/status.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"

namespace Envoy {
namespace Network {

namespace {

constexpr absl::string_view kExtraIpsEnvironmentVariable = "ENVOY_UB_EXTRA_IPS";
constexpr absl::string_view kBuiltInIpv4Addresses[] = {"141.61.17.202", "141.61.17.204",
                                                       "141.61.17.206", "141.61.17.208"};

absl::Status addIpv4Address(absl::string_view value, UbIpv4AddressSet& addresses) {
  const auto parsed = IpAddressParsing::parseIPv4(std::string(value), /*port=*/0);
  if (!parsed.ok()) {
    return absl::InvalidArgumentError(absl::StrCat("invalid IPv4 address '", value, "'"));
  }
  addresses.insert(parsed->sin_addr.s_addr);
  return absl::OkStatus();
}

const UbIpv4AddressSet& configuredUbIpv4Addresses() {
  static const auto* addresses = []() {
    const char* extra_ips = std::getenv(std::string(kExtraIpsEnvironmentVariable).c_str());
    auto result = buildUbIpv4AddressSet(extra_ips == nullptr ? absl::string_view() : extra_ips);
    if (!result.ok()) {
      ENVOY_LOG_MISC(error, "[UB_ZC_CONFIG] ignoring invalid {}: {}", kExtraIpsEnvironmentVariable,
                     result.status().message());
      result = buildUbIpv4AddressSet("");
      RELEASE_ASSERT(result.ok(), "built-in UB IPv4 addresses must be valid");
    }
    return new UbIpv4AddressSet(std::move(result).value());
  }();
  return *addresses;
}

} // namespace

StatusOr<UbIpv4AddressSet> buildUbIpv4AddressSet(absl::string_view extra_ips) {
  UbIpv4AddressSet addresses;
  for (const absl::string_view address : kBuiltInIpv4Addresses) {
    const absl::Status status = addIpv4Address(address, addresses);
    ASSERT(status.ok());
  }

  if (extra_ips.empty()) {
    return addresses;
  }

  for (const absl::string_view raw_address : absl::StrSplit(extra_ips, ',')) {
    const absl::string_view address = absl::StripAsciiWhitespace(raw_address);
    if (address.empty()) {
      return absl::InvalidArgumentError("empty IPv4 address entry");
    }
    const absl::Status status = addIpv4Address(address, addresses);
    if (!status.ok()) {
      return status;
    }
  }
  return addresses;
}

bool isUbIpv4Address(uint32_t address, const UbIpv4AddressSet& addresses) {
  return addresses.contains(address);
}

bool isConfiguredUbIpv4Address(uint32_t address) {
  return isUbIpv4Address(address, configuredUbIpv4Addresses());
}

} // namespace Network
} // namespace Envoy
