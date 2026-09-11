#include <string>

#include "source/common/network/ip_address_parsing.h"
#include "source/common/network/ub_address_selector.h"

#include "test/test_common/status_utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Network {
namespace {

uint32_t parseAddress(absl::string_view address) {
  const auto parsed = IpAddressParsing::parseIPv4(std::string(address), /*port=*/0);
  EXPECT_OK(parsed);
  return parsed->sin_addr.s_addr;
}

TEST(UbAddressSelectorTest, KeepsBuiltInAddressesWithoutExtras) {
  const auto addresses = buildUbIpv4AddressSet("");
  ASSERT_OK(addresses);
  EXPECT_EQ(4, addresses->size());
  EXPECT_TRUE(isUbIpv4Address(parseAddress("141.61.17.202"), *addresses));
  EXPECT_TRUE(isUbIpv4Address(parseAddress("141.61.17.204"), *addresses));
  EXPECT_TRUE(isUbIpv4Address(parseAddress("141.61.17.206"), *addresses));
  EXPECT_TRUE(isUbIpv4Address(parseAddress("141.61.17.208"), *addresses));
  EXPECT_FALSE(isUbIpv4Address(parseAddress("141.61.17.210"), *addresses));
}

TEST(UbAddressSelectorTest, AddsTrimmedExtraAddressesAndDeduplicates) {
  const auto addresses = buildUbIpv4AddressSet(" 141.61.85.70,141.61.85.74 , 141.61.17.202 ");
  ASSERT_OK(addresses);
  EXPECT_EQ(6, addresses->size());
  EXPECT_TRUE(isUbIpv4Address(parseAddress("141.61.85.70"), *addresses));
  EXPECT_TRUE(isUbIpv4Address(parseAddress("141.61.85.74"), *addresses));
}

TEST(UbAddressSelectorTest, RejectsMalformedExtraAddresses) {
  EXPECT_FALSE(buildUbIpv4AddressSet("not-an-ip").ok());
  EXPECT_FALSE(buildUbIpv4AddressSet("141.61.85.70,").ok());
  EXPECT_FALSE(buildUbIpv4AddressSet(",141.61.85.70").ok());
  EXPECT_FALSE(buildUbIpv4AddressSet("141.61.85.70,,141.61.85.74").ok());
  EXPECT_FALSE(buildUbIpv4AddressSet(" ").ok());
  EXPECT_FALSE(buildUbIpv4AddressSet("2001:db8::1").ok());
}

} // namespace
} // namespace Network
} // namespace Envoy
