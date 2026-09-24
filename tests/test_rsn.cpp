// RSN element parsing: generations, ciphers, MFP bits, and malformed input.
#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <tuple>

#include "support.hpp"
#include "wifi/rsn.hpp"

using namespace airlock;
using namespace airlock::wifi;
using airlock::testing::contains;

namespace {

using Strings = std::vector<std::string>;

bool any_weakness(const RSNInfo& info, const std::string& fragment) {
  const Strings w = info.weaknesses();
  return std::any_of(w.begin(), w.end(), [&](const std::string& s) { return contains(s, fragment); });
}

}  // namespace

TEST(Rsn, Wpa2Psk) {
  const RSNInfo info = parse_rsn_element(build_rsn_element({.akm_suites = {2}}));
  EXPECT_EQ(info.generation(), "WPA2-Personal (PSK)");
  EXPECT_EQ(info.group_cipher, "CCMP-128");
  EXPECT_EQ(info.pairwise_ciphers, Strings{"CCMP-128"});
  EXPECT_EQ(info.akm_suites, Strings{"PSK"});
  EXPECT_EQ(info.mfp_state(), "not supported");
}

TEST(Rsn, Wpa3SaeWithMfpRequired) {
  const RSNInfo info = parse_rsn_element(build_rsn_element(
      {.akm_suites = {8}, .mfp_capable = true, .mfp_required = true, .group_mgmt_cipher = 6}));
  EXPECT_EQ(info.generation(), "WPA3-Personal (SAE)");
  EXPECT_TRUE(info.mfp_required && info.mfp_capable);
  EXPECT_EQ(info.mfp_state(), "required");
  EXPECT_EQ(info.group_mgmt_cipher, "BIP-CMAC-128");
  // A correctly configured WPA3 network should raise no findings at all.
  EXPECT_TRUE(info.weaknesses().empty());
}

TEST(Rsn, TransitionModeIsFlaggedAsADowngradePath) {
  const RSNInfo info =
      parse_rsn_element(build_rsn_element({.akm_suites = {8, 2}, .mfp_capable = true}));
  EXPECT_EQ(info.generation(), "WPA3/WPA2 transition mode");
  EXPECT_TRUE(any_weakness(info, "downgrade"));
}

TEST(Rsn, EnterpriseIsRecognised) {
  const RSNInfo info = parse_rsn_element(build_rsn_element({.akm_suites = {1}}));
  EXPECT_TRUE(contains(info.generation(), "802.1X"));
}

TEST(Rsn, OweIsRecognised) {
  const RSNInfo info =
      parse_rsn_element(build_rsn_element({.akm_suites = {18}, .mfp_capable = true}));
  EXPECT_TRUE(info.generation().starts_with("OWE"));
}

TEST(Rsn, TkipIsReportedAsBroken) {
  const RSNInfo info =
      parse_rsn_element(build_rsn_element({.group_cipher = 2, .pairwise_ciphers = {2, 4}}));
  EXPECT_NE(std::find(info.pairwise_ciphers.begin(), info.pairwise_ciphers.end(), "TKIP"),
            info.pairwise_ciphers.end());
  const Strings w = info.weaknesses();
  EXPECT_TRUE(std::any_of(w.begin(), w.end(), [](const std::string& s) {
    return contains(s, "TKIP") && contains(s, "broken");
  }));
}

namespace {

class MfpBits : public ::testing::TestWithParam<std::tuple<int, bool, bool>> {};

TEST_P(MfpBits, AreReadFromTheRightPositions) {
  // MFPR is bit 6 and MFPC is bit 7; swapping them inverts the finding.
  const auto& [capabilities, capable, required] = GetParam();
  const RSNInfo info = parse_rsn_element(build_rsn_element(
      {.mfp_capable = (capabilities & 0x0080) != 0, .mfp_required = (capabilities & 0x0040) != 0}));
  EXPECT_EQ(info.raw_capabilities, capabilities);
  EXPECT_EQ(info.mfp_capable, capable);
  EXPECT_EQ(info.mfp_required, required);
}

INSTANTIATE_TEST_SUITE_P(Words, MfpBits,
                         ::testing::Values(std::tuple{0x0000, false, false},
                                           std::tuple{0x0080, true, false},
                                           std::tuple{0x00C0, true, true},
                                           std::tuple{0x0040, false, true}));

}  // namespace

TEST(Rsn, MissingMfpIsAFinding) {
  const RSNInfo info = parse_rsn_element(build_rsn_element({.akm_suites = {2}}));
  EXPECT_TRUE(any_weakness(info, "management frame protection"));
}

TEST(Rsn, OptionalMfpIsStillAFinding) {
  const RSNInfo info =
      parse_rsn_element(build_rsn_element({.akm_suites = {2}, .mfp_capable = true}));
  EXPECT_TRUE(any_weakness(info, "optional"));
}

TEST(Rsn, BuildAndParseRoundTrip) {
  // The encoder and decoder are checked against each other.
  const RSNInfo info = parse_rsn_element(build_rsn_element({.group_cipher = 9,
                                                            .pairwise_ciphers = {9, 4},
                                                            .akm_suites = {8, 2},
                                                            .mfp_capable = true,
                                                            .mfp_required = true,
                                                            .group_mgmt_cipher = 12}));
  EXPECT_EQ(info.group_cipher, "GCMP-256");
  EXPECT_EQ(info.pairwise_ciphers, (Strings{"GCMP-256", "CCMP-128"}));
  EXPECT_EQ(info.akm_suites, (Strings{"SAE", "PSK"}));
  EXPECT_EQ(info.group_mgmt_cipher, "BIP-GMAC-256");
}

TEST(Rsn, TruncatedElementRaisesRatherThanInventingDefaults) {
  // Silently defaulting a cut-off element would fabricate a finding.
  EXPECT_THROW(parse_rsn_element(Bytes{0x01}), RSNParseError);
  const Bytes body = build_rsn_element({.pairwise_ciphers = {4, 4}});
  // Promises two ciphers, supplies part of one.
  EXPECT_THROW(parse_rsn_element(ByteView(body).first(10)), RSNParseError);
}

TEST(Rsn, PartialElementStopsCleanlyAtAFieldBoundary) {
  // An element that simply ends early is legal: later fields are optional.
  const Bytes body = build_rsn_element({.akm_suites = {2}});
  const RSNInfo info = parse_rsn_element(ByteView(body).first(6));
  EXPECT_EQ(info.group_cipher, "CCMP-128");
  EXPECT_TRUE(info.pairwise_ciphers.empty());
  EXPECT_FALSE(info.mfp_capable);
}

TEST(Rsn, UnknownSuiteTypesAreReportedNotDropped) {
  const RSNInfo info = parse_rsn_element(build_rsn_element({.akm_suites = {99}}));
  EXPECT_EQ(info.akm_suites, Strings{"unknown-99"});
  EXPECT_EQ(info.generation(), "unknown");
}

TEST(Rsn, VendorSuiteSelectorsAreLabelledWithTheirOui) {
  Bytes body = build_rsn_element({.akm_suites = {2}});
  // Rewrite the AKM suite's OUI (bytes 14..16) to a vendor's.
  body[14] = 0x00;
  body[15] = 0x11;
  body[16] = 0x22;
  EXPECT_EQ(parse_rsn_element(body).akm_suites, Strings{"vendor-001122-2"});
}

TEST(Rsn, Wpa1VendorElement) {
  // Microsoft OUI, type 1, version 1, TKIP group and pairwise, PSK AKM.
  const Bytes body = from_hex("0050f201 0100 0050f202 0100 0050f202 0100 0050f202");
  const std::optional<RSNInfo> info = parse_wpa1_element(body);
  ASSERT_TRUE(info.has_value());
  EXPECT_TRUE(info->is_wpa1);
  EXPECT_EQ(info->generation(), "WPA1-Personal (PSK)");
  EXPECT_TRUE(any_weakness(*info, "WPA1"));
}

TEST(Rsn, NonWpaVendorElementIsIgnored) {
  // Most vendor elements are not WPA1 and must not be misread as security.
  EXPECT_FALSE(parse_wpa1_element(from_hex("0050f2020101")).has_value());  // WMM
  EXPECT_FALSE(parse_wpa1_element(from_hex("001122010100")).has_value());
  EXPECT_FALSE(parse_wpa1_element(Bytes{0x00}).has_value());
}
