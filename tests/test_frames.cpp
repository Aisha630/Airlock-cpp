// Frame type/subtype classification tables.
#include <gtest/gtest.h>

#include <set>
#include <string>
#include <tuple>

#include "support.hpp"
#include "wifi/frames.hpp"

using namespace airlock::wifi;
using airlock::testing::contains;

namespace {

class KnownSubtype : public ::testing::TestWithParam<std::tuple<int, int, std::string>> {};

TEST_P(KnownSubtype, IsNamed) {
  const auto& [frame_type, subtype, expected] = GetParam();
  EXPECT_EQ(subtype_name(frame_type, subtype), expected);
}

INSTANTIATE_TEST_SUITE_P(
    Table, KnownSubtype,
    ::testing::Values(std::tuple{TYPE_MANAGEMENT, 8, "beacon"},
                      std::tuple{TYPE_MANAGEMENT, 4, "probe-request"},
                      std::tuple{TYPE_MANAGEMENT, 5, "probe-response"},
                      std::tuple{TYPE_MANAGEMENT, 11, "authentication"},
                      std::tuple{TYPE_MANAGEMENT, 12, "deauthentication"},
                      std::tuple{TYPE_MANAGEMENT, 10, "disassociation"},
                      std::tuple{TYPE_MANAGEMENT, 0, "assoc-request"},
                      std::tuple{TYPE_CONTROL, 13, "ack"}, std::tuple{TYPE_CONTROL, 11, "rts"},
                      std::tuple{TYPE_CONTROL, 12, "cts"},
                      std::tuple{TYPE_CONTROL, 9, "block-ack"}, std::tuple{TYPE_DATA, 0, "data"},
                      std::tuple{TYPE_DATA, 8, "qos-data"}, std::tuple{TYPE_DATA, 4, "null"}),
    [](const auto& info) {
      std::string name = std::get<2>(info.param);
      for (char& c : name) {
        if (c == '-') c = '_';
      }
      return name;
    });

FrameInfo frame(int frame_type, int subtype) {
  FrameInfo f;
  f.frame_type = frame_type;
  f.subtype = subtype;
  f.type_name = type_name(frame_type);
  f.subtype_name = subtype_name(frame_type, subtype);
  return f;
}

}  // namespace

TEST(Frames, SubtypeNumbersDoNotCollideAcrossTypes) {
  // Subtype 13 is an ACK in control and an Action frame in management.
  EXPECT_EQ(subtype_name(TYPE_CONTROL, 13), "ack");
  EXPECT_EQ(subtype_name(TYPE_MANAGEMENT, 13), "action");
}

TEST(Frames, UnknownSubtypeIsLabelledNotDropped) {
  EXPECT_EQ(subtype_name(TYPE_MANAGEMENT, 7), "subtype-7");
  EXPECT_EQ(subtype_name(99, 1), "subtype-1");
}

TEST(Frames, TypeNamesCoverAllFourTypes) {
  std::set<int> keys;
  for (const auto& [key, unused] : type_names()) keys.insert(key);
  EXPECT_EQ(keys, (std::set<int>{0, 1, 2, 3}));
}

TEST(Frames, FramePredicatesAreMutuallyExclusive) {
  for (int frame_type : {TYPE_MANAGEMENT, TYPE_CONTROL, TYPE_DATA}) {
    const FrameInfo f = frame(frame_type, 0);
    EXPECT_EQ(int(f.is_management()) + int(f.is_control()) + int(f.is_data()), 1);
  }
}

TEST(Frames, AddressesUseReceiverTransmitterNaming) {
  // addr1 always receives and addr2 always transmits, whatever the DS bits.
  FrameInfo f = frame(TYPE_DATA, 8);
  f.addr1 = "aa:aa:aa:aa:aa:aa";
  f.addr2 = "bb:bb:bb:bb:bb:bb";
  EXPECT_EQ(f.receiver(), "aa:aa:aa:aa:aa:aa");
  EXPECT_EQ(f.transmitter(), "bb:bb:bb:bb:bb:bb");
}

TEST(Frames, DescribeIncludesTheDecodedReasonCode) {
  FrameInfo f = frame(TYPE_MANAGEMENT, 12);
  f.reason_code = 7;
  const std::string description = f.describe();
  EXPECT_TRUE(contains(description, "deauthentication"));
  EXPECT_TRUE(contains(description, reason_codes().at(7)));
}
