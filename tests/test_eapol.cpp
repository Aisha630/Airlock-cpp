// EAPOL-Key parsing, message identification, and handshake tracking.
#include <gtest/gtest.h>

#include <algorithm>
#include <string>

#include "support.hpp"
#include "wifi/eapol.hpp"

using namespace airlock;
using namespace airlock::wifi;
using airlock::testing::contains;

namespace {

const std::string AP = "02:00:00:aa:00:01";
const std::string STA = "02:00:00:11:11:11";

constexpr std::uint16_t M1 = KEY_INFO_PAIRWISE | KEY_INFO_ACK;
constexpr std::uint16_t M2 = KEY_INFO_PAIRWISE | KEY_INFO_MIC;
constexpr std::uint16_t M3 = KEY_INFO_PAIRWISE | KEY_INFO_ACK | KEY_INFO_MIC | KEY_INFO_SECURE |
                             KEY_INFO_INSTALL | KEY_INFO_ENCRYPTED;
constexpr std::uint16_t M4 = KEY_INFO_PAIRWISE | KEY_INFO_MIC | KEY_INFO_SECURE;

Bytes build(std::uint16_t key_info, std::uint64_t replay_counter = 1,
            const Bytes& nonce = repeat(0xa1, 32), const Bytes& key_data = {}) {
  Bytes body = {2};
  put_be16(body, key_info);
  put_be16(body, 16);
  put_be64(body, replay_counter);
  append(body, nonce);
  body.insert(body.end(), 32, 0);   // key IV, RSC, reserved
  body.insert(body.end(), 16, 0x0f);  // MIC
  put_be16(body, static_cast<std::uint16_t>(key_data.size()));
  append(body, key_data);
  Bytes out = {2, 3};
  put_be16(out, static_cast<std::uint16_t>(body.size()));
  append(out, body);
  return out;
}

Bytes pmkid_key_data(const Bytes& pmkid) {
  Bytes kde = concat({Bytes{0x00, 0x0f, 0xac, 0x04}, pmkid});
  Bytes out = {221, static_cast<std::uint8_t>(kde.size())};
  append(out, kde);
  return out;
}

bool any_note(const Handshake& handshake, const std::string& fragment) {
  const auto notes = handshake.notes();
  return std::any_of(notes.begin(), notes.end(),
                     [&](const std::string& n) { return contains(n, fragment); });
}

class MessageNumber : public ::testing::TestWithParam<std::pair<std::uint16_t, int>> {};

TEST_P(MessageNumber, IsIdentifiedFromTheFlagBits) {
  EXPECT_EQ(parse_eapol_key(build(GetParam().first)).message_number(), GetParam().second);
}

INSTANTIATE_TEST_SUITE_P(Messages, MessageNumber,
                         ::testing::Values(std::pair{M1, 1}, std::pair{M2, 2}, std::pair{M3, 3},
                                           std::pair{M4, 4}),
                         [](const auto& info) { return "M" + std::to_string(info.param.second); });

}  // namespace

TEST(Eapol, MessageTwoAndFourAreToldApartByTheSecureBit) {
  // The only structural difference between M2 and M4.
  EXPECT_EQ(parse_eapol_key(build(M2)).message_number(), 2);
  EXPECT_EQ(parse_eapol_key(build(M2 | KEY_INFO_SECURE)).message_number(), 4);
}

TEST(Eapol, GroupKeyHandshakeIsNotMistakenForTheFourWay) {
  // Without the Pairwise bit this is a group rekey, not a four-way message.
  const EapolKeyFrame group = parse_eapol_key(build(KEY_INFO_ACK | KEY_INFO_MIC));
  EXPECT_FALSE(group.pairwise());
  EXPECT_FALSE(group.message_number().has_value());
}

TEST(Eapol, FlagAccessors) {
  const EapolKeyFrame frame = parse_eapol_key(build(M3));
  EXPECT_TRUE(frame.pairwise() && frame.ack() && frame.has_mic());
  EXPECT_TRUE(frame.secure() && frame.install() && frame.encrypted_key_data());
}

TEST(Eapol, FieldsAreReadFromTheRightOffsets) {
  const EapolKeyFrame frame = parse_eapol_key(build(M1, 42, repeat(0xbb, 32)));
  EXPECT_EQ(frame.descriptor_type, 2);
  EXPECT_EQ(frame.replay_counter, 42u);
  EXPECT_EQ(frame.nonce, repeat(0xbb, 32));
  EXPECT_EQ(frame.key_mic, repeat(0x0f, 16));
  EXPECT_EQ(frame.key_length, 16);
}

TEST(Eapol, MessageFourCarriesAZeroNonce) {
  EXPECT_TRUE(parse_eapol_key(build(M4, 1, repeat(0x00, 32))).nonce_is_zero());
}

TEST(Eapol, PmkidIsExtractedFromMessageOne) {
  const Bytes pmkid = from_hex("0123456789abcdef0123456789abcdef");
  EXPECT_EQ(parse_eapol_key(build(M1, 1, repeat(0xa1, 32), pmkid_key_data(pmkid))).pmkid(), pmkid);
}

TEST(Eapol, NoPmkidWhenAbsentOrNotMessageOne) {
  EXPECT_FALSE(parse_eapol_key(build(M1)).pmkid().has_value());
  EXPECT_FALSE(
      parse_eapol_key(build(M2, 1, repeat(0xa1, 32), Bytes{0x30, 0x02, 0x01, 0x00})).pmkid());
}

namespace {

class TruncatedFrame : public ::testing::TestWithParam<Bytes> {};

TEST_P(TruncatedFrame, IsRefused) { EXPECT_THROW(parse_eapol_key(GetParam()), EapolParseError); }

INSTANTIATE_TEST_SUITE_P(Payloads, TruncatedFrame,
                         ::testing::Values(Bytes{}, Bytes{0x02, 0x03},
                                           concat({Bytes{0x02, 0x03, 0x00, 0x10}, repeat(0, 10)})));

}  // namespace

TEST(Eapol, NonKeyEapolPacketsAreRefused) {
  EXPECT_THROW_WITH(parse_eapol_key(Bytes{2, 1, 0, 0}), EapolParseError, "not Key");  // Start
}

TEST(Eapol, LyingKeyDataLengthIsRefused) {
  Bytes body = {2};
  put_be16(body, M1);
  put_be16(body, 16);
  put_be64(body, 1);
  append(body, repeat(0xa1, 32));
  body.insert(body.end(), 48, 0);
  put_be16(body, 200);  // claims 200
  Bytes payload = {2, 3};
  put_be16(payload, static_cast<std::uint16_t>(body.size()));
  append(payload, body);
  EXPECT_THROW_WITH(parse_eapol_key(payload), EapolParseError, "data field truncated");
}

namespace {

void run_handshake(HandshakeTracker& tracker, double base_time = 0.0, std::uint64_t counter = 1,
                   const Bytes& key_data = {}) {
  const std::tuple<std::uint16_t, std::string, std::string> steps[] = {
      {M1, AP, STA}, {M2, STA, AP}, {M3, AP, STA}, {M4, STA, AP}};
  for (std::size_t index = 0; index < 4; ++index) {
    const auto& [key_info, transmitter, receiver] = steps[index];
    const EapolKeyFrame frame = parse_eapol_key(build(key_info, counter + (index >= 2),
                                                      repeat(0xa1, 32),
                                                      index == 0 ? key_data : Bytes{}));
    tracker.observe(frame, transmitter, receiver, base_time + static_cast<double>(index) * 0.01,
                    index);
  }
}

}  // namespace

TEST(Eapol, TrackerAssemblesACompleteHandshake) {
  HandshakeTracker tracker;
  run_handshake(tracker);
  ASSERT_EQ(tracker.all().size(), 1u);
  const Handshake& handshake = tracker.all()[0];
  EXPECT_TRUE(handshake.complete());
  EXPECT_EQ(handshake.observed(), (std::vector<int>{1, 2, 3, 4}));
  EXPECT_EQ(handshake.ap, AP);
  EXPECT_EQ(handshake.station, STA);
  EXPECT_NEAR(*handshake.duration_ms(), 30.0, 0.1);
}

TEST(Eapol, TrackerInfersRolesFromDirection) {
  // Messages 1 and 3 carry Ack, so their transmitter is the authenticator.
  HandshakeTracker tracker;
  run_handshake(tracker);
  EXPECT_EQ(tracker.all()[0].ap, AP);
}

TEST(Eapol, TrackerKeepsSuccessiveHandshakesSeparate) {
  // A rekey must not overwrite the earlier handshake, PMKID included.
  const Bytes pmkid = from_hex("aabbccddeeff00112233445566778899");
  HandshakeTracker tracker;
  run_handshake(tracker, 0.0, 1, pmkid_key_data(pmkid));
  run_handshake(tracker, 5.0, 9);
  ASSERT_EQ(tracker.all().size(), 2u);
  EXPECT_TRUE(tracker.all()[0].complete() && tracker.all()[1].complete());
  EXPECT_EQ(tracker.all()[0].pmkid, pmkid);
  EXPECT_FALSE(tracker.all()[1].pmkid.has_value());
}

TEST(Eapol, IncompleteHandshakeIsReportedAsSuch) {
  HandshakeTracker tracker;
  tracker.observe(parse_eapol_key(build(M1)), AP, STA, 0.0, 0);
  tracker.observe(parse_eapol_key(build(M2)), STA, AP, 0.01, 1);
  const Handshake& handshake = tracker.all()[0];
  EXPECT_FALSE(handshake.complete());
  EXPECT_FALSE(handshake.duration_ms().has_value());
  EXPECT_TRUE(any_note(handshake, "incomplete: saw messages [1, 2], missing [3, 4]"));
}

TEST(Eapol, OutOfOrderReplayCountersAreNoted) {
  HandshakeTracker tracker;
  const std::tuple<std::uint16_t, std::string, std::string, std::uint64_t> steps[] = {
      {M1, AP, STA, 5}, {M2, STA, AP, 5}, {M3, AP, STA, 2}, {M4, STA, AP, 2}};
  std::size_t index = 0;
  for (const auto& [key_info, transmitter, receiver, counter] : steps) {
    tracker.observe(parse_eapol_key(build(key_info, counter)), transmitter, receiver,
                    static_cast<double>(index) * 0.01, index);
    ++index;
  }
  EXPECT_TRUE(any_note(tracker.all()[0], "out of order"));
}
