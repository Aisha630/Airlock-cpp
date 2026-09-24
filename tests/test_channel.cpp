// The record layer: integrity, ordering, direction, and framing.
#include <gtest/gtest.h>

#include <string>
#include <utility>

#include "akex/channel.hpp"
#include "akex/protocol.hpp"
#include "support.hpp"

using namespace airlock;
using namespace airlock::akex;

namespace {

const Bytes PSK = to_bytes("record layer test key");

std::pair<AuthenticatedChannel, AuthenticatedChannel> pair_up() {
  auto [initiator_keys, responder_keys] = run_handshake(PSK);
  return {AuthenticatedChannel::for_initiator(initiator_keys),
          AuthenticatedChannel::for_responder(responder_keys)};
}

}  // namespace

TEST(Channel, RoundTrip) {
  auto [sender, receiver] = pair_up();
  for (const Bytes& payload : {Bytes{}, to_bytes("short"), repeat('x', 4096)}) {
    EXPECT_EQ(receiver.open_record(sender.seal(payload)), payload);
  }
}

TEST(Channel, BothDirectionsWorkIndependently) {
  auto [initiator, responder] = pair_up();
  EXPECT_EQ(responder.open_record(initiator.seal(to_bytes("ping"))), to_bytes("ping"));
  EXPECT_EQ(initiator.open_record(responder.seal(to_bytes("pong"))), to_bytes("pong"));
}

namespace {

class BitFlip : public ::testing::TestWithParam<int> {};

TEST_P(BitFlip, IsDetected) {
  // Header, payload and tag are all covered by the MAC.
  auto [sender, receiver] = pair_up();
  Bytes record = sender.seal(to_bytes("an important instruction"));
  const int offset = GetParam();
  record[offset >= 0 ? static_cast<std::size_t>(offset) : record.size() - 1] ^= 0x01;
  EXPECT_THROW(receiver.open_record(record), RecordError);
}

INSTANTIATE_TEST_SUITE_P(Offsets, BitFlip, ::testing::Values(0, 8, 12, 15, -1),
                         [](const auto& info) {
                           return info.param < 0 ? std::string("last")
                                                 : "offset_" + std::to_string(info.param);
                         });

}  // namespace

TEST(Channel, ReplayIsRejected) {
  auto [sender, receiver] = pair_up();
  const Bytes record = sender.seal(to_bytes("unlock"));
  EXPECT_EQ(receiver.open_record(record), to_bytes("unlock"));
  EXPECT_THROW_WITH(receiver.open_record(record), RecordError, "replay");
}

TEST(Channel, ReorderingIsRejected) {
  // Records must arrive in order; an out-of-order valid record is refused.
  auto [sender, receiver] = pair_up();
  const Bytes first = sender.seal(to_bytes("one"));
  const Bytes second = sender.seal(to_bytes("two"));
  EXPECT_EQ(receiver.open_record(second), to_bytes("two"));
  EXPECT_THROW_WITH(receiver.open_record(first), RecordError, "replay or reorder");
}

TEST(Channel, ReflectionIsRejected) {
  // A record sent by A must not verify when replayed back at A.
  auto [initiator, responder] = pair_up();
  const Bytes record = initiator.seal(to_bytes("bounce"));
  EXPECT_THROW_WITH(initiator.open_record(record), RecordError, "MAC verification failed");
}

TEST(Channel, RecordsFromADifferentSessionAreRejected) {
  auto [sender, unused1] = pair_up();
  auto [unused2, other_receiver] = pair_up();
  EXPECT_THROW_WITH(other_receiver.open_record(sender.seal(to_bytes("cross-session"))),
                    RecordError, "MAC verification failed");
}

TEST(Channel, TruncatedRecordIsRejected) {
  auto [sender, receiver] = pair_up();
  const Bytes record = sender.seal(to_bytes("payload here"));
  EXPECT_THROW(receiver.open_record(Bytes(record.begin(), record.end() - 1)), RecordError);
  EXPECT_THROW_WITH(receiver.open_record(Bytes(record.begin(), record.begin() + 8)), RecordError,
                    "truncated");
}

TEST(Channel, DeclaredLengthMustMatchTheActualPayload) {
  // A lying length field must not let an attacker reshape the record.
  auto [sender, receiver] = pair_up();
  Bytes record = sender.seal(to_bytes("0123456789"));
  record[8] = 0;
  record[9] = 0;
  record[10] = 0;
  record[11] = 9;  // claim one byte fewer
  EXPECT_THROW(receiver.open_record(record), RecordError);
}

TEST(Channel, SequenceNumbersAdvance) {
  auto [sender, receiver] = pair_up();
  for (std::uint64_t expected = 0; expected < 5; ++expected) {
    EXPECT_EQ(sender.send_seq(), expected);
    receiver.open_record(sender.seal(to_bytes("tick")));
  }
  EXPECT_EQ(receiver.recv_seq(), 5u);
}
