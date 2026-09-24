// Wire encoding: canonical, round-tripping, and strict about malformed input.
#include <gtest/gtest.h>

#include <algorithm>
#include <functional>

#include "akex/wire.hpp"
#include "support.hpp"

using namespace airlock;
using namespace airlock::akex;

namespace {

InitMessage sample_init() { return {14, repeat(0x01, 32), repeat(0x02, 256)}; }
ResponseMessage sample_response() {
  return {14, repeat(0x03, 32), repeat(0x04, 256), repeat(0x05, 32)};
}

}  // namespace

TEST(Wire, InitRoundTrip) {
  EXPECT_EQ(InitMessage::decode(sample_init().encode()), sample_init());
}

TEST(Wire, ResponseRoundTrip) {
  EXPECT_EQ(ResponseMessage::decode(sample_response().encode()), sample_response());
}

TEST(Wire, ConfirmRoundTrip) {
  const ConfirmMessage message{repeat(0x06, 32)};
  EXPECT_EQ(ConfirmMessage::decode(message.encode()), message);
}

TEST(Wire, EncodingIsCanonical) {
  // The same message must always encode to the same bytes.
  EXPECT_EQ(sample_init().encode(), sample_init().encode());
}

TEST(Wire, ResponseCoreExcludesTheTag) {
  // A tag cannot cover itself, so the transcript uses the core bytes.
  const Bytes full = sample_response().encode();
  EXPECT_EQ(sample_response().core_bytes(), Bytes(full.begin(), full.end() - 32));
}

TEST(Wire, MessageTypesDoNotCrossDecode) {
  EXPECT_THROW_WITH(ResponseMessage::decode(sample_init().encode()), WireError, "not a response");
}

namespace {

struct Corruption {
  const char* name;
  std::function<Bytes(Bytes)> apply;
  const char* match;
};

class MalformedInit : public ::testing::TestWithParam<Corruption> {};

TEST_P(MalformedInit, IsRefused) {
  const Bytes raw = GetParam().apply(sample_init().encode());
  EXPECT_THROW_WITH(InitMessage::decode(raw), WireError, GetParam().match);
}

INSTANTIATE_TEST_SUITE_P(
    Corruptions, MalformedInit,
    ::testing::Values(
        Corruption{"bad_magic",
                   [](Bytes raw) {
                     std::fill(raw.begin(), raw.begin() + 4, 'X');
                     return raw;
                   },
                   "magic"},
        Corruption{"one_byte_short",
                   [](Bytes raw) {
                     raw.pop_back();
                     return raw;
                   },
                   "length mismatch"},
        Corruption{"one_byte_long",
                   [](Bytes raw) {
                     raw.push_back(0);
                     return raw;
                   },
                   "length mismatch"},
        Corruption{"header_only", [](Bytes raw) { return Bytes(raw.begin(), raw.begin() + 4); },
                   "truncated"}),
    [](const auto& info) { return std::string(info.param.name); });

}  // namespace

TEST(Wire, TranscriptHashIsOrderSensitive) {
  EXPECT_NE(transcript_hash({to_bytes("a"), to_bytes("b")}),
            transcript_hash({to_bytes("b"), to_bytes("a")}));
}

TEST(Wire, TranscriptHashResistsSplicing) {
  // Length prefixes make concatenation unambiguous.
  EXPECT_NE(transcript_hash({to_bytes("ab"), to_bytes("c")}),
            transcript_hash({to_bytes("a"), to_bytes("bc")}));
}

TEST(Wire, TranscriptHashIsDeterministic) {
  EXPECT_EQ(transcript_hash({to_bytes("x"), to_bytes("y")}),
            transcript_hash({to_bytes("x"), to_bytes("y")}));
  EXPECT_EQ(transcript_hash({to_bytes("x")}).size(), 32u);
}
