// Capture file I/O and link-layer details: pcap variants, radiotap, FCS.
#include <gtest/gtest.h>

#include <format>
#include <fstream>

#include "support.hpp"
#include "wifi/build.hpp"
#include "wifi/capture.hpp"
#include "wifi/pcap.hpp"
#include "wifi/text.hpp"

using namespace airlock;
using namespace airlock::wifi;
using airlock::testing::TempDir;

namespace {

const char* const AP = "02:00:00:aa:00:01";

Bytes beacon_frame(const std::string& ssid) {
  return concat({build::dot11(0, 8, 0, "ff:ff:ff:ff:ff:ff", AP, AP), build::beacon_body(100, 0x0011),
                 build::element(0, to_bytes(ssid)), build::element(3, Bytes{11})});
}

void write_file(const std::string& path, const Bytes& bytes) {
  std::ofstream out(path, std::ios::binary);
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

}  // namespace

TEST(Pcap, WriteThenReadRoundTrips) {
  TempDir dir;
  const std::vector<PcapRecord> records = {
      {1'700'000'000.25, LINKTYPE_IEEE802_11_RADIOTAP, Bytes{1, 2, 3}},
      {1'700'000'001.000001, LINKTYPE_IEEE802_11_RADIOTAP, Bytes(300, 9)},
  };
  write_pcap(dir.file("a.pcap"), records);
  PcapReader reader(dir.file("a.pcap"));
  PcapRecord record;
  for (const PcapRecord& expected : records) {
    ASSERT_TRUE(reader.next(record));
    EXPECT_EQ(record.data, expected.data);
    EXPECT_EQ(record.linktype, LINKTYPE_IEEE802_11_RADIOTAP);
    EXPECT_DOUBLE_EQ(record.timestamp, expected.timestamp);
  }
  EXPECT_FALSE(reader.next(record));
}

TEST(Pcap, TimestampsRoundHalfToEvenAtTheMicrosecond) {
  // The writer stores whole microseconds; the reader returns the double
  // nearest the stored decimal value.
  TempDir dir;
  write_pcap(dir.file("t.pcap"), {{1'700'000'000.1024, LINKTYPE_IEEE802_11_RADIOTAP, Bytes{0}}});
  PcapReader reader(dir.file("t.pcap"));
  PcapRecord record;
  ASSERT_TRUE(reader.next(record));
  EXPECT_EQ(std::format("{:.6f}", record.timestamp), "1700000000.102400");
}

TEST(Pcap, BigEndianNanosecondFilesAreRead) {
  TempDir dir;
  Bytes file;
  put_be32(file, 0xa1b23c4d);  // nanosecond magic, big-endian
  put_be16(file, 2);
  put_be16(file, 4);
  put_be32(file, 0);
  put_be32(file, 0);
  put_be32(file, 65535);
  put_be32(file, LINKTYPE_IEEE802_11);
  const Bytes frame = beacon_frame("BigEndian");
  put_be32(file, 1'700'000'000);
  put_be32(file, 123'456'789);
  put_be32(file, static_cast<std::uint32_t>(frame.size()));
  put_be32(file, static_cast<std::uint32_t>(frame.size()));
  append(file, frame);
  write_file(dir.file("be.pcap"), file);

  const Capture capture = load_capture(dir.file("be.pcap"));
  ASSERT_EQ(capture.frames.size(), 1u);
  EXPECT_EQ(std::format("{:.9f}", capture.frames[0].timestamp).substr(0, 17), "1700000000.123456");
  EXPECT_EQ(capture.networks()[0].ssid, "BigEndian");
  EXPECT_FALSE(capture.frames[0].signal_dbm.has_value());  // no radiotap on this link type
}

TEST(Pcap, PcapngEnhancedPacketBlocksAreRead) {
  TempDir dir;
  auto block = [](std::uint32_t type, const Bytes& body) {
    Bytes out;
    const auto length = static_cast<std::uint32_t>(12 + body.size());
    put_le32(out, type);
    put_le32(out, length);
    append(out, body);
    put_le32(out, length);
    return out;
  };
  Bytes shb;
  put_le32(shb, 0x1A2B3C4D);
  put_le16(shb, 1);
  put_le16(shb, 0);
  append(shb, Bytes(8, 0xff));  // section length unknown
  Bytes idb;
  put_le16(idb, static_cast<std::uint16_t>(LINKTYPE_IEEE802_11_RADIOTAP));
  put_le16(idb, 0);
  put_le32(idb, 0);
  put_le16(idb, 9);  // if_tsresol: 10^-3
  put_le16(idb, 1);
  append(idb, Bytes{3, 0, 0, 0});
  put_le32(idb, 0);  // end of options

  Bytes packet = concat({build::radiotap(2462, 0x00a0, -61), beacon_frame("NG")});
  const std::uint64_t ts = 1'700'000'000'500ULL;  // milliseconds
  Bytes epb;
  put_le32(epb, 0);
  put_le32(epb, static_cast<std::uint32_t>(ts >> 32));
  put_le32(epb, static_cast<std::uint32_t>(ts));
  put_le32(epb, static_cast<std::uint32_t>(packet.size()));
  put_le32(epb, static_cast<std::uint32_t>(packet.size()));
  append(epb, packet);
  epb.resize((epb.size() + 3) & ~std::size_t{3}, 0);

  write_file(dir.file("a.pcapng"),
             concat({block(0x0A0D0D0A, shb), block(1, idb), block(6, epb), block(6, epb)}));
  const Capture capture = load_capture(dir.file("a.pcapng"));
  ASSERT_EQ(capture.frames.size(), 2u);
  EXPECT_DOUBLE_EQ(capture.frames[0].timestamp, 1'700'000'000.5);
  EXPECT_EQ(capture.frames[0].signal_dbm, -61);
  EXPECT_EQ(capture.frames[0].channel, 11);
  EXPECT_EQ(capture.networks()[0].ssid, "NG");
}

TEST(Pcap, RadiotapFcsIsStrippedBeforeParsing) {
  // With the FCS flag set, the last four bytes are a checksum, not an
  // element. Left in place they would be read as a bogus trailing element.
  Bytes header = {0, 0, 15, 0};
  put_le32(header, (1u << 1) | (1u << 3) | (1u << 5));
  header.push_back(0x10);  // offset 8: Flags
  header.push_back(0);     // offset 9: alignment padding
  put_le16(header, 2437);  // offset 10: frequency
  put_le16(header, 0x00a0);
  header.push_back(static_cast<std::uint8_t>(-50));  // offset 14: signal

  const Bytes frame = concat({header, beacon_frame("FCSNet"), Bytes{0xde, 0xad, 0xbe, 0xef}});
  const Capture capture =
      load_records("mem", {{1.0, LINKTYPE_IEEE802_11_RADIOTAP, frame},
                           {2.0, LINKTYPE_IEEE802_11_RADIOTAP, frame}});
  ASSERT_EQ(capture.frames.size(), 2u);
  EXPECT_EQ(capture.frames[0].signal_dbm, -50);
  EXPECT_EQ(capture.frames[0].channel, 6);
  EXPECT_EQ(capture.networks()[0].ssid, "FCSNet");
  EXPECT_EQ(capture.networks()[0].channel, 11);
  EXPECT_TRUE(capture.parse_errors.empty());
}

TEST(Pcap, NonCaptureFilesAreRefused) {
  TempDir dir;
  write_file(dir.file("junk.pcap"), to_bytes("this is not a capture file at all"));
  EXPECT_THROW(load_capture(dir.file("junk.pcap")), PcapError);
  EXPECT_THROW(load_capture(dir.file("missing.pcap")), PcapError);
}

TEST(Pcap, OtherLinkTypesAreIgnored) {
  const Capture capture = load_records("mem", {{1.0, 1 /* Ethernet */, Bytes(64, 0)}});
  EXPECT_TRUE(capture.frames.empty());
}

TEST(Text, Utf8DecodingReplacesMaximalInvalidSubparts) {
  EXPECT_EQ(decode_utf8_lossy(to_bytes("plain")), "plain");
  EXPECT_EQ(decode_utf8_lossy(Bytes{0xc3, 0xa9}), "\xc3\xa9");
  // A truncated three-byte sequence is one replacement, not two.
  EXPECT_EQ(decode_utf8_lossy(Bytes{0xe2, 0x82, 'x'}), "\xEF\xBF\xBDx");
  // Overlong encodings and surrogates are invalid byte by byte.
  EXPECT_EQ(decode_utf8_lossy(Bytes{0xc0, 0xaf}), "\xEF\xBF\xBD\xEF\xBF\xBD");
  EXPECT_EQ(decode_utf8_lossy(Bytes{0xed, 0xa0, 0x80}), "\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD");
}

TEST(Text, ShortestFloatMatchesTheConventionalRepr) {
  EXPECT_EQ(shortest_float(3.1), "3.1");
  EXPECT_EQ(shortest_float(21.0), "21.0");
  EXPECT_EQ(shortest_float(0.0), "0.0");
  EXPECT_EQ(shortest_float(0.0001), "0.0001");
  EXPECT_EQ(shortest_float(0.00001), "1e-05");
  EXPECT_EQ(shortest_float(1e16), "1e+16");
  EXPECT_EQ(shortest_float(-2.5), "-2.5");
  EXPECT_EQ(shortest_float(round_to(21.29999999, 3)), "21.3");
}
