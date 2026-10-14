// Robustness against the things real captures contain and synthetic ones do not.
//
// Radio is a lossy medium: frames arrive truncated, with flipped bits, and
// clipped by the adapter's snap length. A parser that assumes well-formed
// input works on a capture it generated itself and falls over on the first
// real one. Each test here corresponds to a defect found by running the
// analyzer against a real monitor-mode capture.
#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <tuple>

#include "support.hpp"
#include "wifi/anomalies.hpp"
#include "wifi/build.hpp"
#include "wifi/capture.hpp"
#include "wifi/pcap.hpp"
#include "wifi/report.hpp"

using namespace airlock;
using namespace airlock::wifi;
using airlock::testing::contains;
using airlock::testing::TempDir;

namespace {

const Bytes RSN_WPA2 = from_hex("0100000fac040100000fac040100000fac020000");
const char* const GOOD = "02:00:00:aa:00:01";

Bytes beacon(const std::string& bssid, std::optional<std::string> ssid = "RealNet",
             bool with_rsn = true) {
  Bytes out = concat({build::radiotap_empty(),
                      build::dot11(0, 8, 0, "ff:ff:ff:ff:ff:ff", bssid, bssid),
                      build::beacon_body(100, 0x0011)});
  if (ssid) append(out, build::element(0, to_bytes(*ssid)));
  if (with_rsn) append(out, build::element(48, RSN_WPA2));
  return out;
}

Capture write_and_load(const TempDir& dir, const std::vector<Bytes>& frames) {
  std::vector<PcapRecord> records;
  for (std::size_t i = 0; i < frames.size(); ++i) {
    records.push_back({1'700'000'000.0 + static_cast<double>(i) * 0.1,
                       LINKTYPE_IEEE802_11_RADIOTAP, frames[i]});
  }
  const std::string path = dir.file("capture.pcap");
  write_pcap(path, records);
  return load_capture(path);
}

std::vector<Finding> analyze(const Capture& capture) {
  return run_all_detectors(capture, track_handshakes(capture).all());
}

const Finding* titled(const std::vector<Finding>& findings, const std::string& fragment) {
  for (const Finding& f : findings) {
    if (contains(f.title, fragment)) return &f;
  }
  return nullptr;
}

std::string joined(const std::vector<std::string>& parts) {
  std::string out;
  for (const std::string& p : parts) out += p + " ";
  return out;
}

// --- structural transmitter validation -------------------------------------

class TransmitterValidity
    : public ::testing::TestWithParam<std::tuple<std::optional<std::string>, bool>> {};

TEST_P(TransmitterValidity, FollowsTheIndividualGroupBit) {
  // A transmitter address must be an individual address, per IEEE 802.11.
  FrameInfo frame;
  frame.addr2 = std::get<0>(GetParam());
  EXPECT_EQ(frame.transmitter_is_valid(), std::get<1>(GetParam()));
}

INSTANTIATE_TEST_SUITE_P(
    Addresses, TransmitterValidity,
    ::testing::Values(
        std::tuple{std::optional<std::string>("02:00:00:aa:00:01"), true},  // locally administered
        std::tuple{std::optional<std::string>("bc:07:1d:7b:88:c7"), true},  // manufacturer
        std::tuple{std::optional<std::string>("01:00:5e:00:00:01"), false},  // group bit set
        std::tuple{std::optional<std::string>("1f:8a:d7:84:a3:df"), false},  // seen in a real capture
        std::tuple{std::optional<std::string>("ff:ff:ff:ff:ff:ff"), false},  // broadcast
        std::tuple{std::optional<std::string>(), true}));                   // ACK and CTS

}  // namespace

TEST(Robustness, MalformedAddressStringIsNotValid) {
  FrameInfo frame;
  frame.addr2 = "not-a-mac";
  EXPECT_FALSE(frame.transmitter_is_valid());
}

TEST(Robustness, HandshakeRiskRequiresPskOnlyCapabilities) {
  Handshake handshake;
  handshake.ap = GOOD;
  handshake.station = "02:00:00:aa:00:02";
  handshake.pmkid = Bytes(16, 0x42);
  handshake.messages = {{1, 1.0}, {2, 1.1}, {3, 1.2}, {4, 1.3}};
  handshake.replay_counters = {{1, 1}, {2, 1}, {3, 2}, {4, 2}};
  for (const std::vector<std::string>& akms :
       {std::vector<std::string>{"SAE"}, {"FT-SAE"}, {"802.1X"}, {"OWE"},
        {"SAE", "PSK"}, {"PSK", "unknown-99"}, {}}) {
    Capture capture("test");
    auto& network = capture.network_for(GOOD);
    network.rsn = RSNInfo{};
    network.rsn->akm_suites = akms;
    const auto findings = detect_handshake_exposure(capture, {handshake});
    ASSERT_EQ(findings.size(), 1u);
    EXPECT_EQ(findings[0].severity, "info");
  }
  Capture unknown("test");
  EXPECT_EQ(detect_handshake_exposure(unknown, {handshake})[0].severity, "info");
  for (const std::string& akm : {"PSK", "PSK-SHA256"}) {
    Capture capture("test");
    auto& network = capture.network_for(GOOD);
    network.rsn = RSNInfo{};
    network.rsn->akm_suites = {akm};
    const auto findings = detect_handshake_exposure(capture, {handshake});
    ASSERT_EQ(findings.size(), 2u);
    EXPECT_EQ(findings[0].severity, "high");
    EXPECT_EQ(findings[1].severity, "medium");
  }
  const auto notes = handshake.notes();
  EXPECT_TRUE(contains(joined(notes), "depends on the authentication method"));
  EXPECT_FALSE(contains(joined(notes), "this single frame is enough"));
}

namespace {
Capture association_scenario(int attempts, std::uint16_t response_status = 0, bool disconnect = true,
                             double delay = 0.1, bool protected_disconnect = false,
                             std::string disconnect_station = "02:00:00:aa:00:02") {
  constexpr const char* station = "02:00:00:aa:00:02";
  RsnSpec spec;
  spec.akm_suites = {8};
  spec.mfp_capable = spec.mfp_required = true;
  Bytes b = concat({build::radiotap_empty(), build::dot11(0, 8, 0, "ff:ff:ff:ff:ff:ff", GOOD, GOOD),
                    build::beacon_body(100, 0x0011), build::element(0, to_bytes("SAE")),
                    build::element(48, build_rsn_element(spec))});
  std::vector<PcapRecord> records{{0.0, LINKTYPE_IEEE802_11_RADIOTAP, b},
                                 {0.1, LINKTYPE_IEEE802_11_RADIOTAP, b}};
  for (int i = 0; i < attempts; ++i) {
    const double start = 1.0 + i * 7.0;
    auto add = [&](double time, int subtype, std::uint8_t flags, const std::string& rx,
                   const std::string& tx, const Bytes& body) {
      records.push_back({time, LINKTYPE_IEEE802_11_RADIOTAP,
                        concat({build::radiotap_empty(), build::dot11(0, subtype, flags, rx, tx, GOOD), body})});
    };
    add(start, 0, 0, GOOD, station, build::assoc_request_body(0x0011, 10));
    if (disconnect) add(start + delay, 12, protected_disconnect ? build::FC_PROTECTED : 0,
                        disconnect_station, GOOD, build::reason_body(6));
    add(start + delay + 0.1, 1, 0, station, GOOD, build::assoc_response_body(0x0011, response_status, 1));
  }
  return load_records("test", records);
}
}  // namespace

TEST(Robustness, RepeatedConflictingAssociationResponsesAreFlagged) {
  const auto findings = detect_association_disruption(association_scenario(2));
  ASSERT_EQ(findings.size(), 1u);
  EXPECT_EQ(findings[0].severity, "medium");
  EXPECT_TRUE(contains(findings[0].detail, "2 connection attempts"));
  const auto deauth = detect_unprotected_deauth(association_scenario(2));
  ASSERT_EQ(deauth.size(), 1u);
  EXPECT_FALSE(contains(deauth[0].detail, "ineffective"));
  EXPECT_TRUE(contains(deauth[0].detail, "before key installation"));
}

TEST(Robustness, BenignAssociationAndDisconnectCasesDoNotImplySpoofing) {
  EXPECT_TRUE(detect_association_disruption(association_scenario(2, 0, false)).empty());
  EXPECT_TRUE(detect_association_disruption(association_scenario(2, 1)).empty());
  EXPECT_TRUE(detect_association_disruption(association_scenario(1)).empty());
  EXPECT_TRUE(detect_association_disruption(association_scenario(2, 0, true, 2.0)).empty());
  EXPECT_TRUE(detect_association_disruption(association_scenario(2, 0, true, 0.1, true)).empty());
  EXPECT_TRUE(detect_association_disruption(
      association_scenario(2, 0, true, 0.1, false, "02:00:00:aa:00:03")).empty());
}

TEST(Robustness, CorruptBeaconDoesNotInventANetwork) {
  // The defect a real capture exposed: garbled beacons became "networks".
  //
  // A beacon whose transmitter address has the group bit set was corrupted
  // in flight. Before this check, each one was reported as a brand new open
  // access point with a garbage SSID: 19 such findings in a two-minute
  // capture, all of them noise.
  TempDir dir;
  std::vector<Bytes> frames(4, beacon(GOOD));
  frames.insert(frames.end(), 2, beacon("1f:8a:d7:84:a3:df", "garbled"));
  const Capture capture = write_and_load(dir, frames);

  EXPECT_EQ(capture.suspect_frames, 2);
  ASSERT_EQ(capture.networks().size(), 1u);
  EXPECT_EQ(capture.networks()[0].bssid, GOOD);
  // The frames are still counted: they were genuinely received.
  EXPECT_EQ(capture.frames.size(), 6u);
}

TEST(Robustness, SuspectFramesAreCountedNotSilentlyDropped) {
  TempDir dir;
  std::vector<Bytes> frames(3, beacon(GOOD));
  frames.insert(frames.end(), 3, beacon("03:00:00:bb:00:02"));
  const auto findings = analyze(write_and_load(dir, frames));
  const Finding* excluded = titled(findings, "Low-confidence");
  ASSERT_NE(excluded, nullptr) << "exclusions must be reported, not hidden";
  EXPECT_TRUE(contains(joined(excluded->evidence), "structurally invalid"));
}

// --- malformed information elements ----------------------------------------

TEST(Robustness, TruncatedInformationElementDoesNotAbortTheCapture) {
  // A beacon with an element whose length byte overruns the frame. One such
  // beacon killed an entire run before parsing was bounded per frame.
  TempDir dir;
  const Bytes broken = concat(
      {build::radiotap_empty(),
       build::dot11(0, 8, 0, "ff:ff:ff:ff:ff:ff", "02:00:00:cc:00:03", "02:00:00:cc:00:03"),
       build::beacon_body(100, 0x0011),
       Bytes{0, 200, 0x41, 0x42, 0x43}});  // SSID promises 200 bytes, supplies three
  const Capture capture = write_and_load(dir, {beacon(GOOD), broken, beacon(GOOD), beacon(GOOD)});
  EXPECT_EQ(capture.frames.size(), 4u);
  // The well-formed network survives the bad frame in the middle.
  EXPECT_NE(capture.find_network(GOOD), nullptr);
  // The truncated element yields the bytes that are actually there.
  EXPECT_EQ(capture.find_network("02:00:00:cc:00:03")->ssid, "ABC");
}

TEST(Robustness, MalformedRsnElementIsRecordedAsAParseError) {
  // A cut-off RSN element must be reported, not silently read as "open".
  TempDir dir;
  Bytes bad = concat({build::radiotap_empty(),
                      build::dot11(0, 8, 0, "ff:ff:ff:ff:ff:ff", GOOD, GOOD),
                      build::beacon_body(100, 0x0011), build::element(0, to_bytes("BadRSN")),
                      build::element(48, from_hex("0100000fac040200000fac04"))});
  const Capture capture = write_and_load(dir, {bad, bad});
  ASSERT_EQ(capture.parse_errors.size(), 2u);
  EXPECT_TRUE(contains(capture.parse_errors[0], "bad RSN element: pairwise cipher list truncated"));
}

TEST(Robustness, NonUtf8SsidIsDecodedWithoutRaising) {
  // SSIDs are arbitrary bytes, not text.
  TempDir dir;
  const std::string raw = "\xff\xfe\x80 binary";
  const Capture capture = write_and_load(dir, {beacon(GOOD, raw, false), beacon(GOOD, raw, false)});
  EXPECT_EQ(capture.find_network(GOOD)->ssid, "\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD binary");
}

TEST(Robustness, NonAsciiSsidIsEscapedInJson) {
  TempDir dir;
  const Capture capture = write_and_load(dir, {beacon(GOOD, "caf\xc3\xa9 \xf0\x9f\x93\xa1")});
  const std::string json = build_json(capture, track_handshakes(capture), {});
  EXPECT_TRUE(contains(json, "\"ssid\": \"caf\\u00e9 \\ud83d\\udce1\""));
}

TEST(Robustness, EmptyCaptureIsHandled) {
  TempDir dir;
  const Capture capture = write_and_load(dir, {});
  EXPECT_TRUE(capture.frames.empty());
  EXPECT_EQ(capture.duration(), 0.0);
  EXPECT_TRUE(run_all_detectors(capture, {}).empty());
  EXPECT_TRUE(contains(render_report(capture, HandshakeTracker{}, {}),
                       "no 802.11 frames in this capture"));
}

TEST(Robustness, FramesTooShortForAnyHeaderAreSkipped) {
  TempDir dir;
  const Capture capture =
      write_and_load(dir, {Bytes{0, 0}, build::radiotap_empty(),
                           concat({build::radiotap_empty(), Bytes{0x80}}), beacon(GOOD)});
  EXPECT_EQ(capture.frames.size(), 1u);
  EXPECT_TRUE(capture.parse_errors.empty());
}

TEST(Robustness, TruncatedManagementBodiesAreNotRead) {
  // A deauth with no reason field, an auth frame cut short: the header is
  // counted and classified, the missing fields are simply absent.
  TempDir dir;
  const Capture capture = write_and_load(
      dir, {concat({build::radiotap_empty(), build::dot11(0, 12, 0, GOOD, GOOD, GOOD), Bytes{7}}),
            concat({build::radiotap_empty(), build::dot11(0, 11, 0, GOOD, GOOD, GOOD), Bytes{0, 0}}),
            concat({build::radiotap_empty(), build::dot11(0, 8, 0, GOOD, GOOD, GOOD), Bytes(5, 0)})});
  ASSERT_EQ(capture.frames.size(), 3u);
  EXPECT_FALSE(capture.frames[0].reason_code.has_value());
  EXPECT_FALSE(capture.frames[1].auth_algorithm.has_value());
  EXPECT_TRUE(capture.networks().empty());
}

TEST(Robustness, ProtectedManagementFramesAreNotParsedAsPlaintext) {
  TempDir dir;
  const Capture capture = write_and_load(
      dir, {concat({build::radiotap_empty(),
                    build::dot11(0, 12, build::FC_PROTECTED, GOOD, GOOD, GOOD), Bytes(20, 7)})});
  ASSERT_EQ(capture.frames.size(), 1u);
  EXPECT_TRUE(capture.frames[0].is_protected);
  EXPECT_FALSE(capture.frames[0].reason_code.has_value());
}

// --- evidence threshold ------------------------------------------------------

TEST(Robustness, SingleBeaconNetworkIsNotReportedAsAFinding) {
  // One beacon is not evidence of a network; an AP beacons ~10x a second.
  TempDir dir;
  std::vector<Bytes> frames(5, beacon(GOOD));
  frames.push_back(beacon("02:00:00:ff:00:09", "OneOff"));
  const auto findings = analyze(write_and_load(dir, frames));

  std::string reported;
  for (const Finding& f : findings) {
    if (contains(f.title, "Weak")) reported += f.detail + " ";
  }
  EXPECT_TRUE(contains(reported, GOOD));
  EXPECT_FALSE(contains(reported, "02:00:00:ff:00:09"));

  // ...but it is still accounted for.
  const Finding* excluded = titled(findings, "Low-confidence");
  ASSERT_NE(excluded, nullptr);
  EXPECT_TRUE(contains(joined(excluded->evidence), "02:00:00:ff:00:09: 1 beacons, ssid 'OneOff'"));
}

TEST(Robustness, ThresholdIsANamedConstantNotAMagicNumber) {
  EXPECT_GE(MIN_BEACONS_FOR_A_FINDING, 2);
}

TEST(Robustness, MissingSsidIsLabelledRatherThanPrintedAsNone) {
  // A network with no SSID element must not render as the string "None".
  TempDir dir;
  const std::vector<Bytes> frames(3, beacon(GOOD, std::nullopt));
  std::string rendered;
  for (const Finding& f : analyze(write_and_load(dir, frames))) rendered += f.detail + " ";
  EXPECT_FALSE(contains(rendered, "\"None\""));
  EXPECT_TRUE(contains(rendered, "<no SSID element>"));
}
