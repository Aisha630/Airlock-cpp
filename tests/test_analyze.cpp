// End-to-end analysis of the synthetic capture, against known ground truth.
//
// The synth module builds the capture, so exactly what is in it is known. That
// makes these real assertions rather than a smoke test: the expected counts,
// networks, handshakes and findings below are the scenario the generator was
// written to produce, and a regression in any parser shows up as a mismatch.
#include <gtest/gtest.h>

#include <algorithm>
#include <cctype>
#include <format>
#include <map>
#include <memory>
#include <set>
#include <string>

#include "support.hpp"
#include "wifi/anomalies.hpp"
#include "wifi/capture.hpp"
#include "wifi/report.hpp"
#include "wifi/synth.hpp"

using namespace airlock;
using namespace airlock::wifi;
using airlock::testing::contains;

namespace {

class Analysis : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    dir_ = std::make_unique<airlock::testing::TempDir>();
    const std::string path = dir_->file("sample.pcap");
    synth::write_capture(path);
    capture_ = std::make_unique<Capture>(load_capture(path));
    tracker_ = std::make_unique<HandshakeTracker>(track_handshakes(*capture_));
    findings_ = std::make_unique<std::vector<Finding>>(run_all_detectors(*capture_, tracker_->all()));
  }
  static void TearDownTestSuite() {
    findings_.reset();
    tracker_.reset();
    capture_.reset();
    dir_.reset();
  }

  static const Capture& capture() { return *capture_; }
  static const HandshakeTracker& tracker() { return *tracker_; }
  static const std::vector<Finding>& findings() { return *findings_; }
  static const Network& network(const char* bssid) {
    const Network* n = capture_->find_network(bssid);
    if (n == nullptr) throw std::runtime_error(std::string("no network ") + bssid);
    return *n;
  }
  static std::vector<const Finding*> titled(const std::string& fragment) {
    std::vector<const Finding*> out;
    for (const Finding& f : *findings_) {
      std::string lower = f.title;
      for (char& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      if (contains(lower, fragment)) out.push_back(&f);
    }
    return out;
  }

 private:
  static inline std::unique_ptr<airlock::testing::TempDir> dir_;
  static inline std::unique_ptr<Capture> capture_;
  static inline std::unique_ptr<HandshakeTracker> tracker_;
  static inline std::unique_ptr<std::vector<Finding>> findings_;
};

std::string joined(const std::vector<std::string>& parts) {
  std::string out;
  for (const std::string& p : parts) out += p + " ";
  return out;
}

}  // namespace

TEST_F(Analysis, CaptureParsesWithoutErrors) {
  EXPECT_TRUE(capture().parse_errors.empty());
  EXPECT_GT(capture().frames.size(), 100u);
  EXPECT_GT(capture().duration(), 1.0);
}

TEST_F(Analysis, AllThreeFrameClassesArePresent) {
  // The core requirement: management, control and data are told apart.
  std::set<std::string> classes;
  for (const FrameInfo& f : capture().frames) classes.insert(f.type_name);
  for (const char* name : {"management", "control", "data"}) EXPECT_TRUE(classes.count(name));
}

TEST_F(Analysis, FrameCountsMatchTheGeneratedScenario) {
  std::map<std::string, int> by_type;
  for (const FrameInfo& f : capture().frames) by_type[f.type_name] += 1;
  EXPECT_EQ(by_type["management"], 66);
  EXPECT_EQ(by_type["control"], 41);
  EXPECT_EQ(by_type["data"], 32);
  EXPECT_EQ(capture().frames.size(), 139u);
}

TEST_F(Analysis, ExpectedSubtypesAreRecognised) {
  std::set<std::string> subtypes;
  for (const FrameInfo& f : capture().frames) subtypes.insert(f.subtype_name);
  for (const char* name :
       {"beacon", "probe-request", "probe-response", "authentication", "assoc-request",
        "assoc-response", "deauthentication", "ack", "rts", "cts", "block-ack", "data",
        "qos-data"}) {
    EXPECT_TRUE(subtypes.count(name)) << name;
  }
}

TEST_F(Analysis, FourNetworksAreDiscovered) {
  std::set<std::string> bssids;
  for (const Network& n : capture().networks()) bssids.insert(n.bssid);
  EXPECT_EQ(bssids, (std::set<std::string>{synth::AP_WPA2, synth::AP_WPA3, synth::AP_LEGACY,
                                           synth::AP_EVIL_TWIN}));
}

TEST_F(Analysis, SecurityGenerationsAreIdentified) {
  EXPECT_EQ(network(synth::AP_WPA2).security(), "WPA2-Personal (PSK)");
  EXPECT_EQ(network(synth::AP_WPA3).security(), "WPA3-Personal (SAE)");
  EXPECT_EQ(network(synth::AP_EVIL_TWIN).security(), "Open (no RSN element)");
  const auto& pairwise = network(synth::AP_LEGACY).rsn->pairwise_ciphers;
  EXPECT_NE(std::find(pairwise.begin(), pairwise.end(), "TKIP"), pairwise.end());
}

TEST_F(Analysis, MfpStateIsReadPerNetwork) {
  EXPECT_TRUE(network(synth::AP_WPA3).rsn->mfp_required);
  EXPECT_FALSE(network(synth::AP_WPA2).rsn->mfp_capable);
}

TEST_F(Analysis, ChannelsComeFromTheDsParameterElement) {
  EXPECT_EQ(network(synth::AP_WPA2).channel, 6);
  EXPECT_EQ(network(synth::AP_WPA3).channel, 36);
  EXPECT_EQ(network(synth::AP_LEGACY).channel, 11);
}

TEST_F(Analysis, StationsAreAttributedToTheirNetwork) {
  EXPECT_TRUE(network(synth::AP_WPA2).clients.count(synth::STA_ONE));
  EXPECT_TRUE(network(synth::AP_WPA3).clients.count(synth::STA_TWO));
}

TEST_F(Analysis, RadiotapMetadataIsRead) {
  for (const FrameInfo& f : capture().frames) {
    if (f.subtype_name != "beacon") continue;
    ASSERT_TRUE(f.signal_dbm.has_value());
    EXPECT_GT(*f.signal_dbm, -90);
    EXPECT_LT(*f.signal_dbm, 0);
  }
}

TEST_F(Analysis, SaeAuthenticationIsDistinguishedFromOpenSystem) {
  // WPA3 authenticates with Dragonfly; WPA2-PSK's Open System does nothing.
  std::set<std::string> algorithms;
  for (const FrameInfo& f : capture().frames) {
    if (f.subtype_name == "authentication") algorithms.insert(f.auth_algorithm.value_or("?"));
  }
  EXPECT_EQ(algorithms, (std::set<std::string>{"open-system", "SAE"}));
}

TEST_F(Analysis, ProtectedBitIsReadOnDataFrames) {
  // The EAPOL handshake frames precede key installation, so they are not
  // protected. If every data frame looked protected, the bit is being faked.
  bool any_protected = false, any_clear = false;
  for (const FrameInfo& f : capture().frames) {
    if (!f.is_data()) continue;
    (f.is_protected ? any_protected : any_clear) = true;
  }
  EXPECT_TRUE(any_protected);
  EXPECT_TRUE(any_clear);
}

TEST_F(Analysis, BothFourWayHandshakesAreReconstructed) {
  ASSERT_EQ(tracker().all().size(), 2u);
  for (const Handshake& h : tracker().all()) {
    EXPECT_TRUE(h.complete());
    EXPECT_EQ(h.observed(), (std::vector<int>{1, 2, 3, 4}));
    EXPECT_EQ(h.ap, synth::AP_WPA2);
    EXPECT_EQ(h.station, synth::STA_ONE);
    EXPECT_TRUE(h.anonce && h.snonce);
  }
}

TEST_F(Analysis, PmkidIsRecoveredFromTheFirstHandshake) {
  EXPECT_EQ(tracker().all()[0].pmkid, synth::pmkid());
  EXPECT_FALSE(tracker().all()[1].pmkid.has_value());
}

TEST_F(Analysis, DeauthFloodIsDetected) {
  const auto floods = titled("flood");
  ASSERT_FALSE(floods.empty()) << "the deauthentication flood was not detected";
  bool forgeable = false;
  for (const Finding* f : floods) {
    EXPECT_EQ(f->severity, "high");
    forgeable = forgeable || contains(joined(f->evidence), "forgeable");
  }
  EXPECT_TRUE(forgeable);
}

TEST_F(Analysis, EvilTwinIsDetected) {
  const auto twins = titled("evil twin");
  ASSERT_EQ(twins.size(), 1u);
  EXPECT_TRUE(contains(twins[0]->detail, synth::SSID_WPA2));
  EXPECT_TRUE(contains(joined(twins[0]->evidence), synth::AP_EVIL_TWIN));
}

TEST_F(Analysis, MissingMfpIsReported) {
  EXPECT_TRUE(std::any_of(findings().begin(), findings().end(), [](const Finding& f) {
    return contains(f.title, "MFP") || contains(f.detail, "MFP");
  }));
}

TEST_F(Analysis, Wpa3NetworkRaisesNoConfigurationFindings) {
  // The control: a correctly configured network must stay quiet. A detector
  // that flags everything is useless, so the WPA3 AP (SAE, CCMP, MFP
  // required) must produce no weak-configuration finding.
  int configuration = 0;
  for (const Finding& f : findings()) {
    if (!f.title.starts_with("Weak configuration")) continue;
    ++configuration;
    EXPECT_FALSE(contains(f.detail, synth::AP_WPA3));
  }
  EXPECT_GT(configuration, 0);
}

TEST_F(Analysis, EveryFindingIsActionable) {
  for (const Finding& f : findings()) {
    EXPECT_LT(severity_rank(f.severity), 9) << f.severity;
    EXPECT_FALSE(f.detail.empty());
    EXPECT_FALSE(f.title.empty());
    EXPECT_FALSE(f.render().empty());
  }
}

TEST_F(Analysis, FindingsAreSortedBySeverity) {
  std::vector<int> ranks;
  for (const Finding& f : findings()) ranks.push_back(severity_rank(f.severity));
  EXPECT_TRUE(std::is_sorted(ranks.begin(), ranks.end()));
}

TEST_F(Analysis, FindingsMatchTheScenario) {
  // 7 high and 4 medium: two floods (unicast and broadcast), forgeable
  // frames, the open twin, the PMKID, the evil twin and TKIP; then two
  // captured handshakes and two networks without MFP.
  std::map<std::string, int> counts;
  for (const Finding& f : findings()) counts[f.severity] += 1;
  EXPECT_EQ(counts, (std::map<std::string, int>{{"high", 7}, {"medium", 4}}));
}

TEST_F(Analysis, JsonReportIsComplete) {
  const std::string json = build_json(capture(), tracker(), findings());
  EXPECT_TRUE(contains(json, "\"frames\": 139"));
  EXPECT_TRUE(contains(json, "\"management\": 66"));
  EXPECT_TRUE(contains(json, "\"control\": 41"));
  EXPECT_TRUE(contains(json, "\"data\": 32"));
  EXPECT_TRUE(contains(json, "\"pmkid\": \"" + to_hex(synth::pmkid()) + "\""));
  EXPECT_TRUE(contains(json, "\"pmkid\": null"));
  EXPECT_TRUE(contains(json, "\"duration_ms\": 21.3"));
  EXPECT_TRUE(json.starts_with("{\n  \"capture\": {"));
  EXPECT_TRUE(json.ends_with("\n}"));
}

TEST_F(Analysis, TextReportHasEverySection) {
  const std::string report = render_report(capture(), tracker(), findings());
  for (const char* heading :
       {"Capture overview", "Frame classification", "Networks observed",
        "Association and authentication sequence", "WPA four-way handshakes",
        "Security findings", "11 findings: 7 high, 4 medium"}) {
    EXPECT_TRUE(contains(report, heading)) << heading;
  }
  EXPECT_TRUE(contains(report, "... 23 further deauth-class frames collapsed"));
}

TEST_F(Analysis, SyntheticBeaconsAdvertisePrivacyOnlyWhenSecured) {
  // Capability Information sits after radiotap (13), the MAC header (24) and
  // the timestamp and interval (10). Privacy is bit 4, ESS bit 0.
  const std::vector<PcapRecord> records = synth::build_capture();
  int checked = 0;
  for (const PcapRecord& r : records) {
    if (r.data.size() < 49 || r.data[13] != 0x80) continue;  // beacons only
    const std::uint16_t cap = get_le16(r.data, 13 + 24 + 10);
    const std::string bssid = std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", r.data[23],
                                          r.data[24], r.data[25], r.data[26], r.data[27],
                                          r.data[28]);
    EXPECT_TRUE(cap & 0x0001) << "ESS bit clear on " << bssid;
    EXPECT_EQ((cap & 0x0010) != 0, bssid != synth::AP_EVIL_TWIN) << bssid;
    ++checked;
  }
  EXPECT_EQ(checked, 23);
}
