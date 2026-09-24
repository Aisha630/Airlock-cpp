#include "wifi/anomalies.hpp"

#include <algorithm>
#include <cctype>
#include <format>
#include <map>
#include <set>
#include <utility>

#include "wifi/text.hpp"

namespace airlock::wifi {
namespace {

bool is_deauth_class(const FrameInfo& frame) {
  return frame.subtype_name == "deauthentication" || frame.subtype_name == "disassociation";
}

std::string upper(std::string text) {
  for (char& c : text) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return text;
}

// Largest number of frames inside any `window`-second span, and where that
// span starts relative to the first frame.
//
// Two pointers over time-sorted frames: O(n) rather than O(n^2), and it finds
// the true peak instead of only checking fixed bucket boundaries, which would
// miss a burst that straddles two buckets.
std::pair<int, double> max_in_window(const std::vector<const FrameInfo*>& frames, double window) {
  if (frames.empty()) return {0, 0.0};
  std::vector<double> times;
  for (const FrameInfo* f : frames) times.push_back(f->timestamp);
  std::sort(times.begin(), times.end());
  int best = 0;
  double best_start = times[0];
  std::size_t left = 0;
  for (std::size_t right = 0; right < times.size(); ++right) {
    while (times[right] - times[left] > window) ++left;
    const int count = static_cast<int>(right - left + 1);
    if (count > best) {
      best = count;
      best_start = times[left];
    }
  }
  return {best, best_start - times[0]};
}

// True when there is enough evidence that this network is real.
bool well_attested(const Network& network) {
  return network.beacon_count + network.probe_response_count >= MIN_BEACONS_FOR_A_FINDING;
}

// Label a network for a finding, without printing a missing SSID as "None".
std::string describe(const Network& network) {
  return "\"" + network.ssid.value_or("<no SSID element>") + "\" (" + network.bssid + ")";
}

// Networks sorted by BSSID, the order every per-network detector reports in.
std::vector<const Network*> by_bssid(const Capture& capture) {
  std::vector<const Network*> out;
  for (const Network& n : capture.networks()) out.push_back(&n);
  std::sort(out.begin(), out.end(),
            [](const Network* a, const Network* b) { return a->bssid < b->bssid; });
  return out;
}

void extend(std::vector<Finding>& out, std::vector<Finding> more) {
  for (Finding& f : more) out.push_back(std::move(f));
}

}  // namespace

int severity_rank(const std::string& severity) {
  static const std::map<std::string, int> order = {
      {"high", 0}, {"medium", 1}, {"low", 2}, {"info", 3}};
  auto it = order.find(severity);
  return it == order.end() ? 9 : it->second;
}

std::string Finding::render(const std::string& indent) const {
  std::string out = std::format("{}[{:>6}] {}\n{}         {}", indent, upper(severity), title,
                                indent, detail);
  for (const std::string& item : evidence) out += "\n" + indent + "         - " + item;
  if (!false_positive.empty()) {
    out += "\n" + indent + "         benign explanation: " + false_positive;
  }
  return out;
}

std::vector<Finding> detect_deauth_flood(const Capture& capture, double window, int threshold) {
  std::vector<Finding> findings;
  std::map<std::pair<std::string, std::string>, std::vector<const FrameInfo*>> groups;
  for (const FrameInfo& frame : capture.frames) {
    if (!is_deauth_class(frame)) continue;
    const std::string source =
        frame.transmitter() && !frame.transmitter()->empty() ? *frame.transmitter() : "unknown";
    const std::string destination =
        frame.receiver() && !frame.receiver()->empty() ? *frame.receiver() : "unknown";
    groups[{source, destination}].push_back(&frame);
  }

  for (const auto& [key, frames] : groups) {
    const auto& [source, destination] = key;
    const auto [peak, peak_start] = max_in_window(frames, window);
    if (peak < threshold) continue;

    std::set<int> reasons;
    int protected_count = 0;
    for (const FrameInfo* f : frames) {
      if (f->reason_code) reasons.insert(*f->reason_code);
      if (f->is_protected) ++protected_count;
    }
    std::vector<std::string> reason_parts;
    for (int code : reasons) {
      reason_parts.push_back(std::format("{} ({})", code, reason_text(code)));
    }
    const std::string reason_list = join(reason_parts, ", ");
    const std::string target =
        destination.starts_with("ff:") ? "the whole BSS (broadcast)" : destination;

    std::vector<std::string> evidence = {
        std::format("{} frames total, peak {} within {:g} s starting at t+{:.2f} s",
                    frames.size(), peak, window, peak_start),
        std::format("source {} -> target {}", source, target),
        "reason codes seen: " + (reason_list.empty() ? std::string("none decoded") : reason_list),
        std::format("{}/{} frames were cryptographically protected", protected_count,
                    frames.size()),
    };
    if (protected_count == 0) {
      evidence.push_back(
          "none were protected, so every one of them is forgeable by any device in range");
    }

    findings.push_back(Finding{
        "high",
        "Deauthentication / disassociation flood",
        std::format("{} deauth-class frames from {} inside a {:g}-second window -- the signature "
                    "of a forced disconnect, used either as denial of service or to make a "
                    "client reconnect so its four-way handshake can be captured",
                    peak, source, window),
        evidence,
        "an access point rebooting, shedding clients under load, or steering a client to "
        "another band also emits deauths, though rarely this many this fast from one address",
    });
  }
  return findings;
}

std::vector<Finding> detect_unprotected_deauth(const Capture& capture) {
  std::vector<Finding> findings;
  std::set<std::string> deauth_bssids;
  for (const FrameInfo& frame : capture.frames) {
    if (is_deauth_class(frame) && frame.bssid && !frame.bssid->empty() && !frame.is_protected) {
      deauth_bssids.insert(*frame.bssid);
    }
  }
  for (const std::string& bssid : deauth_bssids) {
    const Network* network = capture.find_network(bssid);
    if (network == nullptr || !network->rsn) continue;
    const RSNInfo& rsn = *network->rsn;
    if (rsn.mfp_required) {
      // MFP required and yet an unprotected deauth was on the air: worth
      // seeing, since a compliant client should ignore it.
      findings.push_back(Finding{
          "low",
          "Unprotected deauth on an MFP-required network",
          "\"" + or_none(network->ssid) + "\" (" + bssid +
              ") requires management frame protection, so compliant clients will ignore these "
              "unprotected frames -- the attack is visible but ineffective",
          {"RSN capabilities: MFP " + rsn.mfp_state()},
          "",
      });
      continue;
    }
    findings.push_back(Finding{
        "high",
        "Forgeable management frames (no MFP)",
        "\"" + or_none(network->ssid) + "\" (" + bssid + ") advertises MFP as " +
            rsn.mfp_state() +
            ", and unprotected deauthentication frames were observed on it; these frames are "
            "unauthenticated and can be forged by anyone in range",
        {
            "security: " + rsn.generation(),
            std::format("RSN capabilities word: 0x{:04x}", rsn.raw_capabilities),
            "remediation: enable 802.11w (PMF) as required, which is mandatory in WPA3 and "
            "optional in WPA2",
        },
        "",
    });
  }
  return findings;
}

std::vector<Finding> detect_evil_twin(const Capture& capture) {
  std::vector<Finding> findings;
  std::map<std::string, std::vector<const Network*>> by_ssid;
  for (const Network& network : capture.networks()) {
    if (network.ssid && !network.ssid->empty() && *network.ssid != "<wildcard/hidden>" &&
        well_attested(network)) {
      by_ssid[*network.ssid].push_back(&network);
    }
  }

  for (const auto& [ssid, networks] : by_ssid) {
    if (networks.size() < 2) continue;
    std::set<std::string> profiles;
    for (const Network* n : networks) profiles.insert(n->security());

    if (profiles.size() == 1) {
      std::vector<std::string> evidence;
      for (const Network* n : networks) evidence.push_back(n->bssid + " (" + n->security() + ")");
      findings.push_back(Finding{
          "info",
          "SSID advertised by multiple BSSIDs",
          std::format("\"{}\" is advertised by {} BSSIDs with identical security settings, "
                      "which is what a normal multi-AP or multi-band deployment looks like",
                      ssid, networks.size()),
          evidence,
          "",
      });
      continue;
    }

    std::vector<const Network*> sorted = networks;
    std::sort(sorted.begin(), sorted.end(),
              [](const Network* a, const Network* b) { return a->bssid < b->bssid; });
    std::vector<std::string> evidence;
    for (const Network* n : sorted) {
      evidence.push_back(std::format("{}: {}, {} beacons, channel {}", n->bssid, n->security(),
                                     n->beacon_count, or_none(n->channel)));
    }
    findings.push_back(Finding{
        "high",
        "Possible evil twin: same SSID, different security",
        std::format("\"{}\" is advertised by {} BSSIDs that do not agree on their security "
                    "configuration; a rogue AP cloning an SSID cannot clone the credential, so "
                    "it typically advertises weaker or no security",
                    ssid, networks.size()),
        evidence,
        "a deliberate transition-mode deployment, or an AP mid-way through a configuration "
        "change, produces the same pattern",
    });
  }
  return findings;
}

std::vector<Finding> detect_low_confidence_networks(const Capture& capture) {
  std::vector<const Network*> weak_evidence;
  for (const Network* network : by_bssid(capture)) {
    if (!well_attested(*network)) weak_evidence.push_back(network);
  }
  if (weak_evidence.empty() && capture.suspect_frames == 0) return {};

  std::vector<std::string> evidence;
  if (capture.suspect_frames) {
    evidence.push_back(std::format(
        "{} frames had a structurally invalid transmitter address (group bit set) and were "
        "excluded from network discovery entirely",
        capture.suspect_frames));
  }
  if (!weak_evidence.empty()) {
    evidence.push_back(std::format(
        "{} BSSIDs were seen fewer than {} times and are not reported individually",
        weak_evidence.size(), MIN_BEACONS_FOR_A_FINDING));
    for (std::size_t i = 0; i < weak_evidence.size() && i < 5; ++i) {
      const Network* n = weak_evidence[i];
      evidence.push_back(
          std::format("{}: {} beacons, ssid {}", n->bssid, n->beacon_count, quoted_repr(n->ssid)));
    }
    if (weak_evidence.size() > 5) {
      evidence.push_back(std::format("... and {} more", weak_evidence.size() - 5));
    }
  }

  return {Finding{
      "info",
      "Low-confidence observations excluded from the findings",
      "a real access point beacons about ten times a second, so a BSSID seen once in a capture "
      "of any length is far more likely to be a corrupted frame than a network; these are "
      "listed here rather than reported as findings",
      evidence,
      "a genuine but very distant access point, or one captured for only a moment while "
      "channel hopping, can also appear this way",
  }};
}

std::vector<Finding> detect_weak_security(const Capture& capture) {
  std::vector<Finding> findings;
  for (const Network* network : by_bssid(capture)) {
    if (!well_attested(*network)) continue;  // accounted for by detect_low_confidence_networks
    const std::string label = describe(*network);
    if (!network->rsn) {
      findings.push_back(Finding{
          "high",
          "Open network",
          label + " advertises no RSN element, so traffic is unencrypted and unauthenticated "
                  "on the air",
          {std::format("{} beacons observed", network->beacon_count)},
          "",
      });
      continue;
    }
    const RSNInfo& rsn = *network->rsn;
    for (const std::string& weakness : rsn.weaknesses()) {
      const bool severe = weakness.find("broken") != std::string::npos ||
                          weakness.find("downgrade") != std::string::npos;
      findings.push_back(Finding{
          severe ? "high" : "medium",
          "Weak configuration: " + rsn.generation(),
          label + ": " + weakness,
          {"group cipher " + rsn.group_cipher + ", pairwise " + join(rsn.pairwise_ciphers, "/") +
           ", AKM " + join(rsn.akm_suites, "/") + ", MFP " + rsn.mfp_state()},
          "",
      });
    }
  }
  return findings;
}

std::vector<Finding> detect_handshake_exposure(const Capture& capture,
                                               const std::vector<Handshake>& handshakes) {
  std::vector<Finding> findings;
  for (const Handshake& handshake : handshakes) {
    const Network* network = capture.find_network(handshake.ap);
    const std::string ssid = network ? or_none(network->ssid) : "unknown";
    if (handshake.pmkid) {
      findings.push_back(Finding{
          "high",
          "PMKID disclosed in EAPOL message 1",
          "AP " + handshake.ap + " (\"" + ssid +
              "\") included a PMKID in message 1. Because the PMKID is HMAC-SHA1(PMK, \"PMK "
              "Name\" || AP || STA), this one frame supports an offline dictionary attack on "
              "the passphrase with no client and no full handshake required",
          {
              "PMKID " + to_hex(*handshake.pmkid),
              "station " + handshake.station,
              "remediation: WPA3-SAE, or disable PMKID caching on the AP",
          },
          "",
      });
    }
    if (handshake.complete()) {
      findings.push_back(Finding{
          "medium",
          "Complete four-way handshake captured",
          "the full handshake between " + handshake.station + " and " + handshake.ap + " (\"" +
              ssid +
              "\") is in this capture. WPA2 derives the PTK from the PMK and the two nonces "
              "with no key exchange, so recovering the passphrase later decrypts this session "
              "retroactively -- WPA2-PSK has no forward secrecy",
          {
              std::format("completed in {:.1f} ms", *handshake.duration_ms()),
              handshake.anonce ? "ANonce " + to_hex(*handshake.anonce).substr(0, 16) + "..."
                               : "ANonce not captured",
              handshake.snonce ? "SNonce " + to_hex(*handshake.snonce).substr(0, 16) + "..."
                               : "SNonce not captured",
              "remediation: WPA3-SAE runs a Dragonfly key exchange per session, so a later "
              "passphrase compromise reveals nothing",
          },
          "",
      });
    }
  }
  return findings;
}

std::vector<Finding> run_all_detectors(const Capture& capture,
                                       const std::vector<Handshake>& handshakes) {
  std::vector<Finding> findings;
  extend(findings, detect_deauth_flood(capture));
  extend(findings, detect_unprotected_deauth(capture));
  extend(findings, detect_evil_twin(capture));
  extend(findings, detect_weak_security(capture));
  extend(findings, detect_handshake_exposure(capture, handshakes));
  extend(findings, detect_low_confidence_networks(capture));
  std::stable_sort(findings.begin(), findings.end(), [](const Finding& a, const Finding& b) {
    const int ra = severity_rank(a.severity), rb = severity_rank(b.severity);
    return ra != rb ? ra < rb : a.title < b.title;
  });
  return findings;
}

}  // namespace airlock::wifi
