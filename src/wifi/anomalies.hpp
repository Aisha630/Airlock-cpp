// Anomaly detection over parsed 802.11 metadata.
//
// Every detector here works on unencrypted header fields, which is what makes
// them usable against a WPA2 or WPA3 network whose payloads you cannot read.
// Each returns findings with a severity and an explicit reason, because a
// detector that says only "suspicious" cannot be acted on.
//
// These are heuristics with honest false-positive modes, documented per
// detector. A deauthentication burst is the signature of an attack, but it is
// also what a busy AP does when it sheds clients, and the analyzer says so.
#pragma once

#include <map>
#include <string>
#include <vector>

#include "wifi/capture.hpp"
#include "wifi/eapol.hpp"

namespace airlock::wifi {

// Rank of each severity, most severe first. Unknown severities sort last.
int severity_rank(const std::string& severity);

// A deauth flood is defined by rate, not by count: a handful of deauths over a
// long capture is normal roaming. These thresholds are tuned for a small
// capture and are arguments to the detector so they can be re-tuned.
inline constexpr double DEAUTH_WINDOW_SECONDS = 5.0;
inline constexpr int DEAUTH_BURST_THRESHOLD = 8;

// An access point beacons roughly ten times a second, so over any capture of
// reasonable length a real network produces many beacons. A BSSID seen once is
// far more likely to be a corrupted frame that survived the structural address
// check than a genuine access point. Networks below this threshold are
// summarised rather than reported individually: excluded from the findings,
// but never silently dropped.
inline constexpr int MIN_BEACONS_FOR_A_FINDING = 2;

// One anomaly, with the evidence behind it.
struct Finding {
  std::string severity;
  std::string title;
  std::string detail;
  std::vector<std::string> evidence;
  std::string false_positive;

  std::string render(const std::string& indent = "") const;
};

// Flag bursts of deauthentication or disassociation frames.
//
// A deauth frame is a management frame. On a network without management frame
// protection it carries no authentication whatsoever, so anyone within radio
// range can forge one from any address and knock a client off. That is the
// entire attack: no key material, no association, no knowledge of the
// passphrase. Detection is a sliding window over frames grouped by (source,
// destination): a genuine disconnect is one or two frames, a flood is a
// sustained stream aimed at keeping a client off the network.
std::vector<Finding> detect_deauth_flood(const Capture& capture,
                                         double window = DEAUTH_WINDOW_SECONDS,
                                         int threshold = DEAUTH_BURST_THRESHOLD);

// Flag networks whose deauths are unprotected because MFP is off.
//
// This is the pairing that matters: an MFP-required network makes the
// forged-deauth attack impossible, so the same burst of frames means something
// quite different depending on what the beacon advertised.
std::vector<Finding> detect_unprotected_deauth(const Capture& capture);

// Flag one SSID advertised from more than one BSSID with different security.
//
// A roaming network legitimately has many BSSIDs per SSID, so the BSSID count
// alone proves nothing. What is suspicious is the security of those BSSIDs
// disagreeing: a rogue AP cloning an SSID usually cannot clone the passphrase,
// so it comes up open or with a weaker AKM, hoping clients attach to the
// stronger signal.
std::vector<Finding> detect_evil_twin(const Capture& capture);

// Turn each network's advertised RSN weaknesses into findings.
std::vector<Finding> detect_weak_security(const Capture& capture);

// Flag captured four-way handshakes and PMKIDs as offline-attack material.
std::vector<Finding> detect_handshake_exposure(const Capture& capture,
                                               const std::vector<Handshake>& handshakes);

// Account for what was excluded, so exclusions stay visible.
std::vector<Finding> detect_low_confidence_networks(const Capture& capture);

// Run every detector and return findings sorted by severity, then title.
std::vector<Finding> run_all_detectors(const Capture& capture,
                                       const std::vector<Handshake>& handshakes);

}  // namespace airlock::wifi
