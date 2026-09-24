// Read a pcap of 802.11 frames into FrameInfo records.
//
// The whole link-layer dissection lives here: radiotap, the MAC header, the
// fixed fields of each management frame, information elements, and the
// LLC/SNAP encapsulation that carries EAPOL. Everything is read from the byte
// layout with an explicit length check, because frames come off the air from
// devices this tool does not control.
#pragma once

#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "wifi/eapol.hpp"
#include "wifi/frames.hpp"
#include "wifi/pcap.hpp"
#include "wifi/rsn.hpp"

namespace airlock::wifi {

inline constexpr int ELEMENT_SSID = 0;
inline constexpr int ELEMENT_DS_PARAMETER = 3;
inline constexpr int ELEMENT_RSN = 48;
inline constexpr int ELEMENT_VENDOR = 221;

// An access point seen in the capture, and what it advertises.
struct Network {
  std::string bssid;
  std::optional<std::string> ssid;
  std::optional<int> channel;
  std::optional<RSNInfo> rsn;
  int beacon_count = 0;
  int probe_response_count = 0;
  double first_seen = 0.0;
  double last_seen = 0.0;
  std::set<std::string> clients;

  std::string security() const;
};

// One EAPOL-Key frame and the position of the 802.11 frame that carried it.
struct EapolObservation {
  std::size_t frame;  // index into Capture::frames
  EapolKeyFrame key;
};

// Everything parsed out of one capture file.
class Capture {
 public:
  explicit Capture(std::string path) : path(std::move(path)) {}

  std::string path;
  std::vector<FrameInfo> frames;
  std::vector<EapolObservation> eapol_frames;
  std::vector<std::string> parse_errors;
  int suspect_frames = 0;

  double duration() const;

  // Networks in the order they were first seen.
  const std::vector<Network>& networks() const { return networks_; }
  const Network* find_network(const std::string& bssid) const;
  Network* find_network(const std::string& bssid);
  // The network for `bssid`, created on first sight.
  Network& network_for(const std::string& bssid);

 private:
  std::vector<Network> networks_;
  std::map<std::string, std::size_t> by_bssid_;
};

// Parse a capture file into frames, networks, and EAPOL exchanges.
//
// Frames are streamed rather than read into memory at once: a few minutes of
// monitor-mode capture on a busy channel runs to tens of megabytes, and there
// is no reason to hold all of it.
//
// Each frame is parsed inside its own error boundary. One unparseable frame
// is recorded in `parse_errors` and the run continues; anything else would let
// a single malformed transmission from any device in range destroy the
// analysis of the whole capture. Throws PcapError if the file itself cannot
// be read.
Capture load_capture(const std::string& path);

// The same, from records already in memory.
Capture load_records(const std::string& path, const std::vector<PcapRecord>& records);

}  // namespace airlock::wifi
