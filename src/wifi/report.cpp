#include "wifi/report.hpp"

#include <algorithm>
#include <format>
#include <map>
#include <set>
#include <utility>

#include "wifi/json.hpp"
#include "wifi/text.hpp"

namespace airlock::wifi {
namespace {

std::string rule(const std::string& title) {
  return "\n" + title + "\n" + std::string(display_width(title), '=');
}

std::string sub(const std::string& title) {
  return "\n" + title + "\n" + std::string(display_width(title), '-');
}

// Counts in first-seen order, like a tally kept by hand.
class Tally {
 public:
  void add(const std::string& key) {
    auto [it, inserted] = index_.try_emplace(key, entries_.size());
    if (inserted) entries_.emplace_back(key, 0);
    entries_[it->second].second += 1;
  }
  const std::vector<std::pair<std::string, int>>& entries() const { return entries_; }
  // Highest counts first; ties stay in first-seen order.
  std::vector<std::pair<std::string, int>> most_common() const {
    auto out = entries_;
    std::stable_sort(out.begin(), out.end(),
                     [](const auto& a, const auto& b) { return a.second > b.second; });
    return out;
  }

 private:
  std::map<std::string, std::size_t> index_;
  std::vector<std::pair<std::string, int>> entries_;
};

std::string pad(const std::optional<std::string>& value) {
  return value && !value->empty() ? *value : "-";
}

}  // namespace

HandshakeTracker track_handshakes(const Capture& capture) {
  HandshakeTracker tracker;
  for (const EapolObservation& observation : capture.eapol_frames) {
    const FrameInfo& info = capture.frames[observation.frame];
    if (!info.transmitter() || !info.receiver()) continue;
    tracker.observe(observation.key, *info.transmitter(), *info.receiver(), info.timestamp,
                    info.index);
  }
  return tracker;
}

std::vector<std::string> report_overview(const Capture& capture) {
  std::vector<std::string> lines = {rule("Capture overview")};
  lines.push_back("file:     " + capture.path);
  lines.push_back(std::format("frames:   {}", capture.frames.size()));
  lines.push_back(std::format("duration: {:.2f} s", capture.duration()));
  if (!capture.frames.empty()) {
    std::size_t total = 0;
    for (const FrameInfo& f : capture.frames) total += f.length;
    lines.push_back(std::format("bytes:    {} ({:.1f} KiB)", total, static_cast<double>(total) / 1024));
  }
  if (capture.suspect_frames) {
    lines.push_back(std::format(
        "corrupt:  {} frames with an invalid transmitter address (excluded from network "
        "discovery)",
        capture.suspect_frames));
  }
  if (!capture.parse_errors.empty()) {
    lines.push_back(std::format("parse errors: {}", capture.parse_errors.size()));
    for (std::size_t i = 0; i < capture.parse_errors.size() && i < 5; ++i) {
      lines.push_back("  - " + capture.parse_errors[i]);
    }
  }
  return lines;
}

std::vector<std::string> report_frame_classes(const Capture& capture) {
  std::vector<std::string> lines = {rule("Frame classification")};
  const std::size_t total = capture.frames.size();
  if (total == 0) {
    lines.push_back("no 802.11 frames in this capture");
    return lines;
  }

  std::map<int, int> by_type;
  for (const FrameInfo& f : capture.frames) by_type[f.frame_type] += 1;
  lines.push_back(std::format("{:<12} {:>7} {:>8}   subtypes", "class", "count", "share"));
  lines.push_back(std::string(74, '-'));
  for (const auto& [frame_type, count] : by_type) {
    Tally subtypes;
    for (const FrameInfo& f : capture.frames) {
      if (f.frame_type == frame_type) subtypes.add(f.subtype_name);
    }
    const auto common = subtypes.most_common();
    std::vector<std::string> parts;
    for (std::size_t i = 0; i < common.size() && i < 6; ++i) {
      parts.push_back(std::format("{} x{}", common[i].first, common[i].second));
    }
    std::string breakdown = join(parts, ", ");
    if (common.size() > 6) breakdown += std::format(", +{} more", common.size() - 6);
    lines.push_back(std::format("{:<12} {:>7} {:>7.1f}%   {}", type_name(frame_type), count,
                                static_cast<double>(count) / static_cast<double>(total) * 100,
                                breakdown));
  }
  lines.push_back(std::string(74, '-'));
  lines.push_back(std::format("{:<12} {:>7} {:>7.1f}%", "total", total, 100.0));

  std::size_t protected_total = 0, data_frames = 0, protected_data = 0, retries = 0;
  for (const FrameInfo& f : capture.frames) {
    if (f.is_protected) ++protected_total;
    if (f.is_data()) {
      ++data_frames;
      if (f.is_protected) ++protected_data;
    }
    if (f.retry) ++retries;
  }
  if (data_frames) {
    lines.push_back(std::format(
        "\n{}/{} data frames carry the Protected Frame bit ({} frames overall)", protected_data,
        data_frames, protected_total));
  }
  if (retries) lines.push_back(std::format("{} frames are retransmissions", retries));
  return lines;
}

std::vector<std::string> report_networks(const Capture& capture) {
  std::vector<std::string> lines = {rule("Networks observed")};
  if (capture.networks().empty()) {
    lines.push_back("no beacons or probe responses in this capture");
    return lines;
  }

  std::vector<const Network*> ordered;
  for (const Network& n : capture.networks()) ordered.push_back(&n);
  std::stable_sort(ordered.begin(), ordered.end(), [](const Network* a, const Network* b) {
    return a->beacon_count > b->beacon_count;
  });

  for (const Network* network : ordered) {
    lines.push_back(sub(network->ssid.value_or("<unknown>") + "  [" + network->bssid + "]"));
    lines.push_back("  channel:  " + or_none(network->channel));
    lines.push_back("  security: " + network->security());
    if (network->rsn) {
      const RSNInfo& rsn = *network->rsn;
      const std::string pairwise = join(rsn.pairwise_ciphers, "/");
      const std::string akm = join(rsn.akm_suites, "/");
      lines.push_back("  ciphers:  group " + rsn.group_cipher + ", pairwise " +
                      (pairwise.empty() ? "none" : pairwise));
      lines.push_back("  AKM:      " + (akm.empty() ? std::string("none") : akm));
      lines.push_back(std::format("  MFP:      {} (RSN capabilities 0x{:04x})", rsn.mfp_state(),
                                  rsn.raw_capabilities));
      if (rsn.group_mgmt_cipher) lines.push_back("  group mgmt cipher: " + *rsn.group_mgmt_cipher);
    }
    lines.push_back(std::format("  beacons:  {}, probe responses: {}", network->beacon_count,
                                network->probe_response_count));
    if (!network->clients.empty()) {
      lines.push_back("  stations: " +
                      join(std::vector<std::string>(network->clients.begin(),
                                                    network->clients.end()),
                           ", "));
    }
  }
  return lines;
}

std::vector<std::string> report_association(const Capture& capture) {
  std::vector<std::string> lines = {rule("Association and authentication sequence")};
  static const std::set<std::string> interesting = {
      "probe-request",    "probe-response",   "authentication",
      "assoc-request",    "assoc-response",   "reassoc-request",
      "reassoc-response", "deauthentication", "disassociation",
  };
  std::vector<const FrameInfo*> selected;
  for (const FrameInfo& f : capture.frames) {
    if (f.frame_type == TYPE_MANAGEMENT && interesting.count(f.subtype_name)) selected.push_back(&f);
  }
  if (selected.empty()) {
    lines.push_back("no association-related management frames");
    return lines;
  }

  const double start = capture.frames.front().timestamp;
  lines.push_back(std::format("{:>8}  {:<18} {:<18} {:<18} detail", "t+s", "frame", "transmitter",
                              "receiver"));
  lines.push_back(std::string(100, '-'));
  std::size_t shown = 0;
  int deauth_run = 0;
  for (const FrameInfo* frame : selected) {
    // Collapse the deauth flood: one line for the burst, not dozens.
    if (frame->subtype_name == "deauthentication" || frame->subtype_name == "disassociation") {
      if (++deauth_run > 2) continue;
    } else {
      deauth_run = 0;
    }

    std::vector<std::string> detail;
    if (frame->auth_algorithm) {
      detail.push_back(std::format("algo={} seq={}", *frame->auth_algorithm, *frame->auth_seq));
    }
    if (frame->status_code) detail.push_back(std::format("status={}", *frame->status_code));
    if (frame->reason_code) detail.push_back(std::format("reason={}", *frame->reason_code));
    if (frame->ssid) detail.push_back("ssid=\"" + *frame->ssid + "\"");
    lines.push_back(std::format("{:>8.3f}  {:<18} {:<18} {:<18} {}", frame->timestamp - start,
                                frame->subtype_name, pad(frame->transmitter()),
                                pad(frame->receiver()), join(detail, " ")));
    ++shown;
  }

  if (selected.size() > shown) {
    lines.push_back(std::format("... {} further deauth-class frames collapsed (see findings)",
                                selected.size() - shown));
  }
  return lines;
}

std::vector<std::string> report_handshakes(const Capture& capture,
                                           const HandshakeTracker& tracker) {
  std::vector<std::string> lines = {rule("WPA four-way handshakes")};
  const std::vector<Handshake>& handshakes = tracker.all();
  if (handshakes.empty()) {
    lines.push_back("no EAPOL-Key frames in this capture");
    return lines;
  }

  static const std::map<int, std::string> content = {
      {1, "ANonce, no MIC yet"},
      {2, "SNonce + RSN element, MIC present"},
      {3, "install key, encrypted key data, MIC"},
      {4, "zero nonce, acknowledgement only"},
  };
  const double start = capture.frames.front().timestamp;
  for (const Handshake& handshake : handshakes) {
    const Network* network = capture.find_network(handshake.ap);
    const std::string ssid = network ? or_none(network->ssid) : "unknown";
    lines.push_back(sub(handshake.station + " <-> " + handshake.ap + " (\"" + ssid + "\")"));
    for (const auto& [number, timestamp] : handshake.messages) {
      const std::string role = number == 1 || number == 3 ? "AP -> STA" : "STA -> AP";
      lines.push_back(std::format("  M{}  t+{:>7.3f}s  {}  replay counter {}  ({})", number,
                                  timestamp - start, role, handshake.replay_counters.at(number),
                                  content.at(number)));
    }
    for (const std::string& note : handshake.notes()) lines.push_back("  note: " + note);
  }
  return lines;
}

std::vector<std::string> report_findings(const std::vector<Finding>& findings) {
  std::vector<std::string> lines = {rule("Security findings")};
  if (findings.empty()) {
    lines.push_back("no findings");
    return lines;
  }
  std::map<std::string, int> counts;
  for (const Finding& f : findings) counts[f.severity] += 1;
  std::vector<std::pair<std::string, int>> ordered(counts.begin(), counts.end());
  std::stable_sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
    return severity_rank(a.first) < severity_rank(b.first);
  });
  std::vector<std::string> parts;
  for (const auto& [severity, count] : ordered) parts.push_back(std::format("{} {}", count, severity));
  lines.push_back(std::format("{} findings: {}\n", findings.size(), join(parts, ", ")));
  for (const Finding& finding : findings) {
    lines.push_back(finding.render());
    lines.push_back("");
  }
  return lines;
}

std::string render_report(const Capture& capture, const HandshakeTracker& tracker,
                          const std::vector<Finding>& findings) {
  const std::vector<std::vector<std::string>> sections = {
      report_overview(capture),
      report_frame_classes(capture),
      report_networks(capture),
      report_association(capture),
      report_handshakes(capture, tracker),
      report_findings(findings),
  };
  std::string out;
  for (const auto& section : sections) out += join(section, "\n") + "\n";
  return out;
}

std::string build_json(const Capture& capture, const HandshakeTracker& tracker,
                       const std::vector<Finding>& findings) {
  using json::Array;
  using json::Object;
  using json::Value;

  auto strings = [](const std::vector<std::string>& values) {
    Array out;
    for (const std::string& v : values) out.emplace_back(v);
    return out;
  };

  std::map<int, int> by_type;
  Tally subtypes;
  for (const FrameInfo& f : capture.frames) {
    by_type[f.frame_type] += 1;
    subtypes.add(f.subtype_name);
  }
  Object frame_classes, frame_subtypes;
  for (const auto& [frame_type, count] : by_type) frame_classes.emplace_back(type_name(frame_type), count);
  for (const auto& [name, count] : subtypes.entries()) frame_subtypes.emplace_back(name, count);

  std::vector<const Network*> sorted;
  for (const Network& n : capture.networks()) sorted.push_back(&n);
  std::sort(sorted.begin(), sorted.end(),
            [](const Network* a, const Network* b) { return a->bssid < b->bssid; });
  Array networks;
  for (const Network* n : sorted) {
    const RSNInfo* rsn = n->rsn ? &*n->rsn : nullptr;
    networks.emplace_back(Object{
        {"bssid", n->bssid},
        {"ssid", Value::optional(n->ssid)},
        {"channel", Value::optional(n->channel)},
        {"security", n->security()},
        {"group_cipher", rsn ? Value(rsn->group_cipher) : Value(nullptr)},
        {"pairwise_ciphers", rsn ? strings(rsn->pairwise_ciphers) : Array{}},
        {"akm_suites", rsn ? strings(rsn->akm_suites) : Array{}},
        {"mfp", rsn ? Value(rsn->mfp_state()) : Value(nullptr)},
        {"beacons", n->beacon_count},
        {"clients", strings(std::vector<std::string>(n->clients.begin(), n->clients.end()))},
    });
  }

  Array handshakes;
  for (const Handshake& h : tracker.all()) {
    Array seen;
    for (int number : h.observed()) seen.emplace_back(number);
    handshakes.emplace_back(Object{
        {"ap", h.ap},
        {"station", h.station},
        {"messages_seen", seen},
        {"complete", h.complete()},
        {"duration_ms", h.complete() ? Value(round_to(*h.duration_ms(), 3)) : Value(nullptr)},
        {"pmkid", h.pmkid ? Value(to_hex(*h.pmkid)) : Value(nullptr)},
        {"notes", strings(h.notes())},
    });
  }

  Array finding_list;
  for (const Finding& f : findings) {
    finding_list.emplace_back(Object{
        {"severity", f.severity},
        {"title", f.title},
        {"detail", f.detail},
        {"evidence", strings(f.evidence)},
        {"benign_explanation", f.false_positive},
    });
  }

  const Value report = Object{
      {"capture", Object{
                      {"path", capture.path},
                      {"frames", capture.frames.size()},
                      {"duration_seconds", round_to(capture.duration(), 3)},
                      {"suspect_frames", capture.suspect_frames},
                      {"parse_errors", strings(capture.parse_errors)},
                  }},
      {"frame_classes", frame_classes},
      {"frame_subtypes", frame_subtypes},
      {"networks", networks},
      {"handshakes", handshakes},
      {"findings", finding_list},
  };
  return report.dump();
}

}  // namespace airlock::wifi
