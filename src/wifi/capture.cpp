#include "wifi/capture.hpp"

#include <exception>
#include <format>
#include <functional>

#include "wifi/text.hpp"

namespace airlock::wifi {
namespace {

// --- radiotap -------------------------------------------------------------

// What the capturing adapter recorded about a frame. Radiotap is added by the
// adapter, not by 802.11, so these fields are best-effort: some drivers omit
// them entirely.
struct RadiotapInfo {
  std::size_t length = 0;
  std::optional<int> signal_dbm;
  std::optional<int> frequency_mhz;
  bool has_fcs = false;
};

std::optional<RadiotapInfo> parse_radiotap(ByteView d) {
  if (d.size() < 8) return std::nullopt;
  RadiotapInfo info;
  info.length = get_le16(d, 2);
  if (info.length < 8 || info.length > d.size()) return std::nullopt;

  const std::uint32_t present = get_le32(d, 4);
  // Extended presence bitmaps chain through bit 31. Only the first word's
  // fields are read, but every word has to be skipped to find them.
  std::size_t offset = 8;
  for (std::uint32_t word = present; word & 0x80000000u && offset + 4 <= info.length;) {
    word = get_le32(d, offset);
    offset += 4;
  }

  // Fields 0..5 in order, each with its alignment and size. Alignment is
  // relative to the start of the radiotap header.
  struct Field {
    std::size_t align, size;
  };
  constexpr Field fields[] = {{8, 8}, {1, 1}, {1, 1}, {2, 4}, {2, 2}, {1, 1}};
  for (int bit = 0; bit <= 5; ++bit) {
    if (!(present & (1u << bit))) continue;
    const Field f = fields[bit];
    offset = (offset + f.align - 1) & ~(f.align - 1);
    if (offset + f.size > info.length) break;
    if (bit == 1) info.has_fcs = (d[offset] & 0x10) != 0;
    if (bit == 3) info.frequency_mhz = get_le16(d, offset);
    if (bit == 5) info.signal_dbm = static_cast<std::int8_t>(d[offset]);
    offset += f.size;
  }
  return info;
}

// Convert a centre frequency to a channel number (2.4 and 5 GHz).
std::optional<int> frequency_to_channel(int mhz) {
  if (mhz == 2484) return 14;
  if (mhz >= 2412 && mhz <= 2472) return (mhz - 2412) / 5 + 1;
  if (mhz >= 5000 && mhz <= 5900) return (mhz - 5000) / 5;
  return std::nullopt;
}

// --- MAC header -----------------------------------------------------------

std::string format_mac(ByteView d, std::size_t at) {
  return std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", d[at], d[at + 1], d[at + 2],
                     d[at + 3], d[at + 4], d[at + 5]);
}

struct MacHeader {
  int type = 0;
  int subtype = 0;
  std::uint8_t flags = 0;
  std::optional<std::string> addr1, addr2, addr3, addr4;
  std::size_t length = 0;  // bytes consumed, where the frame body starts
};

// Parse the MAC header. The fields present depend on the type and subtype;
// a frame cut short keeps the fields that fit and loses the rest.
MacHeader parse_mac_header(ByteView d) {
  MacHeader h;
  h.subtype = d[0] >> 4;
  h.type = (d[0] >> 2) & 0x03;
  h.flags = d[1];
  std::size_t at = 2;
  auto field = [&](std::size_t size) {
    if (at + size > d.size()) return false;
    at += size;
    return true;
  };
  auto address = [&](std::optional<std::string>& out) {
    if (at + 6 > d.size()) return false;
    out = format_mac(d, at);
    at += 6;
    return true;
  };

  const bool addr2_present =
      (h.type != 1 && h.type != 3) ||
      h.subtype == 4 || h.subtype == 5 || h.subtype == 6 || h.subtype == 8 || h.subtype == 9 ||
      h.subtype == 10 || h.subtype == 11 || h.subtype == 14 || h.subtype == 15;
  const bool addr3_and_sc = h.type == 0 || h.type == 2;
  const bool addr4_present = h.type == 2 && (h.flags & 0x03) == 0x03;

  bool ok = field(2) && address(h.addr1);
  if (ok && addr2_present) ok = address(h.addr2);
  if (ok && addr3_and_sc) ok = address(h.addr3) && field(2);
  if (ok && addr4_present) ok = address(h.addr4);
  h.length = at;
  return h;
}

// --- information elements -------------------------------------------------

// Call `visit(id, body)` for every information element in `d`.
//
// Defensive by necessity. Information elements come off the air from devices
// this tool does not control, and real captures contain plenty that are
// truncated mid-element, carry a length byte that overruns the frame, or were
// clipped by the adapter's snap length. An element that overruns is handed
// over with the bytes that are actually there, and it ends the walk: nothing
// after it can be located reliably.
void walk_elements(ByteView d, const std::function<void(int, ByteView)>& visit) {
  std::size_t at = 0;
  while (at + 2 <= d.size()) {
    const int id = d[at];
    const std::size_t length = d[at + 1];
    const std::size_t available = std::min(length, d.size() - at - 2);
    visit(id, d.subspan(at + 2, available));
    if (available < length) return;
    at += 2 + length;
  }
}

// Decode an SSID, which is arbitrary bytes and not necessarily UTF-8.
//
// A zero-length SSID means a wildcard probe request or a hidden network; both
// are reported explicitly rather than as an empty string, so the report never
// looks like a parse failure.
std::string decode_ssid(ByteView raw) {
  if (raw.empty()) return "<wildcard/hidden>";
  return decode_utf8_lossy(raw);
}

// Read RSN / WPA1 elements from a beacon or probe response.
void extract_security(ByteView elements, Network& network, std::vector<std::string>& errors) {
  walk_elements(elements, [&](int id, ByteView body) {
    if (id == ELEMENT_RSN) {
      try {
        network.rsn = parse_rsn_element(body);
      } catch (const RSNParseError& exc) {
        errors.push_back(network.bssid + ": bad RSN element: " + exc.what());
      }
    } else if (id == ELEMENT_VENDOR && !network.rsn) {
      // Only fall back to WPA1 when there is no RSN element; an AP running
      // both advertises RSN, and that is the one in force.
      if (auto wpa1 = parse_wpa1_element(body)) network.rsn = *wpa1;
    }
  });
}

std::string auth_algorithm_name(int algorithm) {
  switch (algorithm) {
    case 0: return "open-system";
    case 1: return "shared-key";
    case 2: return "fast-bss-transition";
    case 3: return "SAE";  // WPA3 authenticating with Dragonfly
    default: return "algorithm-" + std::to_string(algorithm);
  }
}

// --- per-frame classification ---------------------------------------------

// Pull SSID, security info and reason/status codes from management frames.
void classify_management(ByteView body, FrameInfo& info, Capture& capture) {
  // A protected management frame's body is ciphertext.
  if (!info.is_management() || info.is_protected) return;

  auto fixed = [&](std::size_t size) { return body.size() >= size; };
  const int subtype = info.subtype;

  if ((subtype == 8 || subtype == 5) && fixed(12)) {  // beacon, probe response
    const std::optional<std::string>& bssid = info.addr3 ? info.addr3 : info.addr2;
    if (!bssid) return;
    Network& network = capture.network_for(*bssid);
    if (network.beacon_count == 0 && network.probe_response_count == 0) {
      network.first_seen = info.timestamp;
    }
    network.last_seen = info.timestamp;
    (subtype == 8 ? network.beacon_count : network.probe_response_count) += 1;

    ByteView elements = body.subspan(12);
    walk_elements(elements, [&](int id, ByteView element) {
      if (id == ELEMENT_SSID) {
        network.ssid = decode_ssid(element);
        info.ssid = network.ssid;
      } else if (id == ELEMENT_DS_PARAMETER && !element.empty()) {
        network.channel = element[0];
        if (!info.channel) info.channel = element[0];
      }
    });
    extract_security(elements, network, capture.parse_errors);
  } else if ((subtype == 4 && fixed(0)) || (subtype == 0 && fixed(4)) ||
             (subtype == 2 && fixed(10))) {  // probe, association, reassociation requests
    const std::size_t skip = subtype == 4 ? 0 : subtype == 0 ? 4 : 10;
    bool found = false;
    walk_elements(body.subspan(skip), [&](int id, ByteView element) {
      if (id == ELEMENT_SSID && !found) {
        info.ssid = decode_ssid(element);
        found = true;
      }
    });
  }

  if ((subtype == 12 || subtype == 10) && fixed(2)) {  // deauthentication, disassociation
    info.reason_code = get_le16(body, 0);
  }
  if (subtype == 11 && fixed(6)) {  // authentication
    info.auth_algorithm = auth_algorithm_name(get_le16(body, 0));
    info.auth_seq = get_le16(body, 2);
    info.status_code = get_le16(body, 4);
  } else if (subtype == 1 && fixed(6)) {  // association response
    info.status_code = get_le16(body, 2);
  }
}

// Parse any EAPOL-Key frame carried in a data frame.
void classify_eapol(ByteView body, FrameInfo& info, Capture& capture) {
  if (!info.is_data()) return;
  // QoS data subtypes carry a two-byte QoS Control field before the body.
  if (info.subtype >= 8 && info.subtype != 13) {
    if (body.size() < 2) return;
    body = body.subspan(2);
  }
  if (info.is_protected) return;  // ciphertext

  // LLC (DSAP, SSAP, control) then SNAP (OUI, EtherType 0x888E).
  if (body.size() < 8 || body[0] != 0xAA || body[1] != 0xAA || body[2] != 0x03) return;
  if (get_be16(body, 6) != 0x888E) return;
  ByteView payload = body.subspan(8);
  if (payload.empty()) return;

  try {
    EapolKeyFrame key = parse_eapol_key(payload);
    info.eapol_message = key.message_number();
    capture.eapol_frames.push_back({capture.frames.size(), std::move(key)});
  } catch (const EapolParseError& exc) {
    capture.parse_errors.push_back(std::format("frame {}: {}", info.index, exc.what()));
  }
}

// Parse one frame into the capture. Throws on anything unexpected.
void load_frame(const PcapRecord& record, std::size_t index, Capture& capture) {
  ByteView frame = record.data;
  std::optional<RadiotapInfo> radiotap;
  if (record.linktype == LINKTYPE_IEEE802_11_RADIOTAP) {
    radiotap = parse_radiotap(frame);
    if (!radiotap) return;
    frame = frame.subspan(radiotap->length);
    if (radiotap->has_fcs && frame.size() >= 4) frame = frame.first(frame.size() - 4);
  } else if (record.linktype != LINKTYPE_IEEE802_11) {
    return;  // not an 802.11 capture
  }
  if (frame.size() < 2) return;

  const MacHeader header = parse_mac_header(frame);
  FrameInfo info;
  info.index = index;
  info.timestamp = record.timestamp;
  info.frame_type = header.type;
  info.subtype = header.subtype;
  info.type_name = type_name(header.type);
  info.subtype_name = subtype_name(header.type, header.subtype);
  info.addr1 = header.addr1;
  info.addr2 = header.addr2;
  info.addr3 = header.addr3;
  info.to_ds = header.flags & 0x01;
  info.from_ds = header.flags & 0x02;
  info.retry = header.flags & 0x08;
  info.is_protected = header.flags & 0x40;
  info.length = record.data.size();
  if (radiotap) {
    info.signal_dbm = radiotap->signal_dbm;
    if (radiotap->frequency_mhz && *radiotap->frequency_mhz != 0) {
      info.channel = frequency_to_channel(*radiotap->frequency_mhz);
    }
  }

  // For infrastructure traffic addr3 is the BSSID, except when both DS bits
  // are set (a mesh/WDS frame), where there is no single BSSID.
  if (info.to_ds && !info.from_ds) {
    info.bssid = info.addr1;
  } else if (info.from_ds && !info.to_ds) {
    info.bssid = info.addr2;
  } else if (!info.to_ds && !info.from_ds) {
    info.bssid = info.addr3;
  }

  // A frame with an impossible transmitter address was corrupted in the air
  // or by the adapter. It is still counted in the frame totals (it was
  // genuinely received) but it must not be allowed to invent a network,
  // because a garbled beacon otherwise appears as a brand new access point
  // with a garbage SSID and gets reported as a finding.
  info.suspect = !info.transmitter_is_valid();
  if (info.suspect) {
    capture.suspect_frames += 1;
  } else {
    ByteView body = frame.subspan(header.length);
    classify_management(body, info, capture);
    classify_eapol(body, info, capture);
  }
  capture.frames.push_back(std::move(info));
}

// Associate stations with the BSSID they are talking through.
void attribute_clients(Capture& capture) {
  for (const FrameInfo& info : capture.frames) {
    if (!info.bssid) continue;
    Network* network = capture.find_network(*info.bssid);
    if (network == nullptr) continue;
    for (const auto* address : {&info.addr1, &info.addr2}) {
      if (*address && !(*address)->empty() && **address != network->bssid &&
          !(*address)->starts_with("ff:")) {
        network->clients.insert(**address);
      }
    }
  }
}

}  // namespace

std::string Network::security() const {
  return rsn ? rsn->generation() : "Open (no RSN element)";
}

double Capture::duration() const {
  if (frames.size() < 2) return 0.0;
  return frames.back().timestamp - frames.front().timestamp;
}

const Network* Capture::find_network(const std::string& bssid) const {
  auto it = by_bssid_.find(bssid);
  return it == by_bssid_.end() ? nullptr : &networks_[it->second];
}

Network* Capture::find_network(const std::string& bssid) {
  auto it = by_bssid_.find(bssid);
  return it == by_bssid_.end() ? nullptr : &networks_[it->second];
}

Network& Capture::network_for(const std::string& bssid) {
  auto [it, inserted] = by_bssid_.try_emplace(bssid, networks_.size());
  if (inserted) {
    Network network;
    network.bssid = bssid;
    networks_.push_back(std::move(network));
  }
  return networks_[it->second];
}

namespace {

void load_one(const PcapRecord& record, std::size_t index, Capture& capture) {
  try {
    load_frame(record, index, capture);
  } catch (const std::exception& exc) {  // the boundary is the point
    capture.parse_errors.push_back(std::format("frame {}: {}", index, exc.what()));
  }
}

}  // namespace

Capture load_capture(const std::string& path) {
  Capture capture(path);
  PcapReader reader(path);
  PcapRecord record;
  for (std::size_t index = 0; reader.next(record); ++index) load_one(record, index, capture);
  attribute_clients(capture);
  return capture;
}

Capture load_records(const std::string& path, const std::vector<PcapRecord>& records) {
  Capture capture(path);
  for (std::size_t index = 0; index < records.size(); ++index) {
    load_one(records[index], index, capture);
  }
  attribute_clients(capture);
  return capture;
}

}  // namespace airlock::wifi
