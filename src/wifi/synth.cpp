#include "wifi/synth.hpp"

#include <map>

#include "wifi/build.hpp"
#include "wifi/eapol.hpp"
#include "wifi/rsn.hpp"

namespace airlock::wifi::synth {
namespace {

using namespace airlock::wifi::build;

// Radiotap channel flags.
constexpr std::uint16_t CHAN_CCK = 0x0020;
constexpr std::uint16_t CHAN_OFDM = 0x0040;
constexpr std::uint16_t CHAN_2GHZ = 0x0080;
constexpr std::uint16_t CHAN_5GHZ = 0x0100;

// Capability Information (IEEE 802.11-2020 Figure 9-68), little-endian on the
// air. Privacy must be set whenever an RSN element is present, and clear on
// the open evil twin.
constexpr std::uint16_t CAP_ESS = 0x0001;
constexpr std::uint16_t CAP_PRIVACY = 0x0010;
constexpr std::uint16_t CAP_SHORT_PREAMBLE = 0x0020;
constexpr std::uint16_t CAP_SHORT_SLOT = 0x0400;
constexpr std::uint16_t CAP_PRIVATE = CAP_ESS | CAP_PRIVACY | CAP_SHORT_PREAMBLE;
constexpr std::uint16_t CAP_OPEN = CAP_ESS | CAP_SHORT_PREAMBLE;

// Fabricated nonces. Fixed, not random, so the capture is byte-identical on
// every regeneration and the tests can assert on it.
const Bytes ANONCE_1 = repeat(0xa1, 32);
const Bytes SNONCE_1 = repeat(0x51, 32);
const Bytes ANONCE_2 = repeat(0xa2, 32);
const Bytes SNONCE_2 = repeat(0x52, 32);

// Radiotap header, as a capturing adapter would prepend.
Bytes rt(int channel, int signal) {
  static const std::map<int, std::uint16_t> frequencies = {
      {1, 2412}, {6, 2437}, {11, 2462}, {36, 5180}};
  auto it = frequencies.find(channel);
  const std::uint16_t frequency = it == frequencies.end() ? 2437 : it->second;
  const std::uint16_t flags = frequency > 3000 ? CHAN_5GHZ | CHAN_OFDM : CHAN_2GHZ | CHAN_CCK;
  return radiotap(frequency, flags, static_cast<std::int8_t>(signal));
}

// Standard beacon element chain: SSID, rates, DS parameter, RSN.
Bytes elements(const std::string& ssid, int channel, const Bytes* rsn) {
  Bytes out = element(0, to_bytes(ssid));
  append(out, element(1, Bytes{0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24}));  // rates
  append(out, element(3, Bytes{static_cast<std::uint8_t>(channel)}));             // DS parameter set
  if (rsn != nullptr) append(out, element(48, *rsn));
  return out;
}

Bytes beacon(const char* bssid, const std::string& ssid, int channel, const Bytes* rsn,
             int signal) {
  return concat({rt(channel, signal), dot11(0, 8, 0, BROADCAST, bssid, bssid),
                 beacon_body(100, rsn ? CAP_PRIVATE : CAP_OPEN), elements(ssid, channel, rsn)});
}

// Assemble an EAPOL-Key body per IEEE 802.11-2020 Figure 12-33.
//
// The MIC is filler. Computing a real one needs the PTK, which needs the
// passphrase, and this project deliberately never derives key material from a
// passphrase. The analyzer reads flag bits, counters and nonces, none of which
// depend on the MIC being valid.
Bytes eapol_key(std::uint16_t key_info, std::uint64_t replay_counter, const Bytes& nonce,
                const Bytes& key_data = {}, const Bytes& key_mic = Bytes(16, 0)) {
  Bytes body = {2};  // descriptor type: RSN
  put_be16(body, key_info);
  put_be16(body, 16);  // key length
  put_be64(body, replay_counter);
  append(body, nonce);
  body.insert(body.end(), 16 + 8 + 8, 0);  // key IV, key RSC, reserved
  append(body, key_mic);
  put_be16(body, static_cast<std::uint16_t>(key_data.size()));
  append(body, key_data);
  return body;
}

// A PMKID KDE: vendor element 221, OUI 00-0F-AC, data type 4.
Bytes pmkid_kde(const Bytes& value) {
  return element(221, concat({Bytes{0x00, 0x0f, 0xac, 0x04}, value}));
}

// Wrap an EAPOL-Key body in a data frame addressed through the AP.
Bytes eapol_frame(const char* source, const char* destination, const char* bssid,
                  const Bytes& body, bool from_ds, int channel, int signal) {
  const Bytes header = from_ds ? dot11(2, 0, FC_FROM_DS, destination, bssid, source)
                               : dot11(2, 0, FC_TO_DS, bssid, source, destination);
  return concat({rt(channel, signal), header, llc_snap_eapol(), eapol(EAPOL_TYPE_KEY, body)});
}

// A protected QoS data frame. The payload is filler standing in for ciphertext.
Bytes data(const char* source, const char* destination, const char* bssid, bool from_ds,
           int channel, int signal, std::size_t size = 128) {
  const Bytes header = from_ds ? dot11(2, 8, FC_FROM_DS | FC_PROTECTED, destination, bssid, source)
                               : dot11(2, 8, FC_TO_DS | FC_PROTECTED, bssid, source, destination);
  return concat({rt(channel, signal), header, repeat(0xcc, size)});
}

// An ACK: control subtype 13, and the only address is the receiver.
Bytes ack(const char* receiver, int channel, int signal) {
  return concat({rt(channel, signal), dot11(1, 13, 0, receiver)});
}

Bytes rts(const char* receiver, const char* transmitter, int channel, int signal) {
  return concat({rt(channel, signal), dot11(1, 11, 0, receiver, transmitter)});
}

Bytes cts(const char* receiver, int channel, int signal) {
  return concat({rt(channel, signal), dot11(1, 12, 0, receiver)});
}

Bytes block_ack(const char* receiver, const char* transmitter, int channel, int signal) {
  return concat({rt(channel, signal), dot11(1, 9, 0, receiver, transmitter), Bytes(10, 0)});
}

Bytes mgmt(int subtype, int channel, int signal, const char* addr1, const char* addr2,
           const char* addr3, const Bytes& body) {
  return concat({rt(channel, signal), dot11(0, subtype, 0, addr1, addr2, addr3), body});
}

class Emitter {
 public:
  // The fixed epoch makes the capture deterministic.
  void operator()(Bytes frame, double step = 0.002) {
    clock_ += step;
    records_.push_back(PcapRecord{clock_, LINKTYPE_IEEE802_11_RADIOTAP, std::move(frame)});
  }
  std::vector<PcapRecord> take() { return std::move(records_); }

 private:
  double clock_ = 1'700'000'000.0;
  std::vector<PcapRecord> records_;
};

// Emit one complete four-way handshake between STA_ONE and AP_WPA2.
void four_way(Emitter& emit, const Bytes& anonce, const Bytes& snonce, bool include_pmkid,
              std::uint64_t counter_base) {
  const Bytes key_data_m1 = include_pmkid ? pmkid_kde(pmkid()) : Bytes{};

  // M1: AP -> STA. ANonce, Ack set, no MIC (the STA has no PTK yet).
  emit(eapol_frame(AP_WPA2, STA_ONE, AP_WPA2,
                   eapol_key(KEY_INFO_PAIRWISE | KEY_INFO_ACK, counter_base, anonce, key_data_m1),
                   true, 6, -42),
       0.02);
  emit(ack(AP_WPA2, 6, -42), 0.0001);

  // M2: STA -> AP. SNonce plus the station's RSN element, MIC now present.
  const Bytes station_rsn = element(48, build_rsn_element({.akm_suites = {2}}));
  emit(eapol_frame(STA_ONE, AP_WPA2, AP_WPA2,
                   eapol_key(KEY_INFO_PAIRWISE | KEY_INFO_MIC, counter_base, snonce, station_rsn,
                             repeat(0x0a, 16)),
                   false, 6, -38),
       0.008);
  emit(ack(STA_ONE, 6, -38), 0.0001);

  // M3: AP -> STA. Install + Secure set; key data is encrypted under the KEK.
  emit(eapol_frame(AP_WPA2, STA_ONE, AP_WPA2,
                   eapol_key(KEY_INFO_PAIRWISE | KEY_INFO_ACK | KEY_INFO_MIC | KEY_INFO_SECURE |
                                 KEY_INFO_INSTALL | KEY_INFO_ENCRYPTED,
                             counter_base + 1, anonce, repeat(0xee, 56), repeat(0x0b, 16)),
                   true, 6, -42),
       0.007);
  emit(ack(AP_WPA2, 6, -42), 0.0001);

  // M4: STA -> AP. Zero nonce, Secure set, no key data. Handshake done.
  emit(eapol_frame(STA_ONE, AP_WPA2, AP_WPA2,
                   eapol_key(KEY_INFO_PAIRWISE | KEY_INFO_MIC | KEY_INFO_SECURE, counter_base + 1,
                             Bytes(32, 0), {}, repeat(0x0c, 16)),
                   false, 6, -38),
       0.006);
  emit(ack(STA_ONE, 6, -38), 0.0001);
}

}  // namespace

Bytes pmkid() { return from_hex("0123456789abcdef0123456789abcdef"); }

std::vector<PcapRecord> build_capture() {
  Emitter emit;

  const Bytes rsn_wpa2 = build_rsn_element({.akm_suites = {2}});  // PSK, CCMP, no MFP
  const Bytes rsn_wpa3 = build_rsn_element(
      {.akm_suites = {8}, .mfp_capable = true, .mfp_required = true, .group_mgmt_cipher = 6});
  const Bytes rsn_legacy = build_rsn_element({.group_cipher = 2, .pairwise_ciphers = {2, 4}});

  // 1. Beacons from three networks.
  for (int round = 0; round < 6; ++round) {
    emit(beacon(AP_WPA2, SSID_WPA2, 6, &rsn_wpa2, -42), 0.1024);
    emit(beacon(AP_WPA3, SSID_WPA3, 36, &rsn_wpa3, -55), 0.0016);
    emit(beacon(AP_LEGACY, SSID_LEGACY, 11, &rsn_legacy, -71), 0.0016);
  }

  // 2. Station one discovers and joins the WPA2 network.
  emit(mgmt(4, 6, -38, BROADCAST, STA_ONE, BROADCAST, element(0, Bytes{})), 0.05);  // wildcard
  emit(ack(STA_ONE, 6, -38), 0.0001);
  emit(mgmt(5, 6, -42, STA_ONE, AP_WPA2, AP_WPA2,
            concat({beacon_body(100, CAP_PRIVATE), elements(SSID_WPA2, 6, &rsn_wpa2)})),
       0.004);

  // Open System authentication: WPA2-PSK does not authenticate here at all,
  // it just says "yes". The real check is the four-way handshake later.
  auto join_wpa2 = [&](double first_step) {
    emit(mgmt(11, 6, -38, AP_WPA2, STA_ONE, AP_WPA2, auth_body(0, 1, 0)), first_step);
    emit(mgmt(11, 6, -42, STA_ONE, AP_WPA2, AP_WPA2, auth_body(0, 2, 0)), 0.003);
    emit(mgmt(0, 6, -38, AP_WPA2, STA_ONE, AP_WPA2,
              concat({assoc_request_body(CAP_PRIVATE, 10), elements(SSID_WPA2, 6, &rsn_wpa2)})),
         0.005);
    emit(mgmt(1, 6, -42, STA_ONE, AP_WPA2, AP_WPA2, assoc_response_body(CAP_PRIVATE, 0, 1)),
         0.004);
  };
  join_wpa2(0.01);

  // 3. Four-way handshake, with a PMKID leaked in message 1.
  four_way(emit, ANONCE_1, SNONCE_1, true, 1);

  // 4. Data exchange with control frames.
  for (std::size_t index = 0; index < 10; ++index) {
    emit(data(STA_ONE, AP_WPA2, AP_WPA2, false, 6, -39, 96 + index * 8), 0.012);
    emit(ack(STA_ONE, 6, -39), 0.0001);
    emit(data(AP_WPA2, STA_ONE, AP_WPA2, true, 6, -43, 512), 0.003);
    emit(ack(AP_WPA2, 6, -43), 0.0001);
    if (index % 4 == 0) {
      emit(rts(AP_WPA2, STA_ONE, 6, -39), 0.0008);
      emit(cts(STA_ONE, 6, -43), 0.0001);
    }
    if (index % 5 == 4) emit(block_ack(STA_ONE, AP_WPA2, 6, -43), 0.0006);
  }

  // 5. Deauthentication flood, spoofing the AP.
  //
  // The attacker transmits with the AP's address in addr2. Nothing in an
  // unprotected deauth prevents that: there is no MIC and no sequence binding,
  // so the frame is indistinguishable from a genuine one at the receiver.
  // Reason 7 ("class 3 frame from nonassociated STA") is the usual choice
  // because clients act on it immediately.
  for (int burst = 0; burst < 12; ++burst) {
    emit(mgmt(12, 6, -50, STA_ONE, AP_WPA2, AP_WPA2, reason_body(7)), 0.05);
    emit(mgmt(12, 6, -50, BROADCAST, AP_WPA2, AP_WPA2, reason_body(7)), 0.02);
  }

  // 6. The station reconnects; a second handshake is captured.
  join_wpa2(0.4);
  four_way(emit, ANONCE_2, SNONCE_2, false, 5);

  // 7. WPA3: SAE authentication on the 5 GHz AP.
  //
  // Authentication algorithm 3 is SAE. Unlike Open System above, these frames
  // carry the actual Dragonfly commit and confirm exchange: the
  // password-authenticated key exchange happens here, before association,
  // which is why WPA3 has no offline dictionary exposure.
  const Bytes commit_sta = concat({Bytes{0x13, 0x00}, repeat(0x5a, 96)});
  const Bytes commit_ap = concat({Bytes{0x13, 0x00}, repeat(0x6b, 96)});
  emit(mgmt(11, 36, -57, AP_WPA3, STA_TWO, AP_WPA3, concat({auth_body(3, 1, 0), commit_sta})), 0.3);
  emit(mgmt(11, 36, -55, STA_TWO, AP_WPA3, AP_WPA3, concat({auth_body(3, 1, 0), commit_ap})), 0.006);
  emit(mgmt(11, 36, -57, AP_WPA3, STA_TWO, AP_WPA3, concat({auth_body(3, 2, 0), Bytes(34, 0)})),
       0.004);  // confirm
  emit(mgmt(11, 36, -55, STA_TWO, AP_WPA3, AP_WPA3, concat({auth_body(3, 2, 0), Bytes(34, 0)})),
       0.004);
  emit(mgmt(0, 36, -57, AP_WPA3, STA_TWO, AP_WPA3,
            concat({assoc_request_body(CAP_PRIVATE | CAP_SHORT_SLOT, 10), elements(SSID_WPA3, 36, &rsn_wpa3)})),
       0.005);
  emit(mgmt(1, 36, -55, STA_TWO, AP_WPA3, AP_WPA3, assoc_response_body(CAP_PRIVATE | CAP_SHORT_SLOT, 0, 2)), 0.004);
  for (int index = 0; index < 4; ++index) {
    emit(data(STA_TWO, AP_WPA3, AP_WPA3, false, 36, -56, 160), 0.02);
    emit(ack(STA_TWO, 36, -56), 0.0001);
  }

  // 8. Evil twin: the WPA2 SSID, beaconed with no security.
  for (int i = 0; i < 5; ++i) emit(beacon(AP_EVIL_TWIN, SSID_WPA2, 6, nullptr, -33), 0.1024);

  // A deauth from the attacker's own address, aimed at pushing the station
  // onto the open clone.
  for (int i = 0; i < 3; ++i) {
    emit(mgmt(12, 6, -33, STA_ONE, ATTACKER, ATTACKER, reason_body(1)), 0.03);
  }

  return emit.take();
}

std::size_t write_capture(const std::string& path) {
  const std::vector<PcapRecord> records = build_capture();
  write_pcap(path, records);
  return records.size();
}

}  // namespace airlock::wifi::synth
