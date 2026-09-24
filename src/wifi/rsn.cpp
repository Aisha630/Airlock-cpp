#include "wifi/rsn.hpp"

#include <algorithm>
#include <array>
#include <map>
#include <set>

namespace airlock::wifi {
namespace {

// The OUI that prefixes every standard cipher and AKM suite selector.
constexpr std::array<std::uint8_t, 3> OUI_IEEE = {0x00, 0x0f, 0xac};
// Legacy WPA1 used Microsoft's OUI with type 1 in a vendor-specific element.
constexpr std::array<std::uint8_t, 3> OUI_MICROSOFT = {0x00, 0x50, 0xf2};

const std::map<int, std::string>& cipher_suites() {
  static const std::map<int, std::string> table = {
      {0, "use-group-cipher"}, {1, "WEP-40"},       {2, "TKIP"},         {4, "CCMP-128"},
      {5, "WEP-104"},          {6, "BIP-CMAC-128"}, {8, "GCMP-128"},     {9, "GCMP-256"},
      {10, "CCMP-256"},        {11, "BIP-GMAC-128"}, {12, "BIP-GMAC-256"}, {13, "BIP-CMAC-256"},
  };
  return table;
}

const std::map<int, std::string>& akm_suites() {
  static const std::map<int, std::string> table = {
      {1, "802.1X"},         {2, "PSK"},     {3, "FT-802.1X"},       {4, "FT-PSK"},
      {5, "802.1X-SHA256"},  {6, "PSK-SHA256"}, {8, "SAE"},          {9, "FT-SAE"},
      {11, "802.1X-SUITE-B"}, {12, "802.1X-SUITE-B-192"}, {18, "OWE"}, {24, "PSK-SHA384"},
  };
  return table;
}

// Ciphers no network should still be offering. Presence is a finding.
const std::set<std::string> BROKEN_CIPHERS = {"WEP-40", "WEP-104", "TKIP"};

bool has_oui(ByteView data, std::size_t at, const std::array<std::uint8_t, 3>& oui) {
  return data.size() >= at + 3 && std::equal(oui.begin(), oui.end(), data.begin() + static_cast<std::ptrdiff_t>(at));
}

// Decode a 4-byte suite selector: 3-byte OUI plus a 1-byte type.
std::string suite_name(ByteView data, std::size_t at, const std::map<int, std::string>& table) {
  if (data.size() < at + 4) throw RSNParseError("suite selector must be 4 bytes");
  const int suite_type = data[at + 3];
  auto named = [&](const std::string& fallback_prefix) {
    auto it = table.find(suite_type);
    return it != table.end() ? it->second : fallback_prefix + std::to_string(suite_type);
  };
  if (has_oui(data, at, OUI_IEEE)) return named("unknown-");
  if (has_oui(data, at, OUI_MICROSOFT)) return named("wpa1-unknown-");
  return "vendor-" + to_hex(data.subspan(at, 3)) + "-" + std::to_string(suite_type);
}

bool contains(const std::set<std::string>& set, const std::vector<std::string>& values) {
  return std::any_of(values.begin(), values.end(),
                     [&](const std::string& v) { return set.count(v) > 0; });
}

}  // namespace

std::string RSNInfo::generation() const {
  const bool has_sae = contains({"SAE", "FT-SAE"}, akm_suites);
  const bool has_psk = contains({"PSK", "FT-PSK", "PSK-SHA256", "PSK-SHA384"}, akm_suites);
  const bool has_enterprise = contains(
      {"802.1X", "FT-802.1X", "802.1X-SHA256", "802.1X-SUITE-B", "802.1X-SUITE-B-192"},
      akm_suites);
  if (contains({"OWE"}, akm_suites)) return "OWE (opportunistic wireless encryption)";
  if (has_sae && has_psk) return "WPA3/WPA2 transition mode";
  if (has_sae) return "WPA3-Personal (SAE)";
  if (has_enterprise) return "WPA2/WPA3-Enterprise (802.1X)";
  if (has_psk) return is_wpa1 ? "WPA1-Personal (PSK)" : "WPA2-Personal (PSK)";
  return "unknown";
}

std::string RSNInfo::mfp_state() const {
  if (mfp_required) return "required";
  if (mfp_capable) return "capable but optional";
  return "not supported";
}

std::vector<std::string> RSNInfo::weaknesses() const {
  std::vector<std::string> issues;
  std::set<std::string> offered(pairwise_ciphers.begin(), pairwise_ciphers.end());
  offered.insert(group_cipher);
  for (const std::string& cipher : offered) {  // std::set iterates in sorted order
    if (BROKEN_CIPHERS.count(cipher) == 0) continue;
    issues.push_back(cipher == group_cipher
                         ? cipher +
                               " is offered; it is cryptographically broken and its presence in "
                               "the group cipher weakens every client"
                         : cipher + " is offered as a pairwise cipher and is broken");
  }
  if (!mfp_capable) {
    issues.push_back(
        "management frame protection is not supported, so deauthentication and "
        "disassociation frames are forgeable");
  } else if (!mfp_required) {
    issues.push_back(
        "management frame protection is optional, so a client that does not negotiate it "
        "stays exposed to forged deauths");
  }
  if (generation() == "WPA3/WPA2 transition mode") {
    issues.push_back(
        "transition mode allows a downgrade from SAE to PSK, which re-exposes the passphrase "
        "to offline dictionary attack");
  }
  if (is_wpa1) issues.push_back("legacy WPA1 element present; WPA1 is deprecated");
  return issues;
}

RSNInfo parse_rsn_element(ByteView data) {
  if (data.size() < 2) throw RSNParseError("RSN element too short for a version field");
  RSNInfo info;
  info.version = get_le16(data, 0);
  std::size_t offset = 2;

  if (data.size() >= offset + 4) {
    info.group_cipher = suite_name(data, offset, cipher_suites());
    offset += 4;
  }

  if (data.size() >= offset + 2) {
    const std::size_t count = get_le16(data, offset);
    offset += 2;
    for (std::size_t i = 0; i < count; ++i) {
      if (data.size() < offset + 4) throw RSNParseError("pairwise cipher list truncated");
      info.pairwise_ciphers.push_back(suite_name(data, offset, cipher_suites()));
      offset += 4;
    }
  }

  if (data.size() >= offset + 2) {
    const std::size_t count = get_le16(data, offset);
    offset += 2;
    for (std::size_t i = 0; i < count; ++i) {
      if (data.size() < offset + 4) throw RSNParseError("AKM suite list truncated");
      info.akm_suites.push_back(suite_name(data, offset, akm_suites()));
      offset += 4;
    }
  }

  if (data.size() >= offset + 2) {
    const int capabilities = get_le16(data, offset);
    offset += 2;
    info.raw_capabilities = capabilities;
    // IEEE 802.11-2020 Figure 9-257: bit 6 MFPR, bit 7 MFPC.
    info.mfp_required = (capabilities & (1 << 6)) != 0;
    info.mfp_capable = (capabilities & (1 << 7)) != 0;
  }

  if (data.size() >= offset + 2) {
    const int pmkid_count = get_le16(data, offset);
    offset += 2;
    info.pmkids = pmkid_count;
    offset += 16 * static_cast<std::size_t>(pmkid_count);
  }

  // The group management cipher only appears when MFP is in use.
  if (data.size() >= offset + 4) {
    info.group_mgmt_cipher = suite_name(data, offset, cipher_suites());
  }
  return info;
}

std::optional<RSNInfo> parse_wpa1_element(ByteView data) {
  if (data.size() < 6 || !has_oui(data, 0, OUI_MICROSOFT) || data[3] != 1) return std::nullopt;
  RSNInfo info;
  info.is_wpa1 = true;
  info.version = get_le16(data, 4);
  std::size_t offset = 6;

  if (data.size() >= offset + 4) {
    info.group_cipher = suite_name(data, offset, cipher_suites());
    offset += 4;
  }
  if (data.size() >= offset + 2) {
    const std::size_t count = get_le16(data, offset);
    offset += 2;
    for (std::size_t i = 0; i < count && data.size() >= offset + 4; ++i) {
      info.pairwise_ciphers.push_back(suite_name(data, offset, cipher_suites()));
      offset += 4;
    }
  }
  if (data.size() >= offset + 2) {
    const std::size_t count = get_le16(data, offset);
    offset += 2;
    for (std::size_t i = 0; i < count && data.size() >= offset + 4; ++i) {
      info.akm_suites.push_back(suite_name(data, offset, akm_suites()));
      offset += 4;
    }
  }
  return info;
}

Bytes build_rsn_element(const RsnSpec& spec) {
  auto suite = [](Bytes& out, std::uint8_t type) {
    out.insert(out.end(), OUI_IEEE.begin(), OUI_IEEE.end());
    out.push_back(type);
  };
  Bytes body;
  put_le16(body, 1);
  suite(body, spec.group_cipher);
  put_le16(body, static_cast<std::uint16_t>(spec.pairwise_ciphers.size()));
  for (std::uint8_t cipher : spec.pairwise_ciphers) suite(body, cipher);
  put_le16(body, static_cast<std::uint16_t>(spec.akm_suites.size()));
  for (std::uint8_t akm : spec.akm_suites) suite(body, akm);
  std::uint16_t capabilities = 0;
  if (spec.mfp_required) capabilities |= 1 << 6;
  if (spec.mfp_capable) capabilities |= 1 << 7;
  put_le16(body, capabilities);
  if (spec.group_mgmt_cipher) {
    put_le16(body, 0);  // PMKID count
    suite(body, *spec.group_mgmt_cipher);
  }
  return body;
}

}  // namespace airlock::wifi
