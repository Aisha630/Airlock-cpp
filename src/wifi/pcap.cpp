#include "wifi/pcap.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <format>

namespace airlock::wifi {
namespace {

constexpr std::uint32_t PCAP_MAGIC_USEC = 0xa1b2c3d4;
constexpr std::uint32_t PCAP_MAGIC_NSEC = 0xa1b23c4d;
constexpr std::uint32_t PCAPNG_SHB = 0x0A0D0D0A;
constexpr std::uint32_t PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D;
constexpr std::uint32_t PCAPNG_IDB = 1;
constexpr std::uint32_t PCAPNG_SPB = 3;
constexpr std::uint32_t PCAPNG_EPB = 6;

// Anything larger is not a packet but a corrupt length field.
constexpr std::uint32_t MAX_RECORD = 16 * 1024 * 1024;

std::uint32_t swap32(std::uint32_t v) {
  return (v >> 24) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | (v << 24);
}

// "units / 10^exponent" as the nearest double to the exact decimal value,
// so a timestamp is read exactly as it was written.
double decimal_seconds(std::uint64_t units, int exponent) {
  std::string digits = std::to_string(units);
  if (exponent > 0) {
    if (digits.size() <= static_cast<std::size_t>(exponent)) {
      digits.insert(0, static_cast<std::size_t>(exponent) - digits.size() + 1, '0');
    }
    digits.insert(digits.size() - static_cast<std::size_t>(exponent), ".");
  }
  double out = 0;
  std::from_chars(digits.data(), digits.data() + digits.size(), out);
  return out;
}

}  // namespace

PcapReader::PcapReader(const std::string& path) : in_(path, std::ios::binary) {
  if (!in_) throw PcapError("cannot open " + path);
  std::uint8_t magic[4];
  if (!read_exact(magic, 4)) throw PcapError(path + ": file too short to be a capture");
  const std::uint32_t le = magic[0] | magic[1] << 8 | magic[2] << 16 |
                           static_cast<std::uint32_t>(magic[3]) << 24;

  if (le == PCAPNG_SHB) {
    pcapng_ = true;
    in_.seekg(0);
    return;
  }
  if (le == PCAP_MAGIC_USEC || le == PCAP_MAGIC_NSEC) {
    big_endian_ = false;
  } else if (swap32(le) == PCAP_MAGIC_USEC || swap32(le) == PCAP_MAGIC_NSEC) {
    big_endian_ = true;
  } else {
    throw PcapError(path + ": not a pcap or pcapng file");
  }
  nanosecond_ = (big_endian_ ? swap32(le) : le) == PCAP_MAGIC_NSEC;

  std::uint8_t rest[20];
  if (!read_exact(rest, sizeof rest)) throw PcapError(path + ": truncated pcap header");
  linktype_ = u32(rest + 16) & 0x0fffffff;
}

bool PcapReader::read_exact(void* out, std::size_t size) {
  in_.read(static_cast<char*>(out), static_cast<std::streamsize>(size));
  return static_cast<std::size_t>(in_.gcount()) == size;
}

std::uint32_t PcapReader::u32(const std::uint8_t* p) const {
  return big_endian_ ? static_cast<std::uint32_t>(p[0]) << 24 | p[1] << 16 | p[2] << 8 | p[3]
                     : p[0] | p[1] << 8 | p[2] << 16 | static_cast<std::uint32_t>(p[3]) << 24;
}

std::uint16_t PcapReader::u16(const std::uint8_t* p) const {
  return static_cast<std::uint16_t>(big_endian_ ? p[0] << 8 | p[1] : p[0] | p[1] << 8);
}

bool PcapReader::next(PcapRecord& record) {
  return pcapng_ ? next_pcapng(record) : next_classic(record);
}

bool PcapReader::next_classic(PcapRecord& record) {
  std::uint8_t header[16];
  if (!read_exact(header, sizeof header)) return false;
  const std::uint32_t sec = u32(header);
  const std::uint32_t frac = u32(header + 4);
  const std::uint32_t caplen = u32(header + 8);
  if (caplen > MAX_RECORD) throw PcapError(std::format("record length {} is implausible", caplen));

  record.data.resize(caplen);
  in_.read(reinterpret_cast<char*>(record.data.data()), caplen);
  // A record cut short by the end of the file is kept as far as it goes.
  record.data.resize(static_cast<std::size_t>(in_.gcount()));
  record.linktype = linktype_;
  const int exponent = nanosecond_ ? 9 : 6;
  const std::uint64_t per_second = nanosecond_ ? 1000000000ULL : 1000000ULL;
  record.timestamp = decimal_seconds(sec * per_second + frac, exponent);
  return true;
}

bool PcapReader::next_pcapng(PcapRecord& record) {
  while (true) {
    std::uint8_t head[8];
    if (!read_exact(head, sizeof head)) return false;

    std::uint32_t type = u32(head);
    if (type == PCAPNG_SHB || swap32(type) == PCAPNG_SHB) {
      // A section header resets the byte order and the interface list.
      std::uint8_t bom[4];
      if (!read_exact(bom, 4)) return false;
      const std::uint32_t le = bom[0] | bom[1] << 8 | bom[2] << 16 |
                               static_cast<std::uint32_t>(bom[3]) << 24;
      if (le == PCAPNG_BYTE_ORDER_MAGIC) {
        big_endian_ = false;
      } else if (swap32(le) == PCAPNG_BYTE_ORDER_MAGIC) {
        big_endian_ = true;
      } else {
        throw PcapError("pcapng section header has a bad byte-order magic");
      }
      interfaces_.clear();
      const std::uint32_t length = u32(head + 4);
      if (length < 12 || length > MAX_RECORD) throw PcapError("pcapng block length is implausible");
      in_.seekg(length - 12, std::ios::cur);
      continue;
    }

    const std::uint32_t length = u32(head + 4);
    if (length < 12 || length > MAX_RECORD) throw PcapError("pcapng block length is implausible");
    Bytes body(length - 8);
    if (!read_exact(body.data(), body.size())) return false;
    body.resize(body.size() - 4);  // trailing copy of the block length

    if (type == PCAPNG_IDB && body.size() >= 8) {
      Interface iface;
      iface.linktype = u16(body.data());
      // Options follow the fixed part; if_tsresol (code 9) sets the clock.
      std::size_t at = 8;
      while (at + 4 <= body.size()) {
        const std::uint16_t code = u16(body.data() + at);
        const std::uint16_t size = u16(body.data() + at + 2);
        at += 4;
        if (code == 0 || at + size > body.size()) break;
        if (code == 9 && size >= 1) {
          iface.binary = (body[at] & 0x80) != 0;
          iface.exponent = body[at] & 0x7f;
        }
        at += (size + 3u) & ~3u;
      }
      interfaces_.push_back(iface);
      continue;
    }

    if (type == PCAPNG_EPB && body.size() >= 20) {
      const std::uint32_t iface_id = u32(body.data());
      if (iface_id >= interfaces_.size()) continue;
      const Interface& iface = interfaces_[iface_id];
      const std::uint64_t ts = static_cast<std::uint64_t>(u32(body.data() + 4)) << 32 |
                               u32(body.data() + 8);
      const std::uint32_t caplen = u32(body.data() + 12);
      const std::size_t available = std::min<std::size_t>(caplen, body.size() - 20);
      record.data.assign(body.begin() + 20, body.begin() + 20 + static_cast<std::ptrdiff_t>(available));
      record.linktype = iface.linktype;
      record.timestamp = iface.binary ? std::ldexp(static_cast<double>(ts), -iface.exponent)
                                      : decimal_seconds(ts, iface.exponent);
      return true;
    }

    if (type == PCAPNG_SPB && body.size() >= 4 && !interfaces_.empty()) {
      const std::uint32_t original = u32(body.data());
      const std::size_t available = std::min<std::size_t>(original, body.size() - 4);
      record.data.assign(body.begin() + 4, body.begin() + 4 + static_cast<std::ptrdiff_t>(available));
      record.linktype = interfaces_[0].linktype;
      record.timestamp = 0.0;  // simple packet blocks carry no timestamp
      return true;
    }
    // Any other block (statistics, name resolution, custom) is skipped.
  }
}

PcapWriter::PcapWriter(const std::string& path, std::uint32_t linktype)
    : out_(path, std::ios::binary | std::ios::trunc) {
  if (!out_) throw PcapError("cannot write " + path);
  Bytes header;
  put_le32(header, PCAP_MAGIC_USEC);
  put_le16(header, 2);  // version 2.4
  put_le16(header, 4);
  put_le32(header, 0);  // GMT offset
  put_le32(header, 0);  // timestamp accuracy
  put_le32(header, 65535);
  put_le32(header, linktype);
  out_.write(reinterpret_cast<const char*>(header.data()), static_cast<std::streamsize>(header.size()));
}

void PcapWriter::write(double timestamp, ByteView data) {
  const double whole = std::trunc(timestamp);
  // nearbyint rounds half-to-even under the default rounding mode.
  const auto usec = static_cast<std::uint32_t>(std::nearbyint((timestamp - whole) * 1e6));
  Bytes header;
  put_le32(header, static_cast<std::uint32_t>(whole));
  put_le32(header, usec);
  put_le32(header, static_cast<std::uint32_t>(data.size()));
  put_le32(header, static_cast<std::uint32_t>(data.size()));
  out_.write(reinterpret_cast<const char*>(header.data()), static_cast<std::streamsize>(header.size()));
  out_.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  if (!out_) throw PcapError("write failed");
}

void write_pcap(const std::string& path, const std::vector<PcapRecord>& records) {
  PcapWriter writer(path, records.empty() ? LINKTYPE_IEEE802_11_RADIOTAP : records[0].linktype);
  for (const PcapRecord& record : records) writer.write(record.timestamp, record.data);
}

}  // namespace airlock::wifi
