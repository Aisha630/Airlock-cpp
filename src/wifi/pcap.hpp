// Reading and writing capture files.
//
// The reader handles classic pcap (either byte order, microsecond or
// nanosecond timestamps) and pcapng (Enhanced and Simple Packet Blocks, with
// per-interface link types and timestamp resolution). The writer produces
// classic little-endian pcap, which is what the synthetic capture uses.
#pragma once

#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "common/bytes.hpp"

namespace airlock::wifi {

inline constexpr std::uint32_t LINKTYPE_IEEE802_11 = 105;
inline constexpr std::uint32_t LINKTYPE_IEEE802_11_RADIOTAP = 127;

class PcapError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

struct PcapRecord {
  double timestamp = 0.0;  // seconds since the epoch
  std::uint32_t linktype = 0;
  Bytes data;
};

class PcapReader {
 public:
  explicit PcapReader(const std::string& path);

  // Read the next packet into `record`. Returns false at the end of the file.
  bool next(PcapRecord& record);

 private:
  bool next_classic(PcapRecord& record);
  bool next_pcapng(PcapRecord& record);
  bool read_exact(void* out, std::size_t size);
  std::uint32_t u32(const std::uint8_t* p) const;
  std::uint16_t u16(const std::uint8_t* p) const;

  struct Interface {
    std::uint32_t linktype = 0;
    // Timestamp units per second, as base^exponent.
    bool binary = false;
    int exponent = 6;
  };

  std::ifstream in_;
  bool pcapng_ = false;
  bool big_endian_ = false;
  bool nanosecond_ = false;
  std::uint32_t linktype_ = 0;
  std::vector<Interface> interfaces_;
};

class PcapWriter {
 public:
  PcapWriter(const std::string& path, std::uint32_t linktype = LINKTYPE_IEEE802_11_RADIOTAP);

  // Append one packet stamped with `timestamp` (seconds since the epoch),
  // stored as whole seconds plus microseconds rounded half-to-even.
  void write(double timestamp, ByteView data);

 private:
  std::ofstream out_;
};

// Write a whole capture in one call.
void write_pcap(const std::string& path, const std::vector<PcapRecord>& records);

}  // namespace airlock::wifi
