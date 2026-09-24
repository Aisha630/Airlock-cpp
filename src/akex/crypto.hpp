// The primitives the key schedule is built from: SHA-256, HMAC-SHA256, a
// CSPRNG and a constant-time comparison. All four come from OpenSSL. What
// this project builds is the protocol around them, not the primitives.
#pragma once

#include <cstddef>
#include <initializer_list>
#include <memory>

#include "common/bytes.hpp"

namespace airlock::akex {

inline constexpr std::size_t HASH_LEN = 32;

Bytes sha256(ByteView data);

// Incremental SHA-256, for hashing a sequence of chunks without first
// concatenating them.
class Sha256 {
 public:
  Sha256();
  ~Sha256();
  Sha256(const Sha256&) = delete;
  Sha256& operator=(const Sha256&) = delete;

  void update(ByteView data);
  Bytes digest();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// HMAC-SHA256. The single primitive the rest of the schedule is built on.
Bytes hmac_sha256(ByteView key, ByteView data);

// Bytes from the OS CSPRNG via OpenSSL's RAND_bytes. Throws on failure
// rather than returning something predictable.
Bytes random_bytes(std::size_t count);

// Compare two byte strings without leaking where they first differ.
//
// A naive comparison returns as soon as it hits a mismatching byte. An
// attacker who can time many verification attempts can use that to recover
// a tag byte by byte, turning a 2^256 forgery into roughly 32 * 256 tries.
bool constant_time_eq(ByteView a, ByteView b);

}  // namespace airlock::akex
