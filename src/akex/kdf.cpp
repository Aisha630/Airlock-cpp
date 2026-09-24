#include "akex/kdf.hpp"

#include <stdexcept>
#include <string>

#include "akex/crypto.hpp"

namespace airlock::akex {

Bytes hkdf_extract(ByteView salt, ByteView ikm) {
  if (salt.empty()) {
    // RFC 5869: an absent salt is HashLen zero bytes.
    const Bytes zeros(HASH_LEN, 0);
    return hmac_sha256(zeros, ikm);
  }
  return hmac_sha256(salt, ikm);
}

Bytes hkdf_expand(ByteView prk, ByteView info, std::size_t length) {
  constexpr std::size_t max_length = 255 * HASH_LEN;
  if (length > max_length) {
    throw std::invalid_argument("cannot expand to more than " + std::to_string(max_length) +
                                " bytes");
  }
  if (prk.size() < HASH_LEN) throw std::invalid_argument("prk is shorter than the hash length");

  Bytes okm;
  okm.reserve(length + HASH_LEN);
  Bytes block;
  std::uint8_t counter = 1;
  while (okm.size() < length) {
    Bytes input = block;
    append(input, info);
    input.push_back(counter);
    block = hmac_sha256(prk, input);
    append(okm, block);
    ++counter;
  }
  okm.resize(length);
  return okm;
}

Bytes hkdf(ByteView ikm, ByteView salt, ByteView info, std::size_t length) {
  return hkdf_expand(hkdf_extract(salt, ikm), info, length);
}

}  // namespace airlock::akex
