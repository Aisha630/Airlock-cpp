#include "akex/crypto.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <limits>
#include <stdexcept>

namespace airlock::akex {

struct Sha256::Impl {
  EVP_MD_CTX* ctx = nullptr;
};

Sha256::Sha256() : impl_(std::make_unique<Impl>()) {
  impl_->ctx = EVP_MD_CTX_new();
  if (impl_->ctx == nullptr || EVP_DigestInit_ex(impl_->ctx, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(impl_->ctx);
    throw std::runtime_error("SHA-256 initialisation failed");
  }
}

Sha256::~Sha256() { EVP_MD_CTX_free(impl_->ctx); }

void Sha256::update(ByteView data) {
  if (EVP_DigestUpdate(impl_->ctx, data.data(), data.size()) != 1) {
    throw std::runtime_error("SHA-256 update failed");
  }
}

Bytes Sha256::digest() {
  Bytes out(HASH_LEN);
  unsigned int length = 0;
  if (EVP_DigestFinal_ex(impl_->ctx, out.data(), &length) != 1 || length != HASH_LEN) {
    throw std::runtime_error("SHA-256 finalisation failed");
  }
  return out;
}

Bytes sha256(ByteView data) {
  Sha256 hash;
  hash.update(data);
  return hash.digest();
}

Bytes hmac_sha256(ByteView key, ByteView data) {
  // OpenSSL treats a null key pointer as "reuse the previous key", so an
  // empty key is passed as a valid pointer with length zero instead.
  static const unsigned char empty = 0;
  const unsigned char* key_ptr = key.empty() ? &empty : key.data();
  if (key.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    throw std::invalid_argument("HMAC key too long");
  }
  Bytes out(HASH_LEN);
  unsigned int length = 0;
  if (HMAC(EVP_sha256(), key_ptr, static_cast<int>(key.size()), data.data(), data.size(),
           out.data(), &length) == nullptr ||
      length != HASH_LEN) {
    throw std::runtime_error("HMAC-SHA256 failed");
  }
  return out;
}

Bytes random_bytes(std::size_t count) {
  Bytes out(count);
  if (count > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
      RAND_bytes(out.data(), static_cast<int>(count)) != 1) {
    throw std::runtime_error("CSPRNG failure");
  }
  return out;
}

bool constant_time_eq(ByteView a, ByteView b) {
  // Lengths are public (tags are fixed-size), so an early return on a length
  // mismatch leaks nothing an observer did not already know.
  if (a.size() != b.size()) return false;
  if (a.empty()) return true;
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

}  // namespace airlock::akex
