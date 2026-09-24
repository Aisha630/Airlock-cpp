// HKDF-SHA256, implemented directly from RFC 5869.
//
// This is deliberately hand-rolled rather than taken from OpenSSL's HKDF: the
// point of the exercise is to build the key schedule out of one primitive
// (HMAC-SHA256) and be able to defend every line of it. tests/test_kdf.cpp
// checks this implementation against the vectors in RFC 5869 Appendix A.
#pragma once

#include <cstddef>

#include "common/bytes.hpp"

namespace airlock::akex {

// RFC 5869 Section 2.2: compress input keying material to a fixed-size PRK.
//
// Extract exists because raw DH output is not uniformly random: it is a
// field element with structure. HMAC with the salt as key is what turns it
// into something we can treat as a uniform 256-bit key.
Bytes hkdf_extract(ByteView salt, ByteView ikm);

// RFC 5869 Section 2.3: stretch a PRK into `length` bytes bound to `info`.
//
// `info` is the domain separator. Two keys derived from the same PRK with
// different `info` strings are computationally independent, which is what
// lets one handshake produce four distinct keys safely. Throws
// std::invalid_argument for an over-long request or a short PRK.
Bytes hkdf_expand(ByteView prk, ByteView info, std::size_t length);

// Full extract-then-expand, for callers that do not reuse the PRK.
Bytes hkdf(ByteView ikm, ByteView salt, ByteView info, std::size_t length);

}  // namespace airlock::akex
