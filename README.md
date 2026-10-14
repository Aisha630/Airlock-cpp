# Airlock (C++)

It needs a C++20 compiler, CMake 3.20 or later, and OpenSSL 3. GoogleTest is
used if installed and fetched otherwise. There are 202 tests.

## Running it

```sh
make build                                   # configure and compile into build/
make test                                    # run the test suite
make demo                                    # exercise both halves
make sanitize                                # tests under ASan and UBSan

build/akex handshake [--psk TEXT] [--group {14,15}]
build/akex attacks
build/wifi synth [OUTPUT]
build/wifi analyze PCAP [--json PATH] [--fail-on-high]
```

`--fail-on-high` exits non-zero when a high-severity finding is present, so
the analyzer can run as an automated check. Sample output is committed at
`docs/sample-report.txt`.

## The key exchange

The handshake is three messages. The initiator sends a group identifier, a
nonce and its public value. The responder replies with its own nonce, public
value and an authentication tag. The initiator returns a second tag.

```
  I -> R    group_id, nonce_i, g^i
  R -> I    nonce_r, g^r, tag_r
  I -> R    tag_i
```

Diffie-Hellman on its own agrees a secret with whoever you actually talked
to, and says nothing about who that was, so I bind the exchange to a
pre-shared key. Each tag is an HMAC-SHA256 over a hash of the transcript so
far, under a key derived from both the DH shared secret and the pre-shared
key, so a valid tag proves you hold the key and saw this exact exchange. The
key schedule follows RFC 5869:

```
salt = SHA256("AKEX v1 salt" || nonce_i || nonce_r || psk)
prk  = HKDF-Extract(salt, g^ir)
th   = SHA256(length-prefixed msg1 || length-prefixed msg2 core)

auth_i      = HKDF-Expand(prk, "AKEX v1 initiator auth"  || th, 32)
auth_r      = HKDF-Expand(prk, "AKEX v1 responder auth"  || th, 32)
session_i2r = HKDF-Expand(prk, "AKEX v1 session key i2r" || th, 32)
session_r2i = HKDF-Expand(prk, "AKEX v1 session key r2i" || th, 32)
```

I wrote HKDF in `src/akex/kdf.cpp` directly from the RFC on top of OpenSSL's
HMAC and check it against the Appendix A vectors. A peer's public value is
validated before any shared secret is computed: the range check
`2 <= y <= p-2` rules out values that pin the secret, and the subgroup test
`y^q mod p == 1` rules out elements that would leak exponent bits. Unknown
group identifiers are refused, which closes the usual route into a
downgrade.

Moving to C++ let me fix the side channel I had to accept in Python. Every
exponentiation with a private exponent now goes through OpenSSL's
`BN_mod_exp_mont_consttime`, private exponents are held in a small RAII
wrapper that wipes them on release, and tags are compared with
`CRYPTO_memcmp`. I kept the dangerous operations behind distinct names
(`mod_exp` for public inputs, `mod_exp_secret` for secret ones) so the
choice is visible at every call site.

`src/akex/channel.cpp` provides an authenticated record layer whose tag
covers the direction, a sequence number and the payload length, which stops
reflection, replay and truncation. It authenticates but does not encrypt.
`build/akex attacks` runs seven attacks, all blocked, plus two controls; the
important control repeats the machine-in-the-middle attack with the
authentication removed, where it succeeds completely.

## The capture analyzer

The Python version leaned on Scapy for link-layer dissection. Here I parse
everything from the byte layout myself: the pcap and pcapng containers,
radiotap with its field alignment rules and optional FCS, the MAC header
whose address fields depend on type and subtype, the fixed fields of each
management frame, information elements, and the LLC/SNAP encapsulation that
carries EAPOL. Every read is length-checked and every frame is parsed inside
its own error boundary, so one malformed transmission cannot end the run.

The RSN element parser in `src/wifi/rsn.cpp` reads the group, pairwise and
AKM suites and the two management frame protection bits, and names the
security generation, including WPA3/WPA2 transition mode, which I report
separately because it allows a downgrade from SAE to PSK. `src/wifi/eapol.cpp`
identifies each four-way handshake message from its Key Information bits,
extracts PMKIDs from message 1, and keeps repeated handshakes between the
same pair separate. Detectors then look for deauthentication floods,
conflicting responses during association, forgeable management frames, evil
twins, weak configurations and offline attack material. Offline password
guessing claims require PSK-only advertised authentication; SAE, enterprise,
mixed and unknown authentication produce informational handshake observations.
PMF protects established associations but does not guarantee connection setup
is immune to unprotected disconnects. Every finding carries its evidence and
a benign explanation where one exists.

## How I checked the port

The generated capture is the same scenario as before, so I could compare the
two implementations directly. The C++ generator reproduces the Python pcap
byte for byte, and the text and JSON reports are identical. I also built
fifteen edge-case captures with Scapy (corrupted transmitter addresses,
truncated and non-UTF-8 elements, malformed RSN, WPA1, FCS trailers,
QoS-encapsulated EAPOL, raw 802.11 and pcapng) and both analyzers agree on
every one. The suite and a mutation fuzz of about 34,000 corrupted frames
also run clean under AddressSanitizer and UBSan.

The comparison found two bugs in the Python version, which I fixed there
too. Scapy's `cap` field numbers its bits differently from the standard, so
the generator's capability words did not mean what its comments said, and
the open evil twin advertised Privacy. And Scapy turns a malformed RSN
element into raw bytes, which hid it from the Python parser instead of
reporting it as a parse error.

## Limitations

The record layer gives integrity and authenticity but not confidentiality.
An attacker who records a handshake can still test guesses against a
low-entropy pre-shared key offline; fixing that needs a password
authenticated key exchange such as SAE or OPAQUE. The analyzer does no
passphrase recovery, key recovery or payload decryption, and its detectors
are heuristics with documented false-positive modes. All capture work was
done against hardware I own, and the deauthentication frames in the
generated capture were never transmitted.

## Layout

```
src/akex/   params     RFC 3526 MODP group definitions
            bignum     OpenSSL BIGNUM wrapper, constant-time modexp
            dh         Diffie-Hellman with public value validation
            crypto     SHA-256, HMAC, CSPRNG, constant-time compare
            kdf        HKDF-SHA256 (RFC 5869)
            wire       Canonical message encoding and transcript hashing
            protocol   Handshake state machines and key schedule
            channel    Authenticated record layer
            attacks    Adversary simulations
src/wifi/   pcap       pcap and pcapng reader, pcap writer
            capture    Radiotap, MAC header, element and EAPOL dissection
            frames     Frame classification, reason and status codes
            rsn        RSN and legacy WPA element parser
            eapol      EAPOL-Key parsing and handshake tracking
            anomalies  Detectors
            report     Text and JSON reports
            synth      Generated capture
tools/      akex.cpp, wifi.cpp command line entry points
```

`THREAT_MODEL.md` has a STRIDE analysis of both halves with mitigations
mapped to tests. `docs/CAPTURE.md` covers the monitor-mode capture procedure
on macOS and Linux and the containment I followed.

## References

- IEEE 802.11-2020, §9.4.2.24 (RSN element) and §12.7 (key hierarchy)
- RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function
- RFC 3526, More Modular Exponential Diffie-Hellman Groups for IKE
- RFC 2104, HMAC: Keyed-Hashing for Message Authentication
- Radiotap, https://www.radiotap.org/
