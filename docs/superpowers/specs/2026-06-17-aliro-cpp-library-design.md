# Aliro C++ Library — Design Spec

**Date:** 2026-06-17
**Spec:** Aliro 1.0 (CSA document 26-42802-001, February 18 2026)
**Language:** C++17
**Build:** CMake 3.20+, Google Test, GitHub Actions CI

---

## 1. Overview

This project implements the full Aliro 1.0 protocol stack in C++ as a modular, open-source library. Aliro is a physical access control protocol (NFC / BLE / UWB) defined by the Connectivity Standards Alliance. It specifies a mutual authentication protocol and access document structure between a Reader and a User Device (smartphone/wallet).

The library implements both the Reader role and the User Device role, a pluggable crypto backend, and all three transport layers (NFC, BLE, UWB) plus a simulated in-process transport for testing.

---

## 2. Architecture: Modular Multi-Library (Approach B)

Five CMake targets with clean layered dependencies:

```
aliro-reader ──┐
               ├── aliro-transport
aliro-device ──┘       │
       │                │
       └──── aliro-crypto
                  │
              aliro-core
```

### 2.1 Module Responsibilities

| Module | Depends on | Responsibility |
|---|---|---|
| `aliro-core` | none | CBOR/TLV codecs, all spec data structures, error types, byte buffer utilities |
| `aliro-crypto` | core | `ICryptoProvider` interface + OpenSSL 3.x and mbedTLS adapters |
| `aliro-transport` | core | `ITransport` interface + NFC / BLE / UWB / SimTransport adapters |
| `aliro-reader` | core, crypto, transport | Reader role state machine, AUTH0/AUTH1, access decision engine |
| `aliro-device` | core, crypto, transport | User Device role state machine, credential management, cryptogram generation |

---

## 3. Project Layout

```
aliro/
├── CMakeLists.txt
├── cmake/
│   ├── AliroVersion.cmake
│   ├── FindOpenSSL.cmake
│   └── AliroOptions.cmake          # BUILD_TESTS, BUILD_EXAMPLES, CRYPTO_BACKEND
│
├── modules/
│   ├── core/
│   │   ├── CMakeLists.txt
│   │   ├── include/aliro/core/
│   │   └── src/
│   ├── crypto/
│   │   ├── CMakeLists.txt
│   │   ├── include/aliro/crypto/
│   │   └── src/
│   ├── transport/
│   │   ├── CMakeLists.txt
│   │   ├── include/aliro/transport/
│   │   └── src/
│   ├── reader/
│   │   ├── CMakeLists.txt
│   │   ├── include/aliro/reader/
│   │   └── src/
│   └── device/
│       ├── CMakeLists.txt
│       ├── include/aliro/device/
│       └── src/
│
├── tests/
│   ├── CMakeLists.txt
│   ├── unit/
│   └── integration/
│
├── examples/
│   └── simulatedTransaction/
│
├── docs/
│   └── superpowers/specs/
│
├── third_party/                    # via CMake FetchContent
├── .github/
│   └── workflows/
│       ├── build.yml
│       └── lint.yml
├── .clang-format
├── .clang-tidy
└── README.md
```

---

## 4. Module Details

### 4.1 aliro-core

- CBOR encoder/decoder (wraps `qcbor` via FetchContent)
- DER-TLV encoder/decoder
- Spec data structures:
  - `AccessDocument`, `AccessDataElement`, `AccessRule`, `Schedule`
  - `RevocationDocument`, `RevocationDataElement`
  - `IssuerAuth`, `IssuerSignedItem`
- Protocol constants (command codes, tag values, namespace strings, version identifiers)
- Error type: `AliroError` enum
- Result type: `Result<T, AliroError>` — `std::expected<T, AliroError>` (C++23) or `tl::expected` fallback
- Byte buffer aliases: `using Bytes = std::vector<uint8_t>`, `using ByteView = std::span<const uint8_t>`

### 4.2 aliro-crypto

Abstract interface injected into Reader and Device:

```cpp
class ICryptoProvider {
public:
    virtual ~ICryptoProvider() = default;

    virtual Result<EcKeyPair, AliroError>   generateKeyPair() = 0;
    virtual Result<Signature, AliroError>   sign(ByteView data, const EcPrivateKey& key) = 0;
    virtual Result<bool, AliroError>        verify(ByteView data, const Signature& sig,
                                                   const EcPublicKey& key) = 0;
    virtual Result<Bytes, AliroError>       aesGcmEncrypt(ByteView plaintext,
                                                          const SessionKey& key,
                                                          ByteView aad) = 0;
    virtual Result<Bytes, AliroError>       aesGcmDecrypt(ByteView ciphertext,
                                                          const SessionKey& key,
                                                          ByteView aad) = 0;
    virtual Result<SessionKey, AliroError>  hkdfDerive(ByteView ikm, ByteView salt,
                                                        ByteView info) = 0;
    virtual Result<Bytes, AliroError>       randomBytes(size_t n) = 0;
};
```

Implementations:
- `OpenSslCryptoProvider` — full implementation, P-256 ECDSA, AES-128-GCM, HKDF-SHA-256
- `MbedTlsCryptoProvider` — stub (interface only, for embedded targets)

### 4.3 aliro-transport

```cpp
class ITransport {
public:
    virtual ~ITransport() = default;
    virtual Result<void, AliroError> send(ByteView message) = 0;
    virtual Result<Bytes, AliroError> receive() = 0;
    virtual void close() = 0;
};
```

Implementations:
- `NfcTransport` — ISO 7816-4 APDU framing, platform hooks provided via callback
- `BleTransport` — L2CAP framing, platform hooks provided via callback
- `UwbTransport` — UWB ranging session integration
- `SimTransport` — synchronous in-process loopback, no hardware; used by all tests and examples

### 4.4 aliro-reader

- `ReaderContext` — reader key pair, Reader System Issuer cert, Credential Issuer trust anchors, Kpersistent store, revocation database, AccessIteration / RevocationIteration counters
- `ReaderTransaction` — state machine:

```
Idle → SendAuth0 → ProcessAuth0Response → SendAuth1 →
ExpeditedComplete → SendEnvelope → ProcessAccessDocument →
Complete / Failed
```

- Builds AUTH0/AUTH1 commands, verifies AUTH1 response signature
- Optional step-up: sends ENVELOPE (DeviceRequest), processes GET DATA (AccessDocument chunks)
- Validates AccessDocument: IssuerAuth signature, validity period, ValidityIteration, AccessRules, Schedules, revocation
- Produces `AccessDecision { granted: bool, reason: AliroError | nullopt }`

### 4.5 aliro-device

- `DeviceContext` — one or more `AccessCredential` (key pair + optional AccessDocument), Kpersistent store indexed by reader_identifier
- `DeviceTransaction` — state machine mirroring Reader states (reactive)
- Receives AUTH0, selects matching AccessCredential
- Expedited-standard: generates ephemeral key pair, derives ExpeditedSK, signs AUTH1
- Expedited-fast: generates cryptogram from Kpersistent
- Step-up: receives DeviceRequest, transmits AccessDocument chunks via GET DATA

---

## 5. Protocol Data Flow

### 5.1 Full Transaction Sequence (expedited-standard + step-up)

```
Reader                                    User Device
  │── AUTH0 (reader ephemeral pubKey, ───▶│
  │         reader_identifier, nonce)      │
  │◀── AUTH0 Response (device ephemeral ──│
  │            pubKey, nonce)              │
  │                                        │
  │  [both: ECDH + HKDF → ExpeditedSK]   │
  │                                        │
  │── AUTH1 (encrypted: reader sig, ─────▶│
  │          optional reader_Cert)         │
  │◀── AUTH1 Response (encrypted: ────────│
  │         device sig, Kpersistent hint)  │
  │                                        │
  │  [optional step-up]                    │
  │── ENVELOPE (DeviceRequest) ──────────▶│
  │◀── GET DATA (AccessDocument) ──────── │
  │                                        │
  │  [Reader validates, makes decision]   │
```

### 5.2 Key Derivation Chain

```
ECDH(readerEphemeral, deviceEphemeral)       → sharedSecret
HKDF(sharedSecret, nonces, "ExpeditedSK")   → expeditedSK   (AUTH1 encryption)
HKDF(sharedSecret, nonces, "StepUpSK")      → stepUpSK      (step-up encryption)
HKDF(expeditedSK, readerIdentifier,
     "Kpersistent")                          → kPersistent   (stored for fast phase)
```

Algorithms: ECDSA P-256 / SHA-256, AES-128-GCM, HKDF-SHA-256.

---

## 6. Testing Strategy

### 6.1 Test Layout

```
tests/
├── unit/
│   ├── core/         cborEncoderTest, tlvEncoderTest, accessDocumentTest, revocationDocumentTest
│   ├── crypto/       ecdsaTest, aesGcmTest, hkdfTest, cryptoProviderTest
│   ├── transport/    simTransportTest
│   ├── reader/       readerContextTest, readerTransactionTest
│   └── device/       deviceContextTest, deviceTransactionTest
└── integration/
    ├── expeditedStandardFlowTest
    ├── expeditedFastFlowTest
    ├── stepUpFlowTest
    └── revocationTest
```

### 6.2 Approach per Layer

| Layer | Method |
|---|---|
| `aliro-core` | CBOR/TLV round-trips against spec examples; Google Test parameterized tests for edge cases |
| `aliro-crypto` | Known-answer tests from NIST FIPS 186-5, RFC 5869, NIST SP 800-38D |
| `aliro-transport` | SimTransport send/receive ordering and framing unit tests |
| `aliro-reader/device` | State machine unit tests with `MockCryptoProvider` (Google Mock) + SimTransport |
| Integration | Full two-party transaction in-process via SimTransport; verifies correct `AccessDecision` |

Every `AliroError` path has at least one test that deliberately triggers it.

### 6.3 CI Pipeline

```yaml
# .github/workflows/build.yml
on: [push, pull_request]
jobs:
  build-and-test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
    steps:
      - cmake --preset debug    # -DBUILD_TESTS=ON -DASAN=ON
      - cmake --build
      - ctest --output-on-failure
  lint:
    steps:
      - clang-format --dry-run  # fails PR on style violation
      - clang-tidy              # static analysis
```

---

## 7. Coding Style & Conventions

| Element | Convention | Example |
|---|---|---|
| Classes / structs | PascalCase | `AccessDocument`, `ReaderTransaction` |
| Methods / functions | camelCase | `verifySignature()`, `deriveSessionKey()` |
| Variables / params | camelCase | `sessionKey`, `readerIdentifier` |
| Enum values | UPPER_SNAKE | `AliroError::CRYPTO_FAILURE` |
| Private members | camelCase with `m` prefix | `mState`, `mCrypto`, `mTransport` |
| Files | camelCase | `accessDocument.cpp`, `readerTransaction.h` |
| Test files | camelCase + `Test` suffix | `accessDocumentTest.cpp` |

Additional rules:
- C++17 standard
- No raw `new`/`delete` — use `std::make_shared` / `std::make_unique`
- No `using namespace` in headers
- `Result<T, AliroError>` — no exceptions in protocol code
- Doxygen `///` for public API, inline `//` for non-obvious implementation choices only
- `.clang-format` and `.clang-tidy` enforced in CI (4-space indent, 100-char line limit)

---

## 8. Third-Party Dependencies

All fetched via CMake `FetchContent` — no manual install required:

| Library | Purpose |
|---|---|
| Google Test + Google Mock | Unit and integration testing |
| OpenSSL 3.x | Default crypto backend |
| qcbor | CBOR encoding/decoding in `aliro-core` |
| tl::expected | `Result<T,E>` on compilers without C++23 `std::expected` |
