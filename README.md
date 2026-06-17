# Aliro

> A C++20 implementation of the **Aliro 1.0** physical access control protocol  
> (CSA document 26-42802-001)

Aliro defines a cryptographically authenticated NFC/BLE/UWB exchange between a **Reader** (door lock, turnstile, gate) and a **User Device** (phone, wearable, key fob). This library implements both roles in portable C++20 with pluggable cryptography — runs on desktop and embedded targets alike.

---

## Table of Contents

- [What is Aliro?](#what-is-aliro)
- [Features](#features)
- [Project structure](#project-structure)
- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Clone](#clone)
  - [Build](#build)
  - [Test](#test)
- [Usage](#usage)
  - [Reader side](#reader-side)
  - [Device side](#device-side)
  - [Crypto provider](#crypto-provider)
  - [Secure channel](#secure-channel)
  - [Logging](#logging)
- [Architecture](#architecture)
- [Donate](#donate)

---

## What is Aliro?

Aliro is an open access-control standard from the Connectivity Standards Alliance. A transaction looks like this:

```
Phone (Device)                          Door Lock (Reader)
      │                                        │
      │◄──────────── SELECT AID ───────────────│
      │                                        │
      │◄──────────── AUTH0 ────────────────────│  reader ephemeral key + nonce + identity
      │                                        │
      │──────────── AUTH0 response ───────────►│  device ephemeral key + nonce + signature
      │                                        │     (ECDH → session key derived here)
      │◄──────────── AUTH1 ────────────────────│  reader transcript signature
      │                                        │
      │──────────── AccessDocument ───────────►│  door opens 🎉
```

All crypto is P-256 ECDH + ECDSA / SHA-256, HKDF-SHA-256 for key derivation, and AES-128-GCM for the post-auth secure channel.

---

## Features

- **Full protocol** — SELECT AID → AUTH0 → AUTH1 state machines for both reader and device roles
- **Pluggable crypto** — swap between OpenSSL 3.x and MbedTLS 3.x at runtime; bring your own provider for custom hardware
- **Embedded-ready** — MbedTLS provider requires no exceptions, no RTTI; suitable for bare-metal targets
- **Secure channel** — counter-based AES-128-GCM with independent send/receive counters after authentication
- **Structured logging** — callback-based `ALIRO_LOG_{DEBUG,INFO,WARN,ERROR}` macros; define `ALIRO_LOG_DISABLE` for zero overhead
- **Self-contained** — MbedTLS 3.6.2 and OpenSSL 3.3.1 vendored as git submodules; no system installs required
- **140 tests** — unit tests for every module, integration tests for the full exchange, cross-provider interop tests

---

## Project structure

```
aliro/
├── modules/
│   ├── core/        — CBOR/TLV codecs, APDU framing, protocol constants, logging
│   ├── crypto/      — ICryptoProvider interface, OpenSSL & MbedTLS implementations, SecureChannel
│   ├── transport/   — ITransport interface, SimTransport for testing
│   ├── reader/      — ReaderSession (initiator role)
│   └── device/      — DeviceSession (responder role)
├── tests/
│   ├── unit/        — per-module unit tests
│   └── integration/ — full SELECT→AUTH0→AUTH1 end-to-end tests
├── third_party/
│   ├── mbedtls/     — Mbed-TLS/mbedtls @ v3.6.2  (git submodule)
│   └── openssl/     — openssl/openssl   @ openssl-3.3.1  (git submodule)
└── cmake/           — AliroOptions, AliroVersion helpers
```

---

## Getting started

### Prerequisites

| Tool | Minimum version | Notes |
|---|---|---|
| CMake | 3.20 | |
| Ninja | any | |
| C++ compiler | C++20 | Clang 15+, GCC 12+, MSVC 19.34+ |
| Git | 2.10+ | for submodule shallow clone support |
| Perl | any | only needed if building the OpenSSL submodule on a system without OpenSSL installed |

**macOS** (Homebrew — recommended):

```bash
brew install cmake ninja openssl@3
```

**Ubuntu / Debian**:

```bash
sudo apt-get install cmake ninja-build libssl-dev perl
```

**Bare / embedded**: only MbedTLS is needed. OpenSSL is not required.

### Clone

```bash
git clone https://github.com/voitaynguyen00/aliro.git
cd aliro

# Pull vendored libraries
git submodule update --init

# MbedTLS 3.6.x requires its own nested 'framework' submodule
git -C third_party/mbedtls submodule update --init
```

### Build

```bash
# Debug build (includes tests)
cmake --preset debug
cmake --build --preset debug

# Optimised release build
cmake --preset release
cmake --build --preset release
```

### Test

```bash
ctest --preset debug
```

Expected output:

```
100% tests passed, 0 tests failed out of 140
Total Test time (real) =   0.92 sec
```

---

## Usage

### Reader side

```cpp
#include "aliro/crypto/openSslCryptoProvider.h"   // or mbedTlsCryptoProvider.h
#include "aliro/reader/readerSession.h"

using namespace aliro;

// ITransport has one method: Result<Bytes> transceive(ByteView command)
MyNfcTransport transport;
OpenSslCryptoProvider crypto;

// Long-term key pair provisioned to this reader
EcKeyPair    readerKp       = loadReaderKeyPair();
// Public key of the device expected to authenticate
EcPublicKey  devicePubKey   = loadTrustedDeviceKey();

ReaderSession session(crypto, transport);
auto result = session.authenticate(readerKp, devicePubKey);

if (result) {
    const AccessDocument& doc       = result->accessDoc;
    const Bytes&          sessionKey = result->sessionKey; // AES-128, use with SecureChannel
    unlockDoor();
} else {
    // result.error() is an AliroError enum value — no exceptions thrown
    handleError(result.error());
}
```

### Device side

```cpp
#include "aliro/crypto/mbedTlsCryptoProvider.h"
#include "aliro/device/deviceSession.h"

using namespace aliro;

MbedTlsCryptoProvider crypto;
EcPrivateKey          devicePrivKey = loadDevicePrivateKey();
AccessDocument        accessDoc     = buildAccessDocument();

DeviceSession session(crypto, devicePrivKey, accessDoc);

// Route incoming APDUs from your NFC stack
void onApduReceived(uint8_t ins, ByteView data) {
    Result<Bytes> response;
    switch (ins) {
        case 0xA4: response = session.handleSelect(data); break;
        case 0x50: response = session.handleAuth0(data);  break;
        case 0x51: response = session.handleAuth1(data);  break;
        default:   response = tl::unexpected(AliroError::INVALID_MESSAGE);
    }

    if (response) sendApduResponse(*response);
    else          sendStatusWord(0x6F00);
}
```

### Crypto provider

Two built-in providers implement `ICryptoProvider` identically — swap at will:

```cpp
// Desktop / server
#include "aliro/crypto/openSslCryptoProvider.h"
OpenSslCryptoProvider crypto;   // links OpenSSL 3.x

// Embedded / no-OS
#include "aliro/crypto/mbedTlsCryptoProvider.h"
MbedTlsCryptoProvider crypto;   // links MbedTLS 3.x

// Custom hardware security module
class MyHsmProvider : public aliro::ICryptoProvider { /* implement 8 methods */ };
```

The full `ICryptoProvider` interface:

```cpp
Result<EcKeyPair> generateKeyPair();
Result<Bytes>     ecdhCompute(const EcPrivateKey&, const EcPublicKey&);
Result<Signature> sign(ByteView data, const EcPrivateKey&);
Result<bool>      verify(ByteView data, const Signature&, const EcPublicKey&);
Result<Bytes>     aesGcmEncrypt(ByteView plaintext, const SessionKey&, ByteView nonce, ByteView aad);
Result<Bytes>     aesGcmDecrypt(ByteView ciphertext, const SessionKey&, ByteView nonce, ByteView aad);
Result<Bytes>     hkdfDerive(ByteView ikm, ByteView salt, ByteView info, size_t len);
Result<Bytes>     randomBytes(size_t n);
```

### Secure channel

After a successful exchange both sides hold the same 16-byte AES-128 session key. `SecureChannel` wraps it with counter-based AES-128-GCM so nonces are never reused:

```cpp
#include "aliro/crypto/secureChannel.h"

SecureChannel readerChannel(crypto, result->sessionKey);
SecureChannel deviceChannel(crypto, session.sessionKey());

// Reader encrypts a message
auto ciphertext = readerChannel.encrypt(plaintext);

// Device decrypts it — send/receive counters track independently
auto plaintext = deviceChannel.decrypt(*ciphertext);
```

### Logging

Install a callback once at startup and all `ALIRO_LOG_*` calls route through it:

```cpp
#include "aliro/core/log.h"

aliro::log::setCallback(
    [](aliro::log::Level level, const char* file, int line, const char* msg) {
        printf("[%s] %s:%d  %s\n", levelName(level), file, line, msg);
    },
    aliro::log::Level::INFO  // filter out DEBUG messages in production
);

// Disable at runtime
aliro::log::setCallback(nullptr);
```

Log levels: `DEBUG` < `INFO` < `WARN` < `ERROR` < `NONE`

Compile-time zero overhead: define `ALIRO_LOG_DISABLE` before including `log.h` and all macros expand to nothing.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Application                      │
└────────────┬────────────────────────┬───────────────┘
             │                        │
      ┌──────▼──────┐          ┌──────▼──────┐
      │ ReaderSession│          │ DeviceSession│
      └──────┬──────┘          └──────┬───────┘
             │                        │
      ┌──────▼────────────────────────▼──────┐
      │               aliro-core             │
      │   CBOR · TLV · APDU · AccessDocument │
      │   IssuerAuth · Logging               │
      └──────────────────┬───────────────────┘
                         │
             ┌───────────▼───────────┐
             │      aliro-crypto     │
             │   ICryptoProvider     │
             │  ┌─────────────────┐  │
             │  │  OpenSSL 3.x    │  │
             │  │  MbedTLS 3.x    │  │
             │  │  Custom HSM     │  │
             │  └─────────────────┘  │
             │   SecureChannel       │
             └───────────┬───────────┘
                         │
             ┌───────────▼───────────┐
             │    aliro-transport    │
             │   ITransport          │
             │  (NFC · BLE · UWB ·  │
             │   Sim · your driver) │
             └───────────────────────┘
```

All public APIs return `Result<T>` (`tl::expected<T, AliroError>`) — no exceptions are thrown anywhere in the library.

---

## Donate

If this library saved you from hand-rolling P-256 ECDH at 2 AM, consider buying me a coffee ☕

Every donation goes directly towards more caffeine, fewer bugs, and the occasional victory snack.

| Method | |
|---|---|
| ☕ Ko-fi | [ko-fi.com/voitaynguyen](https://ko-fi.com/voitaynguyen) |
| ₿ Bitcoin | `bc1q_YOUR_BTC_ADDRESS` |
| Ξ Ethereum | `0x_YOUR_ETH_ADDRESS` |

> *"Open source is love. Donations are more love."*  — me, kekeke 🐸

---

<sub>Aliro 1.0 specification © Connectivity Standards Alliance 2026. This project is an independent implementation and is not affiliated with or endorsed by CSA.</sub>
