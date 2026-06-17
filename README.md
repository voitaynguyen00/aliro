<div align="center">

# 🔐 Aliro

### C++20 implementation of the Aliro 1.0 physical access control protocol

*The open standard that lets your phone unlock doors over NFC · BLE · UWB*

[![Build](https://github.com/voitaynguyen00/aliro/actions/workflows/build.yml/badge.svg)](https://github.com/voitaynguyen00/aliro/actions)
[![Tests](https://img.shields.io/badge/tests-140%20passing-brightgreen)](#test)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Vibe coded](https://img.shields.io/badge/vibe%20coded%20with-Claude%20Code-blueviolet?logo=anthropic)](https://claude.ai/code)

</div>

---

> **⚡ TL;DR** — Drop-in C++20 library that does the full Aliro handshake (SELECT → AUTH0 → AUTH1) for both the reader and the device side. Pluggable crypto (OpenSSL 3.x or MbedTLS 3.x), runs on embedded, no exceptions, no RTTI, 140 tests. Vibe coded from scratch with [Claude Code](https://claude.ai/code).

---

## 🤖 The origin story

This entire library was built through **AI-assisted vibe coding** using [Claude Code](https://claude.ai/code) by Anthropic.

Every module, every test, every CMake file — designed and written in a collaborative back-and-forth with an AI. No copy-pasting from Stack Overflow. No half-remembered blog posts. Just a spec PDF, a blank repo, and a conversation.

The result: a clean, well-tested C++20 library in the time it would normally take to just understand the spec.

> If you're curious what AI-assisted systems programming looks like in practice, this repo is a live example. Star it and find out 👇

---

## What is Aliro?

Aliro is a physical access control standard from the [Connectivity Standards Alliance](https://csa-iot.org/). Think: your phone unlocking a hotel room, an office turnstile, or a car door — without touching anything — using cryptographically authenticated NFC or BLE.

```
Phone (User Device)                     Door Lock (Reader)
       │                                       │
       │◄──────────── SELECT AID ──────────────│
       │                                       │
       │◄──────────── AUTH0 ───────────────────│  ephemeral key + nonce + reader identity
       │                                       │
       │────────── AUTH0 response ────────────►│  ephemeral key + nonce + device signature
       │                                       │       ↑ ECDH → session key derived here
       │◄──────────── AUTH1 ───────────────────│  reader transcript signature
       │                                       │
       │─────────── AccessDocument ───────────►│  🚪 door opens
```

Under the hood: **P-256 ECDH** key agreement → **HKDF-SHA-256** session key derivation → **ECDSA/SHA-256** mutual authentication → **AES-128-GCM** secure channel. All in one 3-message exchange.

---

## ✨ Features

| | |
|---|---|
| 🔄 **Both roles** | Reader (initiator) and Device (responder) state machines |
| 🔌 **Pluggable crypto** | OpenSSL 3.x or MbedTLS 3.x — swap at compile time, or bring your own HSM driver |
| 📦 **Embedded-ready** | MbedTLS provider: no exceptions, no RTTI, no dynamic linking required |
| 🔒 **Secure channel** | Counter-based AES-128-GCM with independent send/receive counters |
| 📝 **Structured logging** | Callback-based `ALIRO_LOG_*` macros — zero overhead with `ALIRO_LOG_DISABLE` |
| 📎 **Self-contained** | MbedTLS 3.6.2 + OpenSSL 3.3.1 vendored as git submodules |
| ✅ **140 tests** | Unit, integration, and cross-provider interop tests |
| 🚫 **No exceptions** | All APIs return `Result<T>` (`tl::expected<T, AliroError>`) |

---

## 📁 Project structure

```
aliro/
├── modules/
│   ├── core/        — CBOR · TLV · APDU · AccessDocument · logging
│   ├── crypto/      — ICryptoProvider · OpenSSL · MbedTLS · SecureChannel
│   ├── transport/   — ITransport · SimTransport (for tests)
│   ├── reader/      — ReaderSession  (SELECT → AUTH0 → AUTH1 initiator)
│   └── device/      — DeviceSession  (SELECT → AUTH0 → AUTH1 responder)
├── tests/
│   ├── unit/        — per-module unit tests
│   └── integration/ — full end-to-end exchange tests
└── third_party/
    ├── mbedtls/     — Mbed-TLS/mbedtls @ v3.6.2       (git submodule)
    └── openssl/     — openssl/openssl   @ openssl-3.3.1 (git submodule)
```

---

## 🚀 Getting started

### Prerequisites

| Tool | Min version |
|---|---|
| CMake | 3.20 |
| Ninja | any |
| C++ compiler | C++20 (Clang 15+, GCC 12+, MSVC 19.34+) |
| Git | 2.10+ |

**macOS** (Homebrew):
```bash
brew install cmake ninja openssl@3
```

**Ubuntu / Debian**:
```bash
sudo apt-get install cmake ninja-build libssl-dev
```

**Bare / embedded**: only MbedTLS is needed — OpenSSL is entirely optional.

### Clone

```bash
git clone https://github.com/voitaynguyen00/aliro.git
cd aliro

# Pull vendored crypto libraries
git submodule update --init

# MbedTLS 3.6.x needs its own nested framework submodule
git -C third_party/mbedtls submodule update --init
```

### Build

```bash
cmake --preset debug
cmake --build --preset debug
```

### Test

```bash
ctest --preset debug
```

```
100% tests passed, 0 tests failed out of 140
Total Test time (real) =   0.92 sec
```

---

## 📖 Usage

### Reader side

```cpp
#include "aliro/crypto/openSslCryptoProvider.h"
#include "aliro/reader/readerSession.h"

using namespace aliro;

OpenSslCryptoProvider crypto;
MyNfcTransport        transport;          // your ITransport implementation

EcKeyPair   readerKp     = loadReaderKeyPair();
EcPublicKey devicePubKey = loadTrustedDeviceKey();

ReaderSession session(crypto, transport);
auto result = session.authenticate(readerKp, devicePubKey);

if (result) {
    // Authentication succeeded — result->sessionKey is the AES-128 channel key
    unlockDoor();
} else {
    handleError(result.error());   // AliroError enum, no exceptions
}
```

### Device side

```cpp
#include "aliro/crypto/mbedTlsCryptoProvider.h"   // <-- embedded-friendly
#include "aliro/device/deviceSession.h"

using namespace aliro;

MbedTlsCryptoProvider crypto;
DeviceSession session(crypto, loadDevicePrivKey(), buildAccessDocument());

// Route incoming APDUs from your NFC stack
void onApdu(uint8_t ins, ByteView data) {
    Result<Bytes> resp;
    switch (ins) {
        case 0xA4: resp = session.handleSelect(data); break;
        case 0x50: resp = session.handleAuth0(data);  break;
        case 0x51: resp = session.handleAuth1(data);  break;
        default:   resp = tl::unexpected(AliroError::INVALID_MESSAGE);
    }
    resp ? sendApdu(*resp) : sendSw(0x6F00);
}
```

### Pluggable crypto

```cpp
// Option A — desktop/server, links OpenSSL 3.x
OpenSslCryptoProvider crypto;

// Option B — embedded/bare-metal, links MbedTLS 3.x
MbedTlsCryptoProvider crypto;

// Option C — custom hardware (HSM, SE, TPM)
class MyHsmProvider : public aliro::ICryptoProvider {
    Result<EcKeyPair> generateKeyPair() override { /* call your HSM */ }
    // ...7 more methods
};
```

Both built-in providers are interoperable — you can sign with OpenSSL and verify with MbedTLS (tested).

### Secure channel

```cpp
#include "aliro/crypto/secureChannel.h"

// Both sides use the session key produced by authenticate() / session.sessionKey()
SecureChannel reader(crypto, result->sessionKey);
SecureChannel device(crypto, session.sessionKey());

auto ct = reader.encrypt(message);    // AES-128-GCM, auto-increments nonce counter
auto pt = device.decrypt(*ct);        // counters tracked independently per direction
```

### Logging

```cpp
#include "aliro/core/log.h"

aliro::log::setCallback([](aliro::log::Level lv, const char* file, int line, const char* msg) {
    printf("[%s] %s:%d  %s\n", levelName(lv), file, line, msg);
}, aliro::log::Level::INFO);

// Silence at runtime
aliro::log::setCallback(nullptr);

// Silence at compile time (truly zero overhead)
#define ALIRO_LOG_DISABLE
```

Levels: `DEBUG` · `INFO` · `WARN` · `ERROR` · `NONE`

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Your Application                 │
└────────────┬──────────────────────────┬─────────────┘
             │                          │
      ┌──────▼──────┐            ┌──────▼───────┐
      │ ReaderSession│            │ DeviceSession │
      └──────┬──────┘            └──────┬────────┘
             │                          │
      ┌──────▼──────────────────────────▼──────┐
      │                aliro-core               │
      │    CBOR · TLV · APDU · AccessDocument   │
      │    IssuerAuth · Revocation · Logging     │
      └─────────────────┬───────────────────────┘
                        │
            ┌───────────▼────────────┐
            │      aliro-crypto      │
            │   ┌────────────────┐   │
            │   │  OpenSSL 3.x   │   │
            │   │  MbedTLS 3.x   │   │
            │   │  Your HSM/SE   │   │
            │   └────────────────┘   │
            │   SecureChannel        │
            └───────────┬────────────┘
                        │
            ┌───────────▼────────────┐
            │    aliro-transport     │
            │   NFC · BLE · UWB ·   │
            │   Sim · Your Driver   │
            └────────────────────────┘
```

All public APIs return `Result<T>` (`tl::expected<T, AliroError>`) — no exceptions anywhere.

---

## 🤖 Built with Claude Code

This project is a real-world example of **vibe coding a systems library with AI**.

The entire implementation — protocol state machines, crypto layer, CMake build system, 140 unit and integration tests — was written through conversation with [Claude Code](https://claude.ai/code). The workflow:

1. Feed the Aliro spec PDF to Claude
2. Describe what needs to be built next
3. Review the output, push back, iterate
4. Run tests, fix failures in dialogue
5. Repeat until green

No boilerplate generators. No copy-paste. The AI held the full architecture in context across multiple sessions and made real design decisions (error propagation strategy, transcript construction, nonce scheme, MbedTLS RAII wrappers).

**What this shows:**
- AI can implement a non-trivial cryptographic protocol from a spec document
- The output is readable, idiomatic C++20 — not generated slop
- TDD works well in the AI-assisted workflow (write the failing test → implement → green)
- Embedded-friendly design choices (no exceptions, pluggable crypto) survive AI collaboration

If you're building something similar, or just want to see how this workflow plays out at library scale — this is the repo to study.

---

## 💖 Donate

If this library saved you from hand-rolling P-256 ECDH and BER-TLV parsing at 2 AM, consider sponsoring on GitHub ☕

All sponsorships go directly toward more caffeine, fewer bugs, and the occasional victory snack after a clean `100% tests passed`.

<div align="center">

[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-pink?logo=github-sponsors)](https://github.com/sponsors/voitaynguyen00)

*"Open source is love. Sponsoring is more love."*

*kekeke 🐸*

</div>

---

## 📄 License

MIT — do whatever you want, just don't blame me if the door doesn't open.

---

<div align="center">

**If this project is useful or interesting, a ⭐ star goes a long way — it helps others find it.**

Made with 🤖 + ☕ · Powered by [Claude Code](https://claude.ai/code)

<sub>Aliro 1.0 specification © Connectivity Standards Alliance 2026. This project is an independent implementation and is not affiliated with or endorsed by CSA.</sub>

</div>
