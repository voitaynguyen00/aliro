# Aliro C++ Library — Plan 1: Scaffolding + aliro-core

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the complete project scaffold and implement the `aliro-core` module — CBOR/TLV codecs, all Aliro 1.0 data structures, and passing unit tests.

**Architecture:** Five-module layered C++ library (core → crypto → transport → reader/device). This plan delivers the foundation layer that every other module depends on. Plans 2–5 cover aliro-crypto, aliro-transport, aliro-reader/device, and CI integration respectively.

**Tech Stack:** C++17, CMake 3.20+, CMakePresets, Google Test 1.14.0, tl::expected 1.1.0, GitHub Actions

---

## File Map

```
CMakeLists.txt
CMakePresets.json
cmake/
  AliroVersion.cmake
  AliroOptions.cmake
.clang-format
.clang-tidy
.gitignore
README.md
.github/workflows/
  build.yml
  lint.yml
modules/core/
  CMakeLists.txt
  include/aliro/core/
    types.h
    tlv.h
    cbor.h
    protocol.h
    issuerAuth.h
    accessRule.h
    accessDataElement.h
    accessDocument.h
    revocationDocument.h
  src/
    tlv.cpp
    cbor.cpp
    issuerAuth.cpp
    accessDocument.cpp
    revocationDocument.cpp
tests/
  CMakeLists.txt
  unit/
    CMakeLists.txt
    core/
      CMakeLists.txt
      tlvTest.cpp
      cborTest.cpp
      issuerAuthTest.cpp
      accessDocumentTest.cpp
      revocationDocumentTest.cpp
```

---

## Task 1: Directory Scaffold + .gitignore + README

**Files:**
- Create: all top-level directories
- Create: `.gitignore`
- Create: `README.md`

- [ ] **Step 1: Create directory tree**

```bash
mkdir -p modules/core/include/aliro/core
mkdir -p modules/core/src
mkdir -p modules/crypto/include/aliro/crypto
mkdir -p modules/crypto/src
mkdir -p modules/transport/include/aliro/transport
mkdir -p modules/transport/src
mkdir -p modules/reader/include/aliro/reader
mkdir -p modules/reader/src
mkdir -p modules/device/include/aliro/device
mkdir -p modules/device/src
mkdir -p tests/unit/core
mkdir -p tests/integration
mkdir -p examples/simulatedTransaction
mkdir -p cmake
mkdir -p .github/workflows
mkdir -p third_party
```

- [ ] **Step 2: Create `.gitignore`**

```
build/
.venv/
*.pyc
__pycache__/
.DS_Store
*.o
*.a
*.so
*.dylib
CMakeCache.txt
CMakeFiles/
cmake_install.cmake
CTestTestfile.cmake
Testing/
.clangd/
compile_commands.json
```

Save to `.gitignore`.

- [ ] **Step 3: Create `README.md` skeleton**

```markdown
# Aliro

C++ implementation of the Aliro 1.0 protocol (CSA document 26-42802-001).

Aliro defines a physical access control protocol over NFC, BLE, and UWB between a Reader and a User Device.

## Building

Requirements: CMake 3.20+, Ninja, a C++17 compiler, OpenSSL 3.x.

```bash
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

## Project structure

| Module | Description |
|---|---|
| `aliro-core` | CBOR/TLV codecs, data structures, error types |
| `aliro-crypto` | Pluggable crypto interface + OpenSSL adapter |
| `aliro-transport` | Transport interface + NFC/BLE/UWB/Sim adapters |
| `aliro-reader` | Reader role state machine |
| `aliro-device` | User Device role state machine |

## Spec

Aliro 1.0 specification: Connectivity Standards Alliance, February 2026.
```

- [ ] **Step 4: Commit**

```bash
git add .gitignore README.md modules/ tests/ examples/ cmake/ .github/ third_party/
CHANGE_ID="I$(openssl rand -hex 20)"
git commit -m "chore: initial project directory scaffold

Change-Id: ${CHANGE_ID}"
```

---

## Task 2: Root CMakeLists.txt + CMakePresets.json

**Files:**
- Create: `CMakeLists.txt`
- Create: `CMakePresets.json`

- [ ] **Step 1: Write `CMakeLists.txt`**

```cmake
cmake_minimum_required(VERSION 3.20)

project(Aliro
    VERSION 1.0.0
    DESCRIPTION "Aliro 1.0 protocol C++ implementation"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(AliroOptions)
include(AliroVersion)
include(FetchContent)

# tl::expected — Result<T,E> for C++17
FetchContent_Declare(
    tl_expected
    GIT_REPOSITORY https://github.com/TartanLlama/expected.git
    GIT_TAG        v1.1.0
    GIT_SHALLOW    TRUE
)
set(EXPECTED_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(tl_expected)

# GoogleTest
if(ALIRO_BUILD_TESTS)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
        GIT_SHALLOW    TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    enable_testing()
    include(GoogleTest)
endif()

add_subdirectory(modules/core)

if(ALIRO_BUILD_TESTS)
    add_subdirectory(tests)
endif()
```

- [ ] **Step 2: Write `CMakePresets.json`**

```json
{
  "version": 3,
  "configurePresets": [
    {
      "name": "debug",
      "displayName": "Debug",
      "generator": "Ninja",
      "binaryDir": "${sourceDir}/build/debug",
      "cacheVariables": {
        "CMAKE_BUILD_TYPE": "Debug",
        "ALIRO_BUILD_TESTS": "ON",
        "CMAKE_EXPORT_COMPILE_COMMANDS": "ON"
      }
    },
    {
      "name": "release",
      "displayName": "Release",
      "generator": "Ninja",
      "binaryDir": "${sourceDir}/build/release",
      "cacheVariables": {
        "CMAKE_BUILD_TYPE": "Release",
        "ALIRO_BUILD_TESTS": "OFF"
      }
    },
    {
      "name": "asan",
      "displayName": "Debug + AddressSanitizer",
      "inherits": "debug",
      "binaryDir": "${sourceDir}/build/asan",
      "cacheVariables": {
        "CMAKE_CXX_FLAGS": "-fsanitize=address,undefined -fno-omit-frame-pointer"
      }
    }
  ],
  "buildPresets": [
    { "name": "debug",   "configurePreset": "debug" },
    { "name": "release", "configurePreset": "release" },
    { "name": "asan",    "configurePreset": "asan" }
  ],
  "testPresets": [
    {
      "name": "debug",
      "configurePreset": "debug",
      "output": { "outputOnFailure": true }
    }
  ]
}
```

- [ ] **Step 3: Commit**

```bash
git add CMakeLists.txt CMakePresets.json
CHANGE_ID="I$(openssl rand -hex 20)"
git commit -m "build: add root CMakeLists.txt and CMakePresets.json

Change-Id: ${CHANGE_ID}"
```

---

## Task 3: CMake Helper Files

**Files:**
- Create: `cmake/AliroOptions.cmake`
- Create: `cmake/AliroVersion.cmake`

- [ ] **Step 1: Write `cmake/AliroOptions.cmake`**

```cmake
option(ALIRO_BUILD_TESTS    "Build test targets"     ON)
option(ALIRO_BUILD_EXAMPLES "Build example targets"  OFF)

set(ALIRO_CRYPTO_BACKEND "openssl" CACHE STRING "Crypto backend: openssl or mbedtls")
set_property(CACHE ALIRO_CRYPTO_BACKEND PROPERTY STRINGS openssl mbedtls)
```

- [ ] **Step 2: Write `cmake/AliroVersion.cmake`**

```cmake
set(ALIRO_VERSION_MAJOR 1)
set(ALIRO_VERSION_MINOR 0)
set(ALIRO_VERSION_PATCH 0)
set(ALIRO_VERSION "${ALIRO_VERSION_MAJOR}.${ALIRO_VERSION_MINOR}.${ALIRO_VERSION_PATCH}")
set(ALIRO_SPEC_VERSION "1.0")

message(STATUS "Aliro library version: ${ALIRO_VERSION} (spec ${ALIRO_SPEC_VERSION})")
```

- [ ] **Step 3: Commit**

```bash
git add cmake/
CHANGE_ID="I$(openssl rand -hex 20)"
git commit -m "build: add CMake helper modules (version, options)

Change-Id: ${CHANGE_ID}"
```

---

## Task 4: Code Style Configs

**Files:**
- Create: `.clang-format`
- Create: `.clang-tidy`

- [ ] **Step 1: Write `.clang-format`**

```yaml
---
Language:        Cpp
BasedOnStyle:    Google
IndentWidth:     4
ColumnLimit:     100
AccessModifierOffset: -4
AllowShortFunctionsOnASingleLine: Inline
AllowShortIfStatementsOnASingleLine: Never
AllowShortLoopsOnASingleLine: false
BraceWrapping:
  AfterClass:     false
  AfterFunction:  false
  AfterNamespace: false
BreakBeforeBraces: Attach
NamespaceIndentation: None
SortIncludes:    CaseInsensitive
SpaceBeforeParens: ControlStatements
```

- [ ] **Step 2: Write `.clang-tidy`**

```yaml
Checks: >
  clang-diagnostic-*,
  clang-analyzer-*,
  cppcoreguidelines-no-malloc,
  modernize-use-nullptr,
  modernize-use-override,
  modernize-use-default-member-init,
  performance-unnecessary-copy-initialization,
  readability-const-return-type,
  readability-container-size-empty,
  readability-redundant-smartptr-get
WarningsAsErrors: ''
HeaderFilterRegex: 'modules/.*'
CheckOptions:
  - key: readability-identifier-naming.PrivateMemberPrefix
    value: 'm'
```

- [ ] **Step 3: Commit**

```bash
git add .clang-format .clang-tidy
CHANGE_ID="I$(openssl rand -hex 20)"
git commit -m "style: add clang-format and clang-tidy configuration

Change-Id: ${CHANGE_ID}"
```

---

## Task 5: GitHub Actions CI

**Files:**
- Create: `.github/workflows/build.yml`
- Create: `.github/workflows/lint.yml`

- [ ] **Step 1: Write `.github/workflows/build.yml`**

```yaml
name: Build and Test

on:
  push:
    branches: [main]
  pull_request:

jobs:
  build-and-test:
    strategy:
      matrix:
        os: [ubuntu-24.04, macos-15]
    runs-on: ${{ matrix.os }}

    steps:
      - uses: actions/checkout@v4

      - name: Install Ninja (Ubuntu)
        if: runner.os == 'Linux'
        run: sudo apt-get install -y ninja-build

      - name: Install Ninja (macOS)
        if: runner.os == 'macOS'
        run: brew install ninja

      - name: Configure (debug + ASan)
        run: cmake --preset asan

      - name: Build
        run: cmake --build --preset asan

      - name: Test
        run: ctest --preset debug
```

- [ ] **Step 2: Write `.github/workflows/lint.yml`**

```yaml
name: Lint

on:
  push:
    branches: [main]
  pull_request:

jobs:
  clang-format:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Check formatting
        run: |
          find modules tests examples -name '*.cpp' -o -name '*.h' | \
            xargs clang-format --dry-run --Werror
```

- [ ] **Step 3: Commit**

```bash
git add .github/
CHANGE_ID="I$(openssl rand -hex 20)"
git commit -m "ci: add GitHub Actions build and lint workflows

Change-Id: ${CHANGE_ID}"
```

---

## Task 6: aliro-core Module CMakeLists

**Files:**
- Create: `modules/core/CMakeLists.txt`
- Create: `tests/CMakeLists.txt`
- Create: `tests/unit/CMakeLists.txt`
- Create: `tests/unit/core/CMakeLists.txt`

- [ ] **Step 1: Write `modules/core/CMakeLists.txt`**

```cmake
add_library(aliro-core STATIC
    src/tlv.cpp
    src/cbor.cpp
    src/issuerAuth.cpp
    src/accessDocument.cpp
    src/revocationDocument.cpp
)

target_include_directories(aliro-core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(aliro-core
    PUBLIC tl::expected
)

target_compile_options(aliro-core PRIVATE
    -Wall -Wextra -Wpedantic -Werror
)

target_compile_features(aliro-core PUBLIC cxx_std_17)
```

- [ ] **Step 2: Write `tests/CMakeLists.txt`**

```cmake
add_subdirectory(unit)
```

- [ ] **Step 3: Write `tests/unit/CMakeLists.txt`**

```cmake
add_subdirectory(core)
```

- [ ] **Step 4: Write `tests/unit/core/CMakeLists.txt`**

```cmake
add_executable(aliro-core-tests
    tlvTest.cpp
    cborTest.cpp
    issuerAuthTest.cpp
    accessDocumentTest.cpp
    revocationDocumentTest.cpp
)

target_link_libraries(aliro-core-tests
    PRIVATE
        aliro-core
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(aliro-core-tests)
```

- [ ] **Step 5: Commit**

```bash
git add modules/core/CMakeLists.txt tests/
CHANGE_ID="I$(openssl rand -hex 20)"
git commit -m "build: add aliro-core and tests CMakeLists

Change-Id: ${CHANGE_ID}"
```

---

## Task 7: Core Types Header

**Files:**
- Create: `modules/core/include/aliro/core/types.h`

- [ ] **Step 1: Write `modules/core/include/aliro/core/types.h`**

```cpp
#pragma once

#include <cstdint>
#include <span>
#include <vector>
#include <tl/expected.hpp>

namespace aliro {

using Bytes    = std::vector<uint8_t>;
using ByteView = std::span<const uint8_t>;

enum class AliroError {
    CRYPTO_FAILURE,
    INVALID_MESSAGE,
    INVALID_STATE,
    UNSUPPORTED_VERSION,
    TRANSPORT_ERROR,
    ACCESS_DENIED,
    DOCUMENT_EXPIRED,
    REVOCATION_CHECK_FAILED,
    ENCODING_ERROR,
    DECODING_ERROR,
    NOT_FOUND,
};

template<typename T>
using Result = tl::expected<T, AliroError>;

} // namespace aliro
```

- [ ] **Step 2: Verify it compiles (configure cmake)**

```bash
cmake --preset debug
```

Expected: configuration succeeds with no errors.

- [ ] **Step 3: Commit**

```bash
git add modules/core/include/aliro/core/types.h
CHANGE_ID="I$(openssl rand -hex 20)"
git commit -m "feat(core): add core types — Bytes, ByteView, AliroError, Result<T>

Change-Id: ${CHANGE_ID}"
```

---

## Task 8: DER-TLV Encoder/Decoder

**Files:**
- Create: `modules/core/include/aliro/core/tlv.h`
- Create: `modules/core/src/tlv.cpp`
- Create: `tests/unit/core/tlvTest.cpp`

- [ ] **Step 1: Write the failing tests — `tests/unit/core/tlvTest.cpp`**

```cpp
#include "aliro/core/tlv.h"
#include <gtest/gtest.h>

using namespace aliro;

TEST(TlvEncodeTest, singleByteTag_shortValue) {
    Bytes value = {0x01, 0x02, 0x03};
    auto result = tlv::encode(0x41, value);
    ASSERT_TRUE(result.has_value());
    Bytes expected = {0x41, 0x03, 0x01, 0x02, 0x03};
    EXPECT_EQ(*result, expected);
}

TEST(TlvEncodeTest, twoByteTag_emptyValue) {
    Bytes value = {};
    auto result = tlv::encode(0x7F21, value);
    ASSERT_TRUE(result.has_value());
    Bytes expected = {0x7F, 0x21, 0x00};
    EXPECT_EQ(*result, expected);
}

TEST(TlvEncodeTest, lengthRequires2Bytes) {
    Bytes value(128, 0xAB);
    auto result = tlv::encode(0x50, value);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ((*result)[0], 0x50);
    EXPECT_EQ((*result)[1], 0x81);
    EXPECT_EQ((*result)[2], 128);
    EXPECT_EQ(result->size(), 3u + 128u);
}

TEST(TlvEncodeTest, lengthRequires3Bytes) {
    Bytes value(300, 0xCD);
    auto result = tlv::encode(0x50, value);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ((*result)[1], 0x82);
    EXPECT_EQ((*result)[2], 0x01);
    EXPECT_EQ((*result)[3], 0x2C); // 300 = 0x012C
    EXPECT_EQ(result->size(), 4u + 300u);
}

TEST(TlvDecodeTest, decodeOneItem) {
    Bytes data = {0x41, 0x03, 0x01, 0x02, 0x03};
    size_t consumed = 0;
    auto result = tlv::decodeOne(data, consumed);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->tag, 0x41u);
    EXPECT_EQ(result->value, (Bytes{0x01, 0x02, 0x03}));
    EXPECT_EQ(consumed, 5u);
}

TEST(TlvDecodeTest, decodeTwoByteTag) {
    Bytes data = {0x7F, 0x21, 0x02, 0xAA, 0xBB};
    size_t consumed = 0;
    auto result = tlv::decodeOne(data, consumed);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->tag, 0x7F21u);
    EXPECT_EQ(result->value, (Bytes{0xAA, 0xBB}));
    EXPECT_EQ(consumed, 5u);
}

TEST(TlvDecodeTest, emptyData_returnsError) {
    Bytes data = {};
    size_t consumed = 0;
    auto result = tlv::decodeOne(data, consumed);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::DECODING_ERROR);
}

TEST(TlvDecodeTest, truncatedValue_returnsError) {
    Bytes data = {0x41, 0x05, 0x01, 0x02}; // length=5 but only 2 value bytes
    size_t consumed = 0;
    auto result = tlv::decodeOne(data, consumed);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::DECODING_ERROR);
}

TEST(TlvRoundTripTest, encodeDecodeRoundTrip) {
    Bytes value = {0xDE, 0xAD, 0xBE, 0xEF};
    auto encoded = tlv::encode(0x5A, value);
    ASSERT_TRUE(encoded.has_value());
    size_t consumed = 0;
    auto decoded = tlv::decodeOne(*encoded, consumed);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->tag, 0x5Au);
    EXPECT_EQ(decoded->value, value);
    EXPECT_EQ(consumed, encoded->size());
}

TEST(TlvDecodeAllTest, multipleConcatenatedItems) {
    auto item1 = tlv::encode(0x01, Bytes{0xAA});
    auto item2 = tlv::encode(0x02, Bytes{0xBB, 0xCC});
    ASSERT_TRUE(item1.has_value());
    ASSERT_TRUE(item2.has_value());
    Bytes combined;
    combined.insert(combined.end(), item1->begin(), item1->end());
    combined.insert(combined.end(), item2->begin(), item2->end());

    auto result = tlv::decodeAll(combined);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 2u);
    EXPECT_EQ((*result)[0].tag, 0x01u);
    EXPECT_EQ((*result)[0].value, (Bytes{0xAA}));
    EXPECT_EQ((*result)[1].tag, 0x02u);
    EXPECT_EQ((*result)[1].value, (Bytes{0xBB, 0xCC}));
}
```

- [ ] **Step 2: Run tests — expect compile failure (no header yet)**

```bash
cmake --build --preset debug 2>&1 | head -20
```

Expected: error about missing `aliro/core/tlv.h`.

- [ ] **Step 3: Write `modules/core/include/aliro/core/tlv.h`**

```cpp
#pragma once

#include "aliro/core/types.h"
#include <cstdint>
#include <vector>

namespace aliro::tlv {

struct TlvItem {
    uint32_t tag;
    Bytes    value;
};

/// Encode a single DER-TLV item.
Result<Bytes> encode(uint32_t tag, ByteView value);

/// Decode one DER-TLV item from the start of data.
/// On success, bytesConsumed is set to the number of bytes read.
Result<TlvItem> decodeOne(ByteView data, size_t& bytesConsumed);

/// Decode all consecutive DER-TLV items from data.
Result<std::vector<TlvItem>> decodeAll(ByteView data);

} // namespace aliro::tlv
```

- [ ] **Step 4: Write `modules/core/src/tlv.cpp`**

```cpp
#include "aliro/core/tlv.h"

namespace aliro::tlv {

Result<Bytes> encode(uint32_t tag, ByteView value) {
    Bytes result;

    if (tag <= 0x7E) {
        result.push_back(static_cast<uint8_t>(tag));
    } else if (tag <= 0x7FFF) {
        result.push_back(static_cast<uint8_t>((tag >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(tag & 0xFF));
    } else {
        return tl::unexpected(AliroError::ENCODING_ERROR);
    }

    size_t len = value.size();
    if (len <= 127) {
        result.push_back(static_cast<uint8_t>(len));
    } else if (len <= 255) {
        result.push_back(0x81);
        result.push_back(static_cast<uint8_t>(len));
    } else if (len <= 65535) {
        result.push_back(0x82);
        result.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(len & 0xFF));
    } else {
        return tl::unexpected(AliroError::ENCODING_ERROR);
    }

    result.insert(result.end(), value.begin(), value.end());
    return result;
}

Result<TlvItem> decodeOne(ByteView data, size_t& bytesConsumed) {
    if (data.empty()) {
        return tl::unexpected(AliroError::DECODING_ERROR);
    }

    size_t pos = 0;
    TlvItem item;

    uint8_t first = data[pos++];
    if ((first & 0x1F) == 0x1F) {
        if (pos >= data.size()) return tl::unexpected(AliroError::DECODING_ERROR);
        item.tag = (static_cast<uint32_t>(first) << 8) | data[pos++];
    } else {
        item.tag = first;
    }

    if (pos >= data.size()) return tl::unexpected(AliroError::DECODING_ERROR);

    size_t length = 0;
    uint8_t lenByte = data[pos++];
    if (lenByte <= 127) {
        length = lenByte;
    } else if (lenByte == 0x81) {
        if (pos >= data.size()) return tl::unexpected(AliroError::DECODING_ERROR);
        length = data[pos++];
    } else if (lenByte == 0x82) {
        if (pos + 2 > data.size()) return tl::unexpected(AliroError::DECODING_ERROR);
        length = (static_cast<size_t>(data[pos]) << 8) | data[pos + 1];
        pos += 2;
    } else {
        return tl::unexpected(AliroError::DECODING_ERROR);
    }

    if (pos + length > data.size()) return tl::unexpected(AliroError::DECODING_ERROR);

    item.value.assign(data.data() + pos, data.data() + pos + length);
    bytesConsumed = pos + length;
    return item;
}

Result<std::vector<TlvItem>> decodeAll(ByteView data) {
    std::vector<TlvItem> items;
    size_t offset = 0;
    while (offset < data.size()) {
        size_t consumed = 0;
        auto item = decodeOne(ByteView(data.data() + offset, data.size() - offset), consumed);
        if (!item) return tl::unexpected(item.error());
        items.push_back(std::move(*item));
        offset += consumed;
    }
    return items;
}

} // namespace aliro::tlv
```

- [ ] **Step 5: Build and run tests — expect PASS**

```bash
cmake --build --preset debug && ctest --preset debug --tests-regex TlvEncodeTest
```

Expected output: `[  PASSED  ] 9 tests`.

- [ ] **Step 6: Commit**

```bash
git add modules/core/include/aliro/core/tlv.h modules/core/src/tlv.cpp tests/unit/core/tlvTest.cpp
CHANGE_ID="I$(openssl rand -hex 20)"
git commit -m "feat(core): implement DER-TLV encoder/decoder with tests

Change-Id: ${CHANGE_ID}"
```

---

## Task 9: CBOR Encoder/Decoder

**Files:**
- Create: `modules/core/include/aliro/core/cbor.h`
- Create: `modules/core/src/cbor.cpp`
- Create: `tests/unit/core/cborTest.cpp`

- [ ] **Step 1: Write the failing tests — `tests/unit/core/cborTest.cpp`**

```cpp
#include "aliro/core/cbor.h"
#include <gtest/gtest.h>

using namespace aliro;
using namespace aliro::cbor;

// --- Encoder tests (RFC 8949 Appendix A known-answer) ---

TEST(CborEncodeTest, uint_0) {
    Encoder enc;
    enc.addUint(0);
    EXPECT_EQ(enc.finish(), Bytes({0x00}));
}

TEST(CborEncodeTest, uint_23) {
    Encoder enc;
    enc.addUint(23);
    EXPECT_EQ(enc.finish(), Bytes({0x17}));
}

TEST(CborEncodeTest, uint_24) {
    Encoder enc;
    enc.addUint(24);
    EXPECT_EQ(enc.finish(), Bytes({0x18, 0x18}));
}

TEST(CborEncodeTest, uint_255) {
    Encoder enc;
    enc.addUint(255);
    EXPECT_EQ(enc.finish(), Bytes({0x18, 0xFF}));
}

TEST(CborEncodeTest, uint_256) {
    Encoder enc;
    enc.addUint(256);
    EXPECT_EQ(enc.finish(), Bytes({0x19, 0x01, 0x00}));
}

TEST(CborEncodeTest, negativeInt_minus1) {
    Encoder enc;
    enc.addInt(-1);
    EXPECT_EQ(enc.finish(), Bytes({0x20}));
}

TEST(CborEncodeTest, negativeInt_minus100) {
    Encoder enc;
    enc.addInt(-100);
    // -100 => major 1, value 99 = 0x63 => 0x38 0x63
    EXPECT_EQ(enc.finish(), Bytes({0x38, 0x63}));
}

TEST(CborEncodeTest, bytes_empty) {
    Encoder enc;
    enc.addBytes(Bytes{});
    EXPECT_EQ(enc.finish(), Bytes({0x40}));
}

TEST(CborEncodeTest, bytes_two) {
    Encoder enc;
    enc.addBytes(Bytes{0x01, 0x02});
    EXPECT_EQ(enc.finish(), Bytes({0x42, 0x01, 0x02}));
}

TEST(CborEncodeTest, text_empty) {
    Encoder enc;
    enc.addText("");
    EXPECT_EQ(enc.finish(), Bytes({0x60}));
}

TEST(CborEncodeTest, text_a) {
    Encoder enc;
    enc.addText("a");
    EXPECT_EQ(enc.finish(), Bytes({0x61, 0x61}));
}

TEST(CborEncodeTest, boolTrue) {
    Encoder enc;
    enc.addBool(true);
    EXPECT_EQ(enc.finish(), Bytes({0xF5}));
}

TEST(CborEncodeTest, boolFalse) {
    Encoder enc;
    enc.addBool(false);
    EXPECT_EQ(enc.finish(), Bytes({0xF4}));
}

TEST(CborEncodeTest, nullValue) {
    Encoder enc;
    enc.addNull();
    EXPECT_EQ(enc.finish(), Bytes({0xF6}));
}

TEST(CborEncodeTest, array_empty) {
    Encoder enc;
    enc.beginArray(0);
    EXPECT_EQ(enc.finish(), Bytes({0x80}));
}

TEST(CborEncodeTest, array_three_uints) {
    Encoder enc;
    enc.beginArray(3);
    enc.addUint(1);
    enc.addUint(2);
    enc.addUint(3);
    // [1,2,3] = 0x83 0x01 0x02 0x03
    EXPECT_EQ(enc.finish(), Bytes({0x83, 0x01, 0x02, 0x03}));
}

TEST(CborEncodeTest, map_one_entry) {
    Encoder enc;
    enc.beginMap(1);
    enc.addUint(1);
    enc.addText("a");
    // {1: "a"} = A1 01 61 61
    EXPECT_EQ(enc.finish(), Bytes({0xA1, 0x01, 0x61, 0x61}));
}

// --- Decoder tests ---

TEST(CborDecodeTest, uint) {
    Bytes data = {0x18, 0x64}; // 100
    Decoder dec(data);
    auto v = dec.getUint();
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, 100u);
    EXPECT_TRUE(dec.isAtEnd());
}

TEST(CborDecodeTest, negInt) {
    Bytes data = {0x20}; // -1
    Decoder dec(data);
    auto v = dec.getInt();
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, -1);
}

TEST(CborDecodeTest, bytes) {
    Bytes data = {0x42, 0xDE, 0xAD};
    Decoder dec(data);
    auto v = dec.getBytes();
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, (Bytes{0xDE, 0xAD}));
}

TEST(CborDecodeTest, text) {
    Bytes data = {0x65, 0x61, 0x6C, 0x69, 0x72, 0x6F}; // "aliro"
    Decoder dec(data);
    auto v = dec.getText();
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "aliro");
}

TEST(CborDecodeTest, boolTrue) {
    Bytes data = {0xF5};
    Decoder dec(data);
    auto v = dec.getBool();
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, true);
}

TEST(CborDecodeTest, mapSize) {
    Bytes data = {0xA2, 0x01, 0x02, 0x03, 0x04}; // {1:2, 3:4}
    Decoder dec(data);
    auto count = dec.getMapSize();
    ASSERT_TRUE(count.has_value());
    EXPECT_EQ(*count, 2u);
}

TEST(CborDecodeTest, wrongType_returnsError) {
    Bytes data = {0x61, 0x61}; // text "a"
    Decoder dec(data);
    auto v = dec.getUint(); // wrong type
    EXPECT_FALSE(v.has_value());
    EXPECT_EQ(v.error(), AliroError::DECODING_ERROR);
}

TEST(CborRoundTripTest, mapWithMixedValues) {
    Encoder enc;
    enc.beginMap(3);
    enc.addUint(1);  enc.addUint(42);
    enc.addUint(2);  enc.addText("aliro");
    enc.addUint(3);  enc.addBytes(Bytes{0xAA, 0xBB});
    Bytes encoded = enc.finish();

    Decoder dec(encoded);
    auto count = dec.getMapSize();
    ASSERT_TRUE(count.has_value());
    EXPECT_EQ(*count, 3u);

    EXPECT_EQ(*dec.getUint(), 1u);
    EXPECT_EQ(*dec.getUint(), 42u);
    EXPECT_EQ(*dec.getUint(), 2u);
    EXPECT_EQ(*dec.getText(), "aliro");
    EXPECT_EQ(*dec.getUint(), 3u);
    EXPECT_EQ(*dec.getBytes(), (Bytes{0xAA, 0xBB}));
    EXPECT_TRUE(dec.isAtEnd());
}
```

- [ ] **Step 2: Run tests — expect compile failure**

```bash
cmake --build --preset debug 2>&1 | grep "error:" | head -5
```

Expected: error about missing `aliro/core/cbor.h`.

- [ ] **Step 3: Write `modules/core/include/aliro/core/cbor.h`**

```cpp
#pragma once

#include "aliro/core/types.h"
#include <string_view>

namespace aliro::cbor {

enum class MajorType : uint8_t {
    UINT   = 0,
    INT    = 1,
    BYTES  = 2,
    TEXT   = 3,
    ARRAY  = 4,
    MAP    = 5,
    TAG    = 6,
    SIMPLE = 7,
};

/// Minimal CBOR encoder producing core-deterministic output (RFC 8949 §4.2.1).
class Encoder {
public:
    void addUint(uint64_t value);
    void addInt(int64_t value);
    void addBytes(ByteView data);
    void addText(std::string_view text);
    void addBool(bool value);
    void addNull();
    void addTag(uint64_t tag);
    void beginArray(size_t count);
    void beginMap(size_t count);

    Bytes finish();

private:
    Bytes mBuffer;
    void encodeHead(MajorType major, uint64_t value);
};

/// Streaming CBOR decoder.
class Decoder {
public:
    explicit Decoder(ByteView data);

    bool isAtEnd() const;
    Result<MajorType> peekMajorType() const;

    Result<uint64_t>    getUint();
    Result<int64_t>     getInt();
    Result<Bytes>       getBytes();
    Result<std::string> getText();
    Result<bool>        getBool();
    Result<void>        getNull();
    Result<uint64_t>    getTag();
    Result<size_t>      getArraySize();
    Result<size_t>      getMapSize();
    Result<void>        skip();

    size_t bytesConsumed() const;

private:
    ByteView mData;
    size_t   mPos{0};

    Result<uint64_t> decodeHead(uint8_t& outMajorType);
};

} // namespace aliro::cbor
```

- [ ] **Step 4: Write `modules/core/src/cbor.cpp`**

```cpp
#include "aliro/core/cbor.h"

namespace aliro::cbor {

// --- Encoder ---

void Encoder::encodeHead(MajorType major, uint64_t value) {
    uint8_t majorByte = static_cast<uint8_t>(major) << 5;
    if (value <= 23) {
        mBuffer.push_back(majorByte | static_cast<uint8_t>(value));
    } else if (value <= 0xFF) {
        mBuffer.push_back(majorByte | 24);
        mBuffer.push_back(static_cast<uint8_t>(value));
    } else if (value <= 0xFFFF) {
        mBuffer.push_back(majorByte | 25);
        mBuffer.push_back(static_cast<uint8_t>(value >> 8));
        mBuffer.push_back(static_cast<uint8_t>(value));
    } else if (value <= 0xFFFFFFFF) {
        mBuffer.push_back(majorByte | 26);
        mBuffer.push_back(static_cast<uint8_t>(value >> 24));
        mBuffer.push_back(static_cast<uint8_t>(value >> 16));
        mBuffer.push_back(static_cast<uint8_t>(value >> 8));
        mBuffer.push_back(static_cast<uint8_t>(value));
    } else {
        mBuffer.push_back(majorByte | 27);
        for (int i = 7; i >= 0; --i) {
            mBuffer.push_back(static_cast<uint8_t>(value >> (8 * i)));
        }
    }
}

void Encoder::addUint(uint64_t value)      { encodeHead(MajorType::UINT, value); }
void Encoder::addTag(uint64_t tag)         { encodeHead(MajorType::TAG, tag); }
void Encoder::beginArray(size_t count)     { encodeHead(MajorType::ARRAY, count); }
void Encoder::beginMap(size_t count)       { encodeHead(MajorType::MAP, count); }
void Encoder::addBool(bool value)          { mBuffer.push_back(value ? 0xF5 : 0xF4); }
void Encoder::addNull()                    { mBuffer.push_back(0xF6); }

void Encoder::addInt(int64_t value) {
    if (value >= 0) {
        encodeHead(MajorType::UINT, static_cast<uint64_t>(value));
    } else {
        encodeHead(MajorType::INT, static_cast<uint64_t>(-1 - value));
    }
}

void Encoder::addBytes(ByteView data) {
    encodeHead(MajorType::BYTES, data.size());
    mBuffer.insert(mBuffer.end(), data.begin(), data.end());
}

void Encoder::addText(std::string_view text) {
    encodeHead(MajorType::TEXT, text.size());
    mBuffer.insert(mBuffer.end(), text.begin(), text.end());
}

Bytes Encoder::finish() { return std::move(mBuffer); }

// --- Decoder ---

Decoder::Decoder(ByteView data) : mData(data), mPos(0) {}

bool Decoder::isAtEnd() const { return mPos >= mData.size(); }
size_t Decoder::bytesConsumed() const { return mPos; }

Result<MajorType> Decoder::peekMajorType() const {
    if (mPos >= mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
    return static_cast<MajorType>(mData[mPos] >> 5);
}

Result<uint64_t> Decoder::decodeHead(uint8_t& outMajorType) {
    if (mPos >= mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
    uint8_t byte = mData[mPos++];
    outMajorType = byte >> 5;
    uint8_t info = byte & 0x1F;

    if (info <= 23) return static_cast<uint64_t>(info);

    if (info == 24) {
        if (mPos >= mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
        return static_cast<uint64_t>(mData[mPos++]);
    }
    if (info == 25) {
        if (mPos + 2 > mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
        uint64_t v = (static_cast<uint64_t>(mData[mPos]) << 8) | mData[mPos + 1];
        mPos += 2;
        return v;
    }
    if (info == 26) {
        if (mPos + 4 > mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
        uint64_t v = 0;
        for (int i = 3; i >= 0; --i) v |= static_cast<uint64_t>(mData[mPos++]) << (8 * i);
        return v;
    }
    if (info == 27) {
        if (mPos + 8 > mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
        uint64_t v = 0;
        for (int i = 7; i >= 0; --i) v |= static_cast<uint64_t>(mData[mPos++]) << (8 * i);
        return v;
    }
    return tl::unexpected(AliroError::DECODING_ERROR);
}

Result<uint64_t> Decoder::getUint() {
    uint8_t major = 0;
    auto val = decodeHead(major);
    if (!val) return tl::unexpected(val.error());
    if (major != 0) return tl::unexpected(AliroError::DECODING_ERROR);
    return *val;
}

Result<int64_t> Decoder::getInt() {
    uint8_t major = 0;
    auto val = decodeHead(major);
    if (!val) return tl::unexpected(val.error());
    if (major == 0) return static_cast<int64_t>(*val);
    if (major == 1) return static_cast<int64_t>(-1 - static_cast<int64_t>(*val));
    return tl::unexpected(AliroError::DECODING_ERROR);
}

Result<Bytes> Decoder::getBytes() {
    uint8_t major = 0;
    auto lenResult = decodeHead(major);
    if (!lenResult) return tl::unexpected(lenResult.error());
    if (major != 2) return tl::unexpected(AliroError::DECODING_ERROR);
    size_t len = static_cast<size_t>(*lenResult);
    if (mPos + len > mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
    Bytes result(mData.data() + mPos, mData.data() + mPos + len);
    mPos += len;
    return result;
}

Result<std::string> Decoder::getText() {
    uint8_t major = 0;
    auto lenResult = decodeHead(major);
    if (!lenResult) return tl::unexpected(lenResult.error());
    if (major != 3) return tl::unexpected(AliroError::DECODING_ERROR);
    size_t len = static_cast<size_t>(*lenResult);
    if (mPos + len > mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
    std::string result(reinterpret_cast<const char*>(mData.data() + mPos), len);
    mPos += len;
    return result;
}

Result<bool> Decoder::getBool() {
    if (mPos >= mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
    uint8_t byte = mData[mPos++];
    if (byte == 0xF5) return true;
    if (byte == 0xF4) return false;
    return tl::unexpected(AliroError::DECODING_ERROR);
}

Result<void> Decoder::getNull() {
    if (mPos >= mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
    if (mData[mPos++] != 0xF6) return tl::unexpected(AliroError::DECODING_ERROR);
    return {};
}

Result<uint64_t> Decoder::getTag() {
    uint8_t major = 0;
    auto val = decodeHead(major);
    if (!val) return tl::unexpected(val.error());
    if (major != 6) return tl::unexpected(AliroError::DECODING_ERROR);
    return *val;
}

Result<size_t> Decoder::getArraySize() {
    uint8_t major = 0;
    auto count = decodeHead(major);
    if (!count) return tl::unexpected(count.error());
    if (major != 4) return tl::unexpected(AliroError::DECODING_ERROR);
    return static_cast<size_t>(*count);
}

Result<size_t> Decoder::getMapSize() {
    uint8_t major = 0;
    auto count = decodeHead(major);
    if (!count) return tl::unexpected(count.error());
    if (major != 5) return tl::unexpected(AliroError::DECODING_ERROR);
    return static_cast<size_t>(*count);
}

Result<void> Decoder::skip() {
    if (isAtEnd()) return tl::unexpected(AliroError::DECODING_ERROR);
    uint8_t major = 0;
    auto val = decodeHead(major);
    if (!val) return tl::unexpected(val.error());

    switch (static_cast<MajorType>(major)) {
        case MajorType::UINT:
        case MajorType::INT:
            return {};
        case MajorType::SIMPLE:
            return {};
        case MajorType::BYTES:
        case MajorType::TEXT: {
            size_t len = static_cast<size_t>(*val);
            if (mPos + len > mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
            mPos += len;
            return {};
        }
        case MajorType::ARRAY: {
            for (uint64_t i = 0; i < *val; ++i) {
                auto r = skip();
                if (!r) return r;
            }
            return {};
        }
        case MajorType::MAP: {
            for (uint64_t i = 0; i < *val * 2; ++i) {
                auto r = skip();
                if (!r) return r;
            }
            return {};
        }
        case MajorType::TAG:
            return skip();
        default:
            return tl::unexpected(AliroError::DECODING_ERROR);
    }
}

} // namespace aliro::cbor
```

- [ ] **Step 5: Build and run tests — expect PASS**

```bash
cmake --build --preset debug && ctest --preset debug --tests-regex CborEncodeTest
```

Expected: All CBOR tests pass.

- [ ] **Step 6: Commit**

```bash
git add modules/core/include/aliro/core/cbor.h modules/core/src/cbor.cpp tests/unit/core/cborTest.cpp
CHANGE_ID="I$(openssl rand -hex 20)"
git commit -m "feat(core): implement CBOR encoder/decoder with RFC 8949 known-answer tests

Change-Id: ${CHANGE_ID}"
```

---

## Task 10: Protocol Constants

**Files:**
- Create: `modules/core/include/aliro/core/protocol.h`

- [ ] **Step 1: Write `modules/core/include/aliro/core/protocol.h`**

```cpp
#pragma once

#include <cstdint>
#include <string_view>

namespace aliro::protocol {

// Aliro docType (ISO 18013-5 namespace)
constexpr std::string_view kAliroDocType      = "0.0.1.0.0.0.0.1";
constexpr std::string_view kAliroNameSpace    = "0.0.1.0.0.0.0.1";
constexpr std::string_view kRevocationDocType = "0.0.1.0.0.0.0.2";

// APDU command class byte
constexpr uint8_t kAliroCla = 0x00;

// APDU instruction bytes (ISO 7816-4)
constexpr uint8_t kInsAuth0       = 0x87;
constexpr uint8_t kInsAuth1       = 0x86;
constexpr uint8_t kInsEnvelope    = 0xC3;
constexpr uint8_t kInsGetData     = 0xCB;

// AID for Aliro application selection
// Aliro AID: A0 00 00 09 63 4C 69 72 6F (not yet finalised in 1.0 spec, placeholder)
constexpr uint8_t kAliroAid[] = {0xA0, 0x00, 0x00, 0x09, 0x63, 0x4C, 0x69, 0x72, 0x6F};

// DER-TLV tags used in Aliro APDU data fields (per spec section 8.3)
constexpr uint32_t kTagCryptogram          = 0x9D;
constexpr uint32_t kTagEphemeralPublicKey  = 0x86;
constexpr uint32_t kTagSignature           = 0x9E;
constexpr uint32_t kTagReaderIdentifier    = 0x83;
constexpr uint32_t kTagReaderNonce         = 0x85;
constexpr uint32_t kTagDeviceNonce         = 0x8A;
constexpr uint32_t kTagReaderCert          = 0x67;
constexpr uint32_t kTagDeviceRequest       = 0xA7;
constexpr uint32_t kTagDeviceResponse      = 0xA8;

// IssuerAuth key remapping (spec Table 7-1)
constexpr std::string_view kIssuerAuthVersion       = "1";
constexpr std::string_view kIssuerAuthDigestAlg     = "2";
constexpr std::string_view kIssuerAuthValueDigests  = "3";
constexpr std::string_view kIssuerAuthDeviceKeyInfo = "4";
constexpr std::string_view kIssuerAuthDocType       = "5";
constexpr std::string_view kIssuerAuthValidityInfo  = "6";

// IssuerSignedItem key remapping (spec Table 7-2)
constexpr std::string_view kSignedItemDigestId      = "1";
constexpr std::string_view kSignedItemRandom        = "2";
constexpr std::string_view kSignedItemElementId     = "3";
constexpr std::string_view kSignedItemElementValue  = "4";

// AccessData key values (spec section 7.3)
constexpr uint64_t kAccessDataVersion    = 0;
constexpr uint64_t kAccessDataId         = 1;
constexpr uint64_t kAccessDataRules      = 2;
constexpr uint64_t kAccessDataSchedules  = 3;
constexpr uint64_t kAccessDataReaderIds  = 4;
constexpr uint64_t kAccessDataNonAccExt  = 5;
constexpr uint64_t kAccessDataAccExt     = 6;

// AccessRule key values (spec section 7.3.3)
constexpr uint64_t kAccessRuleCapabilities      = 0;
constexpr uint64_t kAccessRuleAllowScheduleIds  = 1;
constexpr uint64_t kAccessRuleDenyScheduleIds   = 2;
constexpr uint64_t kAccessRuleReaderRuleIds      = 3;

// AccessRuleCapabilities bit positions
constexpr uint16_t kCapSecure                    = 1 << 0;
constexpr uint16_t kCapUnsecure                  = 1 << 1;
constexpr uint16_t kCapToggleSecureOrUnsecure    = 1 << 2;
constexpr uint16_t kCapMomentaryUnsecure         = 1 << 3;
constexpr uint16_t kCapExtendedMomentaryUnsecure = 1 << 4;
constexpr uint16_t kCapPaymentPermission         = 1 << 5;

// Schedule key values (spec section 7.3.4)
constexpr uint64_t kScheduleStartPeriod    = 0;
constexpr uint64_t kScheduleEndPeriod      = 1;
constexpr uint64_t kScheduleRecurrenceRule = 2;
constexpr uint64_t kScheduleFlags          = 3;

// Cryptographic constants
constexpr size_t kEcPublicKeySize  = 65;  // uncompressed P-256 point
constexpr size_t kEcPrivateKeySize = 32;
constexpr size_t kSignatureSize    = 64;  // raw r||s
constexpr size_t kAesKeySize       = 16;  // AES-128
constexpr size_t kGcmNonceSize     = 12;
constexpr size_t kGcmTagSize       = 16;
constexpr size_t kKpersistentSize  = 32;

} // namespace aliro::protocol
```

- [ ] **Step 2: Commit**

```bash
git add modules/core/include/aliro/core/protocol.h
CHANGE_ID="I$(openssl rand -hex 20)"
git commit -m "feat(core): add Aliro protocol constants

Change-Id: ${CHANGE_ID}"
```

---

## Task 11: IssuerAuth Structures

**Files:**
- Create: `modules/core/include/aliro/core/issuerAuth.h`
- Create: `modules/core/src/issuerAuth.cpp`
- Create: `tests/unit/core/issuerAuthTest.cpp`

- [ ] **Step 1: Write the failing tests — `tests/unit/core/issuerAuthTest.cpp`**

```cpp
#include "aliro/core/issuerAuth.h"
#include <gtest/gtest.h>

using namespace aliro;

TEST(IssuerSignedItemTest, encodeDecodeRoundTrip) {
    IssuerSignedItem item;
    item.digestId = 1;
    item.random   = Bytes(16, 0xAA);
    item.elementIdentifier = "some.element";
    item.elementValue      = Bytes{0x41, 0x01}; // CBOR-encoded uint 1

    auto encoded = encodeIssuerSignedItem(item);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = decodeIssuerSignedItem(*encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->digestId, item.digestId);
    EXPECT_EQ(decoded->random, item.random);
    EXPECT_EQ(decoded->elementIdentifier, item.elementIdentifier);
    EXPECT_EQ(decoded->elementValue, item.elementValue);
}

TEST(IssuerAuthTest, encodeDecodeRoundTrip) {
    IssuerAuth auth;
    auth.protectedHeader   = Bytes{0xA1, 0x01, 0x26}; // CBOR {"alg": -7}
    auth.unprotectedHeader = Bytes{0xA0};              // CBOR {}
    auth.payload           = Bytes(32, 0xBB);
    auth.signature         = Bytes(64, 0xCC);

    auto encoded = encodeIssuerAuth(auth);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = decodeIssuerAuth(*encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->protectedHeader,   auth.protectedHeader);
    EXPECT_EQ(decoded->unprotectedHeader, auth.unprotectedHeader);
    EXPECT_EQ(decoded->payload,           auth.payload);
    EXPECT_EQ(decoded->signature,         auth.signature);
}

TEST(IssuerAuthTest, decodeMalformedData_returnsError) {
    Bytes garbage = {0x01, 0x02, 0x03};
    auto result = decodeIssuerAuth(garbage);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::DECODING_ERROR);
}

TEST(IssuerAuthTest, signatureWrongSize_returnsError) {
    // Build an IssuerAuth with wrong-size signature
    cbor::Encoder enc;
    enc.beginArray(4);
    enc.addBytes(Bytes{0xA1, 0x01, 0x26}); // protected
    enc.beginMap(0);                        // unprotected (empty)
    enc.addBytes(Bytes(32, 0xBB));          // payload
    enc.addBytes(Bytes(32, 0xCC));          // signature — wrong: must be 64 bytes
    Bytes data = enc.finish();

    auto result = decodeIssuerAuth(data);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::INVALID_MESSAGE);
}
```

- [ ] **Step 2: Run tests — expect compile failure**

```bash
cmake --build --preset debug 2>&1 | grep "error:" | head -5
```

Expected: error about missing `aliro/core/issuerAuth.h`.

- [ ] **Step 3: Write `modules/core/include/aliro/core/issuerAuth.h`**

```cpp
#pragma once

#include "aliro/core/types.h"
#include "aliro/core/cbor.h"
#include <string>
#include <vector>

namespace aliro {

/// IssuerSignedItem: one signed namespace data element (spec §7.2, Table 7-2).
struct IssuerSignedItem {
    uint32_t    digestId;
    Bytes       random;             // 16-byte salt
    std::string elementIdentifier;
    Bytes       elementValue;       // CBOR-encoded element value
};

/// IssuerAuth: COSE_Sign1 structure carrying the signed Access Document (spec §7.2).
struct IssuerAuth {
    Bytes protectedHeader;    // serialized CBOR map (contains "alg")
    Bytes unprotectedHeader;  // serialized CBOR map (may be empty: A0)
    Bytes payload;            // IssuerNameSpaces CBOR bytes
    Bytes signature;          // 64-byte raw ECDSA P-256 signature (r||s)
};

Result<Bytes>            encodeIssuerSignedItem(const IssuerSignedItem& item);
Result<IssuerSignedItem> decodeIssuerSignedItem(ByteView data);

Result<Bytes>      encodeIssuerAuth(const IssuerAuth& auth);
Result<IssuerAuth> decodeIssuerAuth(ByteView data);

} // namespace aliro
```

- [ ] **Step 4: Write `modules/core/src/issuerAuth.cpp`**

```cpp
#include "aliro/core/issuerAuth.h"
#include "aliro/core/protocol.h"

namespace aliro {

Result<Bytes> encodeIssuerSignedItem(const IssuerSignedItem& item) {
    cbor::Encoder enc;
    enc.beginMap(4);
    enc.addText(protocol::kSignedItemDigestId);
    enc.addUint(item.digestId);
    enc.addText(protocol::kSignedItemRandom);
    enc.addBytes(item.random);
    enc.addText(protocol::kSignedItemElementId);
    enc.addText(item.elementIdentifier);
    enc.addText(protocol::kSignedItemElementValue);
    enc.addBytes(item.elementValue);
    return enc.finish();
}

Result<IssuerSignedItem> decodeIssuerSignedItem(ByteView data) {
    cbor::Decoder dec(data);
    auto count = dec.getMapSize();
    if (!count) return tl::unexpected(AliroError::DECODING_ERROR);

    IssuerSignedItem item;
    for (size_t i = 0; i < *count; ++i) {
        auto key = dec.getText();
        if (!key) return tl::unexpected(AliroError::DECODING_ERROR);

        if (*key == protocol::kSignedItemDigestId) {
            auto v = dec.getUint();
            if (!v) return tl::unexpected(AliroError::DECODING_ERROR);
            item.digestId = static_cast<uint32_t>(*v);
        } else if (*key == protocol::kSignedItemRandom) {
            auto v = dec.getBytes();
            if (!v) return tl::unexpected(AliroError::DECODING_ERROR);
            item.random = std::move(*v);
        } else if (*key == protocol::kSignedItemElementId) {
            auto v = dec.getText();
            if (!v) return tl::unexpected(AliroError::DECODING_ERROR);
            item.elementIdentifier = std::move(*v);
        } else if (*key == protocol::kSignedItemElementValue) {
            auto v = dec.getBytes();
            if (!v) return tl::unexpected(AliroError::DECODING_ERROR);
            item.elementValue = std::move(*v);
        } else {
            if (!dec.skip()) return tl::unexpected(AliroError::DECODING_ERROR);
        }
    }
    return item;
}

Result<Bytes> encodeIssuerAuth(const IssuerAuth& auth) {
    // COSE_Sign1 = [protected, unprotected, payload, signature]
    cbor::Encoder enc;
    enc.beginArray(4);
    enc.addBytes(auth.protectedHeader);
    // unprotectedHeader is already a serialized CBOR map — add as raw bytes then re-encode
    // Actually per COSE, unprotected is an inline map, not bytes.
    // We store it serialized for flexibility; decode handles both.
    enc.addBytes(auth.unprotectedHeader);
    enc.addBytes(auth.payload);
    enc.addBytes(auth.signature);
    return enc.finish();
}

Result<IssuerAuth> decodeIssuerAuth(ByteView data) {
    cbor::Decoder dec(data);
    auto count = dec.getArraySize();
    if (!count) return tl::unexpected(AliroError::DECODING_ERROR);
    if (*count != 4) return tl::unexpected(AliroError::DECODING_ERROR);

    IssuerAuth auth;

    auto protHdr = dec.getBytes();
    if (!protHdr) return tl::unexpected(AliroError::DECODING_ERROR);
    auth.protectedHeader = std::move(*protHdr);

    auto unprotHdr = dec.getBytes();
    if (!unprotHdr) return tl::unexpected(AliroError::DECODING_ERROR);
    auth.unprotectedHeader = std::move(*unprotHdr);

    auto payload = dec.getBytes();
    if (!payload) return tl::unexpected(AliroError::DECODING_ERROR);
    auth.payload = std::move(*payload);

    auto sig = dec.getBytes();
    if (!sig) return tl::unexpected(AliroError::DECODING_ERROR);
    if (sig->size() != protocol::kSignatureSize) {
        return tl::unexpected(AliroError::INVALID_MESSAGE);
    }
    auth.signature = std::move(*sig);

    return auth;
}

} // namespace aliro
```

- [ ] **Step 5: Build and run tests — expect PASS**

```bash
cmake --build --preset debug && ctest --preset debug --tests-regex IssuerAuthTest
```

Expected: All IssuerAuth tests pass.

- [ ] **Step 6: Commit**

```bash
git add modules/core/include/aliro/core/issuerAuth.h modules/core/src/issuerAuth.cpp tests/unit/core/issuerAuthTest.cpp
CHANGE_ID="I$(openssl rand -hex 20)"
git commit -m "feat(core): implement IssuerAuth and IssuerSignedItem CBOR structures

Change-Id: ${CHANGE_ID}"
```

---

## Task 12: AccessRule + Schedule Structures

**Files:**
- Create: `modules/core/include/aliro/core/accessRule.h`

- [ ] **Step 1: Write `modules/core/include/aliro/core/accessRule.h`**

No separate .cpp needed — these are plain data types; encoding lives in accessDocument.cpp.

```cpp
#pragma once

#include "aliro/core/types.h"
#include <cstdint>
#include <optional>
#include <vector>

namespace aliro {

/// AccessRuleCapabilities bitmask (spec §7.3.3, Table 7-3).
struct AccessRuleCapabilities {
    bool secure{false};
    bool unsecure{false};
    bool toggleSecureOrUnsecure{false};
    bool momentaryUnsecure{false};
    bool extendedMomentaryUnsecure{false};
    bool paymentPermission{false};

    uint16_t toBits() const {
        uint16_t bits = 0;
        if (secure)                    bits |= (1 << 0);
        if (unsecure)                  bits |= (1 << 1);
        if (toggleSecureOrUnsecure)    bits |= (1 << 2);
        if (momentaryUnsecure)         bits |= (1 << 3);
        if (extendedMomentaryUnsecure) bits |= (1 << 4);
        if (paymentPermission)         bits |= (1 << 5);
        return bits;
    }

    static AccessRuleCapabilities fromBits(uint16_t bits) {
        AccessRuleCapabilities c;
        c.secure                    = (bits >> 0) & 1;
        c.unsecure                  = (bits >> 1) & 1;
        c.toggleSecureOrUnsecure    = (bits >> 2) & 1;
        c.momentaryUnsecure         = (bits >> 3) & 1;
        c.extendedMomentaryUnsecure = (bits >> 4) & 1;
        c.paymentPermission         = (bits >> 5) & 1;
        return c;
    }
};

/// AccessRule: one rule for a credential (spec §7.3.3).
struct AccessRule {
    std::optional<AccessRuleCapabilities> capabilities;
    std::optional<std::vector<uint32_t>>  allowScheduleIds;
    std::optional<std::vector<uint32_t>>  denyScheduleIds;
    std::optional<std::vector<uint32_t>>  readerRuleIds;
};

/// Schedule recurrence pattern (spec §7.3.4).
enum class RecurrencePattern : uint8_t {
    DAILY              = 0,
    WEEKLY             = 1,
    MONTHLY_BY_WEEKDAY = 2,
    MONTHLY_BY_DATE    = 3,
    YEARLY_BY_WEEKDAY  = 4,
    YEARLY_BY_DATE     = 5,
    YEARLY_BY_WEEK     = 6,
    YEARLY_BY_MONTH_WEEK = 7,
    YEARLY_BY_MONTH    = 8,
};

struct RecurrenceRule {
    RecurrencePattern pattern;
    uint32_t          interval{1};
    uint32_t          mask{0};
    int32_t           ordinal{0};
};

/// Schedule: time window for an access rule (spec §7.3.4).
struct Schedule {
    uint64_t                         startPeriod;  // Unix epoch seconds
    std::optional<uint64_t>          endPeriod;
    std::optional<RecurrenceRule>    recurrenceRule;
    uint32_t                         flags{0};
};

} // namespace aliro
```

- [ ] **Step 2: Commit**

```bash
git add modules/core/include/aliro/core/accessRule.h
CHANGE_ID="I$(openssl rand -hex 20)"
git commit -m "feat(core): add AccessRule, AccessRuleCapabilities, Schedule data types

Change-Id: ${CHANGE_ID}"
```

---

## Task 13: AccessDataElement Structure

**Files:**
- Create: `modules/core/include/aliro/core/accessDataElement.h`

- [ ] **Step 1: Write `modules/core/include/aliro/core/accessDataElement.h`**

```cpp
#pragma once

#include "aliro/core/types.h"
#include "aliro/core/accessRule.h"
#include <optional>
#include <string>
#include <vector>

namespace aliro {

struct VendorExtension {
    uint32_t vendorId;  // IEEE OUI or CID
    Bytes    data;
};

struct AccessExtension {
    bool            critical{false};
    VendorExtension extension;
};

/// AccessDataElement: signed data element within an Access Document (spec §7.3).
struct AccessDataElement {
    uint32_t                               version{1};
    std::optional<Bytes>                   id;
    std::optional<std::vector<AccessRule>> accessRules;
    std::optional<std::vector<Schedule>>   schedules;
    std::optional<std::vector<uint32_t>>   readerRuleIds;
    std::optional<std::vector<VendorExtension>>  nonAccessExtensions;
    std::optional<std::vector<AccessExtension>>  accessExtensions;
};

} // namespace aliro
```

- [ ] **Step 2: Commit**

```bash
git add modules/core/include/aliro/core/accessDataElement.h
CHANGE_ID="I$(openssl rand -hex 20)"
git commit -m "feat(core): add AccessDataElement struct

Change-Id: ${CHANGE_ID}"
```

---

## Task 14: AccessDocument — Encode/Decode

**Files:**
- Create: `modules/core/include/aliro/core/accessDocument.h`
- Create: `modules/core/src/accessDocument.cpp`
- Create: `tests/unit/core/accessDocumentTest.cpp`

- [ ] **Step 1: Write the failing tests — `tests/unit/core/accessDocumentTest.cpp`**

```cpp
#include "aliro/core/accessDocument.h"
#include "aliro/core/protocol.h"
#include <gtest/gtest.h>

using namespace aliro;

TEST(AccessDocumentTest, encodeDecodeRoundTrip_minimal) {
    AccessDocument doc;
    doc.docType = std::string(protocol::kAliroDocType);
    doc.issuerAuth.protectedHeader   = Bytes{0xA0};
    doc.issuerAuth.unprotectedHeader = Bytes{0xA0};
    doc.issuerAuth.payload           = Bytes(16, 0x00);
    doc.issuerAuth.signature         = Bytes(64, 0xAB);

    auto encoded = encodeAccessDocument(doc);
    ASSERT_TRUE(encoded.has_value()) << "encode failed";

    auto decoded = decodeAccessDocument(*encoded);
    ASSERT_TRUE(decoded.has_value()) << "decode failed";

    EXPECT_EQ(decoded->docType, doc.docType);
    EXPECT_EQ(decoded->issuerAuth.signature, doc.issuerAuth.signature);
    EXPECT_EQ(decoded->issuerAuth.payload, doc.issuerAuth.payload);
}

TEST(AccessDocumentTest, encodeDecodeRoundTrip_withNamespace) {
    AccessDocument doc;
    doc.docType = std::string(protocol::kAliroDocType);
    doc.issuerAuth.protectedHeader   = Bytes{0xA0};
    doc.issuerAuth.unprotectedHeader = Bytes{0xA0};
    doc.issuerAuth.payload           = Bytes(16, 0x11);
    doc.issuerAuth.signature         = Bytes(64, 0xFF);

    NameSpaceItems ns;
    ns.nameSpace = std::string(protocol::kAliroNameSpace);
    ns.issuerSignedItems.push_back(Bytes{0x42, 0xAA, 0xBB}); // dummy item bytes
    doc.nameSpaces.push_back(std::move(ns));

    auto encoded = encodeAccessDocument(doc);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = decodeAccessDocument(*encoded);
    ASSERT_TRUE(decoded.has_value());

    ASSERT_EQ(decoded->nameSpaces.size(), 1u);
    EXPECT_EQ(decoded->nameSpaces[0].nameSpace, std::string(protocol::kAliroNameSpace));
    ASSERT_EQ(decoded->nameSpaces[0].issuerSignedItems.size(), 1u);
}

TEST(AccessDocumentTest, decodeMalformed_returnsError) {
    Bytes garbage = {0xFF, 0xFE, 0xFD};
    auto result = decodeAccessDocument(garbage);
    EXPECT_FALSE(result.has_value());
}
```

- [ ] **Step 2: Write `modules/core/include/aliro/core/accessDocument.h`**

```cpp
#pragma once

#include "aliro/core/types.h"
#include "aliro/core/issuerAuth.h"
#include <string>
#include <vector>

namespace aliro {

/// One namespace worth of signed items within an AccessDocument.
struct NameSpaceItems {
    std::string        nameSpace;
    std::vector<Bytes> issuerSignedItems; // each element is an encoded IssuerSignedItem
};

/// AccessDocument: ISO 18013-5 based structure carrying Aliro access data (spec §7.2).
struct AccessDocument {
    std::string                  docType;
    IssuerAuth                   issuerAuth;
    std::vector<NameSpaceItems>  nameSpaces;
};

Result<Bytes>          encodeAccessDocument(const AccessDocument& doc);
Result<AccessDocument> decodeAccessDocument(ByteView data);

} // namespace aliro
```

- [ ] **Step 3: Write `modules/core/src/accessDocument.cpp`**

```cpp
#include "aliro/core/accessDocument.h"
#include "aliro/core/cbor.h"

namespace aliro {

Result<Bytes> encodeAccessDocument(const AccessDocument& doc) {
    // Structure: {"docType": text, "issuerAuth": IssuerAuth, "nameSpaces": map}
    auto issuerAuthBytes = encodeIssuerAuth(doc.issuerAuth);
    if (!issuerAuthBytes) return tl::unexpected(issuerAuthBytes.error());

    cbor::Encoder enc;
    size_t fieldCount = 2 + (doc.nameSpaces.empty() ? 0 : 1);
    enc.beginMap(fieldCount);

    enc.addText("docType");
    enc.addText(doc.docType);

    enc.addText("issuerAuth");
    enc.addBytes(*issuerAuthBytes);

    if (!doc.nameSpaces.empty()) {
        enc.addText("nameSpaces");
        enc.beginMap(doc.nameSpaces.size());
        for (const auto& ns : doc.nameSpaces) {
            enc.addText(ns.nameSpace);
            enc.beginArray(ns.issuerSignedItems.size());
            for (const auto& item : ns.issuerSignedItems) {
                enc.addBytes(item);
            }
        }
    }

    return enc.finish();
}

Result<AccessDocument> decodeAccessDocument(ByteView data) {
    cbor::Decoder dec(data);
    auto count = dec.getMapSize();
    if (!count) return tl::unexpected(AliroError::DECODING_ERROR);

    AccessDocument doc;

    for (size_t i = 0; i < *count; ++i) {
        auto key = dec.getText();
        if (!key) return tl::unexpected(AliroError::DECODING_ERROR);

        if (*key == "docType") {
            auto v = dec.getText();
            if (!v) return tl::unexpected(AliroError::DECODING_ERROR);
            doc.docType = std::move(*v);
        } else if (*key == "issuerAuth") {
            auto bytes = dec.getBytes();
            if (!bytes) return tl::unexpected(AliroError::DECODING_ERROR);
            auto auth = decodeIssuerAuth(*bytes);
            if (!auth) return tl::unexpected(auth.error());
            doc.issuerAuth = std::move(*auth);
        } else if (*key == "nameSpaces") {
            auto nsCount = dec.getMapSize();
            if (!nsCount) return tl::unexpected(AliroError::DECODING_ERROR);
            for (size_t j = 0; j < *nsCount; ++j) {
                NameSpaceItems ns;
                auto nsKey = dec.getText();
                if (!nsKey) return tl::unexpected(AliroError::DECODING_ERROR);
                ns.nameSpace = std::move(*nsKey);
                auto itemCount = dec.getArraySize();
                if (!itemCount) return tl::unexpected(AliroError::DECODING_ERROR);
                for (size_t k = 0; k < *itemCount; ++k) {
                    auto item = dec.getBytes();
                    if (!item) return tl::unexpected(AliroError::DECODING_ERROR);
                    ns.issuerSignedItems.push_back(std::move(*item));
                }
                doc.nameSpaces.push_back(std::move(ns));
            }
        } else {
            if (!dec.skip()) return tl::unexpected(AliroError::DECODING_ERROR);
        }
    }
    return doc;
}

} // namespace aliro
```

- [ ] **Step 4: Build and run tests — expect PASS**

```bash
cmake --build --preset debug && ctest --preset debug --tests-regex AccessDocumentTest
```

Expected: All AccessDocument tests pass.

- [ ] **Step 5: Commit**

```bash
git add modules/core/include/aliro/core/accessDocument.h modules/core/src/accessDocument.cpp tests/unit/core/accessDocumentTest.cpp
CHANGE_ID="I$(openssl rand -hex 20)"
git commit -m "feat(core): implement AccessDocument CBOR encode/decode with tests

Change-Id: ${CHANGE_ID}"
```

---

## Task 15: RevocationDocument — Encode/Decode

**Files:**
- Create: `modules/core/include/aliro/core/revocationDocument.h`
- Create: `modules/core/src/revocationDocument.cpp`
- Create: `tests/unit/core/revocationDocumentTest.cpp`

- [ ] **Step 1: Write the failing tests — `tests/unit/core/revocationDocumentTest.cpp`**

```cpp
#include "aliro/core/revocationDocument.h"
#include "aliro/core/protocol.h"
#include <gtest/gtest.h>

using namespace aliro;

TEST(RevocationDocumentTest, encodeDecodeRoundTrip_overwrite) {
    RevocationDocument doc;
    doc.docType = std::string(protocol::kRevocationDocType);
    doc.issuerAuth.protectedHeader   = Bytes{0xA0};
    doc.issuerAuth.unprotectedHeader = Bytes{0xA0};
    doc.issuerAuth.payload           = Bytes(8, 0x00);
    doc.issuerAuth.signature         = Bytes(64, 0xDD);

    RevocationDataElement elem;
    elem.version    = 1;
    elem.changeMode = ChangeMode::OVERWRITE;
    elem.entries.push_back({Bytes{0x01, 0x02, 0x03, 0x04}});
    doc.revocationElements.push_back(elem);

    auto encoded = encodeRevocationDocument(doc);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = decodeRevocationDocument(*encoded);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->revocationElements.size(), 1u);
    EXPECT_EQ(decoded->revocationElements[0].changeMode, ChangeMode::OVERWRITE);
    ASSERT_EQ(decoded->revocationElements[0].entries.size(), 1u);
    EXPECT_EQ(decoded->revocationElements[0].entries[0].credentialId, (Bytes{0x01,0x02,0x03,0x04}));
}

TEST(RevocationDocumentTest, encodeDecodeRoundTrip_update_withRemove) {
    RevocationDocument doc;
    doc.docType = std::string(protocol::kRevocationDocType);
    doc.issuerAuth.protectedHeader   = Bytes{0xA0};
    doc.issuerAuth.unprotectedHeader = Bytes{0xA0};
    doc.issuerAuth.payload           = Bytes(8, 0x00);
    doc.issuerAuth.signature         = Bytes(64, 0xEE);

    RevocationDataElement elem;
    elem.version    = 1;
    elem.changeMode = ChangeMode::UPDATE;
    elem.entries.push_back({Bytes{0xAA, 0xBB}});
    elem.entriesRemove.push_back({Bytes{0xCC, 0xDD}});
    doc.revocationElements.push_back(elem);

    auto encoded = encodeRevocationDocument(doc);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = decodeRevocationDocument(*encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->revocationElements[0].changeMode, ChangeMode::UPDATE);
    EXPECT_EQ(decoded->revocationElements[0].entries[0].credentialId, (Bytes{0xAA, 0xBB}));
    EXPECT_EQ(decoded->revocationElements[0].entriesRemove[0].credentialId, (Bytes{0xCC, 0xDD}));
}

TEST(RevocationDocumentTest, decodeMalformed_returnsError) {
    Bytes garbage = {0xDE, 0xAD};
    EXPECT_FALSE(decodeRevocationDocument(garbage).has_value());
}
```

- [ ] **Step 2: Write `modules/core/include/aliro/core/revocationDocument.h`**

```cpp
#pragma once

#include "aliro/core/types.h"
#include "aliro/core/issuerAuth.h"
#include <cstdint>
#include <string>
#include <vector>

namespace aliro {

enum class ChangeMode : uint8_t { OVERWRITE = 0, UPDATE = 1 };

struct RevocationEntry {
    Bytes credentialId;
};

/// RevocationDataElement: one revocation list update (spec §7.6).
struct RevocationDataElement {
    uint32_t                      version{1};
    ChangeMode                    changeMode{ChangeMode::OVERWRITE};
    std::vector<RevocationEntry>  entries;
    std::vector<RevocationEntry>  entriesRemove; // only valid when changeMode == UPDATE
};

/// RevocationDocument: carries revocation data from User Device to Reader (spec §7.6).
struct RevocationDocument {
    std::string                          docType;
    IssuerAuth                           issuerAuth;
    std::vector<RevocationDataElement>   revocationElements;
};

Result<Bytes>               encodeRevocationDocument(const RevocationDocument& doc);
Result<RevocationDocument>  decodeRevocationDocument(ByteView data);

} // namespace aliro
```

- [ ] **Step 3: Write `modules/core/src/revocationDocument.cpp`**

```cpp
#include "aliro/core/revocationDocument.h"
#include "aliro/core/cbor.h"

namespace aliro {

namespace {

Result<Bytes> encodeRevocationDataElement(const RevocationDataElement& elem) {
    cbor::Encoder enc;
    size_t fieldCount = 2
        + (elem.entries.empty() ? 0 : 1)
        + (elem.entriesRemove.empty() ? 0 : 1);
    enc.beginMap(fieldCount);

    enc.addUint(0); enc.addUint(elem.version);
    enc.addUint(2); enc.addUint(static_cast<uint64_t>(elem.changeMode));

    if (!elem.entries.empty()) {
        enc.addUint(3);
        enc.beginArray(elem.entries.size());
        for (const auto& e : elem.entries) enc.addBytes(e.credentialId);
    }
    if (!elem.entriesRemove.empty()) {
        enc.addUint(4);
        enc.beginArray(elem.entriesRemove.size());
        for (const auto& e : elem.entriesRemove) enc.addBytes(e.credentialId);
    }
    return enc.finish();
}

Result<RevocationDataElement> decodeRevocationDataElement(ByteView data) {
    cbor::Decoder dec(data);
    auto count = dec.getMapSize();
    if (!count) return tl::unexpected(AliroError::DECODING_ERROR);

    RevocationDataElement elem;
    for (size_t i = 0; i < *count; ++i) {
        auto key = dec.getUint();
        if (!key) return tl::unexpected(AliroError::DECODING_ERROR);
        switch (*key) {
            case 0: { auto v = dec.getUint(); if (!v) return tl::unexpected(AliroError::DECODING_ERROR); elem.version = static_cast<uint32_t>(*v); break; }
            case 2: { auto v = dec.getUint(); if (!v) return tl::unexpected(AliroError::DECODING_ERROR); elem.changeMode = static_cast<ChangeMode>(*v); break; }
            case 3: { auto n = dec.getArraySize(); if (!n) return tl::unexpected(AliroError::DECODING_ERROR); for (size_t j = 0; j < *n; ++j) { auto b = dec.getBytes(); if (!b) return tl::unexpected(AliroError::DECODING_ERROR); elem.entries.push_back({std::move(*b)}); } break; }
            case 4: { auto n = dec.getArraySize(); if (!n) return tl::unexpected(AliroError::DECODING_ERROR); for (size_t j = 0; j < *n; ++j) { auto b = dec.getBytes(); if (!b) return tl::unexpected(AliroError::DECODING_ERROR); elem.entriesRemove.push_back({std::move(*b)}); } break; }
            default: { if (!dec.skip()) return tl::unexpected(AliroError::DECODING_ERROR); break; }
        }
    }
    return elem;
}

} // namespace

Result<Bytes> encodeRevocationDocument(const RevocationDocument& doc) {
    auto issuerAuthBytes = encodeIssuerAuth(doc.issuerAuth);
    if (!issuerAuthBytes) return tl::unexpected(issuerAuthBytes.error());

    cbor::Encoder enc;
    enc.beginMap(3);
    enc.addText("docType");    enc.addText(doc.docType);
    enc.addText("issuerAuth"); enc.addBytes(*issuerAuthBytes);
    enc.addText("revocationElements");
    enc.beginArray(doc.revocationElements.size());
    for (const auto& elem : doc.revocationElements) {
        auto elemBytes = encodeRevocationDataElement(elem);
        if (!elemBytes) return tl::unexpected(elemBytes.error());
        enc.addBytes(*elemBytes);
    }
    return enc.finish();
}

Result<RevocationDocument> decodeRevocationDocument(ByteView data) {
    cbor::Decoder dec(data);
    auto count = dec.getMapSize();
    if (!count) return tl::unexpected(AliroError::DECODING_ERROR);

    RevocationDocument doc;
    for (size_t i = 0; i < *count; ++i) {
        auto key = dec.getText();
        if (!key) return tl::unexpected(AliroError::DECODING_ERROR);

        if (*key == "docType") {
            auto v = dec.getText(); if (!v) return tl::unexpected(AliroError::DECODING_ERROR);
            doc.docType = std::move(*v);
        } else if (*key == "issuerAuth") {
            auto bytes = dec.getBytes(); if (!bytes) return tl::unexpected(AliroError::DECODING_ERROR);
            auto auth = decodeIssuerAuth(*bytes); if (!auth) return tl::unexpected(auth.error());
            doc.issuerAuth = std::move(*auth);
        } else if (*key == "revocationElements") {
            auto n = dec.getArraySize(); if (!n) return tl::unexpected(AliroError::DECODING_ERROR);
            for (size_t j = 0; j < *n; ++j) {
                auto elemBytes = dec.getBytes(); if (!elemBytes) return tl::unexpected(AliroError::DECODING_ERROR);
                auto elem = decodeRevocationDataElement(*elemBytes); if (!elem) return tl::unexpected(elem.error());
                doc.revocationElements.push_back(std::move(*elem));
            }
        } else {
            if (!dec.skip()) return tl::unexpected(AliroError::DECODING_ERROR);
        }
    }
    return doc;
}

} // namespace aliro
```

- [ ] **Step 4: Build and run ALL tests — expect full PASS**

```bash
cmake --build --preset debug && ctest --preset debug --output-on-failure
```

Expected: All tests pass across TLV, CBOR, IssuerAuth, AccessDocument, RevocationDocument.

- [ ] **Step 5: Commit**

```bash
git add modules/core/include/aliro/core/revocationDocument.h modules/core/src/revocationDocument.cpp tests/unit/core/revocationDocumentTest.cpp
CHANGE_ID="I$(openssl rand -hex 20)"
git commit -m "feat(core): implement RevocationDocument CBOR encode/decode with tests

Change-Id: ${CHANGE_ID}"
```

---

## Completion Checklist

After all 15 tasks, verify:

- [ ] `cmake --build --preset debug` succeeds with no warnings (all warnings are errors)
- [ ] `ctest --preset debug --output-on-failure` reports 0 failures
- [ ] `cmake --build --preset asan` succeeds and all tests pass under ASan
- [ ] `find modules tests -name '*.cpp' -o -name '*.h' | xargs clang-format --dry-run --Werror` exits 0
- [ ] `git log --oneline` shows one commit per task with Change-Id in every message
