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
