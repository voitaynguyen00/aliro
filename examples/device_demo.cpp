// device_demo.cpp — Aliro device-side flow using MbedTLS.
//
// Demonstrates how a device (responder) processes SELECT → AUTH0 → AUTH1
// commands using the MbedTLS crypto backend.  A ReaderSession + SimTransport
// drives the exchange from the reader side.
//
// Build with:  cmake --preset default -DALIRO_BUILD_EXAMPLES=ON
//              cmake --build build --target device_demo

#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>

#include "aliro/core/accessDocument.h"
#include "aliro/core/protocol.h"
#include "aliro/crypto/mbedTlsCryptoProvider.h"
#include "aliro/crypto/openSslCryptoProvider.h"
#include "aliro/device/deviceSession.h"
#include "aliro/reader/readerSession.h"
#include "aliro/transport/simTransport.h"

using namespace aliro;

static std::string toHex(const Bytes& b) {
    std::ostringstream ss;
    for (auto byte : b)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    return ss.str();
}

static AccessDocument makeAccessDoc() {
    AccessDocument doc;
    doc.docType = std::string(protocol::kAliroDocType);
    doc.issuerAuth.protectedHeader = Bytes{0xA0};
    doc.issuerAuth.unprotectedHeader = Bytes{0xA0};
    doc.issuerAuth.payload = Bytes(8, 0x42);
    doc.issuerAuth.signature = Bytes(64, 0xAB);
    return doc;
}

int main() {
    std::cout << "=== Aliro Device Demo (MbedTLS) ===\n\n";

    // Device uses MbedTLS; simulated reader uses OpenSSL.
    MbedTlsCryptoProvider deviceCrypto;
    OpenSslCryptoProvider readerCrypto;

    // 1. Provision device: generate its long-term key pair with MbedTLS.
    auto deviceKp = deviceCrypto.generateKeyPair();
    auto readerKp = readerCrypto.generateKeyPair();
    if (!deviceKp || !readerKp) {
        std::cerr << "Key generation failed\n";
        return 1;
    }
    std::cout << "[device]  Device long-term public key : " << toHex(deviceKp->pub.data) << "\n";
    std::cout << "[reader]  Reader long-term public key : " << toHex(readerKp->pub.data) << "\n\n";

    // 2. Create the device session.  In production this runs on the embedded target.
    auto device = std::make_shared<DeviceSession>(deviceCrypto, deviceKp->priv, makeAccessDoc());

    // 3. Wire a SimTransport that routes incoming reader APDUs to the device session.
    SimTransport transport([&device](ByteView cmd) -> Result<Bytes> {
        if (cmd.size() < 2)
            return tl::unexpected(AliroError::INVALID_MESSAGE);
        uint8_t ins = cmd[1];
        std::cout << "[device]  Received APDU INS=0x" << std::hex << static_cast<int>(ins)
                  << std::dec << "\n";
        if (ins == protocol::kInsSelect)
            return device->handleSelect(cmd);
        if (ins == protocol::kInsAuth0)
            return device->handleAuth0(cmd);
        if (ins == protocol::kInsAuth1)
            return device->handleAuth1(cmd);
        return tl::unexpected(AliroError::INVALID_MESSAGE);
    });

    // 4. Simulated reader drives the exchange.
    std::cout << "[reader]  Starting SELECT → AUTH0 → AUTH1 …\n";
    ReaderSession reader(readerCrypto, transport);
    auto result = reader.authenticate(*readerKp, deviceKp->pub);

    if (!result) {
        std::cerr << "[reader]  Authentication FAILED (error " << static_cast<int>(result.error())
                  << ")\n";
        return 1;
    }

    // 5. Print outcome from the device's perspective.
    std::cout << "\n[device]  Authentication complete\n";
    std::cout << "[device]  Session key  : " << toHex(device->sessionKey()) << "\n";
    std::cout << "[reader]  Session key  : " << toHex(result->sessionKey) << "\n\n";

    if (device->sessionKey() == result->sessionKey)
        std::cout << "[check]   MbedTLS device and OpenSSL reader session keys MATCH ✓\n";
    else
        std::cout << "[check]   Key mismatch — BUG\n";

    return 0;
}
