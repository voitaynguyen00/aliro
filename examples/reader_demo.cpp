// reader_demo.cpp — Aliro reader-side flow using OpenSSL.
//
// Demonstrates the full SELECT → AUTH0 → AUTH1 exchange from the reader's
// perspective.  A DeviceSession + SimTransport stands in for a real NFC device.
//
// Build with:  cmake --preset default -DALIRO_BUILD_EXAMPLES=ON
//              cmake --build build --target reader_demo

#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>

#include "aliro/core/accessDocument.h"
#include "aliro/core/protocol.h"
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
    doc.issuerAuth.protectedHeader   = Bytes{0xA0};
    doc.issuerAuth.unprotectedHeader = Bytes{0xA0};
    doc.issuerAuth.payload           = Bytes(8, 0x42);
    doc.issuerAuth.signature         = Bytes(64, 0xAB);
    return doc;
}

int main() {
    std::cout << "=== Aliro Reader Demo (OpenSSL) ===\n\n";

    OpenSslCryptoProvider crypto;

    // 1. Generate long-term key pairs for both roles.
    auto readerKp = crypto.generateKeyPair();
    auto deviceKp = crypto.generateKeyPair();
    if (!readerKp || !deviceKp) {
        std::cerr << "Key generation failed\n";
        return 1;
    }
    std::cout << "[keygen]  Reader long-term public key : " << toHex(readerKp->pub.data) << "\n";
    std::cout << "[keygen]  Device long-term public key : " << toHex(deviceKp->pub.data) << "\n\n";

    // 2. Set up the simulated device (normally this runs on separate hardware).
    auto device = std::make_shared<DeviceSession>(crypto, deviceKp->priv, makeAccessDoc());

    SimTransport transport([&device](ByteView cmd) -> Result<Bytes> {
        if (cmd.size() < 2)
            return tl::unexpected(AliroError::INVALID_MESSAGE);
        uint8_t ins = cmd[1];
        if (ins == protocol::kInsSelect) return device->handleSelect(cmd);
        if (ins == protocol::kInsAuth0)  return device->handleAuth0(cmd);
        if (ins == protocol::kInsAuth1)  return device->handleAuth1(cmd);
        return tl::unexpected(AliroError::INVALID_MESSAGE);
    });

    // 3. Run the reader-side authentication.
    std::cout << "[reader]  Starting SELECT → AUTH0 → AUTH1 …\n";
    ReaderSession reader(crypto, transport);
    auto result = reader.authenticate(*readerKp, deviceKp->pub);

    if (!result) {
        std::cerr << "[reader]  Authentication FAILED (error "
                  << static_cast<int>(result.error()) << ")\n";
        return 1;
    }

    // 4. Print outcome.
    std::cout << "[reader]  Authentication SUCCEEDED\n";
    std::cout << "[reader]  Session key  : " << toHex(result->sessionKey) << "\n";
    std::cout << "[reader]  AccessDoc type: " << result->accessDoc.docType << "\n";
    std::cout << "[device]  Session key  : " << toHex(device->sessionKey()) << "\n\n";

    if (result->sessionKey == device->sessionKey())
        std::cout << "[check]   Reader and device session keys MATCH ✓\n";
    else
        std::cout << "[check]   Key mismatch — BUG\n";

    return 0;
}
