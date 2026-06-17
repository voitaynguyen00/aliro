#include <gtest/gtest.h>

#include "aliro/crypto/keySerializer.h"
#include "aliro/crypto/mbedTlsCryptoProvider.h"
#include "aliro/crypto/openSslCryptoProvider.h"

using namespace aliro;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static OpenSslCryptoProvider gOpenSsl;
static MbedTlsCryptoProvider gMbed;

// ---------------------------------------------------------------------------
// Public key — DER round-trip
// ---------------------------------------------------------------------------
TEST(KeySerializer, publicKeyToDer_fromDer_roundTrip) {
    auto kp = gOpenSsl.generateKeyPair();
    ASSERT_TRUE(kp);

    auto der = publicKeyToDer(kp->pub);
    ASSERT_TRUE(der);
    EXPECT_EQ(der->size(), 91u);

    auto recovered = publicKeyFromDer(*der);
    ASSERT_TRUE(recovered);
    EXPECT_EQ(recovered->data, kp->pub.data);
}

// ---------------------------------------------------------------------------
// Public key — PEM round-trip
// ---------------------------------------------------------------------------
TEST(KeySerializer, publicKeyToPem_fromPem_roundTrip) {
    auto kp = gOpenSsl.generateKeyPair();
    ASSERT_TRUE(kp);

    auto pem = publicKeyToPem(kp->pub);
    ASSERT_TRUE(pem);
    EXPECT_NE(pem->find("-----BEGIN PUBLIC KEY-----"), std::string::npos);
    EXPECT_NE(pem->find("-----END PUBLIC KEY-----"), std::string::npos);

    auto recovered = publicKeyFromPem(*pem);
    ASSERT_TRUE(recovered);
    EXPECT_EQ(recovered->data, kp->pub.data);
}

// ---------------------------------------------------------------------------
// Private key — DER round-trip
// ---------------------------------------------------------------------------
TEST(KeySerializer, privateKeyToDer_fromDer_roundTrip) {
    auto kp = gOpenSsl.generateKeyPair();
    ASSERT_TRUE(kp);

    auto der = privateKeyToDer(kp->priv);
    ASSERT_TRUE(der);
    EXPECT_EQ(der->size(), 51u);

    auto recovered = privateKeyFromDer(*der);
    ASSERT_TRUE(recovered);
    EXPECT_EQ(recovered->data, kp->priv.data);
}

// ---------------------------------------------------------------------------
// Private key — PEM round-trip
// ---------------------------------------------------------------------------
TEST(KeySerializer, privateKeyToPem_fromPem_roundTrip) {
    auto kp = gOpenSsl.generateKeyPair();
    ASSERT_TRUE(kp);

    auto pem = privateKeyToPem(kp->priv);
    ASSERT_TRUE(pem);
    EXPECT_NE(pem->find("-----BEGIN EC PRIVATE KEY-----"), std::string::npos);
    EXPECT_NE(pem->find("-----END EC PRIVATE KEY-----"), std::string::npos);

    auto recovered = privateKeyFromPem(*pem);
    ASSERT_TRUE(recovered);
    EXPECT_EQ(recovered->data, kp->priv.data);
}

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------
TEST(KeySerializer, publicKeyFromDer_wrongLength_returnsError) {
    Bytes bad(90, 0x00);
    auto r = publicKeyFromDer(bad);
    EXPECT_FALSE(r);
    EXPECT_EQ(r.error(), AliroError::DECODING_ERROR);
}

TEST(KeySerializer, publicKeyFromDer_wrongPrefix_returnsError) {
    auto kp = gOpenSsl.generateKeyPair();
    ASSERT_TRUE(kp);
    auto der = publicKeyToDer(kp->pub);
    ASSERT_TRUE(der);
    (*der)[0] ^= 0xFF;  // corrupt first byte
    auto r = publicKeyFromDer(*der);
    EXPECT_FALSE(r);
    EXPECT_EQ(r.error(), AliroError::DECODING_ERROR);
}

TEST(KeySerializer, privateKeyFromDer_wrongLength_returnsError) {
    Bytes bad(50, 0x00);
    auto r = privateKeyFromDer(bad);
    EXPECT_FALSE(r);
    EXPECT_EQ(r.error(), AliroError::DECODING_ERROR);
}

TEST(KeySerializer, publicKeyFromPem_missingHeader_returnsError) {
    auto r = publicKeyFromPem("not a pem string");
    EXPECT_FALSE(r);
    EXPECT_EQ(r.error(), AliroError::DECODING_ERROR);
}

TEST(KeySerializer, privateKeyFromPem_missingHeader_returnsError) {
    auto r = privateKeyFromPem("not a pem string");
    EXPECT_FALSE(r);
    EXPECT_EQ(r.error(), AliroError::DECODING_ERROR);
}

TEST(KeySerializer, publicKeyToDer_invalidKeySize_returnsError) {
    EcPublicKey bad;
    bad.data = {0x04, 0x01};  // too short
    auto r = publicKeyToDer(bad);
    EXPECT_FALSE(r);
    EXPECT_EQ(r.error(), AliroError::ENCODING_ERROR);
}

TEST(KeySerializer, privateKeyToDer_invalidKeySize_returnsError) {
    EcPrivateKey bad;
    bad.data = {0x01, 0x02};  // too short
    auto r = privateKeyToDer(bad);
    EXPECT_FALSE(r);
    EXPECT_EQ(r.error(), AliroError::ENCODING_ERROR);
}

// ---------------------------------------------------------------------------
// Cross-provider: MbedTLS key survives serialize → deserialize
// ---------------------------------------------------------------------------
TEST(KeySerializer, mbedtlsKey_publicKeyPem_roundTrip) {
    auto kp = gMbed.generateKeyPair();
    ASSERT_TRUE(kp);

    auto pem = publicKeyToPem(kp->pub);
    ASSERT_TRUE(pem);

    auto recovered = publicKeyFromPem(*pem);
    ASSERT_TRUE(recovered);
    EXPECT_EQ(recovered->data, kp->pub.data);
}

TEST(KeySerializer, mbedtlsKey_privateKeyPem_roundTrip) {
    auto kp = gMbed.generateKeyPair();
    ASSERT_TRUE(kp);

    auto pem = privateKeyToPem(kp->priv);
    ASSERT_TRUE(pem);

    auto recovered = privateKeyFromPem(*pem);
    ASSERT_TRUE(recovered);
    EXPECT_EQ(recovered->data, kp->priv.data);
}

// ---------------------------------------------------------------------------
// Cross-provider: serialize with OpenSSL, sign, verify with MbedTLS on
// the deserialized key — proves the bytes are cryptographically correct.
// ---------------------------------------------------------------------------
TEST(KeySerializer, opensslKey_serializeThenMbedtlsVerify) {
    auto kp = gOpenSsl.generateKeyPair();
    ASSERT_TRUE(kp);

    // Serialize public key via PEM then deserialize
    auto pem = publicKeyToPem(kp->pub);
    ASSERT_TRUE(pem);
    auto recoveredPub = publicKeyFromPem(*pem);
    ASSERT_TRUE(recoveredPub);

    // Sign with OpenSSL private key
    Bytes msg = {0xDE, 0xAD, 0xBE, 0xEF};
    auto sig = gOpenSsl.sign(msg, kp->priv);
    ASSERT_TRUE(sig);

    // Verify with MbedTLS using the recovered public key
    auto ok = gMbed.verify(msg, *sig, *recoveredPub);
    ASSERT_TRUE(ok);
    EXPECT_TRUE(*ok);
}
