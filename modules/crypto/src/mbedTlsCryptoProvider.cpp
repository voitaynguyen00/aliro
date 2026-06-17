#include "aliro/crypto/mbedTlsCryptoProvider.h"

#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#include <array>

namespace aliro {

namespace {

static constexpr size_t kP256ScalarSize = 32;
static constexpr size_t kP256PubSize = 65;  // 0x04 || X || Y

// ---------------------------------------------------------------------------
// Lightweight RAII wrappers for MbedTLS contexts
// ---------------------------------------------------------------------------
template <typename T, void (*Init)(T*), void (*Free)(T*)>
struct MbedCtx {
    T val{};
    MbedCtx() { Init(&val); }
    ~MbedCtx() { Free(&val); }
    T* get() { return &val; }
    const T* get() const { return &val; }
    MbedCtx(const MbedCtx&) = delete;
    MbedCtx& operator=(const MbedCtx&) = delete;
};

using MbedMpi = MbedCtx<mbedtls_mpi, mbedtls_mpi_init, mbedtls_mpi_free>;
using MbedEcpGroup = MbedCtx<mbedtls_ecp_group, mbedtls_ecp_group_init, mbedtls_ecp_group_free>;
using MbedEcpPoint = MbedCtx<mbedtls_ecp_point, mbedtls_ecp_point_init, mbedtls_ecp_point_free>;
using MbedEcpKp = MbedCtx<mbedtls_ecp_keypair, mbedtls_ecp_keypair_init, mbedtls_ecp_keypair_free>;
using MbedGcm = MbedCtx<mbedtls_gcm_context, mbedtls_gcm_init, mbedtls_gcm_free>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static std::array<uint8_t, 32> sha256(ByteView data) {
    std::array<uint8_t, 32> hash{};
    mbedtls_sha256(data.data(), data.size(), hash.data(), 0 /* SHA-256 */);
    return hash;
}

static int loadP256Group(mbedtls_ecp_group& grp) {
    return mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
}

}  // namespace

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------
MbedTlsCryptoProvider::MbedTlsCryptoProvider() {
    mbedtls_entropy_init(&mEntropy);
    mbedtls_ctr_drbg_init(&mCtrDrbg);

    static const uint8_t kPers[] = "aliro-mbedtls";
    mInitialized = (mbedtls_ctr_drbg_seed(&mCtrDrbg, mbedtls_entropy_func, &mEntropy, kPers,
                                          sizeof(kPers) - 1) == 0);
}

MbedTlsCryptoProvider::~MbedTlsCryptoProvider() {
    mbedtls_ctr_drbg_free(&mCtrDrbg);
    mbedtls_entropy_free(&mEntropy);
}

// ---------------------------------------------------------------------------
// generateKeyPair
// ---------------------------------------------------------------------------
Result<EcKeyPair> MbedTlsCryptoProvider::generateKeyPair() {
    if (!mInitialized)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    MbedEcpKp kp;
    if (mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, kp.get(), mbedtls_ctr_drbg_random,
                            &mCtrDrbg) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    MbedEcpGroup grp;
    MbedMpi d;
    MbedEcpPoint Q;
    if (mbedtls_ecp_export(kp.get(), grp.get(), d.get(), Q.get()) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    Bytes privBytes(kP256ScalarSize);
    if (mbedtls_mpi_write_binary(d.get(), privBytes.data(), kP256ScalarSize) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    Bytes pubBytes(kP256PubSize);
    size_t olen = 0;
    if (mbedtls_ecp_point_write_binary(grp.get(), Q.get(), MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                       pubBytes.data(), kP256PubSize) != 0 ||
        olen != kP256PubSize)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    return EcKeyPair{EcPublicKey{std::move(pubBytes)}, EcPrivateKey{std::move(privBytes)}};
}

// ---------------------------------------------------------------------------
// ecdhCompute
// ---------------------------------------------------------------------------
Result<Bytes> MbedTlsCryptoProvider::ecdhCompute(const EcPrivateKey& priv,
                                                 const EcPublicKey& peerPub) {
    if (priv.data.size() != kP256ScalarSize || peerPub.data.size() != kP256PubSize)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    MbedEcpGroup grp;
    if (loadP256Group(*grp.get()) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    MbedMpi d;
    if (mbedtls_mpi_read_binary(d.get(), priv.data.data(), kP256ScalarSize) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    MbedEcpPoint Q;
    if (mbedtls_ecp_point_read_binary(grp.get(), Q.get(), peerPub.data.data(), kP256PubSize) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    MbedEcpPoint shared;
    if (mbedtls_ecp_mul(grp.get(), shared.get(), d.get(), Q.get(), mbedtls_ctr_drbg_random,
                        &mCtrDrbg) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    // Extract X-coordinate (the ECDH shared secret for P-256)
    MbedMpi x;
    if (mbedtls_mpi_copy(x.get(), &shared.get()->MBEDTLS_PRIVATE(X)) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    Bytes result(kP256ScalarSize);
    if (mbedtls_mpi_write_binary(x.get(), result.data(), kP256ScalarSize) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    return result;
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------
Result<Signature> MbedTlsCryptoProvider::sign(ByteView data, const EcPrivateKey& key) {
    if (key.data.size() != kP256ScalarSize)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    auto hash = sha256(data);

    MbedEcpGroup grp;
    if (loadP256Group(*grp.get()) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    MbedMpi d;
    if (mbedtls_mpi_read_binary(d.get(), key.data.data(), kP256ScalarSize) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    MbedMpi r, s;
    if (mbedtls_ecdsa_sign(grp.get(), r.get(), s.get(), d.get(), hash.data(), hash.size(),
                           mbedtls_ctr_drbg_random, &mCtrDrbg) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    Bytes sigBytes(64);
    if (mbedtls_mpi_write_binary(r.get(), sigBytes.data(), kP256ScalarSize) != 0 ||
        mbedtls_mpi_write_binary(s.get(), sigBytes.data() + 32, kP256ScalarSize) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    return Signature{std::move(sigBytes)};
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------
Result<bool> MbedTlsCryptoProvider::verify(ByteView data, const Signature& sig,
                                           const EcPublicKey& key) {
    if (sig.data.size() != 64 || key.data.size() != kP256PubSize)
        return tl::unexpected(AliroError::INVALID_MESSAGE);

    auto hash = sha256(data);

    MbedEcpGroup grp;
    if (loadP256Group(*grp.get()) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    MbedEcpPoint Q;
    if (mbedtls_ecp_point_read_binary(grp.get(), Q.get(), key.data.data(), kP256PubSize) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    MbedMpi r, s;
    if (mbedtls_mpi_read_binary(r.get(), sig.data.data(), kP256ScalarSize) != 0 ||
        mbedtls_mpi_read_binary(s.get(), sig.data.data() + 32, kP256ScalarSize) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    int ret = mbedtls_ecdsa_verify(grp.get(), hash.data(), hash.size(), Q.get(), r.get(), s.get());
    if (ret == 0)
        return true;
    if (ret == MBEDTLS_ERR_ECP_VERIFY_FAILED)
        return false;
    return tl::unexpected(AliroError::CRYPTO_FAILURE);
}

// ---------------------------------------------------------------------------
// aesGcmEncrypt
// ---------------------------------------------------------------------------
Result<Bytes> MbedTlsCryptoProvider::aesGcmEncrypt(ByteView plaintext, const SessionKey& key,
                                                   ByteView nonce, ByteView aad) {
    if (key.data.size() != 16 || nonce.size() != 12)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    MbedGcm ctx;
    if (mbedtls_gcm_setkey(ctx.get(), MBEDTLS_CIPHER_ID_AES, key.data.data(),
                           static_cast<unsigned int>(key.data.size() * 8)) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    Bytes ciphertext(plaintext.size());
    uint8_t tag[16]{};

    if (mbedtls_gcm_crypt_and_tag(ctx.get(), MBEDTLS_GCM_ENCRYPT, plaintext.size(), nonce.data(),
                                  nonce.size(), aad.empty() ? nullptr : aad.data(), aad.size(),
                                  plaintext.empty() ? nullptr : plaintext.data(),
                                  ciphertext.empty() ? nullptr : ciphertext.data(), sizeof(tag),
                                  tag) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    ciphertext.insert(ciphertext.end(), tag, tag + sizeof(tag));
    return ciphertext;
}

// ---------------------------------------------------------------------------
// aesGcmDecrypt
// ---------------------------------------------------------------------------
Result<Bytes> MbedTlsCryptoProvider::aesGcmDecrypt(ByteView ciphertext, const SessionKey& key,
                                                   ByteView nonce, ByteView aad) {
    if (key.data.size() != 16 || nonce.size() != 12 || ciphertext.size() < 16)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    size_t dataLen = ciphertext.size() - 16;
    const uint8_t* tagPtr = ciphertext.data() + dataLen;

    MbedGcm ctx;
    if (mbedtls_gcm_setkey(ctx.get(), MBEDTLS_CIPHER_ID_AES, key.data.data(),
                           static_cast<unsigned int>(key.data.size() * 8)) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    Bytes plaintext(dataLen);

    int ret = mbedtls_gcm_auth_decrypt(ctx.get(), dataLen, nonce.data(), nonce.size(),
                                       aad.empty() ? nullptr : aad.data(), aad.size(), tagPtr, 16,
                                       dataLen == 0 ? nullptr : ciphertext.data(),
                                       dataLen == 0 ? nullptr : plaintext.data());
    if (ret != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);
    return plaintext;
}

// ---------------------------------------------------------------------------
// hkdfDerive
// ---------------------------------------------------------------------------
Result<Bytes> MbedTlsCryptoProvider::hkdfDerive(ByteView ikm, ByteView salt, ByteView info,
                                                size_t outputLen) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    Bytes output(outputLen);
    if (mbedtls_hkdf(md, salt.empty() ? nullptr : salt.data(), salt.size(), ikm.data(), ikm.size(),
                     info.empty() ? nullptr : info.data(), info.size(), output.data(),
                     outputLen) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    return output;
}

// ---------------------------------------------------------------------------
// randomBytes
// ---------------------------------------------------------------------------
Result<Bytes> MbedTlsCryptoProvider::randomBytes(size_t n) {
    if (!mInitialized)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);
    if (n == 0)
        return Bytes{};
    Bytes result(n);
    if (mbedtls_ctr_drbg_random(&mCtrDrbg, result.data(), n) != 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);
    return result;
}

}  // namespace aliro
