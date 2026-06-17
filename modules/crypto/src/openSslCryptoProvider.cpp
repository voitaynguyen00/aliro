#include "aliro/crypto/openSslCryptoProvider.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

#include <memory>
#include <vector>

namespace aliro {

namespace {

struct PkeyDel {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
struct PkeyCtxDel {
    void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
};
struct MdCtxDel {
    void operator()(EVP_MD_CTX* p) const noexcept { EVP_MD_CTX_free(p); }
};
struct CipherDel {
    void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); }
};
struct KdfDel {
    void operator()(EVP_KDF* p) const noexcept { EVP_KDF_free(p); }
};
struct KdfCtxDel {
    void operator()(EVP_KDF_CTX* p) const noexcept { EVP_KDF_CTX_free(p); }
};
struct EcSigDel {
    void operator()(ECDSA_SIG* p) const noexcept { ECDSA_SIG_free(p); }
};
struct BnDel {
    void operator()(BIGNUM* p) const noexcept { BN_free(p); }
};
struct ParamBldDel {
    void operator()(OSSL_PARAM_BLD* p) const noexcept { OSSL_PARAM_BLD_free(p); }
};
struct ParamDel {
    void operator()(OSSL_PARAM* p) const noexcept { OSSL_PARAM_free(p); }
};

using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDel>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDel>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDel>;
using CipherPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherDel>;
using KdfPtr = std::unique_ptr<EVP_KDF, KdfDel>;
using KdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, KdfCtxDel>;
using EcSigPtr = std::unique_ptr<ECDSA_SIG, EcSigDel>;
using BnPtr = std::unique_ptr<BIGNUM, BnDel>;
using ParamBldPtr = std::unique_ptr<OSSL_PARAM_BLD, ParamBldDel>;
using ParamPtr = std::unique_ptr<OSSL_PARAM, ParamDel>;

PkeyPtr evpKeyFromPrivate(const EcPrivateKey& privKey) {
    ParamBldPtr bld(OSSL_PARAM_BLD_new());
    if (!bld)
        return nullptr;

    BnPtr priv(BN_bin2bn(privKey.data.data(), 32, nullptr));
    if (!priv)
        return nullptr;

    if (!OSSL_PARAM_BLD_push_utf8_string(bld.get(), "group", "P-256", 5) ||
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, priv.get()))
        return nullptr;

    ParamPtr params(OSSL_PARAM_BLD_to_param(bld.get()));
    if (!params)
        return nullptr;

    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0)
        return nullptr;

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_KEYPAIR, params.get()) <= 0)
        return nullptr;
    return PkeyPtr(pkey);
}

PkeyPtr evpKeyFromPublic(const EcPublicKey& pubKey) {
    ParamBldPtr bld(OSSL_PARAM_BLD_new());
    if (!bld)
        return nullptr;

    if (!OSSL_PARAM_BLD_push_utf8_string(bld.get(), "group", "P-256", 5) ||
        !OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, pubKey.data.data(),
                                          65))
        return nullptr;

    ParamPtr params(OSSL_PARAM_BLD_to_param(bld.get()));
    if (!params)
        return nullptr;

    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0)
        return nullptr;

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0)
        return nullptr;
    return PkeyPtr(pkey);
}

}  // namespace

// ---------------------------------------------------------------------------
// generateKeyPair
// ---------------------------------------------------------------------------
Result<EcKeyPair> OpenSslCryptoProvider::generateKeyPair() {
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    OSSL_PARAM params[] = {OSSL_PARAM_utf8_string("group", const_cast<char*>("P-256"), 5),
                           OSSL_PARAM_END};
    if (EVP_PKEY_CTX_set_params(ctx.get(), params) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_generate(ctx.get(), &raw) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);
    PkeyPtr pkey(raw);

    Bytes pubBytes(65);
    size_t pubLen = 65;
    if (EVP_PKEY_get_octet_string_param(pkey.get(), OSSL_PKEY_PARAM_PUB_KEY, pubBytes.data(), 65,
                                        &pubLen) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);
    pubBytes.resize(pubLen);

    BIGNUM* rawBn = nullptr;
    if (EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_PRIV_KEY, &rawBn) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);
    BnPtr privBn(rawBn);
    Bytes privBytes(32, 0);
    BN_bn2binpad(privBn.get(), privBytes.data(), 32);

    return EcKeyPair{EcPublicKey{std::move(pubBytes)}, EcPrivateKey{std::move(privBytes)}};
}

// ---------------------------------------------------------------------------
// ecdhCompute
// ---------------------------------------------------------------------------
Result<Bytes> OpenSslCryptoProvider::ecdhCompute(const EcPrivateKey& priv,
                                                 const EcPublicKey& peerPub) {
    PkeyPtr privKey = evpKeyFromPrivate(priv);
    PkeyPtr pubKey = evpKeyFromPublic(peerPub);
    if (!privKey || !pubKey)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    PkeyCtxPtr ctx(EVP_PKEY_CTX_new(privKey.get(), nullptr));
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx.get(), pubKey.get()) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    size_t secretLen = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &secretLen) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    Bytes secret(secretLen);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &secretLen) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);
    secret.resize(secretLen);
    return secret;
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------
Result<Signature> OpenSslCryptoProvider::sign(ByteView data, const EcPrivateKey& key) {
    PkeyPtr pkey = evpKeyFromPrivate(key);
    if (!pkey)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    size_t derLen = 0;
    if (EVP_DigestSign(ctx.get(), nullptr, &derLen, data.data(), data.size()) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    Bytes derSig(derLen);
    if (EVP_DigestSign(ctx.get(), derSig.data(), &derLen, data.data(), data.size()) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);
    derSig.resize(derLen);

    const uint8_t* p = derSig.data();
    EcSigPtr ecSig(d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(derSig.size())));
    if (!ecSig)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(ecSig.get(), &r, &s);

    Bytes rawSig(64, 0);
    BN_bn2binpad(r, rawSig.data(), 32);
    BN_bn2binpad(s, rawSig.data() + 32, 32);
    return Signature{std::move(rawSig)};
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------
Result<bool> OpenSslCryptoProvider::verify(ByteView data, const Signature& sig,
                                           const EcPublicKey& key) {
    if (sig.data.size() != 64)
        return tl::unexpected(AliroError::INVALID_MESSAGE);

    EcSigPtr ecSig(ECDSA_SIG_new());
    if (!ecSig)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    BnPtr r(BN_bin2bn(sig.data.data(), 32, nullptr));
    BnPtr s(BN_bin2bn(sig.data.data() + 32, 32, nullptr));
    if (!r || !s)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);
    ECDSA_SIG_set0(ecSig.get(), r.release(), s.release());

    int derLen = i2d_ECDSA_SIG(ecSig.get(), nullptr);
    if (derLen <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);
    Bytes derSig(static_cast<size_t>(derLen));
    uint8_t* derPtr = derSig.data();
    i2d_ECDSA_SIG(ecSig.get(), &derPtr);

    PkeyPtr pkey = evpKeyFromPublic(key);
    if (!pkey)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    int rc = EVP_DigestVerify(ctx.get(), derSig.data(), derSig.size(), data.data(), data.size());
    if (rc == 1)
        return true;
    if (rc == 0)
        return false;
    return tl::unexpected(AliroError::CRYPTO_FAILURE);
}

// ---------------------------------------------------------------------------
// aesGcmEncrypt
// ---------------------------------------------------------------------------
Result<Bytes> OpenSslCryptoProvider::aesGcmEncrypt(ByteView plaintext, const SessionKey& key,
                                                   ByteView nonce, ByteView aad) {
    if (key.data.size() != 16 || nonce.size() != 12)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    CipherPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) <= 0 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data.data(), nonce.data()) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    if (!aad.empty()) {
        int aadOut = 0;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &aadOut, aad.data(),
                              static_cast<int>(aad.size())) <= 0)
            return tl::unexpected(AliroError::CRYPTO_FAILURE);
    }

    Bytes ciphertext(plaintext.size());
    int outLen = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &outLen, plaintext.data(),
                              static_cast<int>(plaintext.size())) <= 0)
            return tl::unexpected(AliroError::CRYPTO_FAILURE);
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outLen, &finalLen) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);
    ciphertext.resize(static_cast<size_t>(outLen + finalLen));

    Bytes tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data()) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
    return ciphertext;
}

// ---------------------------------------------------------------------------
// aesGcmDecrypt
// ---------------------------------------------------------------------------
Result<Bytes> OpenSslCryptoProvider::aesGcmDecrypt(ByteView ciphertext, const SessionKey& key,
                                                   ByteView nonce, ByteView aad) {
    if (key.data.size() != 16 || nonce.size() != 12 || ciphertext.size() < 16)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    size_t dataLen = ciphertext.size() - 16;
    const uint8_t* tagPtr = ciphertext.data() + dataLen;

    CipherPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) <= 0 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data.data(), nonce.data()) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    if (!aad.empty()) {
        int aadOut = 0;
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &aadOut, aad.data(),
                              static_cast<int>(aad.size())) <= 0)
            return tl::unexpected(AliroError::CRYPTO_FAILURE);
    }

    Bytes plaintext(dataLen);
    int outLen = 0;
    if (dataLen > 0) {
        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outLen, ciphertext.data(),
                              static_cast<int>(dataLen)) <= 0)
            return tl::unexpected(AliroError::CRYPTO_FAILURE);
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tagPtr)) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outLen, &finalLen) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    plaintext.resize(static_cast<size_t>(outLen + finalLen));
    return plaintext;
}

// ---------------------------------------------------------------------------
// hkdfDerive
// ---------------------------------------------------------------------------
Result<Bytes> OpenSslCryptoProvider::hkdfDerive(ByteView ikm, ByteView salt, ByteView info,
                                                size_t outputLen) {
    KdfPtr kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    KdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);

    std::vector<OSSL_PARAM> params;
    params.push_back(
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 6));
    params.push_back(OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(ikm.data()), ikm.size()));
    if (!salt.empty()) {
        params.push_back(OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(salt.data()), salt.size()));
    }
    if (!info.empty()) {
        params.push_back(OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, const_cast<uint8_t*>(info.data()), info.size()));
    }
    params.push_back(OSSL_PARAM_END);

    Bytes output(outputLen);
    if (EVP_KDF_derive(ctx.get(), output.data(), outputLen, params.data()) <= 0)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);
    return output;
}

// ---------------------------------------------------------------------------
// randomBytes
// ---------------------------------------------------------------------------
Result<Bytes> OpenSslCryptoProvider::randomBytes(size_t n) {
    if (n == 0)
        return Bytes{};
    Bytes result(n);
    if (RAND_bytes(result.data(), static_cast<int>(n)) != 1)
        return tl::unexpected(AliroError::CRYPTO_FAILURE);
    return result;
}

}  // namespace aliro
