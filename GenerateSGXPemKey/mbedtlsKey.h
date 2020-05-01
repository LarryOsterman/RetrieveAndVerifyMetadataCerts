#pragma once

#include <mbedtls\pk.h>
#include <mbedtls\ctr_drbg.h>
#include <mbedtls\error.h>
#include <mbedtls\entropy.h>
#include <memory>
#include <vector>
#include <string>


namespace details
{
    template <typename T, void(*InitFunc)(T*), void(*FreeFunc)(T*)>
    class mbedtls_context : public T
    {
    public:
        // Delete copy/move
        mbedtls_context(const mbedtls_context&) = delete;
        mbedtls_context& operator=(const mbedtls_context&) = delete;

        mbedtls_context()
        {
            InitFunc(this);
        }

        ~mbedtls_context()
        {
            FreeFunc(this);
        }

        inline operator T* ()
        {
            return this;
        }

        inline operator const T* () const
        {
            return this;
        }

        inline T* operator->()
        {
            return this;
        }

        inline const T* operator->() const
        {
            return this;
        }
    };
}

typedef details::mbedtls_context<mbedtls_pk_context, mbedtls_pk_init, mbedtls_pk_free> pk_context;
typedef details::mbedtls_context<mbedtls_mpi, mbedtls_mpi_init, mbedtls_mpi_free> mbedtls_bignum;
typedef details::mbedtls_context<mbedtls_ctr_drbg_context, mbedtls_ctr_drbg_init, mbedtls_ctr_drbg_free> mbedtls_drbg_context;
typedef details::mbedtls_context<mbedtls_entropy_context, mbedtls_entropy_init, mbedtls_entropy_free> entropy_context;


class mbedtlsRsaKey;

class mbedtlsKey
{
public:
    enum class KeyKind
    {
        RSA,
        ECC
    };

    enum class KeyType
    {
        PublicKey,
        FullKey
    };

protected:

    const KeyKind _keyKind;
    const KeyType _keyType;
    std::unique_ptr<pk_context> _pkContext;

    static uint32_t GetKeyLengthInBits(_In_ KeyKind keyKind)
    {
        switch (keyKind)
        {
        case KeyKind::RSA:
            return _ulKeyLengthInBits;

        case KeyKind::ECC:
            return _ulKeyLengthInBitsEcc;

        default:
            return 0;
        }
    }

private:
    constexpr static uint32_t _ulKeyLengthInBits = 2048; // Regular strength
    constexpr static uint32_t _ulKeyLengthInBitsEcc = 256;

public:
    mbedtlsKey(KeyKind keyKind, KeyType keyType, std::unique_ptr<pk_context>&& context)
        : _keyKind(keyKind)
        , _keyType(keyType)
        , _pkContext(std::move(context))
    {
    }

    virtual ~mbedtlsKey() {}
    const std::unique_ptr<pk_context>& PkeyContext() const { return _pkContext; }

//    virtual std::vector<uint8_t> SignHash(_In_ const std::vector<uint8_t>& bufferToHash) const = 0;
//    virtual bool VerifyHashSignature(const std::vector<uint8_t>& hash, const std::vector<uint8_t>& signature) const = 0;
//    virtual std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plaintext) const = 0;
//    virtual std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& plaintext) const = 0;

    KeyKind GetKeyKind() const { return _keyKind; }

    static std::unique_ptr<mbedtlsKey> GenerateKeyPair(KeyKind keyKind);
    static std::unique_ptr<mbedtlsKey> ImportKey(_In_ KeyKind keyKind, _In_ KeyType keyType, _In_ const std::vector<uint8_t>& key)
    {
        throw std::exception("Not implemented");
    }
#define PEM_BEGIN_PRIVATE_KEY_RSA   "-----BEGIN RSA PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY_RSA     "-----END RSA PRIVATE KEY-----\n"
#define PEM_BEGIN_PRIVATE_KEY_EC    "-----BEGIN EC PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY_EC      "-----END EC PRIVATE KEY-----\n"
    std::string ExportKey(KeyType keyType) const;

};

class mbedtlsRsaKey: public mbedtlsKey
{
private:
    uint32_t InnerKeyLengthInBits() const
    {
        return 256;
    }

public:
    mbedtlsRsaKey(mbedtlsKey::KeyType keyType, std::unique_ptr<pk_context>&& context)
        : mbedtlsKey(KeyKind::RSA, keyType, std::move(context))
    {
    }
    virtual ~mbedtlsRsaKey()
    {
    }

//    virtual std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plaintext) const override;
//    virtual std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& cyphertext) const override;
//    std::vector<uint8_t> SignHash(_In_ const std::vector<uint8_t>& bufferToHash) const override;
//    bool VerifyHashSignature(const std::vector<uint8_t>& hash, const std::vector<uint8_t>& signature) const override;
    static size_t MaxDerBytes(mbedtlsKey::KeyType keyType)
    {
        if (keyType == mbedtlsKey::KeyType::PublicKey)
        {
            return 38 + 2 * MBEDTLS_MPI_MAX_SIZE;
        }
        else
        {
            return 47 + 3 * MBEDTLS_MPI_MAX_SIZE + 5 * (MBEDTLS_MPI_MAX_SIZE / 2 + MBEDTLS_MPI_MAX_SIZE % 2);
        }
    }


    static std::unique_ptr<pk_context> ImportFromBCryptKey(mbedtlsKey::KeyType keyType, const std::vector<uint8_t>& key);

    static std::unique_ptr<mbedtlsKey> GenerateKeyPair()
    {
        std::unique_ptr<pk_context> pkContext(std::make_unique<pk_context>());
        mbedtls_drbg_context ctr_drbg;
        entropy_context entropy;


        int res = mbedtls_pk_setup(pkContext.get(), mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
        if (res < 0)
        {
            char buffer[512];
            mbedtls_strerror(res, buffer, sizeof(buffer));
            throw std::exception(buffer);
        }

        const char* personalization = "GenerateSGXPemKey";

        res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, reinterpret_cast<const unsigned char *>(personalization), strlen(personalization));
        if (res < 0)
        {
            char buffer[512];
            mbedtls_strerror(res, buffer, sizeof(buffer));
            throw std::exception(buffer);
        }

        res = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*pkContext), mbedtls_ctr_drbg_random, &ctr_drbg, mbedtlsRsaKey::GetKeyLengthInBits(KeyKind::RSA), 65537);
        if (res < 0)
        {
            char buffer[512];
            mbedtls_strerror(res, buffer, sizeof(buffer));
            throw std::exception(buffer);
        }

        return std::make_unique<mbedtlsRsaKey>(KeyType::FullKey, std::move(pkContext));

    }
//        static std::unique_ptr<mbedtlsKey> CreateFromCert(const EnclavePal::X509Certificate* const certificate);
//    static std::unique_ptr<mbedtlsKey> CreateFromRawBuffer(const std::vector<uint8_t>& buffer);
};

