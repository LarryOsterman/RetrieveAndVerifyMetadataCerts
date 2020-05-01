#include "mbedtlsKey.h"

std::unique_ptr<mbedtlsKey> mbedtlsKey::GenerateKeyPair(KeyKind keyKind)
{
    std::unique_ptr<mbedtlsKey> keyHandle;
    switch (keyKind)
    {
    case KeyKind::ECC:
        //            keyHandle = mbedtlsEccKey::GenerateKeyPair();
        break;
    case KeyKind::RSA:
        keyHandle = mbedtlsRsaKey::GenerateKeyPair();
        break;
    }

    return keyHandle;
}

std::string mbedtlsKey::ExportKey(KeyType keyType) const
{
    uint32_t exportedKeyMaxSize = 0;

    switch (_keyKind)
    {
    case KeyKind::ECC:
        //            exportedKeyMaxSize = static_cast<uint32_t>((SgxEcdsaAsymmetricKey::MaxDerBytes(keyType) * 4 / 3 + 1) +
        //                sizeof(PEM_BEGIN_PRIVATE_KEY_EC) + sizeof(PEM_END_PRIVATE_KEY_EC));
        //            break;
    case KeyKind::RSA:
        exportedKeyMaxSize = static_cast<uint32_t>((mbedtlsRsaKey::MaxDerBytes(keyType) * 4 / 3 + 1) +
            sizeof(PEM_BEGIN_PRIVATE_KEY_RSA) + sizeof(PEM_END_PRIVATE_KEY_RSA));
        break;
    }
    auto keyBuffer = std::vector<uint8_t>(exportedKeyMaxSize);

    switch (keyType)
    {
    case KeyType::FullKey:
    {
        int res = mbedtls_pk_write_key_pem(_pkContext.get(), keyBuffer.data(), keyBuffer.size());
        if (res < 0)
        {
            char buffer[512];
            mbedtls_strerror(res, buffer, sizeof(buffer));
            throw std::exception(buffer);
        }
        break;
    }
    case KeyType::PublicKey:
    {
        int res = mbedtls_pk_write_pubkey_pem(_pkContext.get(), keyBuffer.data(), keyBuffer.size());
        if (res < 0)
        {
            char buffer[512];
            mbedtls_strerror(res, buffer, sizeof(buffer));
            throw std::exception(buffer);
        }
        break;
    }
    default:
        throw std::exception("not supported");
    }

    return std::string(keyBuffer.data(), keyBuffer.data() + strlen(reinterpret_cast<char *>(keyBuffer.data())));
}
