#pragma once

#include <mbedtls\x509.h>
#include <mbedtls\x509_crt.h>
#include <mbedtls\pk_internal.h>
#include "mbedtlsKey.h"
#include <ctime>
#include "Base64.h"

//  RAII Wrapper for an mbedtls x509write_cert structure.
typedef details::mbedtls_context<mbedtls_x509write_cert, mbedtls_x509write_crt_init, mbedtls_x509write_crt_free> x509write_cert;
typedef details::mbedtls_context<mbedtls_x509_crt, mbedtls_x509_crt_init, mbedtls_x509_crt_free> x509_cert;
typedef details::mbedtls_context<mbedtls_x509_crl, mbedtls_x509_crl_init, mbedtls_x509_crl_free> x509_crl;

static const char pemPrefix[] = "-----BEGIN CERTIFICATE-----";
static constexpr size_t pemPrefixLen = sizeof(pemPrefix) - 1;

class mbedtlsCert
{
public:
    mbedtlsCert(std::unique_ptr<x509_cert>&& cert)
        : _certificate(std::move(cert))
    {}

    static std::unique_ptr<mbedtlsCert> CreateForKey(
        _In_ const std::unique_ptr<mbedtlsKey>& key,
        _In_z_ const char* certificateSubjectName,
        _In_ const std::time_t& expirationTimeDelta/*,
        _In_ const std::vector<std::unique_ptr<mbedtlsCertificateExtension>>& extensionsToAdd*/)
    {
        x509write_cert writeCert;

        mbedtls_x509write_crt_set_version(&writeCert, MBEDTLS_X509_CRT_VERSION_3);

        int res = mbedtls_x509write_crt_set_issuer_name(&writeCert, certificateSubjectName);
        if (res < 0)
        {
            char buffer[512];
            mbedtls_strerror(res, buffer, sizeof(buffer));
            throw std::exception(buffer);
        }

        res = mbedtls_x509write_crt_set_subject_name(&writeCert, certificateSubjectName);
        if (res < 0)
        {
            char buffer[512];
            mbedtls_strerror(res, buffer, sizeof(buffer));
            throw std::exception(buffer);
        }

        const mbedtlsKey* sgxKey = key.get();

        // Set the issuer and subject keys to the same value to self-sign the certificate.
        mbedtls_x509write_crt_set_issuer_key(&writeCert, sgxKey->PkeyContext().get());
        mbedtls_x509write_crt_set_subject_key(&writeCert, sgxKey->PkeyContext().get());

        mbedtls_x509write_crt_set_md_alg(&writeCert, MBEDTLS_MD_SHA256);

        mbedtls_bignum serialNumber;
        mbedtls_mpi_init(&serialNumber);
        mbedtls_mpi_lset(&serialNumber, 1);
        res = mbedtls_x509write_crt_set_serial(&writeCert, &serialNumber);
        if (res < 0)
        {
            char buffer[512];
            mbedtls_strerror(res, buffer, sizeof(buffer));
            throw std::exception(buffer);
        }

        res = mbedtls_x509write_crt_set_basic_constraints(&writeCert, 1/* isCA */, 0/* pathlen */);
        if (res < 0)
        {
            char buffer[512];
            mbedtls_strerror(res, buffer, sizeof(buffer));
            throw std::exception(buffer);
        }

        // Format the current time in YYYYMMDDhhmmss format.
        auto curTime(time(nullptr));
        struct std::tm currentTime;
        gmtime_s(&currentTime, &curTime);
        char x5cNotBeforeTime[128];
        strftime(x5cNotBeforeTime, sizeof(x5cNotBeforeTime), "%Y%m%d%H%M%S", &currentTime);

        // If the caller provided an expiration time, use that, otherwise use the default (1 year).
        if (expirationTimeDelta != 0)
        {
            time_t expirationTime = curTime + expirationTimeDelta;
            gmtime_s(&currentTime, &expirationTime);
        }
        else
        {
            // Certificate is valid for 1 year.
            currentTime.tm_year += 1;
            mktime(&currentTime); // mkTime will normalize the new time adjusting for leap years etc.
        }

        char x5cNotAfterTime[128];
        strftime(x5cNotAfterTime, sizeof(x5cNotAfterTime), "%Y%m%d%H%M%S", &currentTime);

        res = mbedtls_x509write_crt_set_validity(&writeCert, x5cNotBeforeTime, x5cNotAfterTime);
        if (res < 0)
        {
            char buffer[512];
            mbedtls_strerror(res, buffer, sizeof(buffer));
            throw std::exception(buffer);
        }
#if 0
        for (const auto& extensionToAdd : extensionsToAdd)
        {
            res = mbedtls_x509write_crt_set_extension(&writeCert,
                reinterpret_cast<const char*>(extensionToAdd->GetExtensionOid().PbBuffer()), extensionToAdd->GetExtensionOid().CbBuffer(),
                0,
                extensionToAdd->GetExtensionData().PbBuffer(), extensionToAdd->GetExtensionData().CbBuffer());
            if (res < 0)
            {
                char buffer[512];
                mbedtls_strerror(res, buffer, sizeof(buffer));
                throw std::exception(buffer);
            }
        }
#endif

        res = mbedtls_x509write_crt_set_subject_key_identifier(&writeCert);
        if (res < 0)
        {
            char buffer[512];
            mbedtls_strerror(res, buffer, sizeof(buffer));
            throw std::exception(buffer);
        }
        res = mbedtls_x509write_crt_set_authority_key_identifier(&writeCert);
        if (res < 0)
        {
            char buffer[512];
            mbedtls_strerror(res, buffer, sizeof(buffer));
            throw std::exception(buffer);
        }

        res = mbedtls_x509write_crt_set_key_usage(&writeCert, MBEDTLS_X509_KU_KEY_CERT_SIGN);
        if (res < 0)
        {
            char buffer[512];
            mbedtls_strerror(res, buffer, sizeof(buffer));
            throw std::exception(buffer);
        }

        auto certificateBuffer(std::vector<uint8_t>(16 * 1024));

        mbedtls_drbg_context ctr_drbg;
        entropy_context entropy;
        const char *personalization = "GenerateSGXPemKey";
        res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, reinterpret_cast<const unsigned char *>(personalization), strlen(personalization));
        if (res < 0)
        {
            char buffer[512];
            mbedtls_strerror(res, buffer, sizeof(buffer));
            throw std::exception(buffer);
        }


        res = mbedtls_x509write_crt_pem(&writeCert, certificateBuffer.data(), certificateBuffer.size(), mbedtls_ctr_drbg_random, ctr_drbg);
        if (res < 0)
        {
            char buffer[512];
            mbedtls_strerror(res, buffer, sizeof(buffer));
            throw std::exception(buffer);
        }

        std::string certificateString = std::string(certificateBuffer.data(), certificateBuffer.data() + strlen(reinterpret_cast<char *>(certificateBuffer.data())));

        return mbedtlsCert::Deserialize(certificateString);

    }

    static std::unique_ptr<mbedtlsCert> Deserialize(_In_ const std::string& serializedCertificate)
    {
        std::unique_ptr<x509_cert> certificate = std::make_unique<x509_cert>();

        const unsigned char* certificateStart = reinterpret_cast<const unsigned char*>(serializedCertificate.c_str());
        size_t certificateLength = serializedCertificate.size() + 1;
        std::vector<uint8_t> certificateAsBuffer;
        if (serializedCertificate.size() <= pemPrefixLen || strstr(serializedCertificate.c_str(), pemPrefix) == nullptr)
        {
            certificateAsBuffer = base64::decode(serializedCertificate);
            certificateStart = certificateAsBuffer.data();
            certificateLength = certificateAsBuffer.size();
        }
        int res = mbedtls_x509_crt_parse(certificate.get(), certificateStart, certificateLength);
        if (res < 0)
        {
            char buffer[512];
            mbedtls_strerror(res, buffer, sizeof(buffer));
            throw std::exception(buffer);
        }

        return std::make_unique<mbedtlsCert>(std::move(certificate));
    }
    std::vector<uint8_t> ExportAsBinary() const
    {
        return std::vector<uint8_t>(_certificate->raw.p, _certificate->raw.p + _certificate->raw.len);
    }

    std::string ExportAsBase64() const
    {
        return base64::encode(ExportAsBinary());
    }

    std::string ExportAsPEM()
    {
        std::string returnedValue = "-----BEGIN CERTIFICATE-----\r\n";
        std::string encodedKey(ExportAsBase64());
        // Insert crlf characters every 80 characters into the base64 encoded key to make it
        // prettier.
        size_t insertPos = 80;
        while (insertPos < encodedKey.length())
        {
            encodedKey.insert(insertPos, "\r\n");
            insertPos += 82; /* 80 characters plus the \r\n we just inserted */
        }

        returnedValue += encodedKey;
        returnedValue += "\r\n-----END CERTIFICATE-----\r\n";

        return returnedValue;
    }

    mbedtls_rsa_context *RsaContext()
    {
        return mbedtls_pk_rsa(_certificate->pk);
    }



private:
    std::unique_ptr<x509_cert> _certificate;
};

