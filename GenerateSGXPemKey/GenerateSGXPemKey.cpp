// GenerateSGXPemKey.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#include "mbedtlsKey.h"
#include "mbedtlsCert.h"
#include "X509Cert.h"

int main()
{
    std::cout << "Hello World!\n";

    auto rsaKey = mbedtlsKey::GenerateKeyPair(mbedtlsKey::KeyKind::RSA);

    auto signedKey = rsaKey->ExportKey(mbedtlsKey::KeyType::PublicKey);

    auto cert = mbedtlsCert::CreateForKey(rsaKey, "CN=MyCertificate", 0);
    auto encodedCert = cert->ExportAsPEM();
    auto rsaContext = cert->RsaContext();

    auto wincert = X509Cert::Deserialize(encodedCert);

    auto publicKey = wincert->GetPublicKey();
    auto exportedPublicKey = publicKey->ExportKey(PublicKey::KeyType::PublicKey);
    BCRYPT_RSAKEY_BLOB* rsaKeyBlob = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(exportedPublicKey.data());

    auto publicRawKey = wincert->ExportPublicKey();

    auto enclaveHeldData = wincert->ExportPublicKeyAsPEM();

    std::cout << "Exported Key: " << std::endl;
    std::cout << signedKey << std::endl;

    std::cout << "Retrieved Key: " << std::endl;
    std::cout << enclaveHeldData << std::endl;

    if (enclaveHeldData == signedKey)
    {
        std::cout << "Key Matches" << std::endl;
    }
    else
    {
        std::cout << "Key does not match" << std::endl;
    }

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
