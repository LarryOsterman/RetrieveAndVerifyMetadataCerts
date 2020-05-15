// RetrieveAndVerifyMetadataCerts.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#include "curl.h"
#pragma warning(push)
#pragma warning(disable: 26812)
#include <json11.hpp>
#pragma warning(pop)
#include <ios>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <VerifyMetadataCertificates.h>
#pragma warning(push)
#pragma warning(disable: 6319)
#include <wil\com.h>
#pragma warning(pop)


std::pair<size_t, std::string> FormatBufferLine(size_t startOffset, _In_reads_bytes_(cb) const uint8_t* const pb, _In_ size_t cb)
{
    // scratch buffer which will hold the data being logged.
    std::stringstream ss;

    size_t bytesToWrite = (cb < 0x10 ? cb : 0x10);

    ss << std::hex << std::right << std::setw(8) << std::setfill('0') << startOffset << ": ";

    // Write the buffer data out.
    for (size_t i = 0; i < bytesToWrite; i += 1)
    {
        ss << std::hex << std::right << std::setw(2) << std::setfill('0') << static_cast<int>(pb[i]) << " ";
    }

    // Now write the data in string format (similar to what the debugger does).
    // Start by padding partial lines to a fixed end.
    for (size_t i = bytesToWrite; i < 0x10; i += 1)
    {
        ss << "   ";
    }
    ss << "  * ";
    for (size_t i = 0; i < bytesToWrite; i += 1)
    {
        if (isprint(pb[i]))
        {
            ss << pb[i];
        }
        else
        {
            ss << ".";
        }
    }
    for (size_t i = bytesToWrite; i < 0x10; i += 1)
    {
        ss << " ";
    }

    ss << " *";

    ss << std::endl;

    return std::make_pair(bytesToWrite, ss.str());
}


std::string FormatBuffer(const char *prefix, const std::vector<uint8_t>& buffer)
{
    std::string returnedString;
    const uint8_t* pb = buffer.data();
    size_t cb = buffer.size();
    size_t currentOffset = 0;
    do
    {
        auto stringToLog = FormatBufferLine(currentOffset, pb, cb);
        pb += stringToLog.first;
        cb -= stringToLog.first;
        currentOffset += stringToLog.first;
        returnedString += prefix;
        returnedString += stringToLog.second;
    } while (cb);
    return returnedString;
}


template<size_t size>
std::string FormatBuffer(const char *prefix, const uint8_t (&bufferToPrint)[size])
{
    return FormatBuffer(prefix, std::vector<uint8_t>(bufferToPrint, bufferToPrint + size));
}



int main()
{
    SetEnvironmentVariable(L"AZCDAP_CACHE", L"c:\\temp");
    SetEnvironmentVariable(L"OE_LOG_LEVEL", L"INFO");
    _putenv("OE_LOG_LEVEL=INFO");
    _putenv("AZDCAP_CACHE=c:\\temp");

    std::cout << "Retrieve Metadata Signing Certificates from MAA" << std::endl;

    bool foundExtension = false;

    wil::com_ptr_t<IVerifyMetadataCertificates> certificateVerifier;
    GetMetadataCertificateVerifier(certificateVerifier.addressof());
    {
        curl mycurl;

        auto urljwksBytes = mycurl.RetrieveUrlData("https://ahmattestuks1.uks.attest.azure.net/certs");
        std::string urljwks(reinterpret_cast<char*>(urljwksBytes.data()), urljwksBytes.size());
        std::string error;
        json11::Json parsedJwk = json11::Json::parse(urljwks, error);

        auto keys = parsedJwk["keys"];

        for (const auto& key : keys.array_items())
        {
            if (key["kty"].is_string() && key["kty"].string_value() == "RSA")
            {
                if (key["x5c"].is_array())
                {
                    auto base64Cert = key["x5c"].array_items()[0];

                    bool extensionFound = false;
                    if (FAILED(certificateVerifier->VerifyQuoteExtensionInCertificate(base64Cert.string_value().c_str(), &extensionFound)) || !extensionFound)
                    {
                        foundExtension = true;
                        break;
                    }
                }
            }
        }
    }

    if (!foundExtension)
    {
        std::cout << "Could not find SGX quote extension in any of the provided certificates." << std::endl;
        exit(1);
    }

    std::cout << "Found a certificate which contains an embedded SGX Quote " << std::endl;

    bool quoteIsValid = false;
    if (FAILED(certificateVerifier->VerifyQuoteInExtension(&quoteIsValid)) || !quoteIsValid)
    {
        std::cout << "Could not verify SGX quote extension the certificate." << std::endl;
        exit(1);
    }

    std::cout << "SGX Quote has been successfully verified." << std::endl;



    std::cout << "Parsed SGX Report: " << std::endl;
    std::cout << " Security Version: " << certificateVerifier->SecurityVersion() << std::endl;
    std::cout << FormatBuffer("       Product ID : ", certificateVerifier->ProductId()) << std::endl;
    std::cout << FormatBuffer("         Signer ID: ", certificateVerifier->SignerId()) << std::endl;
    std::cout << FormatBuffer("        Enclave ID: ", certificateVerifier->UniqueId()) << std::endl;

    std::cout << FormatBuffer("       report data: ", certificateVerifier->ReportData());

    bool keyMatchesHash = false;
    if (FAILED(certificateVerifier->VerifyCertificateKeyMatchesHash(&keyMatchesHash)) || !keyMatchesHash)
    {
        std::cout << "Could not verify that key hash matches the quote hash." << std::endl;
        exit(1);
    }
    std::cout << "Verified that certificate key matches the hash." << std::endl;


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
